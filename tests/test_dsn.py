"""Delivery-Status Notification (DSN) tests for hermes-mesh."""
import asyncio
import json
import os
import re
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hermes_mesh import auth as mesh_auth, common, session_relay


def _identity(name, url="http://127.0.0.1:8645/mesh/receive", public_key="test-public-key-pem"):
    return {
        "id": name,
        "name": name,
        "transports": {
            "hermes_webhook": {
                "url": url,
                "auth": {"public_key": public_key},
            },
        },
    }


class TestDSNHelpers:
    def test_make_dsn_text_format(self):
        text = session_relay._make_dsn_text(
            "from_agent", "to_agent", "orig-123", "unreachable", "sender", "target"
        )
        assert text.startswith("[mesh]")
        assert "[mesh-dsn]" in text
        assert "[ref:orig-123]" in text
        assert "unreachable" in text

    def test_parse_mesh_header(self):
        text = "[mesh][v:1][from:a][to:b][id:c][action:do][reply:no][ref:d] hello"
        parsed = common.parse_mesh_header(text)
        assert parsed["sender"] == "a"
        assert parsed["recipient"] == "b"
        assert parsed["msg_id"] == "c"
        assert parsed["ref"] == "d"
        assert parsed["body_text"] == "hello"

    def test_parse_mesh_header_no_ref(self):
        text = "[mesh][from:a][to:b][id:c][action:do][reply:yes] hello"
        parsed = common.parse_mesh_header(text)
        assert parsed["ref"] is None


class TestDSNDelivery:
    def test_send_delivery_error_best_effort(self):
        """_send_delivery_error builds a DSN and sends it with X-Mesh-DSN."""
        from_agent = _identity("from_agent")
        to_agent = _identity("to_agent")

        with (
            patch.dict(
                os.environ,
                {
                    "MESH_DSN_ENABLED": "1",
                    "MESH_DSN_RATE_LIMIT": "10",
                },
            ),
            patch(
                "hermes_mesh.identity.get_raw_agent_identity"
            ) as mock_raw,
            patch(
                "hermes_mesh.auth.resolve_sender"
            ) as mock_resolve_sender,
            patch(
                "hermes_mesh.session_relay._deliver_webhook"
            ) as mock_deliver,
        ):
            mock_deliver.return_value = ("dsn-delivery-id", None)
            mock_resolve_sender.return_value = ("fake-private-key-pem", None)

            def _raw(name):
                if name == "from_agent":
                    return from_agent
                return to_agent

            mock_raw.side_effect = _raw

            session_relay._send_delivery_error(
                "from_agent",
                "to_agent",
                "orig-123",
                "unreachable",
                "from_agent",
                "to_agent",
            )

            assert mock_deliver.called
            call = mock_deliver.call_args
            extra_headers = call.kwargs.get("extra_headers") or call[1].get("extra_headers")
            assert extra_headers == {"X-Mesh-DSN": "1"}
            body = call[0][1]
            payload = json.loads(body)
            assert payload["from"] == "from_agent"
            assert "[mesh-dsn]" in payload["text"]


class TestDSNSendFailure:
    def test_handle_mesh_send_fails_with_dsn(self):
        """A failed mesh_send (no outbox) triggers a DSN to the sender."""
        with (
            patch.dict(
                os.environ,
                {
                    "MESH_AGENT_NAME": "sender",
                    "MESH_OUTBOX_ENABLED": "0",
                    "MESH_DSN_ENABLED": "1",
                    "MESH_DSN_RATE_LIMIT": "10",
                },
            ),
            patch(
                "hermes_mesh.identity.get_raw_agent_identity"
            ) as mock_raw,
            patch(
                "hermes_mesh.auth.resolve_sender"
            ) as mock_resolve_sender,
            patch(
                "hermes_mesh.session_relay._deliver_webhook"
            ) as mock_deliver,
            patch("hermes_mesh.session_relay._float.send"),
        ):

            def _raw(name):
                if name == "sender":
                    return _identity("sender")
                return _identity("target")

            mock_raw.side_effect = _raw
            mock_resolve_sender.return_value = ("fake-private-key-pem", None)
            mock_deliver.return_value = (None, "unreachable")


            result = session_relay.handle_mesh_send(
                {"message": "hi", "agent": "target", "action": "info", "reply": "no"}
            )

            assert result.get("error")

            # First call is the message; second call should be the DSN.
            assert mock_deliver.call_count == 2
            dsn_call = mock_deliver.call_args_list[1]
            extra = dsn_call.kwargs.get("extra_headers") or dsn_call[1].get("extra_headers")
            assert extra == {"X-Mesh-DSN": "1"}


class TestF2_NoDSNForDSN:
    """F2 AC-2.3: DSN responses never spawn DSNs — on the receive side
    (`_send_receive_dsn` bails on DSN-shaped requests) and on the send side
    (`_send_delivery_error` bails on `is_dsn=True`)."""

    def test_dsn_shaped_receive_failure_does_not_spawn_dsn(self):
        """A DSN-shaped inbound that fails receive-side (recipient mismatch)
        sends no DSN back."""
        from hermes_mesh.adapter import MeshAdapter
        from gateway.config import PlatformConfig

        adapter = MeshAdapter(
            PlatformConfig(
                extra={
                    "secret": "INSECURE_NO_AUTH",
                    "agent_name": "ada",
                    "target_session": "telegram:dm:123",
                }
            )
        )
        text = (
            "[mesh][from:ada][to:OTHER][id:m1][action:info][reply:no][ref:orig-1] "
            "[mesh-dsn][status:failed][reason:unreachable]"
        )
        req = MagicMock()
        req.read = AsyncMock(return_value=json.dumps({"from": "ada", "text": text}).encode())
        req.headers = {"X-Mesh-Timestamp": str(time.time())}
        with patch("hermes_mesh.adapter._send_delivery_error") as mock_send, \
             patch.dict(os.environ, {"MESH_DSN_ENABLED": "1"}):
            resp = asyncio.run(adapter._handle_mesh(req))
        assert resp.status == 404
        mock_send.assert_not_called()

    def test_send_delivery_error_skips_dsn_for_dsn(self):
        """_send_delivery_error(is_dsn=True) never delivers a DSN."""
        with patch.dict(os.environ, {"MESH_DSN_ENABLED": "1", "MESH_DSN_RATE_LIMIT": "10"}), \
             patch("hermes_mesh.session_relay._deliver_webhook") as mock_deliver:
            session_relay._send_delivery_error(
                "from_agent", "to_agent", "orig-123", "unreachable",
                "from_agent", "to_agent", is_dsn=True,
            )
            mock_deliver.assert_not_called()
