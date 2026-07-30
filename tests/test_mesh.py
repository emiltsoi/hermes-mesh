"""Tests for hermes-mesh session relay — includes SEC-01 and SEC-02 regression tests."""
import asyncio
import hashlib
import hmac
import json
import os
import stat
import tempfile
import time
import urllib.error
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hermes_mesh.adapter import MeshAdapter
from hermes_mesh.network import is_loopback_bind_host
from hermes_mesh.common import validate_envelope_token
from hermes_mesh.identity import (
    resolve_agent,
    get_raw_agent_identity,
    list_agents,
    _resolve_env,
    write_agent_identity,
)
from hermes_mesh.session_relay import (
    handle_mesh_send,
    handle_mesh_list,
    handle_mesh_register,
    _validate_target_url,
    _validate_agent_webhook_config,
    _validate_agent_name,
    _pinned_request,
    _is_ip_blocked,
)
from gateway.config import PlatformConfig
from hermes_mesh import float as float_module


class TestIdentity:
    def test_resolve_agent_not_found(self):
        with patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh:
            mock_mesh.return_value = Path("/nonexistent/path")
            result = resolve_agent("nonexistent")
            assert result is None

    def test_get_raw_agent_not_found(self):
        with patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh:
            mock_mesh.return_value = Path("/nonexistent/path")
            result = get_raw_agent_identity("nonexistent")
            assert result is None

    def test_list_agents_empty(self):
        with patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh:
            mock_mesh.return_value = Path("/nonexistent/path")
            result = list_agents()
            assert result == []

    def test_resolve_and_get_raw_agent(self):
        """Integration test: create a temp identity and resolve it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            agent_dir = Path(tmpdir) / "testagent"
            agent_dir.mkdir()
            identity = {
                "id": "testagent",
                "name": "testagent",
                "description": "Test agent",
                "role": "tester",
                "transports": {
                    "hermes_webhook": {
                        "url": "http://127.0.0.1:9999/webhook",
                        "auth": {"type": "hmac-sha256", "secret": "test-secret"},
                    },
                },
            }
            with open(agent_dir / "identity.yaml", "w") as f:
                import yaml
                yaml.safe_dump(identity, f)

            with patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh:
                mock_mesh.return_value = Path(tmpdir)

                resolved = resolve_agent("testagent")
                assert resolved is not None
                assert resolved["name"] == "testagent"
                assert resolved["url"] == "http://127.0.0.1:9999/webhook"

                raw = get_raw_agent_identity("testagent")
                assert raw is not None
                assert raw["transports"]["hermes_webhook"]["auth"]["secret"] == "test-secret"

    def test_resolve_agent_without_webhook_returns_empty_url(self):
        """Regression: identity without hermes_webhook should return no mesh url."""
        with tempfile.TemporaryDirectory() as tmpdir:
            agent_dir = Path(tmpdir) / "notarget"
            agent_dir.mkdir()
            identity = {
                "id": "notarget",
                "name": "notarget",
                "description": "No webhook",
                "role": "tester",
                "transports": {},
            }
            import yaml
            with open(agent_dir / "identity.yaml", "w") as f:
                yaml.safe_dump(identity, f)

            with patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh:
                mock_mesh.return_value = Path(tmpdir)
                resolved = resolve_agent("notarget")
                assert resolved is not None
                assert resolved["url"] == ""


class TestSEC01_EnvVarProtection:
    """SEC-01: Fail-closed when env var is not set."""

    def test_unset_env_var_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="not set"):
                _resolve_env("${UNSET_VAR}")

    def test_set_env_var_resolves(self):
        with patch.dict(os.environ, {"MY_SECRET": "actual-secret"}):
            result = _resolve_env("${MY_SECRET}")
            assert result == "actual-secret"

    def test_plain_value_passes_through(self):
        result = _resolve_env("plain-secret")
        assert result == "plain-secret"

    def test_non_string_coerced_to_str(self):
        result = _resolve_env(42)
        assert result == "42"


class TestSEC02_AgentNameValidation:
    """SEC-02: Reject path traversal and injection characters in agent names."""

    def test_valid_names_accepted(self):
        for name in ["linda", "britney", "agent0", "my_agent", "test.agent", "agent-1"]:
            assert _validate_agent_name(name) == name.lower()

    def test_path_traversal_rejected(self):
        with pytest.raises(ValueError):
            _validate_agent_name("../../../etc/passwd")
        with pytest.raises(ValueError):
            _validate_agent_name("agent/../britney")

    def test_dots_only_rejected(self):
        with pytest.raises(ValueError, match="contains '..'"):
            _validate_agent_name("..")

    def test_injection_characters_rejected(self):
        for name in ["agent;", "agent\nbritney", "agent]", "linda?"]:
            with pytest.raises(ValueError):
                _validate_agent_name(name)

    def test_empty_rejected(self):
        with pytest.raises(ValueError, match="empty"):
            _validate_agent_name("")

    def test_strips_whitespace(self):
        assert _validate_agent_name("  linda  ") == "linda"

    def test_rejected_at_session_relay_level(self):
        result = handle_mesh_send(
            {"message": "hello", "agent": "../../../etc"}
        )
        assert "error" in result
        assert "contains '..'" in result["error"]


class TestSSRF:
    def test_blocks_loopback(self):
        with pytest.raises(ValueError, match="Loopback"):
            _validate_target_url("http://127.0.0.1:8080/webhook")

    def test_allows_loopback_when_permitted(self):
        url = _validate_target_url("http://127.0.0.1:8080/webhook", allow_loopback=True)
        assert "127.0.0.1" in url

    def test_blocks_private_ip(self):
        with pytest.raises(ValueError, match="Private"):
            _validate_target_url("http://192.168.1.1/admin")

    def test_allows_public_ip(self):
        # Use a literal public IP so the test does not depend on external DNS.
        url = _validate_target_url("https://1.1.1.1/api")
        assert url == "https://1.1.1.1/api"

    def test_blocks_172_17_private(self):
        # 172.16.0.0/12 is private; string-prefix checks used to miss 172.17-172.31.
        with pytest.raises(ValueError, match="Private"):
            _validate_target_url("http://172.17.0.1/admin")

    def test_rejects_non_http(self):
        with pytest.raises(ValueError, match="http/https"):
            _validate_target_url("ftp://example.com")

    def test_blocks_benchmark_when_loopback_allowed(self):
        # 198.18.0.0/15 is benchmark; it must not be treated as a local target.
        with pytest.raises(ValueError):
            _validate_target_url("http://198.18.0.1/admin", allow_loopback=True)

    def test_ip_blocked_blocks_benchmark_even_in_local_mode(self):
        import ipaddress
        assert _is_ip_blocked(ipaddress.ip_address("198.18.0.1"), allow_loopback=True)
        assert _is_ip_blocked(ipaddress.ip_address("100.64.0.1"), allow_loopback=True)


class TestWebhookValidation:
    def test_missing_url(self):
        ok, err = _validate_agent_webhook_config({"transports": {}})
        assert not ok
        assert "url" in err.lower()

    def test_missing_secret(self):
        ok, err = _validate_agent_webhook_config({
            "transports": {
                "hermes_webhook": {
                    "url": "http://127.0.0.1:9999",
                    "auth": {"type": "hmac-sha256"},
                }
            }
        })
        assert not ok
        assert "secret" in err.lower()

    def test_valid_config(self):
        ok, err = _validate_agent_webhook_config({
            "transports": {
                "hermes_webhook": {
                    "url": "http://127.0.0.1:9999/webhook",
                    "auth": {"type": "hmac-sha256", "secret": "test-secret"},
                }
            }
        })
        assert ok
        assert err == ""


class TestSessionRelay:
    def test_missing_message(self):
        result = handle_mesh_send({"agent": "test"})
        assert "error" in result
        assert "message" in result["error"].lower()

    def test_missing_agent(self):
        result = handle_mesh_send({"message": "hello"})
        assert "error" in result
        assert "agent" in result["error"].lower()

    def test_agent_not_found(self):
        with patch("hermes_mesh.session_relay.get_raw_agent_identity") as mock_raw:
            mock_raw.return_value = None
            result = handle_mesh_send(
                {"message": "hello", "agent": "nonexistent"}
            )
            assert "error" in result
            assert "not found" in result["error"].lower()

    def test_successful_delivery(self):
        """End-to-end test of session relay delivery."""
        import os
        import yaml

        with tempfile.TemporaryDirectory() as tmpdir:
            agent_dir = Path(tmpdir) / "testagent"
            agent_dir.mkdir()
            identity = {
                "id": "testagent",
                "name": "testagent",
                "transports": {
                    "hermes_webhook": {
                        "url": "http://127.0.0.1:19999/webhook",
                        "auth": {"type": "hmac-sha256", "secret": "test-secret"},
                    },
                },
            }
            with open(agent_dir / "identity.yaml", "w") as f:
                yaml.safe_dump(identity, f)

            with (
                patch.dict(os.environ, {"MESH_AGENT_NAME": "testagent"}),
                patch("hermes_mesh.session_relay.get_raw_agent_identity") as mock_raw,
                patch("hermes_mesh.session_relay._deliver_webhook") as mock_deliver,
                patch("hermes_mesh.session_relay._float.send") as mock_float,
            ):
                mock_raw.return_value = identity
                mock_deliver.return_value = ("delivery-123", None)

                result = handle_mesh_send(
                    {"message": "hello test", "agent": "testagent"}
                )

                assert result.get("state") == "completed"
                assert result.get("status") == "delivered"
                assert result.get("agent") == "testagent"
                assert result.get("message_id") == "delivery-123"
                assert "task_id" in result

                mock_deliver.assert_called_once()
                body = mock_deliver.call_args[0][1]
                assert "hello test" in body
                assert "[mesh]" in body

                mock_float.assert_called_once()

class TestMeshListRegister:
    """mesh_list and mesh_register tool handlers."""

    def test_mesh_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            agent_dir = Path(tmpdir) / "agent0"
            agent_dir.mkdir()
            identity = {
                "id": "agent0",
                "name": "agent0",
                "transports": {
                    "hermes_webhook": {
                        "url": "http://127.0.0.1:8645/mesh/receive",
                        "auth": {"type": "hmac-sha256", "secret": "secret"},
                    },
                },
            }
            import yaml
            with open(agent_dir / "identity.yaml", "w") as f:
                yaml.safe_dump(identity, f)

            with patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh:
                mock_mesh.return_value = Path(tmpdir)

                from hermes_mesh.session_relay import handle_mesh_list
                result = handle_mesh_list()
                assert result["count"] == 1
                assert result["agents"][0]["name"] == "agent0"

    def test_mesh_register(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"MESH_REGISTER_ALLOW_LOOPBACK": "1"}), \
                 patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh:
                mock_mesh.return_value = Path(tmpdir)

                from hermes_mesh.session_relay import handle_mesh_register
                result = handle_mesh_register({
                    "name": "daji",
                    "url": "http://127.0.0.1:8645/mesh/receive",
                    "secret": "daji-secret",
                    "role": "operator",
                })
                assert result["registered"] is True
                assert result["name"] == "daji"

                # mesh_list should now include daji
                from hermes_mesh.session_relay import handle_mesh_list
                result2 = handle_mesh_list()
                assert any(a["name"] == "daji" for a in result2["agents"])



class TestHMACSecretSelection:
    """mesh_send signs with the sender's own secret for per-agent HMAC."""

    def test_uses_sender_secret(self):
        """When a sender identity exists, mesh_send signs with that secret."""
        import os
        from unittest.mock import patch
        from hermes_mesh.session_relay import handle_mesh_send

        target_identity = {
            "id": "target",
            "name": "target",
            "transports": {
                "hermes_webhook": {
                    "url": "http://127.0.0.1:8645/mesh/receive",
                    "auth": {"type": "hmac-sha256", "secret": "target-secret"},
                },
            },
        }
        sender_identity = {
            "id": "sender",
            "name": "sender",
            "transports": {
                "hermes_webhook": {
                    "url": "http://127.0.0.1:8645/mesh/receive",
                    "auth": {"type": "hmac-sha256", "secret": "sender-secret"},
                },
            },
        }

        def _raw(name):
            if name == "sender":
                return sender_identity
            return target_identity

        with patch.dict(os.environ, {"MESH_AGENT_NAME": "sender"}),              patch("hermes_mesh.session_relay.get_raw_agent_identity", side_effect=_raw),              patch("hermes_mesh.session_relay._deliver_webhook") as mock_deliver,              patch("hermes_mesh.session_relay._float.send"):
            mock_deliver.return_value = ("delivered", None)

            result = handle_mesh_send({"message": "hi", "agent": "target"})
            assert result.get("status") == "delivered"
            mock_deliver.assert_called_once()
            assert mock_deliver.call_args[0][2] == "sender-secret"


class TestAdapterHandleMesh:
    """Adapter intake: replay window, envelope validation, per-agent HMAC."""

    @staticmethod
    def _make_adapter(secret="INSECURE_NO_AUTH", agent_name="ada", target_session="telegram:dm:123", host=None):
        return MeshAdapter(
            PlatformConfig(
                extra={
                    "secret": secret,
                    "agent_name": agent_name,
                    "target_session": target_session,
                    "host": host,
                }
            )
        )

    @staticmethod
    def _make_request(body, headers):
        request = MagicMock()
        request.read = AsyncMock(return_value=json.dumps(body).encode())
        request.headers = headers
        return request

    @staticmethod
    def _envelope(sender="ada", recipient="ADA", msg_id="testid-123", action="do", reply="yes", ref=None, body="hello"):
        header = (
            f"[mesh][from:{sender}][to:{recipient}][id:{msg_id}]"
            f"[action:{action}][reply:{reply}]"
        )
        if ref:
            header += f"[ref:{ref}]"
        return f"{header} {body}"

    @staticmethod
    def _run(coro):
        return asyncio.run(coro)

    def test_lowercase_agent_name(self):
        adapter = self._make_adapter(agent_name="ADA")
        assert adapter._agent_name == "ada"

    def test_rejects_nan_timestamp(self):
        adapter = self._make_adapter()
        text = self._envelope()
        req = self._make_request(
            {"from": "ada", "text": text},
            {"X-Mesh-Timestamp": "NaN"},
        )
        resp = self._run(adapter._handle_mesh(req))
        assert resp.status == 401

    def test_rejects_inf_timestamp(self):
        adapter = self._make_adapter()
        text = self._envelope()
        req = self._make_request(
            {"from": "ada", "text": text},
            {"X-Mesh-Timestamp": "Infinity"},
        )
        resp = self._run(adapter._handle_mesh(req))
        assert resp.status == 401

    def test_rejects_past_timestamp(self):
        adapter = self._make_adapter()
        text = self._envelope()
        req = self._make_request(
            {"from": "ada", "text": text},
            {"X-Mesh-Timestamp": str(time.time() - 500)},
        )
        resp = self._run(adapter._handle_mesh(req))
        assert resp.status == 401

    def test_rejects_future_timestamp(self):
        adapter = self._make_adapter()
        text = self._envelope()
        req = self._make_request(
            {"from": "ada", "text": text},
            {"X-Mesh-Timestamp": str(time.time() + 500)},
        )
        resp = self._run(adapter._handle_mesh(req))
        assert resp.status == 401

    def test_accepts_valid_timestamp(self):
        adapter = self._make_adapter()
        text = self._envelope()
        req = self._make_request(
            {"from": "ada", "text": text},
            {"X-Mesh-Timestamp": str(time.time())},
        )
        resp = self._run(adapter._handle_mesh(req))
        assert resp.status == 202

    def test_rejects_invalid_action(self):
        adapter = self._make_adapter()
        text = self._envelope(action="drop-table")
        req = self._make_request(
            {"from": "ada", "text": text},
            {"X-Mesh-Timestamp": str(time.time())},
        )
        resp = self._run(adapter._handle_mesh(req))
        assert resp.status == 400

    def test_rejects_invalid_sender(self):
        adapter = self._make_adapter()
        text = self._envelope(sender="ada; rm -rf /")
        req = self._make_request(
            {"from": "ada; rm -rf /", "text": text},
            {"X-Mesh-Timestamp": str(time.time())},
        )
        resp = self._run(adapter._handle_mesh(req))
        assert resp.status in (400, 401)

    def test_hmac_verifies_with_sender_secret(self):
        adapter = self._make_adapter(secret="receiver-secret")
        sender = "daji"
        text = self._envelope(sender=sender, recipient="ada")
        body = json.dumps({"from": sender, "text": text}, sort_keys=True).encode()
        sig = "sha256=" + hmac.new(b"sender-secret", body, hashlib.sha256).hexdigest()
        req = self._make_request(
            {"from": sender, "text": text},
            {
                "X-Mesh-Timestamp": str(time.time()),
                "X-Hub-Signature-256": sig,
            },
        )
        with patch("hermes_mesh.adapter.get_raw_agent_identity") as mock_raw, \
             patch("hermes_mesh.adapter._transport") as mock_transport, \
             patch("hermes_mesh.adapter._transport_auth_value", return_value="sender-secret"):
            mock_raw.return_value = {"id": sender}
            mock_transport.return_value = {"auth": {"secret": "sender-secret"}}
            resp = self._run(adapter._handle_mesh(req))
        assert resp.status == 202

    def test_hmac_rejects_bad_signature(self):
        adapter = self._make_adapter(secret="receiver-secret")
        sender = "daji"
        text = self._envelope(sender=sender, recipient="ada")
        req = self._make_request(
            {"from": sender, "text": text},
            {
                "X-Mesh-Timestamp": str(time.time()),
                "X-Hub-Signature-256": "sha256=badcafe",
            },
        )
        with patch("hermes_mesh.adapter.get_raw_agent_identity") as mock_raw, \
             patch("hermes_mesh.adapter._transport") as mock_transport, \
             patch("hermes_mesh.adapter._transport_auth_value", return_value="sender-secret"):
            mock_raw.return_value = {"id": sender}
            mock_transport.return_value = {"auth": {"secret": "sender-secret"}}
            resp = self._run(adapter._handle_mesh(req))
        assert resp.status == 401

    def test_rejects_non_object_json_body(self):
        adapter = self._make_adapter()
        req = self._make_request("plain string", {"X-Mesh-Timestamp": str(time.time())})
        resp = self._run(adapter._handle_mesh(req))
        assert resp.status == 400

    def test_rejects_unspecified_ipv6_for_insecure_mode(self):
        # :: is the unspecified (all-interfaces) address, not loopback.
        assert not is_loopback_bind_host("::")
        assert is_loopback_bind_host("::1")


class TestPinnedRequest:
    """_pinned_request should try every resolved IP, not just the first."""

    def test_tries_multiple_resolved_ips(self):
        import socket as _socket

        addrinfo = [
            (_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("1.2.3.4", 80)),
            (_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("1.2.3.5", 80)),
        ]

        conn1 = MagicMock()
        conn1.request.side_effect = ConnectionRefusedError("refused")
        conn2 = MagicMock()
        fake_resp = MagicMock()
        fake_resp.status = 200
        fake_resp.reason = "OK"
        fake_resp.headers = {}
        fake_resp.read.return_value = b'{"status":"ok"}'
        conn2.getresponse.return_value = fake_resp

        with patch("hermes_mesh.session_relay.socket.getaddrinfo", return_value=addrinfo), \
             patch("hermes_mesh.session_relay.http.client.HTTPConnection") as MockConn:
            MockConn.side_effect = [conn1, conn2]
            data = _pinned_request("http://example.com/webhook", b"body", {}, 5.0, allow_loopback=False)

        assert data == b'{"status":"ok"}'
        assert MockConn.call_count == 2
        assert conn1.request.called
        assert conn2.request.called

    def test_blocks_private_ip_immediately(self):
        import socket as _socket

        addrinfo = [
            (_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("192.168.1.1", 80)),
        ]
        with patch("hermes_mesh.session_relay.socket.getaddrinfo", return_value=addrinfo), \
             patch("hermes_mesh.session_relay.http.client.HTTPConnection"):
            with pytest.raises(ValueError, match="Private"):
                _pinned_request("http://example.com/webhook", b"body", {}, 5.0, allow_loopback=False)


class TestIdentityFilePermissions:
    """Identity files should be 0o600 and parent directories 0o700."""

    def test_write_agent_identity_sets_secure_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh:
                mock_mesh.return_value = Path(tmpdir)
                path = write_agent_identity("testagent", {"id": "testagent"})
                assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
                assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700


class TestFloatTokenRedaction:
    """Telegram bot token must not appear in float logs."""

    def test_http_error_logs_redact_token(self, caplog):
        with patch.dict(os.environ, {"HERMES_TELEGRAM_BOT_TOKEN": "secret-token-123", "HERMES_TELEGRAM_DEFAULT_CHAT_ID": "987654"}), \
             patch("urllib.request.urlopen") as mock_open:
            err = urllib.error.HTTPError(
                "https://api.telegram.org/botsecret-token-123/sendMessage",
                401,
                "Forbidden",
                None,
                None,
            )
            mock_open.side_effect = err
            with caplog.at_level("ERROR", logger="hermes_mesh.float"):
                float_module.send("hello", sender_name="test")
        assert "secret-token-123" not in caplog.text

    def test_generic_exception_logs_redact_token(self, caplog):
        with patch.dict(os.environ, {"HERMES_TELEGRAM_BOT_TOKEN": "secret-token-123", "HERMES_TELEGRAM_DEFAULT_CHAT_ID": "987654"}), \
             patch("urllib.request.urlopen") as mock_open:
            mock_open.side_effect = Exception(
                "failed: https://api.telegram.org/botsecret-token-123/sendMessage"
            )
            with caplog.at_level("ERROR", logger="hermes_mesh.float"):
                float_module.send("hello", sender_name="test")
        assert "secret-token-123" not in caplog.text


class TestMeshRegister:
    """mesh_register should create and optionally overwrite identities."""

    def test_refuses_overwrite_by_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"MESH_REGISTER_ALLOW_LOOPBACK": "1"}), \
                 patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh:
                mock_mesh.return_value = Path(tmpdir)

                handle_mesh_register({
                    "name": "daji",
                    "url": "http://127.0.0.1:8645/mesh/receive",
                    "secret": "daji-secret",
                })
                result = handle_mesh_register({
                    "name": "daji",
                    "url": "http://127.0.0.1:8646/mesh/receive",
                    "secret": "new-secret",
                })
                assert result["registered"] is False
                assert "overwrite=True" in result["error"]

    def test_allows_overwrite_when_requested(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"MESH_REGISTER_ALLOW_LOOPBACK": "1"}), \
                 patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh:
                mock_mesh.return_value = Path(tmpdir)

                handle_mesh_register({
                    "name": "daji",
                    "url": "http://127.0.0.1:8645/mesh/receive",
                    "secret": "daji-secret",
                })
                result = handle_mesh_register({
                    "name": "daji",
                    "url": "http://127.0.0.1:8646/mesh/receive",
                    "secret": "new-secret",
                    "overwrite": True,
                })
                assert result["registered"] is True


class TestEnvelopeToken:
    """Shared envelope-token validator."""

    def test_accepts_valid_tokens(self):
        assert validate_envelope_token("msg-123") == "msg-123"
        assert validate_envelope_token("a.b_c:1-2") == "a.b_c:1-2"

    def test_rejects_empty_or_too_long(self):
        with pytest.raises(ValueError):
            validate_envelope_token("")
        with pytest.raises(ValueError):
            validate_envelope_token("x" * 129)

    def test_rejects_invalid_characters(self):
        with pytest.raises(ValueError):
            validate_envelope_token("bad token")
        with pytest.raises(ValueError):
            validate_envelope_token("bad\nchar")


class TestMeshSendValidation:
    """handle_mesh_send validates envelope tokens including task_id."""

    def test_rejects_invalid_task_id(self):
        with pytest.raises(ValueError):
            validate_envelope_token("bad id")

    def test_uses_custom_task_id_in_envelope(self):
        import os

        target_identity = {
            "id": "target",
            "name": "target",
            "transports": {
                "hermes_webhook": {
                    "url": "http://127.0.0.1:8645/mesh/receive",
                    "auth": {"type": "hmac-sha256", "secret": "target-secret"},
                },
            },
        }
        sender_identity = {
            "id": "sender",
            "name": "sender",
            "transports": {
                "hermes_webhook": {
                    "url": "http://127.0.0.1:8645/mesh/receive",
                    "auth": {"type": "hmac-sha256", "secret": "sender-secret"},
                },
            },
        }

        def _raw(name):
            if name == "sender":
                return sender_identity
            return target_identity

        with patch.dict(os.environ, {"MESH_AGENT_NAME": "sender"}), \
             patch("hermes_mesh.session_relay.get_raw_agent_identity", side_effect=_raw), \
             patch("hermes_mesh.session_relay._deliver_webhook") as mock_deliver, \
             patch("hermes_mesh.session_relay._float.send"):
            mock_deliver.return_value = ("delivered", None)
            result = handle_mesh_send({"message": "hi", "agent": "target", "task_id": "custom-123"})
            assert result.get("status") == "delivered"
            assert result.get("task_id") == "custom-123"
            body = mock_deliver.call_args[0][1]
            assert "[id:custom-123]" in body


class TestMeshAdapterLifecycle:
    """MeshAdapter send/connect behavior."""

    def test_send_is_no_op(self):
        adapter = TestAdapterHandleMesh._make_adapter()
        result = self._run(adapter.send("mesh:sender:123", "reply text"))
        assert result.success is True

    def test_insecure_no_auth_blocks_non_loopback_bind(self):
        with patch("hermes_mesh.adapter.web"):
            adapter = TestAdapterHandleMesh._make_adapter(host="0.0.0.0")
            with pytest.raises(ValueError, match="INSECURE_NO_AUTH"):
                self._run(adapter.connect())

    def test_insecure_no_auth_allows_loopback_bind(self):
        with patch("hermes_mesh.adapter.web") as mock_web:
            mock_web.AppRunner.return_value.setup = AsyncMock()
            site = MagicMock()
            site.start = AsyncMock()
            mock_web.TCPSite.return_value = site
            adapter = TestAdapterHandleMesh._make_adapter(host="127.0.0.1")
            ok = self._run(adapter.connect())
            assert ok is True

    @staticmethod
    def _run(coro):
        return asyncio.run(coro)



class TestRegistrySend:
    """mesh_send using mesh-peer-registry for identity and Ed25519 signing."""

    def test_registry_send_signs_with_ed25519(self, tmp_path, monkeypatch):
        pytest.importorskip("mesh_peer_registry")
        import yaml
        from mesh_peer_registry.crypto import (
            generate_keypair,
            verify_message,
        )
        from mesh_peer_registry.models import PeerInfo
        from cryptography.hazmat.primitives import serialization

        hermes_home = tmp_path
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))
        monkeypatch.setenv("MESH_AGENT_NAME", "sender")

        # Pre-generate sender keypair so handle_mesh_send can load it
        private_pem, public_pem = generate_keypair()
        key_dir = hermes_home / ".mesh" / "keys"
        key_dir.mkdir(parents=True)
        key_path = key_dir / "sender.pem"
        key_path.write_text(private_pem)

        # Agent config: identity_source = registry
        config = {
            "platforms": {
                "mesh": {
                    "extra": {
                        "identity_source": "registry",
                        "registry_url": "http://127.0.0.1:8646",
                        "private_key_path": str(key_path),
                    }
                }
            }
        }
        (hermes_home / "config.yaml").write_text(yaml.safe_dump(config))

        # Public key for verification
        priv_key = serialization.load_pem_private_key(
            private_pem.encode("utf-8"), password=None
        )
        sender_public = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        fake_peer = PeerInfo(
            name="target",
            url="http://127.0.0.1:8646/mock-receive",
            public_key=sender_public,
        )

        with patch("hermes_mesh.session_relay._pinned_request") as mock_pinned, \
             patch("hermes_mesh.registry_bridge.RegistryClient") as MockClient:
            mock_pinned.return_value = b'{"delivery_id":"d1"}'
            MockClient.return_value.get_peer.return_value = fake_peer

            result = handle_mesh_send({"message": "hello registry", "agent": "target"})

        assert result.get("status") == "delivered"
        assert result.get("message_id") == "d1"
        assert mock_pinned.call_count == 1

        url, body, headers, *_ = mock_pinned.call_args[0]
        assert url == "http://127.0.0.1:8646/mock-receive"
        assert "hello registry" in body.decode("utf-8")
        assert headers.get("X-Mesh-Signature")
        assert headers.get("X-Mesh-Timestamp")
        assert "X-Hub-Signature-256" not in headers

        sig = headers["X-Mesh-Signature"]
        assert verify_message(sender_public, body, sig)
