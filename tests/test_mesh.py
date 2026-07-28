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

from hermes_mesh.adapter import MeshAdapter, _is_loopback_host
from hermes_mesh.identity import (
    resolve_agent,
    get_raw_agent_identity,
    list_agents,
    _resolve_env,
    write_agent_identity,
)
from hermes_mesh.session_relay import (
    handle_mesh_send,
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
        with patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh, \
             patch("hermes_mesh.identity._legacy_a2a_agents_root") as mock_legacy:
            mock_mesh.return_value = Path("/nonexistent/path")
            mock_legacy.return_value = Path("/nonexistent2/path")
            result = resolve_agent("nonexistent")
            assert result is None

    def test_get_raw_agent_not_found(self):
        with patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh, \
             patch("hermes_mesh.identity._legacy_a2a_agents_root") as mock_legacy:
            mock_mesh.return_value = Path("/nonexistent/path")
            mock_legacy.return_value = Path("/nonexistent2/path")
            result = get_raw_agent_identity("nonexistent")
            assert result is None

    def test_list_agents_empty(self):
        with patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh, \
             patch("hermes_mesh.identity._legacy_a2a_agents_root") as mock_legacy:
            mock_mesh.return_value = Path("/nonexistent/path")
            mock_legacy.return_value = Path("/nonexistent2/path")
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
                    "a2a_rpc": {
                        "url": "http://127.0.0.1:9999",
                        "auth": {"type": "none"},
                    },
                    "hermes_webhook": {
                        "url": "http://127.0.0.1:9999/webhook",
                        "auth": {"type": "hmac-sha256", "secret": "test-secret"},
                    },
                },
            }
            with open(agent_dir / "identity.yaml", "w") as f:
                import yaml
                yaml.safe_dump(identity, f)

            with patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh, \
                 patch("hermes_mesh.identity._legacy_a2a_agents_root") as mock_legacy:
                mock_mesh.return_value = Path(tmpdir)
                mock_legacy.return_value = Path("/nonexistent/path")

                resolved = resolve_agent("testagent")
                assert resolved is not None
                assert resolved["name"] == "testagent"
                assert resolved["a2a_url"] == "http://127.0.0.1:9999/webhook"

                raw = get_raw_agent_identity("testagent")
                assert raw is not None
                assert raw["transports"]["hermes_webhook"]["auth"]["secret"] == "test-secret"


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
        for name in ["agent;", "agent\nbritney", "agent]", "agent]", "linda?"]:
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
        assert _is_ip_blocked(ipaddress.ip_address("198.18.0.1"), allow_local=True)
        assert _is_ip_blocked(ipaddress.ip_address("100.64.0.1"), allow_local=True)


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
                mock_deliver.return_value = "delivery-123"

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

            with patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh,                  patch("hermes_mesh.identity._legacy_a2a_agents_root") as mock_legacy:
                mock_mesh.return_value = Path(tmpdir)
                mock_legacy.return_value = Path("/nonexistent/path")

                from hermes_mesh.session_relay import handle_mesh_list
                result = handle_mesh_list()
                assert result["count"] == 1
                assert result["agents"][0]["name"] == "agent0"

    def test_mesh_register(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("hermes_mesh.identity._mesh_agents_root") as mock_mesh,                  patch("hermes_mesh.identity._legacy_a2a_agents_root") as mock_legacy:
                mock_mesh.return_value = Path(tmpdir)
                mock_legacy.return_value = Path("/nonexistent/path")

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

            result = handle_mesh_send({"message": "hi", "agent": "target"})
            assert result.get("status") == "delivered"
            mock_deliver.assert_called_once()
            assert mock_deliver.call_args[0][2] == "sender-secret"


class TestAdapterHandleMesh:
    """Adapter intake: replay window, envelope validation, per-agent HMAC."""

    @staticmethod
    def _make_adapter(secret="INSECURE_NO_AUTH", agent_name="ada", target_session="telegram:dm:123"):
        return MeshAdapter(
            PlatformConfig(
                extra={
                    "secret": secret,
                    "agent_name": agent_name,
                    "target_session": target_session,
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
        assert not _is_loopback_host("::")
        assert _is_loopback_host("::1")


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
            data = _pinned_request("http://example.com/webhook", b"body", {}, 5.0, allow_local=False)

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
                _pinned_request("http://example.com/webhook", b"body", {}, 5.0, allow_local=False)


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
