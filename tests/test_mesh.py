"""Tests for hermes-mesh session relay."""
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from hermes_mesh.identity import (
    resolve_agent,
    get_raw_agent_identity,
    list_agents,
)
from hermes_mesh.session_relay import (
    handle_send_session_message,
    _validate_target_url,
    _validate_agent_webhook_config,
)


class TestIdentity:
    def test_resolve_agent_not_found(self):
        with patch("hermes_mesh.identity._fleet_agents_root") as mock_root:
            mock_root.return_value = Path("/nonexistent/path")
            result = resolve_agent("nonexistent")
            assert result is None

    def test_get_raw_agent_not_found(self):
        with patch("hermes_mesh.identity._fleet_agents_root") as mock_root:
            mock_root.return_value = Path("/nonexistent/path")
            result = get_raw_agent_identity("nonexistent")
            assert result is None

    def test_list_agents_empty(self):
        with patch("hermes_mesh.identity._fleet_agents_root") as mock_root:
            mock_root.return_value = Path("/nonexistent/path")
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

            with patch("hermes_mesh.identity._fleet_agents_root") as mock_root:
                mock_root.return_value = Path(tmpdir)

                # resolve_agent returns safe (no credentials)
                resolved = resolve_agent("testagent")
                assert resolved is not None
                assert resolved["name"] == "testagent"
                assert resolved["a2a_url"] == "http://127.0.0.1:9999"

                # get_raw_agent_identity returns full identity
                raw = get_raw_agent_identity("testagent")
                assert raw is not None
                assert raw["transports"]["hermes_webhook"]["auth"]["secret"] == "test-secret"


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

    def test_allows_public_url(self):
        url = _validate_target_url("https://example.com/api")
        assert url == "https://example.com/api"

    def test_rejects_non_http(self):
        with pytest.raises(ValueError, match="http/https"):
            _validate_target_url("ftp://example.com")


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
        result = handle_send_session_message({"agent": "test"})
        assert "error" in result
        assert "message" in result["error"].lower()

    def test_missing_agent(self):
        result = handle_send_session_message({"message": "hello"})
        assert "error" in result
        assert "agent" in result["error"].lower()

    def test_agent_not_found(self):
        with patch("hermes_mesh.session_relay._resolve_agent_by_name") as mock_resolve:
            mock_resolve.return_value = None
            result = handle_send_session_message(
                {"message": "hello", "agent": "nonexistent"}
            )
            assert "error" in result
            assert "not found" in result["error"].lower()

    def test_successful_delivery(self):
        """End-to-end test of session relay delivery."""
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
                patch("hermes_mesh.session_relay._resolve_agent_by_name") as mock_resolve,
                patch("hermes_mesh.session_relay.get_raw_agent_identity") as mock_raw,
                patch("hermes_mesh.session_relay._deliver_webhook") as mock_deliver,
                patch("hermes_mesh.session_relay._float.send") as mock_float,
                patch("hermes_mesh.session_relay._is_local_fleet_agent") as mock_local,
            ):
                mock_resolve.return_value = {
                    "name": "testagent",
                    "a2a_url": "http://127.0.0.1:19999",
                }
                mock_raw.return_value = identity
                mock_deliver.return_value = "delivery-123"
                mock_local.return_value = True

                result = handle_send_session_message(
                    {"message": "hello test", "agent": "testagent"}
                )

                assert result.get("state") == "completed"
                assert result.get("status") == "delivered"
                assert result.get("agent") == "testagent"
                assert result.get("message_id") == "delivery-123"
                assert "task_id" in result

                # Verify webhook was called with padded message
                mock_deliver.assert_called_once()
                body = mock_deliver.call_args[0][1]
                assert "hello test" in body
                assert "[a2a]" in body

                # Verify float was called
                mock_float.assert_called_once()
