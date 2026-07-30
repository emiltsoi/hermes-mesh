"""Persistent outbox for messages that fail mesh webhook delivery.

When `MESH_OUTBOX_ENABLED=1`, a failed `mesh_send` is written to an on-disk
queue instead of returning an immediate hard error.  The `MeshAdapter` runs a
background reaper that retries queued items with exponential backoff and moves
dead items to a `dead/` folder after `MESH_OUTBOX_MAX_ATTEMPTS`.
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Optional

from .common import parse_mesh_header, record_metric, validate_envelope_token
from .network import is_local_target_host

logger = logging.getLogger(__name__)


def _outbox_root() -> Path:
    """Return the on-disk outbox directory."""
    from .identity import _fleet_root

    return Path(
        os.environ.get("MESH_OUTBOX_PATH")
        or str(_fleet_root() / "mesh" / "outbox")
    )


def _dead_letter_root() -> Path:
    """Return the dead-letter folder."""
    return _outbox_root().parent / "dead"


def outbox_enabled() -> bool:
    """Return True when the outbox is enabled."""
    env = os.environ.get("MESH_OUTBOX_ENABLED", "0")
    return env.lower() in ("1", "true", "yes")


def outbox_max_attempts() -> int:
    """Return the configured retry cap."""
    raw = os.environ.get("MESH_OUTBOX_MAX_ATTEMPTS", "5")
    try:
        return max(1, int(raw))
    except ValueError:
        return 5


def outbox_backoff() -> float:
    """Return the base retry backoff in seconds."""
    raw = os.environ.get("MESH_OUTBOX_BACKOFF", "5.0")
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 5.0


def queue_message(
    from_agent: str,
    to_agent: str,
    padded_message: str,
    body: str,
    *,
    attempt: int = 0,
    ref: str | None = None,
    is_dsn: bool = False,
) -> Path:
    """Persist a failed delivery to the outbox for later retry."""
    root = _outbox_root()
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    item = {
        "id": str(uuid.uuid4()),
        "from": from_agent,
        "to": to_agent,
        "padded_message": padded_message,
        "body": body,
        "attempt": attempt,
        "created_at": time.time(),
        "next_retry": time.time(),
        "ref": ref,
        "is_dsn": is_dsn,
    }
    path = root / f"{item['id']}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(item, f, sort_keys=True)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    record_metric("send", "outbox_queued")
    logger.info("Mesh outbox: queued message %s for %s", item["id"], to_agent)
    return path


def outbox_count() -> int:
    """Return the number of items currently in the outbox."""
    root = _outbox_root()
    if not root.is_dir():
        return 0
    return sum(1 for p in root.iterdir() if p.is_file() and p.suffix == ".json")


def _resolve_material_and_url(
    from_agent: str, to_agent: str, extra: dict | None = None
) -> tuple[Optional[str], Optional[str], Optional[str], str]:
    """Resolve signing material, target URL, and auth type for a retry.

    Returns (signing_material, target_url, auth_type, error_message).
    """
    from . import registry_bridge as _registry_bridge
    from .identity import get_raw_agent_identity
    from .session_relay import _transport, _transport_auth_value

    if _registry_bridge.identity_source(extra) == "registry":
        target = _registry_bridge.resolve_target(to_agent, extra)
        if not target:
            return None, None, None, f"Agent '{to_agent}' not found in registry"
        target_url = target.get("url", "")
        if not target_url:
            return None, None, None, f"Agent '{to_agent}' has no webhook URL in registry"
        auth = target.get("auth", {})
        if auth.get("type") != "ed25519" or not auth.get("public_key"):
            return None, None, None, f"Agent '{to_agent}' has no Ed25519 public key"
        signing_material, auth_type, _ = _registry_bridge.resolve_sender(from_agent, extra)
        if not signing_material or auth_type != "ed25519":
            return None, None, None, f"Sender '{from_agent}' has no Ed25519 private key"
        return signing_material, target_url, auth_type, ""

    raw_info = get_raw_agent_identity(to_agent)
    if not raw_info:
        return None, None, None, f"Agent '{to_agent}' not found in fleet vault"
    sender_info = get_raw_agent_identity(from_agent)
    if not sender_info:
        return None, None, None, f"Sender '{from_agent}' has no identity in fleet vault"
    sender_secret = _transport_auth_value(
        _transport(sender_info, "hermes_webhook"), "secret"
    )
    if not sender_secret:
        return None, None, None, f"Sender '{from_agent}' has no webhook secret"
    webhook = _transport(raw_info, "hermes_webhook")
    target_url = webhook.get("url", "")
    if not target_url:
        return None, None, None, f"Agent '{to_agent}' has no webhook URL in vault"
    return sender_secret, target_url, "hmac-sha256", ""


def _is_local_url(url: str) -> bool:
    """Return True when the URL's host is a known local/loopback/private endpoint."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return is_local_target_host(parsed.hostname or "")


def _webhook_allow_loopback() -> bool:
    """Return True when loopback/private webhook delivery is explicitly allowed."""
    env = (
        os.getenv("MESH_WEBHOOK_ALLOW_LOOPBACK")
        or os.getenv("A2A_WEBHOOK_ALLOW_LOOPBACK")
        or ""
    )
    return env.lower() in ("1", "true", "yes")


def _attempt_item(item: dict, extra: dict | None = None) -> bool:
    """Try to deliver one outbox item.  Return True on success."""
    from .session_relay import _deliver_webhook, _sign_timestamp_enabled

    from_agent = item["from"]
    to_agent = item["to"]
    body = item["body"]
    signing_material, target_url, auth_type, error = _resolve_material_and_url(
        from_agent, to_agent, extra
    )
    if error:
        logger.warning("Mesh outbox: cannot resolve %s -> %s: %s", from_agent, to_agent, error)
        return False
    sign_timestamp = bool(extra and extra.get("sign_timestamp")) or _sign_timestamp_enabled()
    delivery_id, _ = _deliver_webhook(
        target_url,
        body,
        signing_material,
        allow_loopback=_webhook_allow_loopback() or _is_local_url(target_url),
        auth_type=auth_type,
        sign_timestamp=sign_timestamp,
    )
    if delivery_id is not None:
        record_metric("send", "outbox_delivered")
        return True
    return False


def retry_outbox(
    max_attempts: int | None = None,
    backoff: float | None = None,
    extra: dict | None = None,
) -> dict:
    """Scan the outbox and retry due items.

    Items that exceed `max_attempts` are moved to the dead-letter folder.
    Returns {"retried": N, "delivered": N}.
    """
    if not outbox_enabled():
        return {"retried": 0, "delivered": 0}
    if max_attempts is None:
        max_attempts = outbox_max_attempts()
    if backoff is None:
        backoff = outbox_backoff()

    root = _outbox_root()
    if not root.is_dir():
        return {"retried": 0, "delivered": 0}

    retried = 0
    delivered = 0
    now = time.time()
    for path in sorted(root.iterdir()):
        if not path.is_file() or path.suffix != ".json":
            continue
        try:
            with open(path, encoding="utf-8") as f:
                item = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        if item.get("next_retry", 0) > now:
            continue

        retried += 1
        item["attempt"] = item.get("attempt", 0) + 1

        if _attempt_item(item, extra):
            path.unlink()
            delivered += 1
            continue

        if item["attempt"] >= max_attempts:
            _dead_letter_root().mkdir(parents=True, exist_ok=True)
            dead_path = _dead_letter_root() / path.name
            try:
                os.replace(path, dead_path)
            except OSError:
                path.unlink()
            record_metric("send", "outbox_dead")
            logger.warning(
                "Mesh outbox: message %s exceeded max attempts, moved to dead letter",
                item.get("id"),
            )
            if not item.get("is_dsn"):
                try:
                    from .session_relay import _send_delivery_error
                    header = parse_mesh_header(item.get("padded_message", ""))
                    if header:
                        original_from = header["sender"]
                        original_to = header["recipient"]
                        original_id = validate_envelope_token(header["msg_id"])
                        ref = item.get("ref") or header.get("ref")
                        dsn_to = original_to if ref else original_from
                        _send_delivery_error(
                            original_from,
                            dsn_to,
                            original_id,
                            "dead-letter",
                            original_from,
                            original_to,
                        )
                except Exception as e:
                    logger.warning("Mesh outbox: failed to send DSN for dead letter %s: %s", item.get("id"), e)
        else:
            item["next_retry"] = now + (backoff * (2 ** (item["attempt"] - 1)))
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(item, f, sort_keys=True)
            except OSError:
                pass

    return {"retried": retried, "delivered": delivered}
