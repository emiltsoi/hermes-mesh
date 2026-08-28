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

from . import threads as _threads
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
) -> tuple[Optional[str], Optional[str], str]:
    """Resolve signing material and target URL for a retry.

    Returns (signing_material, target_url, error_message).
    """
    from . import auth

    target_url, error = auth.resolve_target(to_agent)
    if error:
        return None, None, error
    signing_material, error = auth.resolve_sender(from_agent, extra)
    if error:
        return None, None, error
    return signing_material, target_url, ""


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

    # B5: re-check the thread is still open before POST. A reply queued while
    # its thread was open may be retried after the thread closed — sending it
    # would just bounce THREAD_CLOSED and burn retries. Drop + log instead.
    # DSN items are exempt: their ref is correlation (delivery notification),
    # not reply intent — mirrors the inbound DSN exemption (B2).
    ref = item.get("ref")
    if ref is not None and not item.get("is_dsn") and _threads.is_closed(ref):
        logger.warning(
            "Mesh outbox: message %s references closed thread %s; dropping",
            item.get("id"), ref,
        )
        return True

    from_agent = item["from"]
    to_agent = item["to"]
    # Deliver the raw envelope (padded_message); _deliver_webhook performs the
    # JSON wire-wrap. The stored "body" field is retained for back-compat with
    # items queued before the wrap moved into the delivery path.
    envelope = item.get("padded_message") or item["body"]
    signing_material, target_url, error = _resolve_material_and_url(
        from_agent, to_agent, extra
    )
    if error:
        logger.warning("Mesh outbox: cannot resolve %s -> %s: %s", from_agent, to_agent, error)
        return False
    sign_timestamp = bool(extra and extra.get("sign_timestamp")) or _sign_timestamp_enabled()
    delivery_id, _ = _deliver_webhook(
        target_url,
        envelope,
        signing_material,
        allow_loopback=_webhook_allow_loopback() or _is_local_url(target_url),
        sign_timestamp=sign_timestamp,
        sender=from_agent,
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
