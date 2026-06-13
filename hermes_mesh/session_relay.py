"""Session relay — the core mesh primitive.

handle_send_session_message routes a message into another fleet agent's
live gateway session with full sender context preserved.

Two-part delivery:
  1. HMAC-signed webhook POST to target agent's gateway relay
  2. Echo float to sender's Telegram DM for visibility

Auto-pads [a2a][from:<self>][to:<agent>][id:<uuid>][action:<action>][reply:<reply>]
header. Caller passes raw message; tool handles all mesh metadata.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from typing import Optional
from urllib.parse import urlparse

from . import float as _float
from .identity import get_raw_agent_identity
from . import signatures as _signatures

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SSRF protection (focused subset of old security.py)
# ---------------------------------------------------------------------------

_BLOCKED_HOSTS = {"0.0.0.0", "127.0.0.1", "localhost", "::1", "[::1]"}
_BLOCKED_PREFIXES = ("169.254.", "0.", "127.", "10.", "172.16.", "192.168.")

_LOCAL_PREFIXES = ("127.", "10.", "172.16.", "192.168.")


def _is_loopback(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return host.lower() in _BLOCKED_HOSTS


def _is_local(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return any(host.startswith(p) for p in _LOCAL_PREFIXES)


def _validate_target_url(url: str, allow_loopback: bool = False) -> str:
    """Validate a target URL for SSRF protection.

    Blocks loopback/non-routable addresses by default.
    When allow_loopback=True, permits loopback and local addresses.
    """
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"URL must use http/https: {url}")

    host = urlparse(url).hostname or ""
    if host.lower() in _BLOCKED_HOSTS:
        if not allow_loopback:
            raise ValueError(f"Loopback address blocked: {host}")
        return url

    if any(host.startswith(p) for p in _BLOCKED_PREFIXES) and not allow_loopback:
        raise ValueError(f"Private/reserved address blocked: {host}")

    return url


# ---------------------------------------------------------------------------
# Agent name validation
# ---------------------------------------------------------------------------

_AGENT_NAME_RE = __import__("re").compile(r"^[a-z0-9][a-z0-9_.-]*$", __import__("re").IGNORECASE)


def _validate_agent_name(name: str) -> str:
    """Validate agent name against allowlist pattern.

    Returns the lowercased, stripped name.
    Raises ValueError if the name contains path traversal or injection characters.
    """
    name = (name or "").strip()
    if not name:
        raise ValueError("Agent name must not be empty")
    if ".." in name:
        raise ValueError(f"Agent name contains '..': {name!r}")
    if not _AGENT_NAME_RE.match(name):
        raise ValueError(
            f"Invalid agent name: {name!r}. "
            f"Allowed: a-z, 0-9, underscore, dot, hyphen, starting with alphanumeric."
        )
    return name.lower()


# ---------------------------------------------------------------------------
# Header sanitization
# ---------------------------------------------------------------------------

def _sanitize_header_field(value: str) -> str:
    """Strip header delimiter characters to prevent field injection.

    The mesh header uses [ and ] as field delimiters. User-provided values
    like agent names or task IDs must not contain these characters, or an
    attacker could inject spurious fields that overwrite the sender.
    """
    if not isinstance(value, str):
        return str(value)
    return value.replace("[", "").replace("]", "")


# ---------------------------------------------------------------------------
# Identity helpers
# ---------------------------------------------------------------------------

def _transport(agent_info: dict, name: str) -> dict:
    if not isinstance(agent_info, dict):
        return {}
    transport = agent_info.get("transports", {}).get(name, {})
    return transport if isinstance(transport, dict) else {}


def _transport_auth_value(transport: dict, key: str) -> str:
    auth = transport.get("auth", {}) if isinstance(transport, dict) else {}
    if not isinstance(auth, dict):
        return ""
    return auth.get(key, "") or ""


def _is_local_fleet_agent(agent_name: str) -> bool:
    """Check if an agent is a local fleet agent with a valid URL."""
    try:
        from .identity import list_agents
        agents = list_agents()
        for agent in agents:
            if agent.get("name", "").lower() == agent_name.lower():
                url = agent.get("a2a_url", "")
                if url:
                    _validate_target_url(url, allow_loopback=True)
                    return True
        return False
    except Exception:
        return False


def _validate_agent_webhook_config(agent_info: dict) -> tuple[bool, str]:
    """Validate that an agent has the required webhook configuration."""
    webhook = _transport(agent_info, "hermes_webhook")
    webhook_url = webhook.get("url", "")
    webhook_secret = _transport_auth_value(webhook, "secret")

    if not webhook_url:
        return False, "Agent has no hermes_webhook.url configured"
    if not webhook_secret:
        return False, "Agent has no hermes_webhook.secret — HMAC signature required"
    return True, ""


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

_DELIVERY_RETRIES = int(os.getenv("A2A_WEBHOOK_DELIVERY_RETRIES", "3"))
_DELIVERY_BACKOFF = float(os.getenv("A2A_WEBHOOK_DELIVERY_BACKOFF", "1.0"))
_DELIVERY_TIMEOUT = int(os.getenv("A2A_WEBHOOK_DELIVERY_TIMEOUT", "10"))


def _deliver_webhook(
    url: str,
    body: str,
    secret: str,
    extra_headers: Optional[dict] = None,
) -> Optional[str]:
    """Deliver an HMAC-signed webhook POST with retry.

    Returns the delivery_id on success, or None if all retries fail.
    """
    import urllib.request

    sig = hmac.new(
        secret.encode(),
        body.encode(),
        hashlib.sha256,
    ).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-Hub-Signature-256": f"sha256={sig}",
    }
    if extra_headers:
        headers.update(extra_headers)

    for attempt in range(_DELIVERY_RETRIES):
        try:
            req = urllib.request.Request(
                url,
                data=body.encode(),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=_DELIVERY_TIMEOUT) as resp:
                result = json.loads(resp.read().decode())
                delivery_id = result.get("delivery_id", "unknown")
            if attempt > 0:
                logger.info(
                    "Mesh relay: delivery succeeded on attempt %d/%d",
                    attempt + 1, _DELIVERY_RETRIES,
                )
            return delivery_id
        except Exception as exc:
            if attempt < _DELIVERY_RETRIES - 1:
                backoff = _DELIVERY_BACKOFF * (2 ** attempt)
                logger.warning(
                    "Mesh relay: delivery attempt %d/%d failed: %s, retrying in %.1fs",
                    attempt + 1, _DELIVERY_RETRIES, exc, backoff,
                )
                time.sleep(backoff)
            else:
                logger.error(
                    "Mesh relay: delivery failed after %d attempts: %s",
                    _DELIVERY_RETRIES, exc,
                )
                return None
    return None


# ---------------------------------------------------------------------------
# handle_send_session_message
# ---------------------------------------------------------------------------

def handle_send_session_message(args: dict | None = None, **kwargs) -> dict:
    """Send a session-aware message to a Hermes mesh peer.

    Routes the message to the target agent's gateway webhook so the
    target gateway resolves it into the target session and invokes the
    target agent. Also echoes to the sender's Telegram DM via float.

    Args:
        message: The message text (required).
        agent: Target agent name (required).
        action: CTA action — "do" (default) or "info".
        reply: Reply expected — "yes" (default) or "no".
        ref: Optional message ID being replied to (for threading).
        task_id: Optional task ID override (auto-generated if omitted).

    Returns:
        {task_id, state, status, delivery, agent, gateway_delivery}
    """
    merged = dict(args) if args else {}
    merged.update(kwargs)

    message = merged.get("message", "")
    agent = merged.get("agent", "")
    action = merged.get("action", "do")
    reply = merged.get("reply", "yes")
    ref = merged.get("ref")
    task_id = merged.get("task_id")

    if not message:
        return {"error": "'message' is required"}
    if not agent:
        return {"error": "'agent' is required"}

    # SEC-02: Validate agent name before path construction
    try:
        agent = _validate_agent_name(agent)
    except ValueError as e:
        return {"error": str(e)}

    # Resolve target and validate
    raw_info = get_raw_agent_identity(agent)
    if not raw_info:
        return {"error": f"Agent '{agent}' not found in fleet vault"}

    is_valid, error = _validate_agent_webhook_config(raw_info)
    if not is_valid:
        return {"error": f"Agent '{agent}' webhook config invalid: {error}"}

    # Build mesh metadata header
    from_agent = os.getenv("A2A_AGENT_NAME", "hermes-agent")
    task_id = task_id or str(uuid.uuid4())
    # SEC-06: Sanitize all field values to prevent header injection
    from_agent = _sanitize_header_field(from_agent)
    agent = _sanitize_header_field(agent)
    task_id = _sanitize_header_field(task_id)
    action = _sanitize_header_field(action)
    reply = _sanitize_header_field(reply)
    header = f"[a2a][from:{from_agent}][to:{agent}][id:{task_id}][action:{action}][reply:{reply}]"
    if ref:
        header += f"[ref:{_sanitize_header_field(ref)}]"
    padded_message = f"{header} {message}"

    # Part 1: Webhook to target
    webhook = _transport(raw_info, "hermes_webhook")
    target_url = webhook.get("url", "")
    webhook_secret = _transport_auth_value(webhook, "secret")

    if not target_url:
        return {"error": f"Agent '{agent}' has no webhook URL in vault"}
    if not webhook_secret:
        return {"error": "Webhook delivery failed — no shared secret"}

    # SSRF check
    try:
        target_url = _validate_target_url(
            target_url,
            allow_loopback=_is_local_fleet_agent(agent),
        )
    except ValueError as e:
        return {"error": f"Agent '{agent}' webhook URL failed SSRF check: {e}"}

    # SEC-06: Per-agent Ed25519 signature for identity binding
    extra_headers = {}
    try:
        sender_identity = get_raw_agent_identity(from_agent)
        if sender_identity:
            signer_key = _signatures.load_signer_key(sender_identity)
            if signer_key:
                extra_headers["X-Mesh-Signature"] = _signatures.sign_message(
                    signer_key, from_agent, agent, task_id, message
                )
    except Exception as exc:
        logger.debug("Mesh relay: signing skipped for %s: %s", from_agent, exc)

    body = json.dumps({"text": padded_message}, sort_keys=True)
    delivery_id = _deliver_webhook(target_url, body, webhook_secret, extra_headers=extra_headers)

    if delivery_id is None:
        return {"error": f"Webhook to agent '{agent}' failed after {_DELIVERY_RETRIES} attempts"}

    # Part 2: Telegram float (best-effort, non-blocking)
    _float.send(text=padded_message, sender_name=from_agent)

    return {
        "task_id": task_id,
        "state": "completed",
        "status": "delivered",
        "delivery": "delivered",
        "reply_expected": reply == "yes",
        "message_id": delivery_id,
        "agent": agent,
        "gateway_delivery": True,
    }
