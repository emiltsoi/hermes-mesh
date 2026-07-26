"""Session relay — the core mesh primitive.

handle_mesh_send routes a message into another fleet agent's
live gateway session with full sender context preserved.

Two-part delivery:
  1. HMAC-signed webhook POST to target agent's gateway relay
  2. Echo float to sender's Telegram DM for visibility

Auto-pads [mesh][from:<self>][to:<agent>][id:<uuid>][action:<action>][reply:<reply>]
header. Caller passes raw message; tool handles all mesh metadata.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import socket
import urllib.request
import time
import uuid
from typing import Optional
from urllib.parse import urlparse

from . import float as _float
from .common import transport as _transport, transport_auth_value as _transport_auth_value
from .identity import get_raw_agent_identity, list_agents, resolve_agent as _resolve_agent_by_name, write_agent_identity

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
    return any(host.startswith(p) for p in _LOCAL_PREFIXES) or host.lower() in {"::1", "[::1]"}


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

_AGENT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$", re.IGNORECASE)


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
# Identity helpers
# ---------------------------------------------------------------------------

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

_DELIVERY_RETRIES = int(
    os.getenv("MESH_WEBHOOK_DELIVERY_RETRIES")
    or os.getenv("A2A_WEBHOOK_DELIVERY_RETRIES", "3")
)
_DELIVERY_BACKOFF = float(
    os.getenv("MESH_WEBHOOK_DELIVERY_BACKOFF")
    or os.getenv("A2A_WEBHOOK_DELIVERY_BACKOFF", "1.0")
)
_DELIVERY_TIMEOUT = int(
    os.getenv("MESH_WEBHOOK_DELIVERY_TIMEOUT")
    or os.getenv("A2A_WEBHOOK_DELIVERY_TIMEOUT", "10")
)


def _validate_resolved_ip(host: str, allow_loopback: bool = False) -> str:
    """Resolve hostname and validate all returned IPs for SSRF protection.

    urllib's urlopen and asyncio TCP stacks resolve via ``getaddrinfo``,
    which can prefer IPv6. ``socket.gethostbyname`` is IPv4-only, so a
    clean A record plus a loopback/Private AAAA record would bypass the
    old check. We validate every A and AAAA record here.
    """
    if not host:
        raise ValueError("Empty host")
    try:
        addrinfo = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve host {host}: {exc}") from exc
    if not addrinfo:
        raise ValueError(f"No addresses for host {host}")

    first_ip = None
    for _, _, _, _, sockaddr in addrinfo:
        ip_str = sockaddr[0]
        if first_ip is None:
            first_ip = ip_str
        # When the caller explicitly allows local/loopback delivery, skip
        # the private/reserved checks entirely.
        if allow_loopback:
            continue
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip_obj.is_loopback:
            raise ValueError(f"Loopback address blocked: {ip_str}")
        # Private, link-local, multicast, reserved, unspecified, and the
        # CGNAT (100.64.0.0/10) and benchmark (198.18.0.0/15) ranges.
        if (
            ip_obj.is_private
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
            or ip_obj in ipaddress.ip_network("100.64.0.0/10")
            or ip_obj in ipaddress.ip_network("198.18.0.0/15")
        ):
            raise ValueError(f"Private/reserved address blocked: {ip_str}")

    return first_ip or host


def _deliver_webhook(
    url: str,
    body: str,
    secret: str,
    allow_loopback: bool = False,
) -> Optional[str]:
    """Deliver an HMAC-signed webhook POST with retry.

    Returns the delivery_id on success, or None if all retries fail.
    """
    sig = hmac.new(
        secret.encode(),
        body.encode(),
        hashlib.sha256,
    ).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-Hub-Signature-256": f"sha256={sig}",
    }

    parsed = urlparse(url)
    host = parsed.hostname or ""

    # Enforce a single total deadline across all attempts instead of letting
    # each attempt run for the full _DELIVERY_TIMEOUT and accumulate linearly.
    deadline = time.monotonic() + _DELIVERY_TIMEOUT

    for attempt in range(_DELIVERY_RETRIES):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            logger.error("Mesh relay: delivery exceeded total timeout budget")
            return None

        try:
            _validate_resolved_ip(host, allow_loopback=allow_loopback)
            req = urllib.request.Request(
                url,
                data=body.encode(),
                headers=headers,
                method="POST",
            )
            # Give each attempt an equal share of the remaining budget so a
            # slow/dead target cannot consume the whole timeout on one attempt.
            attempt_timeout = max(1.0, remaining / (_DELIVERY_RETRIES - attempt))
            with urllib.request.urlopen(req, timeout=attempt_timeout) as resp:
                result = json.loads(resp.read().decode())
                delivery_id = result.get("delivery_id", "unknown")
            if attempt > 0:
                logger.info(
                    "Mesh relay: delivery succeeded on attempt %d/%d",
                    attempt + 1, _DELIVERY_RETRIES,
                )
            return delivery_id
        except Exception as exc:
            remaining = deadline - time.monotonic()
            if attempt < _DELIVERY_RETRIES - 1 and remaining > 0:
                backoff = _DELIVERY_BACKOFF * (2 ** attempt)
                # Never sleep past the deadline; leave at least 1s for next attempt.
                sleep_time = min(backoff, max(0.0, remaining - 1.0))
                if sleep_time > 1e-3:
                    logger.warning(
                        "Mesh relay: delivery attempt %d/%d failed: %s, retrying in %.1fs",
                        attempt + 1, _DELIVERY_RETRIES, exc, sleep_time,
                    )
                    time.sleep(sleep_time)
            else:
                logger.error(
                    "Mesh relay: delivery failed after %d attempts: %s",
                    _DELIVERY_RETRIES, exc,
                )
                return None
    return None


# ---------------------------------------------------------------------------
# handle_mesh_send
# ---------------------------------------------------------------------------

def handle_mesh_send(args: dict | None = None, **kwargs) -> dict:
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
    # The Hermes tool executor invokes handlers as handler(args, **kwargs) and
    # injects runtime context (task_id, session_id, user_task, etc.) into kwargs.
    # Those are not tool arguments. Mesh parameters come from the `args` dict;
    # we accept non-runtime kwargs for convenience, but we must never let the
    # framework's task_id (the conversation session id) become the mesh message
    # id, otherwise every mesh_send in a single turn has the same id.
    merged = dict(args) if args else {}
    for key, value in kwargs.items():
        if key in {
            "task_id",
            "session_id",
            "user_task",
            "tool_call_id",
            "turn_id",
            "api_request_id",
            "enabled_tools",
            "enabled_toolsets",
            "disabled_toolsets",
            "skip_pre_tool_call_hook",
            "skip_tool_request_middleware",
            "tool_request_middleware_trace",
        }:
            continue
        merged.setdefault(key, value)

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

    # Resolve target
    target_info = _resolve_agent_by_name(agent)
    if not target_info:
        return {"error": f"Agent '{agent}' not found in fleet vault"}

    # Validate webhook config
    raw_info = get_raw_agent_identity(agent)
    if not raw_info:
        return {"error": f"Agent '{agent}' has no identity in fleet vault"}
    is_valid, error = _validate_agent_webhook_config(raw_info)
    if not is_valid:
        return {"error": f"Agent '{agent}' webhook config invalid: {error}"}

    # Build mesh metadata header
    from_agent = os.getenv("MESH_AGENT_NAME") or os.getenv("A2A_AGENT_NAME", "hermes-agent")
    task_id = task_id or str(uuid.uuid4())
    header = f"[mesh][from:{from_agent}][to:{agent}][id:{task_id}][action:{action}][reply:{reply}]"
    if ref:
        header += f"[ref:{ref}]"
    padded_message = f"{header} {message}"

    # Part 1: Webhook to target
    webhook = _transport(raw_info, "hermes_webhook")
    target_url = webhook.get("url", "")
    webhook_secret = _transport_auth_value(webhook, "secret")

    if not target_url:
        return {"error": f"Agent '{agent}' has no webhook URL in vault"}
    if not webhook_secret:
        return {"error": "Webhook delivery failed — no shared secret"}

    # M2: target_info already resolved; derive local allow from the URL itself
    try:
        target_url = _validate_target_url(
            target_url,
            allow_loopback=_is_loopback(target_url) or _is_local(target_url),
        )
    except ValueError as e:
        return {"error": f"Agent '{agent}' webhook URL failed SSRF check: {e}"}

    # C5: per-agent HMAC — sign with the sender's own webhook secret if available
    sender_info = get_raw_agent_identity(from_agent)
    sender_secret = _transport_auth_value(_transport(sender_info, "hermes_webhook"), "secret") if sender_info else ""
    signing_secret = sender_secret or webhook_secret

    body = json.dumps({"from": from_agent, "text": padded_message}, sort_keys=True)
    delivery_id = _deliver_webhook(target_url, body, signing_secret, allow_loopback=_is_loopback(target_url) or _is_local(target_url))

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

# ---------------------------------------------------------------------------
# mesh_list / mesh_register tools
# ---------------------------------------------------------------------------

def handle_mesh_list(args: dict | None = None, **kwargs) -> dict:
    """List all agents registered in the fleet mesh vault."""
    agents = list_agents()
    return {"agents": agents, "count": len(agents)}


def handle_mesh_register(args: dict | None = None, **kwargs) -> dict:
    """Register or update an agent identity in the fleet mesh vault.

    Args:
        name: Agent name (defaults to MESH_AGENT_NAME env var).
        url: Hermes webhook URL for this agent.
        secret: Shared HMAC secret for this agent.
        role: Optional role description (default "agent").
        description: Optional human-readable description.
        overwrite: Whether to overwrite an existing identity (default False).
    """
    merged = dict(args) if args else {}
    merged.update(kwargs)

    name = merged.get("name") or os.getenv("MESH_AGENT_NAME") or os.getenv("A2A_AGENT_NAME", "")
    url = merged.get("url", "")
    secret = merged.get("secret", "")
    role = merged.get("role", "agent")
    description = merged.get("description", "")
    overwrite = bool(merged.get("overwrite", False))

    if not name:
        return {"error": "'name' is required (or set MESH_AGENT_NAME)"}
    try:
        name = _validate_agent_name(name)
    except ValueError as e:
        return {"error": str(e)}

    if not url:
        return {"error": "'url' is required"}
    if not url.startswith(("http://", "https://")):
        return {"error": f"URL must use http/https: {url}"}
    if not secret:
        return {"error": "'secret' is required for HMAC webhook auth"}

    if not overwrite and get_raw_agent_identity(name):
        return {"registered": False, "error": f"Agent '{name}' already exists; set overwrite=True to replace"}

    identity = {
        "id": name,
        "name": name,
        "description": description,
        "role": role,
        "transports": {
            "hermes_webhook": {
                "url": url,
                "auth": {"type": "hmac-sha256", "secret": secret},
            },
        },
    }
    try:
        path = write_agent_identity(name, identity)
    except Exception as e:
        return {"registered": False, "error": f"Failed to write identity: {e}"}

    return {"registered": True, "name": name, "path": str(path)}

