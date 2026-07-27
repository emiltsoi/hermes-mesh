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
import http.client
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import time
import urllib.error
import uuid
from typing import Optional
from urllib.parse import urlparse

from . import float as _float
from .common import transport as _transport, transport_auth_value as _transport_auth_value
from .identity import get_raw_agent_identity, list_agents, write_agent_identity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SSRF protection (focused subset of old security.py)
# ---------------------------------------------------------------------------

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_BENCHMARK = ipaddress.ip_network("198.18.0.0/15")


def _is_ip_blocked(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_local: bool) -> bool:
    """Return True when `ip_obj` must be rejected for the given policy."""
    if allow_local:
        if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
            return False
    else:
        if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
            return True
    return (
        ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or ip_obj in _CGNAT
        or ip_obj in _BENCHMARK
    )


def _resolve_host(host: str) -> tuple[list[ipaddress.IPv4Address | ipaddress.IPv6Address], bool]:
    """Resolve a hostname and validate all returned addresses.

    Returns a list of parsed IP objects plus a flag that is True when *every*
    returned address is loopback/private/link-local. A mixed set (e.g. DNS
    rebinding returning both 127.0.0.1 and a public IP) is treated as untrusted.
    """
    if not host:
        raise ValueError("Empty host")
    try:
        addrinfo = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve host {host}: {exc}") from exc
    if not addrinfo:
        raise ValueError(f"No addresses for host {host}")

    ip_objs: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for _, _, _, _, sockaddr in addrinfo:
        try:
            ip_objs.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    if not ip_objs:
        raise ValueError(f"No valid IP addresses for host {host}")

    all_local = all(
        ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local for ip_obj in ip_objs
    )
    return ip_objs, all_local


def _is_local_url(url: str) -> bool:
    """Return True when the URL's host is a known local/loopback endpoint.

    This is used by callers (e.g. mesh_send) to decide whether loopback/private
    addresses are expected for a target. Literal IPs are classified with
    ipaddress; hostnames must be localhost/loopback literals to avoid treating
    an attacker-controlled public domain as local.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if host in {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}:
        return True
    # Handle bracketed IPv6 and literal IPs.
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local)


def _validate_target_url(url: str, allow_loopback: bool = False) -> str:
    """Validate a target URL for SSRF protection.

    Blocks loopback/non-routable addresses by default.
    When allow_loopback=True, permits loopback and local addresses.
    """
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"URL must use http/https: {url}")

    parsed = urlparse(url)
    host = parsed.hostname or ""
    ip_objs, _ = _resolve_host(host)
    for ip_obj in ip_objs:
        if _is_ip_blocked(ip_obj, allow_local=allow_loopback):
            if allow_loopback:
                scope = "Private/reserved"
            elif ip_obj.is_loopback:
                scope = "Loopback"
            else:
                scope = "Private/reserved"
            raise ValueError(f"{scope} address blocked: {ip_obj}")
    return url


def _pinned_request(
    url: str,
    body: bytes,
    headers: dict,
    timeout: float,
    allow_local: bool,
) -> bytes:
    """Make a single POST to the resolved IP while preserving SNI/Host.

    This closes the DNS-rebinding/TOCTOU window: the hostname is resolved once,
    all returned IPs are validated, and the connection is opened to one of the
    validated IPs while the TLS certificate is still checked against the original
    hostname. The caller is responsible for deciding whether loopback/private
    targets are expected.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL must use http/https: {url}")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("Empty host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    ip_objs, _ = _resolve_host(host)
    if not ip_objs:
        raise ValueError(f"No valid IP addresses for host {host}")
    for ip_obj in ip_objs:
        if _is_ip_blocked(ip_obj, allow_local=allow_local):
            if allow_local:
                scope = "Private/reserved"
            elif ip_obj.is_loopback:
                scope = "Loopback"
            else:
                scope = "Private/reserved"
            raise ValueError(f"{scope} address blocked: {ip_obj}")

    resolved_ip = str(ip_objs[0])
    host_header = host if parsed.port is None else f"{host}:{port}"
    req_headers = dict(headers)
    req_headers.setdefault("Host", host_header)

    if parsed.scheme == "https":
        if allow_local:
            # Local/self-signed testing: disable verification to avoid hostname
            # mismatch errors for 127.0.0.1 / localhost certificates.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            context = ssl.create_default_context()
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            resolved_ip, port, timeout=timeout, context=context, server_hostname=host
        )
    else:
        conn = http.client.HTTPConnection(resolved_ip, port, timeout=timeout)

    try:
        conn.request("POST", path, body=body, headers=req_headers)
        resp = conn.getresponse()
        data = resp.read()
        if resp.status >= 400:
            raise urllib.error.HTTPError(url, resp.status, resp.reason, resp.headers, resp)
        return data
    finally:
        conn.close()


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


def _deliver_webhook(
    url: str,
    body: str,
    secret: str,
    allow_loopback: bool = False,
) -> Optional[str]:
    """Deliver an HMAC-signed webhook POST with retry.

    The hostname is resolved once per attempt and the connection is pinned to
    the validated IP. This prevents DNS-rebinding / TOCTOU races where a TTL
    flip returns a loopback/private address after validation passed.

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
        "X-Mesh-Timestamp": str(time.time()),
    }

    # Enforce a single total deadline across all attempts instead of letting
    # each attempt run for the full _DELIVERY_TIMEOUT and accumulate linearly.
    deadline = time.monotonic() + _DELIVERY_TIMEOUT

    for attempt in range(_DELIVERY_RETRIES):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            logger.error("Mesh relay: delivery exceeded total timeout budget")
            return None

        try:
            # Give each attempt an equal share of the remaining budget so a
            # slow/dead target cannot consume the whole timeout on one attempt.
            attempt_timeout = max(1.0, remaining / (_DELIVERY_RETRIES - attempt))
            data = _pinned_request(
                url,
                body.encode(),
                headers,
                attempt_timeout,
                allow_local=allow_loopback,
            )
            result = json.loads(data.decode())
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

    # Validate envelope fields before they are inserted into the bracket header.
    if action not in {"do", "info"}:
        return {"error": f"Invalid action '{action}'; must be 'do' or 'info'"}
    if reply not in {"yes", "no"}:
        return {"error": f"Invalid reply '{reply}'; must be 'yes' or 'no'"}
    if ref is not None and ref != "":
        if not isinstance(ref, str) or not re.fullmatch(r"^[A-Za-z0-9_.:-]*$", ref):
            return {"error": "Invalid ref; must be alphanumeric, dots, dashes, underscores, colons or periods"}
    else:
        ref = None

    # Resolve target identity once (A1: get_raw_agent_identity is enough).
    raw_info = get_raw_agent_identity(agent)
    if not raw_info:
        return {"error": f"Agent '{agent}' not found in fleet vault"}
    is_valid, error = _validate_agent_webhook_config(raw_info)
    if not is_valid:
        return {"error": f"Agent '{agent}' webhook config invalid: {error}"}

    # Build mesh metadata header
    from_agent = os.getenv("MESH_AGENT_NAME") or os.getenv("A2A_AGENT_NAME", "hermes-agent")
    try:
        from_agent = _validate_agent_name(from_agent)
    except ValueError as e:
        return {"error": f"Invalid sender name: {e}"}

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

    # C5: per-agent HMAC — sign with the sender's own webhook secret only.
    # Never fall back to the target's secret; that would let a sender that the
    # receiver does not know claim an arbitrary identity.
    sender_info = get_raw_agent_identity(from_agent)
    if not sender_info:
        return {"error": f"Sender '{from_agent}' has no identity in fleet vault"}
    sender_secret = _transport_auth_value(_transport(sender_info, "hermes_webhook"), "secret")
    if not sender_secret:
        return {"error": f"Sender '{from_agent}' has no webhook secret configured"}
    signing_secret = sender_secret

    body = json.dumps({"from": from_agent, "text": padded_message}, sort_keys=True)
    delivery_id = _deliver_webhook(
        target_url,
        body,
        signing_secret,
        allow_loopback=_is_local_url(target_url),
    )

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

