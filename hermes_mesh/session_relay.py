"""Session relay — the core mesh primitive.

handle_mesh_send routes a message into another fleet agent's
live gateway session with full sender context preserved.

Two-part delivery:
  1. Ed25519-signed webhook POST to target agent's gateway relay
  2. Echo float to sender's Telegram DM for visibility

Auto-pads [mesh][from:<self>][to:<agent>][id:<uuid>][action:<action>][reply:<reply>]
header. Caller passes raw message; tool handles all mesh metadata.
"""
from __future__ import annotations

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
from .common import (
    MESH_DSN_HEADER,
    MESH_DSN_VALUE,
    get_metrics_summary,
    mesh_extra,
    record_metric,
    validate_envelope_token,
)
from .identity import get_raw_agent_identity, list_agents, write_agent_identity
from . import outbox
from .network import is_local_target_host

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SSRF protection (focused subset of old security.py)
# ---------------------------------------------------------------------------

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_BENCHMARK = ipaddress.ip_network("198.18.0.0/15")


def _register_allow_loopback() -> bool:
    """Return True when mesh_register should accept loopback/private URLs.

    By default mesh_register rejects loopback and private-network targets to
    prevent SSRF-registration of malicious locally-routed URLs. Set
    MESH_REGISTER_ALLOW_LOOPBACK=1 to allow local testing and single-machine
    deployments.
    """
    env = os.getenv("MESH_REGISTER_ALLOW_LOOPBACK", "")
    return env.lower() in ("1", "true", "yes")


def _webhook_allow_loopback() -> bool:
    """Return True when mesh_send should deliver to loopback/private URLs.

    By default delivery still rejects private/loopback targets unless the
    stored URL itself is local. Set MESH_WEBHOOK_ALLOW_LOOPBACK=1 (or
    A2A_WEBHOOK_ALLOW_LOOPBACK=1) to override for single-machine deployments.
    """
    env = (
        os.getenv("MESH_WEBHOOK_ALLOW_LOOPBACK")
        or os.getenv("A2A_WEBHOOK_ALLOW_LOOPBACK")
        or ""
    )
    return env.lower() in ("1", "true", "yes")


def _sign_timestamp_enabled() -> bool:
    """Return True when mesh_send should include X-Mesh-Timestamp in the signed payload."""
    env = os.getenv("MESH_SIGN_TIMESTAMP", "")
    return env.lower() in ("1", "true", "yes")


def _is_ip_blocked(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_loopback: bool) -> bool:
    """Return True when `ip_obj` must be rejected for the given policy.

    CGNAT and benchmark ranges, reserved, multicast, and unspecified addresses
    are always rejected — even in loopback-allowed mode — because Python's
    `is_private` short-circuits on them otherwise.
    """
    if ip_obj in _CGNAT or ip_obj in _BENCHMARK:
        return True
    if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
        return True
    if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
        return not allow_loopback
    return False


def _resolve_host(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve a hostname and validate all returned addresses."""
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

    return ip_objs


def _is_local_url(url: str) -> bool:
    """Return True when the URL's host is a known local/loopback/private endpoint."""
    parsed = urlparse(url)
    return is_local_target_host(parsed.hostname or "")


def _resolve_target_url(url: str, allow_loopback: bool = False) -> tuple[str, list[ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    """Resolve a target URL once for SSRF protection.

    Returns the cleaned URL and the list of IP addresses that are allowed by
    the given policy.  This separates resolution from connection so the same
    getaddrinfo result can be reused across attempts, closing the DNS-rebinding
    / TOCTOU window.

    Blocks loopback/non-routable addresses by default.
    When allow_loopback=True, permits loopback and local addresses and drops
    non-local reserved/multicast/CGNAT/benchmark addresses from the list.
    """
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"URL must use http/https: {url}")

    parsed = urlparse(url)
    host = parsed.hostname or ""
    ip_objs = _resolve_host(host)
    allowed: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for ip_obj in ip_objs:
        if _is_ip_blocked(ip_obj, allow_loopback=allow_loopback):
            if allow_loopback:
                # In loopback-allowed mode a blocked address is reserved/
                # multicast/CGNAT/benchmark; skip it and try other addresses.
                continue
            if ip_obj.is_loopback:
                scope = "Loopback"
            else:
                scope = "Private/reserved"
            raise ValueError(f"{scope} address blocked: {ip_obj}")
        allowed.append(ip_obj)
    if not allowed:
        raise ValueError(f"No valid IP addresses for host {host}")
    return url, allowed


def _validate_target_url(url: str, allow_loopback: bool = False) -> str:
    """Validate a target URL for SSRF protection."""
    url, _ = _resolve_target_url(url, allow_loopback=allow_loopback)
    return url


def _pinned_request(
    url: str,
    body: bytes,
    headers: dict,
    timeout: float,
    allow_loopback: bool,
    resolved_ip_objs: Optional[list[ipaddress.IPv4Address | ipaddress.IPv6Address]] = None,
) -> bytes:
    """Make a single POST to a resolved IP while preserving SNI/Host.

    This closes the DNS-rebinding/TOCTOU window: the hostname is resolved once,
    all returned IPs are validated, and the connection is opened to one of the
    validated IPs while the TLS certificate is still checked against the original
    hostname. The caller is responsible for deciding whether loopback/private
    targets are expected.

    If the first resolved IP is unreachable, the remaining IPs are tried in
    getaddrinfo order (commonly IPv6 first, then IPv4 fallback).
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

    if resolved_ip_objs is None:
        resolved_ip_objs = _resolve_target_url(url, allow_loopback=allow_loopback)[1]
    if not resolved_ip_objs:
        raise ValueError(f"No valid IP addresses for host {host}")

    host_header = host if parsed.port is None else f"{host}:{port}"
    req_headers = dict(headers)
    req_headers.setdefault("Host", host_header)

    last_exc: Optional[Exception] = None
    for ip_obj in resolved_ip_objs:
        if _is_ip_blocked(ip_obj, allow_loopback=allow_loopback):
            if allow_loopback:
                continue
            scope = "Loopback" if ip_obj.is_loopback else "Private/reserved"
            raise ValueError(f"{scope} address blocked: {ip_obj}")

        resolved_ip = str(ip_obj)
        if parsed.scheme == "https":
            if allow_loopback:
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
        except (OSError, socket.timeout, http.client.HTTPException) as exc:
            last_exc = exc
            continue
        finally:
            conn.close()

    if last_exc is not None:
        raise last_exc
    raise ValueError(f"Could not connect to any resolved IP for {host}")


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
# Delivery
# ---------------------------------------------------------------------------

_DELIVERY_RETRIES = int(os.getenv("MESH_WEBHOOK_DELIVERY_RETRIES", "3"))
_DELIVERY_BACKOFF = float(os.getenv("MESH_WEBHOOK_DELIVERY_BACKOFF", "1.0"))
_DELIVERY_TIMEOUT = int(os.getenv("MESH_WEBHOOK_DELIVERY_TIMEOUT", "10"))


_DSN_RATE_BUCKETS: dict[str, tuple[int, float]] = {}


def _exception_to_reason(exc: Exception) -> str:
    """Map a delivery exception to a short, stable reason code."""
    from urllib.error import HTTPError

    if isinstance(exc, HTTPError):
        code = exc.code
        if code in (401, 403):
            return "unauthorized"
        if code == 404:
            return "not-found"
        if code == 400:
            return "bad-request"
        if code == 429:
            return "rate-limited"
        if code == 503:
            return "busy"
        if code >= 500:
            return "internal-error"
    msg = str(exc).lower()
    if "blocked" in msg or "private" in msg or "loopback" in msg:
        return "loopback-blocked"
    if "timeout" in msg:
        return "unreachable"
    return "unreachable"


def _deliver_webhook(
    url: str,
    body: str,
    signing_material: str,
    *,
    allow_loopback: bool = False,
    sign_timestamp: bool = False,
    extra_headers: dict | None = None,
) -> tuple[str | None, str | None]:
    """Deliver an Ed25519-signed webhook POST with retry.

    The hostname is resolved once per delivery and the connection is pinned to
    a validated IP. This prevents DNS-rebinding / TOCTOU races where a TTL flip
    returns a loopback/private address after validation passed. If the first
    resolved IP is unreachable, the remaining getaddrinfo results are tried.

    Returns (delivery_id, None) on success, or (None, reason_code) if all
    retries fail. The reason_code is a short token such as 'unreachable',
    'unauthorized', or 'loopback-blocked'.
    """
    from . import auth

    try:
        _, resolved_ip_objs = _resolve_target_url(url, allow_loopback=allow_loopback)
    except ValueError as exc:
        logger.error("Mesh relay: invalid target URL %s: %s", url, exc)
        return None, ("loopback-blocked" if "blocked" in str(exc).lower() else "unreachable")

    timestamp = str(time.time())
    headers = {
        "Content-Type": "application/json",
        "X-Mesh-Timestamp": timestamp,
    }
    if extra_headers:
        headers.update(extra_headers)
    signed_body = f"{timestamp}\n{body}".encode() if sign_timestamp else body.encode()
    sig = auth.sign_ed25519(signing_material, signed_body)
    headers["X-Mesh-Signature"] = sig

    # Enforce a single total deadline across all attempts instead of letting
    # each attempt run for the full _DELIVERY_TIMEOUT and accumulate linearly.
    deadline = time.monotonic() + _DELIVERY_TIMEOUT

    for attempt in range(_DELIVERY_RETRIES):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            logger.error("Mesh relay: delivery exceeded total timeout budget")
            return None, "unreachable"

        try:
            # Give each attempt an equal share of the remaining budget so a
            # slow/dead target cannot consume the whole timeout on one attempt.
            attempt_timeout = max(1.0, remaining / (_DELIVERY_RETRIES - attempt))
            data = _pinned_request(
                url,
                body.encode(),
                headers,
                attempt_timeout,
                allow_loopback=allow_loopback,
                resolved_ip_objs=resolved_ip_objs,
            )
            result = json.loads(data.decode())
            delivery_id = result.get("delivery_id", "unknown")
            if attempt > 0:
                logger.info(
                    "Mesh relay: delivery succeeded on attempt %d/%d",
                    attempt + 1, _DELIVERY_RETRIES,
                )
            record_metric("send", "total")
            return delivery_id, None
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
                reason = _exception_to_reason(exc)
                logger.error(
                    "Mesh relay: delivery failed after %d attempts: %s",
                    _DELIVERY_RETRIES, exc,
                )
                record_metric("send", "failed")
                return None, reason
    return None, "unreachable"


# ---------------------------------------------------------------------------
# Delivery-Status Notifications (DSN)
# ---------------------------------------------------------------------------

_DSN_ENABLED: bool | None = None


def _dsn_enabled() -> bool:
    """Return True when DSN generation is enabled."""
    global _DSN_ENABLED
    if _DSN_ENABLED is None:
        _DSN_ENABLED = os.getenv("MESH_DSN_ENABLED", "1").lower() in ("1", "true", "yes")
    return _DSN_ENABLED


def _dsn_rate_limit(auth_failure: bool = False) -> int:
    """Return the per-minute DSN rate limit for a recipient."""
    env = "MESH_DSN_AUTH_FAILURE_RATE_LIMIT" if auth_failure else "MESH_DSN_RATE_LIMIT"
    default = "0" if auth_failure else "10"
    raw = os.getenv(env, default)
    try:
        return int(raw)
    except ValueError:
        return int(default)


def _check_dsn_rate_limit(to_agent: str, auth_failure: bool = False) -> bool:
    """Return True if a DSN to this recipient is still allowed this minute."""
    limit = _dsn_rate_limit(auth_failure=auth_failure)
    if auth_failure and limit <= 0:
        return False
    if limit <= 0:
        return True
    now = time.time()
    bucket = _DSN_RATE_BUCKETS.get(to_agent)
    if bucket is None or now - bucket[1] > 60:
        _DSN_RATE_BUCKETS[to_agent] = (1, now)
        return True
    count, window_start = bucket
    count += 1
    _DSN_RATE_BUCKETS[to_agent] = (count, window_start)
    return count <= limit


def _make_dsn_text(
    dsn_from: str,
    dsn_to: str,
    original_id: str,
    reason: str,
    original_from: str,
    original_to: str,
) -> str:
    """Build a DSN bracketed message body."""
    dsn_id = str(uuid.uuid4())
    safe_reason = re.sub(r"[^A-Za-z0-9_.:-]", "_", reason)[:32]
    body = (
        f"[mesh-dsn][status:failed][reason:{safe_reason}] "
        f"Delivery of message {original_id} from {original_from} to {original_to} "
        f"failed: {safe_reason}."
    )
    header = (
        f"[mesh][v:1][from:{dsn_from}][to:{dsn_to}][id:{dsn_id}]"
        f"[action:info][reply:no][ref:{original_id}]"
    )
    return f"{header} {body}"


def _send_delivery_error(
    dsn_from: str,
    dsn_to: str,
    original_id: str,
    reason: str,
    original_from: str,
    original_to: str,
    *,
    is_dsn: bool = False,
    auth_failure: bool = False,
) -> None:
    """Best-effort delivery of a DSN to the interested party."""
    if not _dsn_enabled():
        return
    if is_dsn:
        logger.debug("[mesh] not sending DSN for a DSN message %s", original_id)
        return
    if not _check_dsn_rate_limit(dsn_to, auth_failure=auth_failure):
        logger.warning("[mesh] DSN rate limit exceeded for %s", dsn_to)
        return

    try:
        dsn_from = _validate_agent_name(dsn_from)
        dsn_to = _validate_agent_name(dsn_to)
        original_id = validate_envelope_token(original_id)
    except ValueError as e:
        logger.warning("[mesh] DSN invalid envelope token: %s", e)
        return

    dsn_text = _make_dsn_text(dsn_from, dsn_to, original_id, reason, original_from, original_to)
    dsn_body = json.dumps({"from": dsn_from, "text": dsn_text}, sort_keys=True)

    from . import auth
    from .common import mesh_extra

    extra = mesh_extra()
    target_url, error = auth.resolve_target(dsn_to)
    if error:
        logger.warning("[mesh] DSN target %s: %s", dsn_to, error)
        return
    signing_material, error = auth.resolve_sender(dsn_from, extra)
    if error:
        logger.warning("[mesh] DSN sender %s: %s", dsn_from, error)
        return

    if not target_url:
        logger.warning("[mesh] DSN target %s has no webhook URL", dsn_to)
        return

    extra_headers = {MESH_DSN_HEADER: MESH_DSN_VALUE}
    allow_loopback = _webhook_allow_loopback() or _is_local_url(target_url)
    sign_timestamp = _sign_timestamp_enabled()
    delivery_id, dsn_error = _deliver_webhook(
        target_url,
        dsn_body,
        signing_material,
        allow_loopback=allow_loopback,
        sign_timestamp=sign_timestamp,
        extra_headers=extra_headers,
    )
    if delivery_id is None:
        logger.warning("[mesh] DSN delivery to %s failed: %s", dsn_to, dsn_error)
        if outbox.outbox_enabled():
            outbox.queue_message(
                dsn_from,
                dsn_to,
                dsn_text,
                dsn_body,
                is_dsn=True,
                ref=original_id,
            )
    else:
        logger.info("[mesh] DSN delivered to %s: %s", dsn_to, delivery_id)


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
        try:
            ref = validate_envelope_token(ref)
        except ValueError as e:
            logger.warning("[mesh_send] dropping invalid ref %r: %s", ref, e)
            ref = None
    else:
        ref = None

    if task_id is not None and task_id != "":
        try:
            task_id = validate_envelope_token(task_id)
        except ValueError as e:
            return {"error": f"Invalid task_id: {e}"}

    # Build mesh metadata header
    from_agent = os.getenv("MESH_AGENT_NAME", "hermes-agent")
    try:
        from_agent = _validate_agent_name(from_agent)
    except ValueError as e:
        return {"error": f"Invalid sender name: {e}"}

    task_id = task_id or str(uuid.uuid4())
    header = f"[mesh][v:1][from:{from_agent}][to:{agent}][id:{task_id}][action:{action}][reply:{reply}]"
    if ref:
        header += f"[ref:{ref}]"
    padded_message = f"{header} {message}"

    # Part 1: Webhook to target
    from . import auth
    from .common import mesh_extra

    extra = mesh_extra()
    target_url, error = auth.resolve_target(agent)
    if error:
        return {"error": error}

    signing_material, error = auth.resolve_sender(from_agent, extra)
    if error:
        return {"error": error}

    body = json.dumps({"from": from_agent, "text": padded_message}, sort_keys=True)
    allow_loopback = _webhook_allow_loopback() or _is_local_url(target_url)
    sign_timestamp = _sign_timestamp_enabled()
    delivery_id, error = _deliver_webhook(
        target_url,
        body,
        signing_material,
        allow_loopback=allow_loopback,
        sign_timestamp=sign_timestamp,
    )

    if delivery_id is None:
        record_metric("send", "failed")
        if outbox.outbox_enabled():
            outbox.queue_message(from_agent, agent, padded_message, body, ref=ref)
            return {
                "task_id": task_id,
                "state": "queued",
                "status": "queued for outbox retry",
                "delivery": "queued",
                "reply_expected": reply == "yes",
                "message_id": task_id,
                "agent": agent,
                "gateway_delivery": False,
            }
        # Immediate final failure: send DSN to the interested party.
        dsn_to = agent if ref else from_agent
        _send_delivery_error(
            from_agent,
            dsn_to,
            task_id,
            error or "unreachable",
            from_agent,
            agent,
        )
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
    """List all agents registered in the local mesh cache."""
    agents = list_agents()
    return {"agents": agents, "count": len(agents)}


def _register_one(
    item: dict,
    overwrite: bool,
    dry_run: bool,
) -> dict:
    """Register a single agent from a bulk or single registration request."""
    from . import auth

    name = item.get("name") or os.getenv("MESH_AGENT_NAME", "")
    url = item.get("url", "")
    public_key = item.get("public_key", "")
    role = item.get("role") or "agent"
    description = item.get("description", "")

    if not name:
        return {"registered": False, "error": "'name' is required (or set MESH_AGENT_NAME)"}
    try:
        name = _validate_agent_name(name)
    except ValueError as e:
        return {"registered": False, "error": str(e)}

    if not url:
        return {"registered": False, "error": "'url' is required"}
    if not url.startswith(("http://", "https://")):
        return {"registered": False, "error": f"URL must use http/https: {url}"}

    try:
        _validate_target_url(url, allow_loopback=_register_allow_loopback())
    except ValueError as exc:
        return {"registered": False, "error": f"Invalid URL: {exc}"}

    if not public_key:
        # Generate a keypair for this agent. The private key is stored locally.
        public_key, error = auth.get_public_key(name)
        if error:
            return {"registered": False, "error": error}

    if dry_run:
        return {
            "registered": False,
            "dry_run": True,
            "would_register": True,
            "name": name,
        }

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
                "auth": {"public_key": public_key},
            },
        },
    }
    try:
        path = write_agent_identity(name, identity)
    except Exception as e:
        return {"registered": False, "error": f"Failed to write identity: {e}"}

    return {"registered": True, "name": name, "path": str(path)}


def handle_mesh_register(args: dict | None = None, **kwargs) -> dict:
    """Register or update an agent identity in the local mesh cache.

    Args:
        name: Agent name (defaults to MESH_AGENT_NAME env var).
        url: Hermes webhook URL for this agent.
        public_key: Optional Ed25519 public key PEM. If omitted, one is generated.
        role: Optional role description (default "agent").
        description: Optional human-readable description.
        overwrite: Whether to overwrite an existing identity (default False).
        dry_run: Validate and return without writing.
        bulk: Optional list of registration objects to process in one call.
    """
    merged = dict(args) if args else {}
    merged.update(kwargs)

    overwrite = bool(merged.get("overwrite", False))
    dry_run = bool(merged.get("dry_run", False))

    bulk = merged.get("bulk")
    if isinstance(bulk, list) and bulk:
        results = [_register_one({**item}, overwrite, dry_run) for item in bulk]
        ok = all(r.get("registered") or r.get("would_register") for r in results)
        return {"ok": ok, "count": len(results), "results": results}

    return _register_one({**merged}, overwrite, dry_run)


def handle_mesh_health(args: dict | None = None, **kwargs) -> dict:
    """Return mesh health and metrics summary."""
    from . import identity as _identity
    metrics = get_metrics_summary()
    metrics["identity_cache_size"] = len(_identity._IDENTITY_CACHE)
    metrics["outbox_count"] = outbox.outbox_count()
    return {"status": "healthy", "metrics": metrics}


def handle_mesh_refresh_identities(args: dict | None = None, **kwargs) -> dict:
    """Clear the identity cache so the next lookup reads from disk or registry.

    Useful after bulk changes to the fleet vault or when an identity was
    edited outside of mesh_register.
    """
    from . import identity as _identity
    _identity.refresh_identities()
    return {"refreshed": True, "cache_size": 0}


def handle_mesh_deregister(args: dict | None = None, **kwargs) -> dict:
    """Deregister an agent from the local mesh cache.

    Args:
        name: Agent name (defaults to MESH_AGENT_NAME env var).
    """
    merged = dict(args) if args else {}
    merged.update(kwargs)

    name = merged.get("name") or os.getenv("MESH_AGENT_NAME", "")
    if not name:
        return {"error": "'name' is required (or set MESH_AGENT_NAME)"}
    try:
        name = _validate_agent_name(name)
    except ValueError as e:
        return {"error": str(e)}

    import shutil
    from .identity import _mesh_agents_root

    agent_dir = _mesh_agents_root() / name
    if not agent_dir.exists():
        return {"deregistered": False, "error": f"Agent '{name}' not found in local cache"}
    try:
        shutil.rmtree(agent_dir)
    except Exception as e:
        return {"deregistered": False, "error": f"Failed to remove identity: {e}"}
    return {"deregistered": True, "name": name, "path": str(agent_dir)}


def handle_mesh_sync(args: dict | None = None, **kwargs) -> dict:
    """Sync one or all peer identities from a mesh-peer-registry to the local cache.

    Args:
        name: Agent name to sync. If omitted, syncs all peers from the registry.
        registry_url: Optional registry URL (defaults to config).
    """
    from .common import mesh_extra
    from . import registry_bridge as _registry_bridge

    merged = dict(args) if args else {}
    merged.update(kwargs)
    extra = dict(mesh_extra(merged.get("extra")))
    if merged.get("registry_url"):
        extra["registry_url"] = merged["registry_url"]

    name = merged.get("name")
    try:
        if name:
            name = _validate_agent_name(name)
    except ValueError as e:
        return {"error": str(e)}

    try:
        if name:
            return _registry_bridge.sync_peer(name, extra)
        # Sync all peers listed in the registry.
        peers = _registry_bridge.list_peers(extra)
        results = []
        for peer in peers:
            try:
                results.append(_registry_bridge.sync_peer(peer.name, extra))
            except Exception as e:
                results.append({"synced": False, "name": getattr(peer, "name", None), "error": str(e)})
        return {"synced": len([r for r in results if r.get("synced")]), "total": len(results), "results": results}
    except Exception as e:
        return {"error": f"Failed to sync from registry: {e}"}


def handle_mesh_publish(args: dict | None = None, **kwargs) -> dict:
    """Publish the local agent's identity to a mesh-peer-registry.

    Args:
        name: Agent name (defaults to MESH_AGENT_NAME env var).
        url: Hermes webhook URL for this agent.
        role: Optional role description (default "agent").
        description: Optional human-readable description.
        ttl: Optional TTL in seconds.
        registry_url: Optional registry URL (defaults to config).
    """
    from .common import mesh_extra
    from . import registry_bridge as _registry_bridge

    merged = dict(args) if args else {}
    merged.update(kwargs)
    extra = dict(mesh_extra(merged.get("extra")))
    if merged.get("registry_url"):
        extra["registry_url"] = merged["registry_url"]

    name = merged.get("name") or os.getenv("MESH_AGENT_NAME", "")
    url = merged.get("url", "")
    role = merged.get("role", "agent")
    description = merged.get("description", "")
    ttl = merged.get("ttl")

    if not name:
        return {"published": False, "error": "'name' is required (or set MESH_AGENT_NAME)"}
    if not url:
        return {"published": False, "error": "'url' is required"}
    try:
        name = _validate_agent_name(name)
    except ValueError as e:
        return {"published": False, "error": str(e)}

    try:
        result = _registry_bridge.publish_peer(name, url, role, description, extra=extra, ttl=ttl)
        return {"published": True, "name": name, "registry": result}
    except Exception as e:
        return {"published": False, "error": f"Failed to publish to registry: {e}"}

