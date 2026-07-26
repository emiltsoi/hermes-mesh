"""Mesh platform adapter — receive HMAC-signed Mesh messages.

Runs an aiohttp HTTP server that receives one-way mesh pings from other
Hermes fleet agents, validates HMAC-SHA256 signatures, parses the mesh
metadata envelope, and routes the message into the configured platform
session (e.g. the local agent's Telegram DM).
"""
import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import errno
import sys
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import yaml
except Exception:  # pragma: no cover - PyYAML is a hard dependency of Hermes
    yaml = None  # type: ignore[assignment]

try:
    from aiohttp import web

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None  # type: ignore[assignment]

from .identity import get_raw_agent_identity
from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter, MessageEvent, MessageType, SendResult

logger = logging.getLogger(__name__)


def _transport(agent_info: dict, name: str) -> dict:
    if not isinstance(agent_info, dict):
        return {}
    transport = agent_info.get("transports", {}).get(name, {})
    return transport if isinstance(transport, dict) else {}


def _transport_auth_value(transport: dict, key: str) -> str:
    auth = transport.get("auth", {}) if isinstance(transport, dict) else {}
    if not isinstance(auth, dict):
        return ""
    value = auth.get(key, "")
    if value is None:
        return ""
    return str(value)


# Default bind host. ``None`` tells aiohttp/asyncio's ``create_server`` to bind
# BOTH address families (IPv4 + IPv6) — the portable dual-stack default.
DEFAULT_HOST = None
DEFAULT_PORT = 8645

_MESH_ENVELOPE_RE = re.compile(
    r'^\s*\[mesh\]\[from:([^\]]+)\]\[to:([^\]]+)\]\[id:([^\]]+)\]'
    r'\[action:([^\]]+)\]\[reply:([^\]]+)\]'
    r'(?:\[ref:([^\]]+)\])?\s*'
)


def _is_loopback_host(host: Optional[str]) -> bool:
    """True when `host` binds only to the local machine."""
    if not host:
        return False
    return host.strip().lower() in {"127.0.0.1", "localhost", "::1"}


def check_mesh_requirements() -> bool:
    """Check if mesh adapter dependencies are available."""
    if not AIOHTTP_AVAILABLE:
        return False
    try:
        import gateway.config
        import gateway.platforms.base
        return True
    except Exception:
        return False


def _global_mesh_target_session() -> Optional[str]:
    """Return target_session from the global ~/.hermes/config.yaml, if any.

    Profile configs can override ``platforms.mesh.extra`` entirely, which
    drops the global ``target_session``. Falling back to the global value
    lets the mesh adapter still route into the configured platform session
    (e.g. ``telegram:dm:<id>``) without requiring the user to duplicate it
    in every profile.
    """
    if yaml is None:
        return None
    try:
        global_cfg = Path.home() / ".hermes" / "config.yaml"
        if not global_cfg.exists():
            return None
        data = yaml.safe_load(global_cfg.read_text(encoding="utf-8")) or {}
        return (
            data.get("platforms", {})
            .get("mesh", {})
            .get("extra", {})
            .get("target_session")
        )
    except Exception:
        return None


def _patch_gateway_runner_authz() -> None:
    """Work around a stale GatewayRunner method signature.

    ``gateway.run:GatewayRunner`` overrides ``_get_unauthorized_dm_behavior``
    without the ``profile`` keyword-only argument that its own
    ``_is_user_authorized`` call site passes (``profile=source.profile``).
    The mixin implementation already has the correct signature and uses
    ``_adapter_dm_policy(platform, profile=profile)``. Bind it onto
    ``GatewayRunner`` at import so unauthorized DMs do not crash the gateway.
    """
    try:
        import inspect
        from gateway.run import GatewayRunner
        from gateway.authz_mixin import GatewayAuthorizationMixin
    except Exception:
        return

    try:
        sig = inspect.signature(GatewayRunner._get_unauthorized_dm_behavior)
    except Exception:
        return
    if "profile" in sig.parameters:
        return

    try:
        GatewayRunner._get_unauthorized_dm_behavior = (
            GatewayAuthorizationMixin._get_unauthorized_dm_behavior
        )
    except Exception:
        return


class MeshAdapter(BasePlatformAdapter):
    """Receive HMAC-signed Mesh messages into a configured platform session."""

    # Mesh deliveries are event-triggered; never prompt for session restoration.
    interactive_resume: bool = False

    # HMAC signature verification at intake acts as an allowlist: only peers
    # whose secret we share can reach this adapter. Tell GatewayRunner that
    # this adapter enforces its own access policy so env allowlists do not
    # double-deny authenticated mesh senders.
    enforces_own_access_policy: bool = True

    def __init__(self, config: PlatformConfig):
        # Patch stale upstream method signature before the adapter is connected.
        _patch_gateway_runner_authz()
        super().__init__(config, Platform("mesh"))
        self._background_tasks = getattr(self, "_background_tasks", set())
        _cfg_host = config.extra.get("host", DEFAULT_HOST)
        self._host: Optional[str] = _cfg_host or None
        self._port: int = int(config.extra.get("port", DEFAULT_PORT))
        self._route: str = config.extra.get("route", "receive")
        self._secret: str = config.extra.get("secret", "")
        self._target_session: Optional[str] = config.extra.get("target_session")
        if not self._target_session:
            self._target_session = _global_mesh_target_session()
        self._agent_name: str = str(
            config.extra.get("agent_name")
            or os.getenv("MESH_AGENT_NAME")
            or os.getenv("A2A_AGENT_NAME", "hermes-agent")
        ).strip()
        # GatewayRunner uses this to decide whether the adapter's intake gating
        # is an allowlist (trustworthy) rather than open/pairing.
        self._dm_policy: str = "allowlist"
        self._runner = None
        self._seen_message_ids: set[str] = set()

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        if not AIOHTTP_AVAILABLE:
            logger.error("[mesh] aiohttp is not installed")
            return False

        if not self._secret:
            raise ValueError(
                "[mesh] HMAC secret is required. Set platforms.mesh.extra.secret "
                "in config.yaml or use INSECURE_NO_AUTH for local testing."
            )

        if self._secret == "INSECURE_NO_AUTH" and not _is_loopback_host(self._host):
            raise ValueError(
                f"[mesh] INSECURE_NO_AUTH is only allowed on loopback interfaces, "
                f"not '{self._host}'."
            )

        app = web.Application(client_max_size=1024 * 1024)
        app.router.add_post(f"/mesh/{self._route}", self._handle_mesh)

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(
            self._runner,
            self._host,
            self._port,
            reuse_address=False if sys.platform == "darwin" else None,
        )
        try:
            await site.start()
        except OSError as exc:
            if exc.errno not in {
                errno.EADDRINUSE, errno.EADDRNOTAVAIL, errno.EACCES, errno.EPERM
            }:
                raise
            await self._runner.cleanup()
            self._runner = None
            logger.error(
                "[mesh] Could not bind %s:%d: %s",
                self._host or "all IPv4+IPv6 interfaces",
                self._port,
                exc,
            )
            return False

        self._mark_connected()
        logger.info(
            "[mesh] Listening on %s:%d — agent '%s'",
            self._host or "* (all interfaces, IPv4+IPv6)",
            self._port,
            self._agent_name,
        )
        return True

    async def disconnect(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        self._mark_disconnected()
        logger.info("[mesh] Disconnected")

    async def _handle_mesh(self, request: "web.Request") -> "web.Response":
        body = await request.read()

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return web.json_response({"status": "invalid json"}, status=400)

        text = str(payload.get("text", ""))
        from_field = payload.get("from")

        # C5: per-agent HMAC — verify with the sender's own webhook secret if known
        provided = request.headers.get("X-Hub-Signature-256", "")
        if self._secret != "INSECURE_NO_AUTH":
            verify_secret = self._secret
            if from_field:
                sender_info = get_raw_agent_identity(from_field)
                if sender_info:
                    sender_secret = _transport_auth_value(_transport(sender_info, "hermes_webhook"), "secret")
                    if sender_secret:
                        verify_secret = sender_secret
            expected = "sha256=" + hmac.new(
                verify_secret.encode(), body, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(provided.encode(), expected.encode()):
                logger.warning("[mesh] HMAC verification failed")
                return web.json_response({"status": "unauthorized"}, status=401)

        m = _MESH_ENVELOPE_RE.match(text)
        if not m:
            return web.json_response({"status": "missing mesh envelope"}, status=400)

        sender, recipient, msg_id, action, reply, ref = m.groups()

        if msg_id in self._seen_message_ids:
            logger.info("[mesh] Duplicate message_id %s dropped", msg_id)
            return web.json_response({"status": "duplicate"}, status=200)
        self._seen_message_ids.add(msg_id)
        if len(self._seen_message_ids) > 10000:
            self._seen_message_ids.clear()

        if from_field and sender != from_field:
            logger.warning("[mesh] Envelope sender '%s' does not match body 'from' field '%s'", sender, from_field)
            return web.json_response({"status": "sender mismatch"}, status=401)
        body_text = text[m.end():].lstrip()

        if recipient != self._agent_name:
            logger.warning(
                "[mesh] Envelope recipient '%s' does not match local agent '%s'",
                recipient,
                self._agent_name,
            )
            return web.json_response(
                {"status": "recipient mismatch", "recipient": recipient},
                status=404,
            )

        # Render the message with routing CTA so the agent sees the mesh context.
        cta = ""
        if action and reply:
            cta = f" [Reply via mesh to {sender} — action: {action}, reply: {reply}]"
        display_text = f"⬡ [Mesh from:{sender}] {body_text}{cta}"

        # Build session source. Prefer target_session routing into an existing
        # platform session (e.g. Telegram DM) so the agent has full context.
        if self._target_session:
            parts = self._target_session.split(":", 2)
            target_platform_str = parts[0]
            if len(parts) == 3:
                target_chat_type = parts[1]
                target_chat_id = parts[2]
            elif len(parts) == 2:
                target_chat_type = "dm"
                target_chat_id = parts[1]
            else:
                target_chat_type = "dm"
                target_chat_id = parts[0]

            # For DM target sessions, use the chat_id as user_id so platform
            # env allowlists (e.g. TELEGRAM_ALLOWED_USERS) match the intended
            # recipient. Keep the mesh sender identity in user_name and
            # user_id_alt for logging and any downstream fallback.
            if target_chat_type == "dm":
                user_id = target_chat_id
                user_id_alt = f"mesh:{sender}"
            else:
                user_id = f"mesh:{sender}"
                user_id_alt = None

            source = self.build_source(
                chat_id=target_chat_id,
                chat_name=f"mesh/{sender}",
                chat_type=target_chat_type,
                user_id=user_id,
                user_id_alt=user_id_alt,
                user_name=sender,
                _platform=Platform(target_platform_str),
            )
        else:
            source = self.build_source(
                chat_id=f"mesh:{sender}:{msg_id}",
                chat_name=f"mesh/{sender}",
                chat_type="mesh",
                user_id=f"mesh:{sender}",
                user_name=sender,
            )

        event = MessageEvent(
            text=display_text,
            message_type=MessageType.TEXT,
            source=source,
            raw_message=payload,
            message_id=msg_id,
        )
        event.metadata["mesh"] = {
            "sender": sender,
            "recipient": recipient,
            "action": action,
            "reply": reply,
            "ref": ref,
            "message_id": msg_id,
        }

        logger.info(
            "[mesh] received from=%s to=%s action=%s reply=%s id=%s",
            sender,
            recipient,
            action,
            reply,
            msg_id,
        )

        task = asyncio.create_task(self.handle_message(event))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        return web.json_response(
            {"status": "accepted", "delivery_id": msg_id},
            status=202,
        )

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        """Return minimal chat info for mesh sessions."""
        return {
            "name": f"mesh/{chat_id}",
            "type": "dm",
        }

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Mesh is one-way inbound; log any agent response locally."""
        logger.info("[mesh] Response for %s: %s", chat_id, content[:200])
        return SendResult(success=True)

    async def on_processing_complete(self, event: MessageEvent, outcome: Any) -> None:
        """Close isolated mesh sessions; leave real platform sessions open."""
        source_chat_type = getattr(event.source, "chat_type", None)
        if source_chat_type == "dm":
            logger.debug("[mesh] Skipping session close for guest delivery")
            return

        runner = self.gateway_runner
        if runner is None:
            return
        session_db = getattr(runner, "_session_db", None)
        store = getattr(runner, "session_store", None)
        if session_db is None or store is None:
            return

        try:
            key_fn = getattr(runner, "_session_key_for_source", None)
            if key_fn is None:
                return
            session_key = key_fn(event.source)
            session_id = store.get(session_key)
            if session_id is None:
                return
            await session_db.end_session(session_id, reason="mesh_complete")
        except Exception as exc:
            logger.warning("[mesh] Failed to end session: %s", exc)
