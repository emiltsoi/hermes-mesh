"""Mesh platform adapter — receive HMAC-signed Mesh messages.

Runs an aiohttp HTTP server that receives one-way mesh pings from other
Hermes fleet agents, validates HMAC-SHA256 signatures, parses the mesh
metadata envelope, and routes the message into the configured platform
session (e.g. the local agent's Telegram DM).
"""
import asyncio
import functools
import hashlib
import hmac
import json
import logging
import math
import os
import re
import errno
import sys
import time
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
from .session_relay import _validate_agent_name
from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
    coerce_plaintext_gateway_command,
)
from gateway.session import build_session_key

from .common import transport as _transport, transport_auth_value as _transport_auth_value

logger = logging.getLogger(__name__)


# Default bind host is loopback-only. Set ``host: 0.0.0.0`` or ``host: ::``
# in config.yaml explicitly to bind externally.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8645

_MESH_ENVELOPE_RE = re.compile(
    r'^\s*\[mesh\]\[from:([^\]]+)\]\[to:([^\]]+)\]\[id:([^\]]+)\]'
    r'\[action:([^\]]+)\]\[reply:([^\]]+)\]'
    r'(?:\[ref:([^\]]+)\])?\s*'
)
_ENVELOPE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


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


@functools.lru_cache(maxsize=1)
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
        ).strip().lower()
        # GatewayRunner uses this to decide whether the adapter's intake gating
        # is an allowlist (trustworthy) rather than open/pairing.
        self._dm_policy: str = "allowlist"
        self._runner = None
        # Ordered dict used as an insertion-ordered bounded set. Evict the
        # oldest id when the cap is exceeded instead of nuking the whole set
        # (which would let an attacker replay previously-seen messages).
        self._seen_message_ids: Dict[str, None] = {}
        self._mesh_inbox: "asyncio.Queue[Optional[MessageEvent]]" = asyncio.Queue(maxsize=256)
        self._mesh_processor: Optional[asyncio.Task] = None

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
        self._mesh_processor = asyncio.create_task(self._mesh_processor_loop())
        logger.info(
            "[mesh] Listening on %s:%d — agent '%s'",
            self._host or "* (all interfaces, IPv4+IPv6)",
            self._port,
            self._agent_name,
        )
        return True

    async def disconnect(self) -> None:
        if self._mesh_processor:
            try:
                self._mesh_inbox.put_nowait(None)
            except asyncio.QueueFull:
                pass
            try:
                # Allow the processor to drain the inbox (including any
                # in-flight per-message task) before cancelling it.
                await asyncio.wait_for(self._mesh_processor, timeout=30)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._mesh_processor.cancel()
                try:
                    await self._mesh_processor
                except asyncio.CancelledError:
                    pass
            self._mesh_processor = None
        await self.cancel_background_tasks()
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

        if not isinstance(payload, dict):
            logger.warning("[mesh] JSON body is not an object")
            return web.json_response({"status": "invalid json"}, status=400)

        text = str(payload.get("text", ""))
        from_field = payload.get("from")

        # H4: require a replay timestamp and reject messages outside a 5-minute window.
        timestamp_str = request.headers.get("X-Mesh-Timestamp", "")
        try:
            msg_ts = float(timestamp_str)
        except (TypeError, ValueError):
            logger.warning("[mesh] Missing or invalid X-Mesh-Timestamp header")
            return web.json_response({"status": "unauthorized"}, status=401)
        if not math.isfinite(msg_ts):
            logger.warning("[mesh] X-Mesh-Timestamp is NaN or infinite")
            return web.json_response({"status": "unauthorized"}, status=401)
        now = time.time()
        if abs(now - msg_ts) > 300:
            logger.warning("[mesh] X-Mesh-Timestamp outside replay window")
            return web.json_response({"status": "unauthorized"}, status=401)

        # S1/S2: per-agent HMAC. Require a valid, non-empty `from` field and
        # verify the signature with the sender's own webhook secret. Never fall
        # back to the receiver's secret: knowing the receiver's secret must not
        # let an attacker spoof an arbitrary sender.
        provided = request.headers.get("X-Hub-Signature-256", "")
        if self._secret != "INSECURE_NO_AUTH":
            if not from_field or not isinstance(from_field, str):
                logger.warning("[mesh] Missing sender 'from' field")
                return web.json_response({"status": "unauthorized"}, status=401)
            try:
                from_field = _validate_agent_name(from_field)
            except ValueError as exc:
                logger.warning("[mesh] Invalid sender name: %s", exc)
                return web.json_response({"status": "unauthorized"}, status=401)

            sender_info = get_raw_agent_identity(from_field)
            if not sender_info:
                logger.warning("[mesh] Unknown sender '%s'", from_field)
                return web.json_response({"status": "unauthorized"}, status=401)
            sender_secret = _transport_auth_value(
                _transport(sender_info, "hermes_webhook"), "secret"
            )
            if not sender_secret:
                logger.warning("[mesh] Sender '%s' has no webhook secret", from_field)
                return web.json_response({"status": "unauthorized"}, status=401)

            expected = "sha256=" + hmac.new(
                sender_secret.encode(), body, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(provided.encode(), expected.encode()):
                logger.warning("[mesh] HMAC verification failed for sender '%s'", from_field)
                return web.json_response({"status": "unauthorized"}, status=401)

        m = _MESH_ENVELOPE_RE.match(text)
        if not m:
            return web.json_response({"status": "bad request"}, status=400)

        sender, recipient, msg_id, action, reply, ref = m.groups()

        # Validate extracted envelope fields before using them in logs, headers, or metadata.
        try:
            sender = _validate_agent_name(sender)
        except ValueError as exc:
            logger.warning("[mesh] Invalid envelope sender: %s", exc)
            return web.json_response({"status": "bad request"}, status=400)
        try:
            recipient = _validate_agent_name(recipient)
        except ValueError as exc:
            logger.warning("[mesh] Invalid envelope recipient: %s", exc)
            return web.json_response({"status": "bad request"}, status=400)
        if action not in {"do", "info"}:
            logger.warning("[mesh] Invalid envelope action: %s", action)
            return web.json_response({"status": "bad request"}, status=400)
        if reply not in {"yes", "no"}:
            logger.warning("[mesh] Invalid envelope reply: %s", reply)
            return web.json_response({"status": "bad request"}, status=400)
        if not _ENVELOPE_TOKEN_RE.match(msg_id):
            logger.warning("[mesh] Invalid envelope message id: %s", msg_id)
            return web.json_response({"status": "bad request"}, status=400)
        if ref is not None and ref != "":
            if not _ENVELOPE_TOKEN_RE.match(ref):
                logger.warning("[mesh] Invalid envelope ref: %s", ref)
                return web.json_response({"status": "bad request"}, status=400)
        else:
            ref = None

        if msg_id in self._seen_message_ids:
            logger.info("[mesh] Duplicate message_id %s dropped", msg_id)
            return web.json_response({"status": "duplicate"}, status=200)
        self._seen_message_ids[msg_id] = None
        while len(self._seen_message_ids) > 10000:
            self._seen_message_ids.pop(next(iter(self._seen_message_ids)))

        if from_field and sender != from_field:
            logger.warning(
                "[mesh] Envelope sender '%s' does not match body 'from' field '%s'",
                sender,
                from_field,
            )
            return web.json_response({"status": "unauthorized"}, status=401)
        body_text = text[m.end():].lstrip()

        if recipient != self._agent_name:
            logger.warning(
                "[mesh] Envelope recipient '%s' does not match local agent '%s'",
                recipient,
                self._agent_name,
            )
            return web.json_response({"status": "not found"}, status=404)

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

        try:
            self._mesh_inbox.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning("[mesh] Inbox full; rejecting message %s", msg_id)
            return web.json_response(
                {"status": "busy", "delivery_id": msg_id},
                status=503,
            )

        return web.json_response(
            {"status": "accepted", "delivery_id": msg_id},
            status=202,
        )

    async def _mesh_processor_loop(self) -> None:
        """Serialize mesh deliveries so each message gets its own gateway turn.

        Without this, rapid consecutive mesh posts are queued as follow-ups
        inside a single ``GatewayRunner._handle_message`` invocation. The
        conversation loop then reuses the same ``GatewayStreamConsumer`` across
        multiple assistant replies, which causes the gateway to suppress the
        final Telegram send for every reply after the first ("final delivery
        already confirmed").

        Each mesh message is wrapped in its own ``asyncio.Task`` so session
        ownership/cancellation points at the per-message task, not at the
        long-lived processor loop. Cancelling the per-message task (e.g.
        ``busy_input_mode=interrupt`` or ``/stop``) therefore cannot kill the
        processor and drop the rest of the inbox queue.
        """
        while True:
            event = await self._mesh_inbox.get()
            if event is None:
                self._mesh_inbox.task_done()
                break
            _task = asyncio.create_task(self._process_mesh_event(event))
            self._background_tasks.add(_task)
            _task.add_done_callback(self._background_tasks.discard)
            try:
                await _task
            except asyncio.CancelledError:
                # Distinguish "this per-message task was cancelled" from
                # "the processor loop itself is being torn down".
                if not _task.cancelled():
                    break
            except Exception:
                logger.exception("[mesh] Failed to process queued message")
            finally:
                self._mesh_inbox.task_done()

    async def _process_mesh_event(self, event: MessageEvent) -> None:
        """Dispatch one mesh message as a fresh gateway turn."""
        coerce_plaintext_gateway_command(event)
        await asyncio.to_thread(self._apply_topic_recovery, event)

        session_key = build_session_key(
            event.source,
            group_sessions_per_user=self.config.extra.get("group_sessions_per_user", True),
            thread_sessions_per_user=self.config.extra.get("thread_sessions_per_user", False),
        )

        # Use the base adapter's session-lifecycle helper. It installs the
        # guard and spawns ``_process_message_background`` as a tracked
        # background task; ``cancel_session_processing`` cancels the child
        # task (not the mesh processor loop) and cleans the guard.
        if not self._start_session_processing(event, session_key):
            logger.warning("[mesh] Failed to start session processing for %s", session_key)
            return

        task = self._session_tasks.get(session_key)
        if task is None:
            return
        try:
            await task
        except asyncio.CancelledError:
            # Expected when a session command or ``busy_input_mode=interrupt``
            # cancels the in-flight turn.
            pass

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
