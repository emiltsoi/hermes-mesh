from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from gateway.config import Platform, PlatformConfig
from gateway.session import SessionSource


class MessageType:
    TEXT = "text"


@dataclass
class MessageEvent:
    text: str
    message_type: str = MessageType.TEXT
    source: SessionSource | None = None
    raw_message: Any = None
    message_id: str | None = None
    platform_update_id: int | None = None
    media_urls: list[str] = field(default_factory=list)
    media_types: list[str] = field(default_factory=list)
    reply_to_message_id: str | None = None
    reply_to_text: str | None = None
    reply_to_author_id: str | None = None
    reply_to_author_name: str | None = None
    reply_to_is_own_message: bool = False
    auto_skill: Any | None = None
    channel_prompt: str | None = None
    channel_context: str | None = None
    internal: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class SendResult:
    success: bool
    message_id: str | None = None
    error: str | None = None
    raw_response: Any = None


@dataclass
class GatewayCommand:
    name: str = ""
    args: str = ""


def coerce_plaintext_gateway_command(event: MessageEvent) -> None:
    """No-op stub."""


class BasePlatformAdapter:
    """Minimal stub of gateway.platforms.base.BasePlatformAdapter for tests."""

    gateway_runner = None
    interactive_resume: bool = True
    enforces_own_access_policy: bool = False

    def __init__(self, config: PlatformConfig, platform: Platform):
        self.config = config
        self.platform = platform
        self._message_handler = None
        self._topic_recovery_fn = None
        self._running = False
        self._fatal_error_code: str | None = None
        self._fatal_error_message: str | None = None
        self._fatal_error_retryable = True
        self._fatal_error_handler = None
        self._active_sessions: dict[str, Any] = {}
        self._pending_messages: dict[str, Any] = {}
        self._session_tasks: dict[str, Any] = {}
        self._busy_text_mode = "interrupt"
        self._background_tasks = set()

    def _mark_disconnected(self) -> None:
        self._running = False

    def _mark_connected(self) -> None:
        self._running = True

    async def cancel_background_tasks(self) -> None:
        """No-op stub."""

    def build_source(
        self,
        chat_id: str,
        chat_name: str | None = None,
        chat_type: str = "dm",
        user_id: str | None = None,
        user_name: str | None = None,
        thread_id: str | None = None,
        chat_topic: str | None = None,
        user_id_alt: str | None = None,
        chat_id_alt: str | None = None,
        is_bot: bool = False,
        scope_id: str | None = None,
        guild_id: str | None = None,
        parent_chat_id: str | None = None,
        message_id: str | None = None,
        role_authorized: bool = False,
        auto_thread_created: bool = False,
        auto_thread_initial_name: str | None = None,
        _platform: Platform | None = None,
        **kwargs: Any,
    ) -> SessionSource:
        if chat_topic is not None and not chat_topic.strip():
            chat_topic = None
        return SessionSource(
            platform=_platform or self.platform,
            chat_id=str(chat_id),
            chat_name=chat_name,
            chat_type=chat_type,
            user_id=str(user_id) if user_id else None,
            user_name=user_name,
            thread_id=str(thread_id) if thread_id else None,
            chat_topic=chat_topic.strip() if chat_topic else None,
            user_id_alt=user_id_alt,
            chat_id_alt=chat_id_alt,
            is_bot=is_bot,
            scope_id=str(scope_id) if scope_id else None,
            guild_id=str(guild_id) if guild_id else None,
            parent_chat_id=str(parent_chat_id) if parent_chat_id else None,
            message_id=str(message_id) if message_id else None,
            role_authorized=role_authorized,
            auto_thread_created=auto_thread_created,
            auto_thread_initial_name=auto_thread_initial_name,
        )

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        raise NotImplementedError

    async def disconnect(self) -> None:
        raise NotImplementedError

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SendResult:
        raise NotImplementedError

    async def get_chat_info(self, chat_id: str) -> dict[str, Any]:
        raise NotImplementedError


__all__ = [
    "BasePlatformAdapter",
    "GatewayCommand",
    "MessageEvent",
    "MessageType",
    "SendResult",
    "coerce_plaintext_gateway_command",
]
