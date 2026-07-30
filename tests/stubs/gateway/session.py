from dataclasses import dataclass

from gateway.config import Platform


@dataclass
class SessionSource:
    platform: Platform
    chat_id: str
    chat_name: str | None = None
    chat_type: str = "dm"
    user_id: str | None = None
    user_name: str | None = None
    thread_id: str | None = None
    chat_topic: str | None = None
    user_id_alt: str | None = None
    chat_id_alt: str | None = None
    is_bot: bool = False
    scope_id: str | None = None
    guild_id: str | None = None
    parent_chat_id: str | None = None
    message_id: str | None = None
    profile: str | None = None
    role_authorized: bool = False
    auto_thread_created: bool = False
    auto_thread_initial_name: str | None = None
    delivered_via_upstream_relay: bool = False

    def __post_init__(self) -> None:
        if self.scope_id is None and self.guild_id is not None:
            self.scope_id = self.guild_id
        elif self.scope_id is not None:
            self.guild_id = self.scope_id


def _session_key_namespace(profile: str | None = None) -> str:
    if not profile or profile == "default":
        return "agent:main"
    return f"agent:{profile}"


def build_session_key(
    source: SessionSource,
    group_sessions_per_user: bool = True,
    thread_sessions_per_user: bool = False,
    profile: str | None = None,
) -> str:
    """Minimal deterministic session-key builder for tests."""
    ns = _session_key_namespace(profile)
    platform = source.platform.value

    if source.chat_type == "dm":
        dm_chat_id = source.chat_id
        if dm_chat_id:
            if source.thread_id:
                return f"{ns}:{platform}:dm:{dm_chat_id}:{source.thread_id}"
            return f"{ns}:{platform}:dm:{dm_chat_id}"
        participant_id = source.user_id_alt or source.user_id
        if participant_id:
            if source.thread_id:
                return f"{ns}:{platform}:dm:{participant_id}:{source.thread_id}"
            return f"{ns}:{platform}:dm:{participant_id}"
        if source.thread_id:
            return f"{ns}:{platform}:dm:{source.thread_id}"
        return f"{ns}:{platform}:dm"

    participant_id = source.user_id_alt or source.user_id
    key_parts = [ns, platform, source.chat_type]
    if source.chat_id:
        key_parts.append(source.chat_id)
    if source.thread_id:
        key_parts.append(source.thread_id)
    isolate_user = group_sessions_per_user
    if source.thread_id and not thread_sessions_per_user:
        isolate_user = False
    if isolate_user and participant_id:
        key_parts.append(str(participant_id))
    return ":".join(key_parts)
