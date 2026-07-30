from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Platform(Enum):
    """Stub Platform enum that accepts any non-empty string."""

    LOCAL = "local"

    @classmethod
    def _missing_(cls, value):
        if not isinstance(value, str) or not value.strip():
            return None
        normalized = value.strip().lower()
        # Check existing map first
        if normalized in cls._value2member_map_:
            return cls._value2member_map_[normalized]
        pseudo = object.__new__(cls)
        pseudo._value_ = normalized
        pseudo._name_ = normalized.upper().replace("-", "_").replace(" ", "_")
        cls._value2member_map_[normalized] = pseudo
        cls._member_map_[pseudo._name_] = pseudo
        return pseudo


@dataclass
class PlatformConfig:
    enabled: bool = False
    token: str | None = None
    api_key: str | None = None
    reply_to_mode: str = "first"
    gateway_restart_notification: bool = True
    typing_indicator: bool = True
    typing_status_text: str | None = None
    channel_overrides: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)
