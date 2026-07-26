"""Shared helpers used by both the mesh adapter and session relay."""
from __future__ import annotations


def transport(agent_info: dict, name: str) -> dict:
    """Return a transport dict from an agent identity, or an empty dict."""
    if not isinstance(agent_info, dict):
        return {}
    value = agent_info.get("transports", {}).get(name, {})
    return value if isinstance(value, dict) else {}


def transport_auth_value(transport_info: dict, key: str) -> str:
    """Return an auth value from a transport dict, or an empty string."""
    auth = transport_info.get("auth", {}) if isinstance(transport_info, dict) else {}
    if not isinstance(auth, dict):
        return ""
    value = auth.get(key, "")
    return value if value is not None else ""
