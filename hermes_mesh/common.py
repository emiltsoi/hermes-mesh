"""Shared helpers used by both the mesh adapter and session relay."""
from __future__ import annotations

import re

_ENVELOPE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def validate_envelope_token(token: object) -> str:
    """Validate a message id, ref, or task id.

    Envelope tokens appear inside the bracket mesh header and in logs, so
    they must be short and free of injection/whitespace characters. Returns
    the token as a string. Raises ValueError if it is empty or invalid.
    """
    if not isinstance(token, str):
        raise ValueError(f"Envelope token must be a string: {token!r}")
    value = token.strip()
    if not value:
        raise ValueError("Envelope token must not be empty")
    if not _ENVELOPE_TOKEN_RE.match(value):
        raise ValueError(
            f"Invalid envelope token: {value!r}. "
            "Allowed: 1-128 characters from A-Z, a-z, 0-9, _, ., -, :"
        )
    return value


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
