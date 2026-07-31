"""Shared helpers used by both the mesh adapter and session relay."""
from __future__ import annotations

import re
import time
from collections import defaultdict
from typing import Any
import os
from pathlib import Path

import yaml

_ENVELOPE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

# DSN (Delivery-Status Notification) constants
MESH_DSN_HEADER = "X-Mesh-DSN"
MESH_DSN_VALUE = "1"

_MESH_HEADER_RE = re.compile(
    r'^\s*\[mesh\](?:\[v:[^\]]+\])?\[from:([^\]]+)\]\[to:([^\]]+)\]\[id:([^\]]+)\]'
    r'\[action:([^\]]+)\]\[reply:([^\]]+)\]'
    r'(?:\[ref:([^\]]+)\])?\s*'
)


def parse_mesh_header(text: str) -> dict | None:
    """Parse the bracketed [mesh] envelope header into a dict, or None."""
    m = _MESH_HEADER_RE.match(text)
    if not m:
        return None
    sender, recipient, msg_id, action, reply, ref = m.groups()
    body_text = text[m.end():].lstrip()
    return {
        "sender": sender,
        "recipient": recipient,
        "msg_id": msg_id,
        "action": action,
        "reply": reply,
        "ref": ref,
        "body_text": body_text,
    }


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

def mesh_extra(extra: dict | None = None) -> dict:
    """Return platforms.mesh.extra from the active Hermes profile config.

    If `extra` is provided (e.g. from a PlatformConfig), use it directly.
    """
    if extra is not None:
        return extra
    home = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")))
    cfg = home / "config.yaml"
    if not cfg.exists():
        return {}
    try:
        data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        return {}
    return data.get("platforms", {}).get("mesh", {}).get("extra", {}) or {}


# ---------------------------------------------------------------------------
# Lightweight metrics
# ---------------------------------------------------------------------------

_METRICS: dict[str, dict[str, Any]] = defaultdict(lambda: defaultdict(int))
_METRICS_TIMES: dict[str, float] = {}


def record_metric(category: str, name: str, value: int = 1) -> None:
    """Record a counter metric under `category.name`."""
    _METRICS[category][name] += value
    _METRICS_TIMES[f"{category}.{name}"] = time.time()


def get_metrics() -> dict[str, dict[str, Any]]:
    """Return a copy of all recorded metrics."""
    return {k: dict(v) for k, v in _METRICS.items()}


def get_metrics_summary() -> dict[str, Any]:
    """Return the canonical mesh health counters."""
    return {
        "mesh_send_total": _METRICS["send"].get("total", 0),
        "mesh_send_failed": _METRICS["send"].get("failed", 0),
        "mesh_receive_total": _METRICS["receive"].get("total", 0),
        "mesh_receive_unauthorized": _METRICS["receive"].get("unauthorized", 0),
        "mesh_receive_rate_limited": _METRICS["receive"].get("rate_limited", 0),
        "mesh_receive_duplicate": _METRICS["receive"].get("duplicate", 0),
        "last_event_time": _METRICS_TIMES,
    }
