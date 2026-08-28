"""Shared helpers used by both the mesh adapter and session relay."""
from __future__ import annotations

import re
import time
from collections import defaultdict
from typing import Any
import os
from pathlib import Path

import yaml

from mesh_core.envelope import parse_envelope as _parse_envelope
from mesh_core.envelope import validate_envelope_token as _validate_envelope_token
from mesh_core.exceptions import EnvelopeError

# DSN (Delivery-Status Notification) constants
MESH_DSN_HEADER = "X-Mesh-DSN"
MESH_DSN_VALUE = "1"


def parse_mesh_header(text: str) -> dict | None:
    """Parse the bracketed [mesh] envelope header into a dict, or None."""
    try:
        envelope = _parse_envelope(text)
    except EnvelopeError:
        return None
    return {
        "sender": envelope.sender,
        "recipient": envelope.recipient,
        "msg_id": envelope.msg_id,
        "action": envelope.action,
        "reply": envelope.reply,
        "ref": envelope.ref,
        "body_text": envelope.body,
    }


def validate_envelope_token(token: object) -> str:
    """Validate a message id, ref, or task id.

    Envelope tokens appear inside the bracket mesh header and in logs, so
    they must be short and free of injection/whitespace characters. Returns
    the token as a string. Raises ValueError if it is empty or invalid.
    """
    try:
        return _validate_envelope_token(token)
    except EnvelopeError as exc:
        raise ValueError(str(exc)) from exc


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
