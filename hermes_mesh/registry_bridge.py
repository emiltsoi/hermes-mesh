"""Bridge between hermes-mesh and the optional mesh-peer-registry server.

This module is the only place that imports mesh_peer_registry, so
hermes-mesh can still be installed and used without mesh-peer-registry
when identity_source is "file" (the default).
"""
from __future__ import annotations

import logging
import math
import os
import time
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    CRYPTOGRAPHY_AVAILABLE = True
except Exception:  # pragma: no cover
    CRYPTOGRAPHY_AVAILABLE = False

try:
    from mesh_peer_registry.client import RegistryClient
    from mesh_peer_registry.crypto import (
        generate_keypair,
        sign_message,
        verify_message,
    )
    from mesh_peer_registry.models import PeerInfo

    MESH_PEER_REGISTRY_AVAILABLE = True
except Exception:  # pragma: no cover
    MESH_PEER_REGISTRY_AVAILABLE = False
    RegistryClient = None  # type: ignore[assignment]
    generate_keypair = None  # type: ignore[assignment]
    sign_message = None  # type: ignore[assignment]
    verify_message = None  # type: ignore[assignment]
    PeerInfo = None  # type: ignore[assignment]


REPLAY_WINDOW_SECONDS = 300


def _hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")))


def mesh_extra(extra: dict | None = None) -> dict:
    """Return platforms.mesh.extra from the active Hermes profile config.

    If `extra` is provided (e.g. from a PlatformConfig), use it directly.
    """
    if extra is not None:
        return extra
    cfg = _hermes_home() / "config.yaml"
    if not cfg.exists():
        return {}
    try:
        data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        logger.warning("mesh config: failed to load %s", cfg)
        return {}
    return data.get("platforms", {}).get("mesh", {}).get("extra", {}) or {}


def identity_source(extra: dict | None = None) -> str:
    return mesh_extra(extra).get("identity_source", "file")


def registry_url(extra: dict | None = None) -> str:
    return mesh_extra(extra).get("registry_url", "")


def private_key_path(name: str, extra: dict | None = None) -> Path:
    path = mesh_extra(extra).get("private_key_path")
    if path:
        return Path(os.path.expanduser(path))
    return Path.home() / ".mesh" / "keys" / f"{name}.pem"


def _ensure_crypto() -> None:
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("cryptography is required for Ed25519 key management")


def _ensure_registry() -> None:
    if not MESH_PEER_REGISTRY_AVAILABLE:
        raise RuntimeError(
            "mesh-peer-registry is required for identity_source=registry"
        )


def _public_from_private(private_pem: str) -> str:
    _ensure_crypto()
    private_key = serialization.load_pem_private_key(
        private_pem.encode("utf-8"), password=None
    )
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def load_or_generate_keypair(name: str, extra: dict | None = None) -> tuple[str, str]:
    """Load or generate the local Ed25519 keypair for this agent.

    Returns (private_key_pem, public_key_pem).
    """
    _ensure_registry()
    path = private_key_path(name, extra)
    if path.exists():
        private_pem = path.read_text(encoding="utf-8")
        return private_pem, _public_from_private(private_pem)

    path.parent.mkdir(parents=True, exist_ok=True)
    private_pem, public_pem = generate_keypair()
    path.write_text(private_pem, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        logger.warning("mesh keys: could not chmod %s", path)
    return private_pem, public_pem


def registry_client(name: str, extra: dict | None = None) -> Any:
    """Return a RegistryClient for this agent against the configured registry."""
    _ensure_registry()
    url = registry_url(extra)
    if not url:
        raise RuntimeError("registry_url is required for identity_source=registry")
    private_pem, public_pem = load_or_generate_keypair(name, extra)
    return RegistryClient(url, private_pem, public_pem)


def resolve_target(name: str, extra: dict | None = None) -> dict | None:
    """Resolve a target peer and return its URL + auth info.

    Returns a dict like:
      {"url": "...", "auth": {"type": "hmac-sha256", "secret": "..."}}
      {"url": "...", "auth": {"type": "ed25519", "public_key": "..."}}
    """
    if identity_source(extra) == "registry":
        return _resolve_target_from_registry(name, extra)
    return _resolve_target_from_file(name)


def _resolve_target_from_registry(name: str, extra: dict | None) -> dict | None:
    _ensure_registry()
    agent_name = _this_agent_name()
    client = registry_client(agent_name, extra)
    peer = client.get_peer(name)
    if not peer:
        return None
    return {
        "url": peer.url,
        "auth": {"type": "ed25519", "public_key": peer.public_key},
    }


def _resolve_target_from_file(name: str) -> dict | None:
    from .identity import get_raw_agent_identity

    raw = get_raw_agent_identity(name)
    if not raw:
        return None
    transport = raw.get("transports", {}).get("hermes_webhook", {}) or {}
    return {
        "url": transport.get("url", ""),
        "auth": {
            "type": "hmac-sha256",
            "secret": (transport.get("auth") or {}).get("secret", ""),
        },
    }


def resolve_sender(name: str, extra: dict | None = None) -> tuple[str, str, str | None]:
    """Resolve the local sender's signing material and auth type.

    Returns (signing_material, auth_type, public_key).
    For HMAC: signing_material is the secret, public_key is None.
    For Ed25519: signing_material is the private key PEM, public_key is the public key PEM.
    """
    if identity_source(extra) == "registry":
        private_pem, public_pem = load_or_generate_keypair(name, extra)
        return private_pem, "ed25519", public_pem
    from .identity import get_raw_agent_identity

    raw = get_raw_agent_identity(name)
    if not raw:
        return "", "", None
    transport = raw.get("transports", {}).get("hermes_webhook", {}) or {}
    secret = (transport.get("auth") or {}).get("secret", "")
    return secret, "hmac-sha256", None


def _this_agent_name() -> str:
    return os.getenv("MESH_AGENT_NAME", "hermes-agent")


def register_peer(
    name: str,
    url: str,
    role: str,
    description: str,
    extra: dict | None = None,
) -> dict:
    """Register this agent on the mesh peer registry."""
    _ensure_registry()
    agent_name = _this_agent_name()
    private_pem, public_pem = load_or_generate_keypair(agent_name, extra)
    client = registry_client(agent_name, extra)
    return client.register(name, url, role=role, description=description)


def deregister_peer(name: str, extra: dict | None = None) -> dict:
    """Deregister an agent from the mesh peer registry."""
    _ensure_registry()
    agent_name = _this_agent_name()
    client = registry_client(agent_name, extra)
    return client.deregister(name)


def list_peers(extra: dict | None = None) -> list[dict]:
    """List peers from the configured source."""
    if identity_source(extra) == "registry":
        _ensure_registry()
        agent_name = _this_agent_name()
        client = registry_client(agent_name, extra)
        return [
            {
                "name": p.name,
                "description": p.description,
                "role": p.role,
                "url": p.url,
            }
            for p in client.list_peers()
        ]
    from .identity import list_agents

    return list_agents()  # already returns `url`


def _lower_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of headers with lower-cased keys.

    HTTP header names are case-insensitive; Node's fetch in particular sends
    lower-case header names, so signature verification must not depend on the
    original casing.
    """
    return {k.lower(): v for k, v in headers.items()}


def verify_request_signature(
    request_headers: dict[str, str],
    body: bytes,
    from_field: str,
    extra: dict | None = None,
) -> tuple[str | None, str]:
    """Verify a mesh request signature (HMAC or Ed25519).

    Returns (from_field, "") on success or (None, error_message) on failure.
    """
    headers = _lower_headers(request_headers)
    hub_sig = headers.get("x-hub-signature-256", "")
    mesh_sig = headers.get("x-mesh-signature", "")

    if hub_sig:
        return _verify_hmac(headers, body, from_field, extra)

    if mesh_sig:
        return _verify_ed25519(headers, body, from_field, extra)

    return None, "missing signature header"


def _verify_hmac(
    request_headers: dict[str, str],
    body: bytes,
    from_field: str,
    extra: dict | None,
) -> tuple[str | None, str]:
    from .identity import get_raw_agent_identity

    raw = get_raw_agent_identity(from_field)
    if not raw:
        return None, f"unknown sender: {from_field}"
    transport = raw.get("transports", {}).get("hermes_webhook", {}) or {}
    secret = (transport.get("auth") or {}).get("secret", "")
    if not secret:
        return None, f"sender {from_field} has no HMAC secret"

    import hashlib
    import hmac

    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(
        request_headers.get("x-hub-signature-256", "").encode("utf-8"),
        expected.encode("utf-8"),
    ):
        return None, "HMAC verification failed"
    return from_field, ""


def verify_ed25519_signature(
    request_headers: dict[str, str],
    body: bytes,
    from_field: str,
    extra: dict | None = None,
) -> tuple[str | None, str]:
    """Verify an Ed25519 mesh request signature using the registry."""
    _ensure_registry()
    headers = _lower_headers(request_headers)
    timestamp_str = headers.get("x-mesh-timestamp", "")
    try:
        msg_ts = float(timestamp_str)
    except (TypeError, ValueError):
        return None, "missing or invalid X-Mesh-Timestamp"
    if not math.isfinite(msg_ts) or abs(time.time() - msg_ts) > REPLAY_WINDOW_SECONDS:
        return None, "X-Mesh-Timestamp outside replay window"

    url = registry_url(extra)
    if not url:
        return None, "registry_url is required to verify Ed25519 signatures"

    agent_name = _this_agent_name()
    client = registry_client(agent_name, extra)
    peer = client.get_peer(from_field)
    if not peer:
        return None, f"unknown sender in registry: {from_field}"

    sig = headers.get("x-mesh-signature", "")
    if not verify_message(peer.public_key, body, sig):
        return None, "Ed25519 verification failed"
    return from_field, ""


# Backward-compatible alias for internal callers.
_verify_ed25519 = verify_ed25519_signature
