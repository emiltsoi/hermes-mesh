"""Optional bridge between hermes-mesh and the mesh-peer-registry server.

This module is the only place that imports mesh_peer_registry, so
hermes-mesh can still be installed and used without mesh-peer-registry
when no registry operations are needed.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from . import auth
from .common import mesh_extra
from .identity import write_agent_identity

logger = logging.getLogger(__name__)

try:
    from mesh_peer_registry.client import RegistryClient
    from mesh_peer_registry.models import PeerInfo

    MESH_PEER_REGISTRY_AVAILABLE = True
except Exception:  # pragma: no cover
    MESH_PEER_REGISTRY_AVAILABLE = False
    RegistryClient = None  # type: ignore[assignment,misc]
    PeerInfo = None  # type: ignore[assignment,misc]


def _this_agent_name() -> str:
    return os.getenv("MESH_AGENT_NAME", "hermes-agent")


def _registry_url(extra: dict | None = None) -> str:
    return mesh_extra(extra).get("registry_url", "")


def _ensure_registry() -> None:
    if not MESH_PEER_REGISTRY_AVAILABLE:
        raise RuntimeError("mesh-peer-registry is required for registry operations")


def _registry_client(name: str, extra: dict | None = None) -> Any:
    """Return a RegistryClient for `name` against the configured registry."""
    _ensure_registry()
    url = _registry_url(extra)
    if not url:
        raise RuntimeError("registry_url is required for registry operations")
    private_pem, public_pem = auth.load_or_generate_keypair(name, extra)
    return RegistryClient(url, private_pem, public_pem)


def list_peers(extra: dict | None = None) -> list[Any]:
    """List peers from the configured registry."""
    return _registry_client(_this_agent_name(), extra).list_peers()


def register_peer(
    name: str,
    url: str,
    role: str,
    description: str,
    extra: dict | None = None,
    ttl: int | None = None,
) -> dict:
    """Register an agent on the mesh peer registry."""
    client = _registry_client(_this_agent_name(), extra)
    return client.register(name, url, role=role, description=description, ttl=ttl)


def deregister_peer(name: str, extra: dict | None = None) -> dict:
    """Deregister an agent from the mesh peer registry."""
    client = _registry_client(_this_agent_name(), extra)
    return client.deregister(name)


def get_peer(name: str, extra: dict | None = None) -> Any:
    """Return a single peer from the registry."""
    client = _registry_client(_this_agent_name(), extra)
    return client.get_peer(name)


def sync_peer(name: str, extra: dict | None = None) -> dict:
    """Fetch a peer from the registry and write it to the local mesh cache.

    The public key is stored under `transports.hermes_webhook.auth.public_key`
    so the local adapter can verify messages from this peer.
    """
    peer = get_peer(name, extra)
    if not peer:
        raise RuntimeError(f"peer '{name}' not found in registry")

    identity = {
        "id": name,
        "name": name,
        "description": peer.description or "",
        "role": peer.role or "agent",
        "transports": {
            "hermes_webhook": {
                "url": peer.url,
                "auth": {"public_key": peer.public_key},
            },
        },
    }
    path = write_agent_identity(name, identity)
    return {"synced": True, "name": name, "path": str(path)}


def publish_peer(
    name: str,
    url: str,
    role: str,
    description: str,
    extra: dict | None = None,
    ttl: int | None = None,
) -> dict:
    """Publish the local agent's identity to the registry."""
    return register_peer(name, url, role, description, extra=extra, ttl=ttl)
