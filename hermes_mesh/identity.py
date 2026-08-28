"""Fleet identity resolution for Hermes mesh.

Resolves agent identities from the fleet vault at:
  $HERMES_HOME/fleet/mesh/agents/<name>/identity.yaml

Delegates the heavy lifting to ``mesh_core.identity.IdentityVault`` while
preserving Hermes-specific environment variables and the existing public API.
"""
from __future__ import annotations

import logging
import os
import re
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Optional

import yaml

from mesh_core.identity import IdentityVault, MeshIdentity

logger = logging.getLogger(__name__)


# TTL cache keyed by absolute path. Each entry stores (load_time, mtime, data).
# Invalidation happens on mtime change and/or TTL expiry. TTL can be tuned via
# MESH_IDENTITY_CACHE_TTL (seconds); 0 disables caching.
_raw_ttl = os.getenv("MESH_IDENTITY_CACHE_TTL") or "1.0"
try:
    _IDENTITY_CACHE_TTL = max(0.0, float(_raw_ttl))
except ValueError:
    _IDENTITY_CACHE_TTL = 1.0

_raw_maxsize = os.getenv("MESH_IDENTITY_CACHE_MAXSIZE") or "256"
try:
    _IDENTITY_CACHE_MAXSIZE = max(1, int(_raw_maxsize))
except ValueError:
    _IDENTITY_CACHE_MAXSIZE = 256


class _HermesIdentityVault(IdentityVault):
    """IdentityVault whose root follows Hermes env conventions."""

    def __init__(self, *, cache_ttl: float, cache_maxsize: int) -> None:
        self._cache_ttl = cache_ttl
        self._cache_maxsize = cache_maxsize
        self._cache: OrderedDict[Path, tuple[float, Optional[float], Optional[dict]]] = OrderedDict()

    @property
    def root(self) -> Path:
        return _fleet_root()

    @root.setter
    def root(self, value: object) -> None:
        # Ignored: the root is always derived from Hermes env vars.
        pass

    @property
    def agents_root(self) -> Path:
        return _mesh_agents_root()

    @agents_root.setter
    def agents_root(self, value: object) -> None:
        # Ignored: the agents root is always derived from Hermes env vars.
        pass

    def _identity_file(self, name: str) -> Path:
        return _mesh_agents_root() / name / "identity.yaml"


vault = _HermesIdentityVault(
    cache_ttl=_IDENTITY_CACHE_TTL,
    cache_maxsize=_IDENTITY_CACHE_MAXSIZE,
)

# Legacy module-level cache alias used by session_relay metrics.
_IDENTITY_CACHE = vault._cache


def _hermes_root() -> Path:
    """Return the Hermes root directory (above profiles/ if inside one)."""
    home = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")))
    parts = home.parts
    if any(p == "profiles" for p in parts):
        idx = parts.index("profiles")
        return Path(*parts[:idx]) if idx > 0 else Path("/")
    return home


def _fleet_root() -> Path:
    """Return the fleet root directory from env or HERMES_HOME/fleet."""
    return Path(
        os.environ.get("MESH_VAULT_PATH")
        or str(_hermes_root() / "fleet")
    )


def _mesh_agents_root() -> Path:
    """Return the primary mesh agents directory."""
    return _fleet_root() / "mesh" / "agents"


def _resolve_env(value: Any) -> str:
    """Resolve ${ENV_VAR} interpolations and coerce values to strings.

    Raises RuntimeError if an env var is referenced but not set —
    fail-closed: never use a template string as a secret.
    """
    if not isinstance(value, str):
        return str(value)
    match = re.fullmatch(r"^\$\{([^}]+)\}$", value.strip())
    if match:
        env_key = match.group(1)
        resolved = os.environ.get(env_key)
        if resolved is None:
            raise RuntimeError(
                f"Vault env var ${env_key} is not set — refusing to use "
                f"template string as a secret. Set {env_key} in the environment."
            )
        return resolved
    return value


def _webhook_url(identity: dict) -> str:
    """Return the canonical mesh webhook URL for an agent identity."""
    if not isinstance(identity, dict):
        return ""
    return (identity.get("transports", {}).get("hermes_webhook", {}) or {}).get("url", "")


def _identity_file_for_agent(agent_key: str) -> Optional[Path]:
    """Return the identity.yaml path for an agent in the mesh vault."""
    candidate = vault._identity_file(agent_key)
    return candidate if candidate.exists() else None


def _identity_to_public(identity: MeshIdentity) -> dict:
    """Convert a MeshIdentity to the public Hermes identity dict."""
    return {
        "name": identity.name,
        "description": identity.description,
        "role": identity.role,
        "url": identity.url,
    }


def resolve_agent(name: str) -> Optional[dict]:
    """Look up an agent by name in the fleet vault.

    Returns:
        {name, url, description, role} or None if not found.
        Does NOT include credentials — safe to return to callers.
    """
    identity = vault.get(name)
    if identity is None:
        return None
    return _identity_to_public(identity)


def get_agent_identity(name: str) -> Optional[dict]:
    """Look up a public agent identity by name (same shape as resolve_agent)."""
    return resolve_agent(name)


def get_raw_agent_identity(name: str) -> Optional[dict]:
    """Return the raw agent identity WITH credentials for internal use.

    Returns the full identity.yaml content including transports and auth.
    Never return this to external callers — use resolve_agent() instead.
    """
    if not name:
        return None
    try:
        path = vault._identity_file(name)
    except ValueError:
        return None
    return vault._load_with_cache(path)


def get_public_key(name: str) -> Optional[str]:
    """Return the Ed25519 public key for an agent, if known."""
    return vault.get_public_key(name)


def get_webhook_url(name: str) -> Optional[str]:
    """Return the hermes webhook URL for an agent, if known."""
    return vault.get_webhook_url(name)


def list_agents() -> list[dict]:
    """Return all fleet agents from the mesh vault (no credentials)."""
    return [_identity_to_public(identity) for identity in vault.list()]


def write_agent_identity(agent_key: str, identity: dict, prefer_mesh: bool = True) -> Path:
    """Write an identity.yaml for an agent, creating parent directories.

    Always writes to fleet/mesh/agents. The `prefer_mesh` argument is kept
    for backward compatibility but is ignored.
    """
    agent_key = agent_key.lower().strip()
    if not agent_key:
        raise ValueError("Agent key must not be empty")

    identity_file = vault._identity_file(agent_key)
    agent_dir = identity_file.parent
    agent_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(agent_dir, 0o700)
    except OSError:
        logger.warning("Mesh identity: could not chmod directory %s", agent_dir)

    with open(identity_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(identity, f, sort_keys=False, allow_unicode=True)
    try:
        os.chmod(identity_file, 0o600)
    except OSError:
        logger.warning("Mesh identity: could not chmod file %s", identity_file)

    vault._cache.pop(identity_file, None)
    return identity_file


def refresh_identities() -> None:
    """Clear the entire identity cache. Useful after bulk vault changes."""
    vault.clear_cache()


def _invalidate_identity(name: str) -> None:
    """Remove a single agent's identity from the cache, if present."""
    agent_key = (name or "").lower().strip()
    if not agent_key:
        return
    try:
        identity_file = vault._identity_file(agent_key)
    except ValueError:
        return
    vault._cache.pop(identity_file, None)
