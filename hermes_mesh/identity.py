"""Fleet identity resolution for Hermes mesh.

Resolves agent identities from the fleet vault at:
  $HERMES_HOME/fleet/mesh/agents/<name>/identity.yaml
"""
from __future__ import annotations

import logging
import os
import re
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Optional

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

# OrderedDict preserves insertion order and lets us move accessed items to the
# end, giving us a simple LRU eviction policy once the cache is bounded.
_IDENTITY_CACHE: OrderedDict[Path, tuple[float, Optional[float], Optional[dict]]] = OrderedDict()


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


def _file_mtime(path: Path) -> Optional[float]:
    """Return the mtime of a path, or None if it does not exist."""
    try:
        return path.stat().st_mtime
    except FileNotFoundError:
        return None


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


def _do_load_identity_yaml(path: Path) -> Optional[dict]:
    """Load and normalize an identity.yaml file from disk."""
    if not path.exists():
        return None
    import yaml
    try:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except (yaml.YAMLError, OSError) as e:
        logger.warning("Mesh identity: failed to load %s: %s", path, e)
        return None
    if not isinstance(raw, dict):
        return None

    # Normalize: resolve env vars in auth secrets
    for transport in raw.get("transports", {}).values():
        if not isinstance(transport, dict):
            continue
        auth = transport.get("auth")
        if isinstance(auth, dict):
            for key in ("token", "secret", "value"):
                if key in auth:
                    auth[key] = _resolve_env(auth[key])
    return raw


def _load_identity_yaml(path: Path) -> Optional[dict]:
    """Load and normalize an identity.yaml file, with TTL+mtime+LRU caching."""
    now = time.monotonic()
    mtime = _file_mtime(path)
    cached = _IDENTITY_CACHE.get(path)
    if cached is not None:
        cached_time, cached_mtime, cached_data = cached
        if (now - cached_time) < _IDENTITY_CACHE_TTL and cached_mtime == mtime:
            # Hit: keep the cached value and update access order for LRU.
            _IDENTITY_CACHE.move_to_end(path)
            return cached_data
    data = _do_load_identity_yaml(path)
    _IDENTITY_CACHE[path] = (now, mtime, data)
    _IDENTITY_CACHE.move_to_end(path)
    # Enforce the bound by evicting the least-recently-used entry.
    while len(_IDENTITY_CACHE) > _IDENTITY_CACHE_MAXSIZE:
        _IDENTITY_CACHE.popitem(last=False)
    return data


def refresh_identities() -> None:
    """Clear the entire identity cache. Useful after bulk vault changes."""
    _IDENTITY_CACHE.clear()


def _invalidate_identity(name: str) -> None:
    """Remove a single agent's identity from the cache, if present."""
    agent_key = (name or "").lower().strip()
    if not agent_key:
        return
    identity_file = _identity_file_for_agent(agent_key)
    if identity_file:
        _IDENTITY_CACHE.pop(identity_file, None)


def _webhook_url(identity: dict) -> str:
    """Return the canonical mesh webhook URL for an agent identity."""
    if not isinstance(identity, dict):
        return ""
    return (identity.get("transports", {}).get("hermes_webhook", {}) or {}).get("url", "")


def _identity_file_for_agent(agent_key: str) -> Optional[Path]:
    """Return the identity.yaml path for an agent in the mesh vault."""
    candidate = _mesh_agents_root() / agent_key / "identity.yaml"
    return candidate if candidate.exists() else None


def resolve_agent(name: str) -> Optional[dict]:
    """Look up an agent by name in the fleet vault.

    Returns:
        {name, url, description, role} or None if not found.
        Does NOT include credentials — safe to return to callers.
    """
    if not name:
        return None
    agent_key = name.lower()
    identity_file = _identity_file_for_agent(agent_key)
    if not identity_file:
        return None
    identity = _load_identity_yaml(identity_file)
    if not identity:
        return None
    return {
        "name": identity.get("name", ""),
        "description": identity.get("description", ""),
        "role": identity.get("role", ""),
        "url": _webhook_url(identity),
    }


def get_raw_agent_identity(name: str) -> Optional[dict]:
    """Return the raw agent identity WITH credentials for internal use.

    Returns the full identity.yaml content including transports and auth.
    Never return this to external callers — use resolve_agent() instead.
    """
    if not name:
        return None
    agent_key = name.lower()
    identity_file = _identity_file_for_agent(agent_key)
    if not identity_file:
        return None
    return _load_identity_yaml(identity_file)


def list_agents() -> list[dict]:
    """Return all fleet agents from the mesh vault (no credentials).

    Builds the public view from the already-loaded identity dict so each
    YAML is parsed only once.
    """
    agents = []
    seen = set()
    root = _mesh_agents_root()
    if not root.is_dir():
        return agents
    for agent_dir in root.iterdir():
        if not agent_dir.is_dir():
            continue
        identity_file = agent_dir / "identity.yaml"
        identity = _load_identity_yaml(identity_file)
        if not identity:
            continue
        name = str(identity.get("name") or agent_dir.name).lower()
        if name in seen:
            continue
        seen.add(name)
        url = _webhook_url(identity)
        agents.append({
            "name": name,
            "description": identity.get("description", ""),
            "role": identity.get("role", ""),
            "url": url,
        })
    return agents


def write_agent_identity(agent_key: str, identity: dict, prefer_mesh: bool = True) -> Path:
    """Write an identity.yaml for an agent, creating parent directories.

    Always writes to fleet/mesh/agents. The `prefer_mesh` argument is kept
    for backward compatibility but is ignored.
    """
    import yaml

    agent_key = agent_key.lower().strip()
    if not agent_key:
        raise ValueError("Agent key must not be empty")
    agent_dir = _mesh_agents_root() / agent_key
    agent_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(agent_dir, 0o700)
    except OSError:
        logger.warning("Mesh identity: could not chmod directory %s", agent_dir)
    identity_file = agent_dir / "identity.yaml"
    with open(identity_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(identity, f, sort_keys=False, allow_unicode=True)
    try:
        os.chmod(identity_file, 0o600)
    except OSError:
        logger.warning("Mesh identity: could not chmod file %s", identity_file)
    _invalidate_identity(agent_key)
    return identity_file
