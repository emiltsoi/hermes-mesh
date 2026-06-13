"""Fleet identity resolution for Hermes mesh.

Resolves agent identities from the fleet vault at:
  $HERMES_HOME/fleet/a2a/agents/<name>/identity.yaml

This is a focused subset of the old hermes-agent-a2a identity.py —
only the fleet agent resolution needed for session relay, not the
full vault resolution chain for outbound A2A protocol calls.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _hermes_root() -> Path:
    """Return the Hermes root directory (above profiles/ if inside one)."""
    home = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")))
    parts = home.parts
    if "profiles" in parts:
        idx = parts.index("profiles")
        return Path(*parts[:idx]) if idx > 0 else Path("/")
    return home


def _fleet_agents_root() -> Path:
    """Return the fleet agents directory."""
    fleet_root = Path(os.environ.get(
        "A2A_VAULT_PATH",
        str(_hermes_root() / "fleet")
    ))
    return fleet_root / "a2a" / "agents"


def _resolve_env(value: str) -> Optional[str]:
    """Resolve ${ENV_VAR} interpolations in vault values."""
    if not isinstance(value, str):
        return value
    match = re.fullmatch(r"^\$\{([^}]+)\}$", value.strip())
    if match:
        return os.environ.get(match.group(1), value)
    return value


def _load_identity_yaml(path: Path) -> Optional[dict]:
    """Load and normalize an identity.yaml file."""
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


def resolve_agent(name: str) -> Optional[dict]:
    """Look up an agent by name in the fleet vault.

    Returns:
        {name, a2a_url, description, role} or None if not found.
        Does NOT include credentials — safe to return to callers.
    """
    if not name:
        return None
    agent_key = name.lower()
    identity_file = _fleet_agents_root() / agent_key / "identity.yaml"
    identity = _load_identity_yaml(identity_file)
    if not identity:
        return None
    return {
        "name": identity.get("name", ""),
        "description": identity.get("description", ""),
        "role": identity.get("role", ""),
        "a2a_url": (
            (identity.get("transports", {}).get("a2a_rpc", {}) or {}).get("url", "")
            or identity.get("a2a_url", "")
        ),
    }


def get_raw_agent_identity(name: str) -> Optional[dict]:
    """Return the raw agent identity WITH credentials for internal use.

    Returns the full identity.yaml content including transports and auth.
    Never return this to external callers — use resolve_agent() instead.
    """
    if not name:
        return None
    agent_key = name.lower()
    identity_file = _fleet_agents_root() / agent_key / "identity.yaml"
    return _load_identity_yaml(identity_file)


def list_agents() -> list[dict]:
    """Return all fleet agents from the vault (no credentials)."""
    agents_dir = _fleet_agents_root()
    if not agents_dir.is_dir():
        return []
    agents = []
    seen = set()
    for agent_dir in agents_dir.iterdir():
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
        agents.append(resolve_agent(name))
    return [a for a in agents if a]
