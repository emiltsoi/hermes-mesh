"""Fleet identity resolution for Hermes mesh.

Resolves agent identities from the fleet vault at:
  $HERMES_HOME/fleet/mesh/agents/<name>/identity.yaml

Falls back to the legacy A2A vault path for backward compatibility:
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
from typing import Any, Optional

logger = logging.getLogger(__name__)


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
        or os.environ.get("A2A_VAULT_PATH")
        or str(_hermes_root() / "fleet")
    )


def _mesh_agents_root() -> Path:
    """Return the primary mesh agents directory."""
    return _fleet_root() / "mesh" / "agents"


def _legacy_a2a_agents_root() -> Path:
    """Return the legacy A2A agents directory for backward compatibility."""
    return _fleet_root() / "a2a" / "agents"


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


def _identity_file_for_agent(agent_key: str) -> Optional[Path]:
    """Return the identity.yaml path for an agent, preferring mesh over legacy a2a."""
    for root in (_mesh_agents_root(), _legacy_a2a_agents_root()):
        candidate = root / agent_key / "identity.yaml"
        if candidate.exists():
            return candidate
    return None


def resolve_agent(name: str) -> Optional[dict]:
    """Look up an agent by name in the fleet vault.

    Returns:
        {name, a2a_url, description, role} or None if not found.
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
        "a2a_url": (
            (identity.get("transports", {}).get("hermes_webhook", {}) or {}).get("url", "")
            or (identity.get("transports", {}).get("a2a_rpc", {}) or {}).get("url", "")
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
    identity_file = _identity_file_for_agent(agent_key)
    if not identity_file:
        return None
    return _load_identity_yaml(identity_file)


def list_agents() -> list[dict]:
    """Return all fleet agents from the vault (no credentials).

    Merges agents from both fleet/mesh/agents and the legacy
    fleet/a2a/agents directories. Builds the public view from the
    already-loaded identity dict so each YAML is parsed only once.
    """
    agents = []
    seen = set()
    for root in (_mesh_agents_root(), _legacy_a2a_agents_root()):
        if not root.is_dir():
            continue
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
            a2a_url = (
                (identity.get("transports", {}).get("hermes_webhook", {}) or {}).get("url", "")
                or (identity.get("transports", {}).get("a2a_rpc", {}) or {}).get("url", "")
                or identity.get("a2a_url", "")
            )
            agents.append({
                "name": name,
                "description": identity.get("description", ""),
                "role": identity.get("role", ""),
                "a2a_url": a2a_url,
            })
    return agents


def write_agent_identity(agent_key: str, identity: dict, prefer_mesh: bool = True) -> Path:
    """Write an identity.yaml for an agent, creating parent directories.

    By default writes to fleet/mesh/agents. Set prefer_mesh=False to
    write to the legacy fleet/a2a/agents location.
    """
    import yaml

    agent_key = agent_key.lower().strip()
    if not agent_key:
        raise ValueError("Agent key must not be empty")
    root = _mesh_agents_root() if prefer_mesh else _legacy_a2a_agents_root()
    agent_dir = root / agent_key
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
    return identity_file
