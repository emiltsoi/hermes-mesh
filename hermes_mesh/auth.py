"""Mesh authentication — Ed25519 signing, key management, and peer resolution.

This module delegates Ed25519 primitives to ``mesh_core.crypto`` while keeping
the Hermes-specific public API unchanged.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional, Tuple

from mesh_core import crypto as _crypto

from . import identity
from .common import transport as _transport

logger = logging.getLogger(__name__)

DEFAULT_KEY_DIR = Path.home() / ".mesh" / "keys"


def _private_key_path(name: str, extra: dict | None = None) -> Path:
    """Return the private key path for an agent.

    `extra` is the `platforms.mesh.extra` dict and may override
    `private_key_path`.
    """
    if extra and extra.get("private_key_path"):
        return Path(os.path.expanduser(extra["private_key_path"]))
    return DEFAULT_KEY_DIR / f"{name}.pem"


def load_or_generate_keypair(
    name: str, extra: dict | None = None
) -> Tuple[str, str]:
    """Load or generate the local Ed25519 keypair for `name`.

    Returns `(private_pem, public_pem)`. The private key is written to
    `~/.mesh/keys/<name>.pem` (or `extra["private_key_path"]`) with 0600
    permissions.
    """
    private_key_path = _private_key_path(name, extra) if extra and extra.get("private_key_path") else None
    return _crypto.load_or_generate_keypair(
        name,
        private_key_path_override=private_key_path,
    )


def sign_ed25519(private_pem: str, message: bytes) -> str:
    """Sign `message` with the private key and return a base64 signature."""
    return _crypto.sign_message(private_pem, message)


def verify_ed25519(public_pem: str, message: bytes, signature_b64: str) -> bool:
    """Verify an Ed25519 signature.

    Delegates to ``mesh_core.crypto.verify_message``, which tolerates PEM SPKI
    and raw base64 SPKI inputs and never raises.
    """
    return _crypto.verify_message(public_pem, message, signature_b64)


def resolve_target(name: str) -> Tuple[Optional[str], Optional[str]]:
    """Resolve the target's mesh webhook URL from the local cache.

    Returns `(url, error)`.
    """
    raw = identity.get_raw_agent_identity(name)
    if not raw:
        return None, f"target '{name}' not found in local cache"
    webhook = _transport(raw, "hermes_webhook")
    url = webhook.get("url", "")
    if not url:
        return None, f"target '{name}' has no hermes_webhook.url"
    return url, None


def resolve_sender(name: str, extra: dict | None = None) -> Tuple[Optional[str], Optional[str]]:
    """Resolve the sender's Ed25519 private key.

    Returns `(private_pem, error)`. Generates the keypair if missing.
    """
    try:
        private_pem, _ = load_or_generate_keypair(name, extra)
        return private_pem, None
    except Exception as exc:
        return None, f"sender '{name}' could not load or generate Ed25519 key: {exc}"


def get_public_key(name: str, extra: dict | None = None) -> Tuple[Optional[str], Optional[str]]:
    """Return the public key PEM for `name`.

    Generates the keypair if missing. This is useful when registering or
    publishing an agent.
    """
    try:
        _, public_pem = load_or_generate_keypair(name, extra)
        return public_pem, None
    except Exception as exc:
        return None, f"could not load or generate Ed25519 key for '{name}': {exc}"
