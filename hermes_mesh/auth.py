"""Mesh authentication — Ed25519 signing, key management, and peer resolution.

This module is the only runtime dependency for mesh auth. It does NOT
import `mesh_peer_registry`; that package is only needed by the optional
`mesh_sync` / `mesh_publish` tools.
"""
from __future__ import annotations

import base64
import logging
import os
from pathlib import Path
from typing import Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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


def _public_from_private(private_pem: str) -> str:
    """Derive the public key PEM from an Ed25519 private key PEM."""
    private = serialization.load_pem_private_key(
        private_pem.encode("utf-8"), password=None
    )
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def load_or_generate_keypair(
    name: str, extra: dict | None = None
) -> Tuple[str, str]:
    """Load or generate the local Ed25519 keypair for `name`.

    Returns `(private_pem, public_pem)`. The private key is written to
    `~/.mesh/keys/<name>.pem` (or `extra["private_key_path"]`) with 0600
    permissions.
    """
    path = _private_key_path(name, extra)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        logger.warning("mesh keys: could not chmod directory %s", path.parent)

    if path.exists():
        private_pem = path.read_text(encoding="utf-8")
        return private_pem, _public_from_private(private_pem)

    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    path.write_text(private_pem, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        logger.warning("mesh keys: could not chmod %s", path)

    return private_pem, public_pem


def sign_ed25519(private_pem: str, message: bytes) -> str:
    """Sign `message` with the private key and return a base64 signature."""
    private = serialization.load_pem_private_key(
        private_pem.encode("utf-8"), password=None
    )
    return base64.b64encode(private.sign(message)).decode("utf-8")


def verify_ed25519(public_pem: str, message: bytes, signature_b64: str) -> bool:
    """Verify an Ed25519 signature."""
    public = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    try:
        signature = base64.b64decode(signature_b64.encode("utf-8"))
    except Exception:
        return False
    try:
        public.verify(signature, message)
        return True
    except InvalidSignature:
        return False


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
