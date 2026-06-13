"""Per-agent Ed25519 message signing for mesh identity binding.

The HMAC authenticates the delivery channel (sender knows target's
webhook secret). Ed25519 signatures authenticate the sender identity
within the mesh — binding the from: field to a keypair stored in
the sender's identity.yaml.
"""

import base64
import hashlib
import json
import time
from typing import Optional


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate Ed25519 keypair. Returns (secret_seed, public_key)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    return (sk.private_bytes_raw(), sk.public_key().public_bytes_raw())


def sign_message(
    secret_seed: bytes,
    from_agent: str,
    to_agent: str,
    task_id: str,
    body: str,
) -> str:
    """Sign mesh message payload. Returns base64 signature string."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(secret_seed)

    body_hash = hashlib.sha256(body.encode()).digest()
    timestamp = int(time.time())

    payload = json.dumps({
        "from": from_agent,
        "to": to_agent,
        "id": task_id,
        "timestamp": timestamp,
        "body_hash": body_hash.hex(),
    }, sort_keys=True).encode()

    sig = sk.sign(payload)
    return base64.b64encode(sig).decode()


def load_signer_key(agent_info: dict) -> Optional[bytes]:
    """Extract signer secret from agent identity. Returns seed bytes or None."""
    mesh = agent_info.get("mesh", {})
    signer_b64 = mesh.get("signer_secret", "")
    if not signer_b64:
        return None
    return base64.b64decode(signer_b64)
