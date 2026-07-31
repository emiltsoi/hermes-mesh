#!/usr/bin/env python3
"""Migrate a fleet mesh cache from HMAC to Ed25519.

Reads every agent identity under `fleet/mesh/agents`, generates an Ed25519
keypair per agent, stores the public key in the identity's
`transports.hermes_webhook.auth.public_key`, and stores the private key at the
calculated location so `hermes_mesh.auth` can load it.

Usage:
    HERMES_HOME=/path/to/profile/home python3 scripts/migrate_fleet_to_ed25519.py

By default the private keys go into `$HOME/.mesh/keys/<agent>.pem`. If you want
per-profile key directories, set `HERMES_MESH_KEY_DIR` before running.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _mesh_agents_root() -> Path:
    home = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")))
    return home / "fleet" / "mesh" / "agents"


def _default_key_dir() -> Path:
    env = os.environ.get("HERMES_MESH_KEY_DIR")
    if env:
        return Path(env)
    return Path.home() / ".mesh" / "keys"


def _generate_keypair() -> tuple[str, str]:
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
    return private_pem, public_pem


def migrate(root: Path, key_dir: Path, dry_run: bool = False) -> dict:
    """Migrate identities in `root` and write private keys to `key_dir`."""
    if not root.is_dir():
        return {"migrated": 0, "skipped": 0, "errors": [f"No such directory: {root}"]}

    key_dir.mkdir(parents=True, exist_ok=True)
    try:
        key_dir.chmod(0o700)
    except OSError:
        pass

    migrated = 0
    skipped = 0
    errors: list[str] = []

    for agent_dir in sorted(root.iterdir()):
        if not agent_dir.is_dir():
            continue
        identity_path = agent_dir / "identity.yaml"
        if not identity_path.exists():
            continue

        try:
            raw = yaml.safe_load(identity_path.read_text(encoding="utf-8")) or {}
        except (yaml.YAMLError, OSError) as e:
            errors.append(f"{agent_dir.name}: failed to read identity: {e}")
            continue

        transport = raw.get("transports", {}).get("hermes_webhook", {}) or {}
        auth = transport.get("auth") or {}

        # Already Ed25519
        if auth.get("public_key") and not auth.get("secret") and auth.get("type") != "hmac-sha256":
            skipped += 1
            continue

        private_pem, public_pem = _generate_keypair()
        name = raw.get("name") or agent_dir.name

        private_path = key_dir / f"{name}.pem"

        if dry_run:
            print(f"[dry-run] {name}: would migrate to Ed25519 and write {private_path}")
            migrated += 1
            continue

        try:
            private_path.write_text(private_pem, encoding="utf-8")
            private_path.chmod(0o600)
        except OSError as e:
            errors.append(f"{name}: failed to write private key: {e}")
            continue

        transport["auth"] = {"public_key": public_pem}
        transport.pop("secret", None)
        transport.pop("type", None)
        raw["transports"] = raw.get("transports", {})
        raw["transports"]["hermes_webhook"] = transport

        try:
            identity_path.write_text(yaml.safe_dump(raw, sort_keys=True), encoding="utf-8")
        except OSError as e:
            errors.append(f"{name}: failed to write identity: {e}")
            continue

        migrated += 1
        print(f"Migrated {name}: public_key in {identity_path}, private key in {private_path}")

    return {"migrated": migrated, "skipped": skipped, "errors": errors}


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate fleet mesh cache to Ed25519")
    parser.add_argument("--root", type=Path, default=_mesh_agents_root(), help="Fleet mesh agents root")
    parser.add_argument("--key-dir", type=Path, default=_default_key_dir(), help="Private key directory")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    args = parser.parse_args()

    result = migrate(args.root, args.key_dir, dry_run=args.dry_run)
    print(f"Migrated: {result['migrated']}, skipped: {result['skipped']}, errors: {len(result['errors'])}")
    for err in result["errors"]:
        print(f"ERROR: {err}", file=sys.stderr)
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
