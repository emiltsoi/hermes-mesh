# Changelog

All notable changes to this project are documented here.

## [0.1.23] - 2026-08-29

### Added
- JSON canonical wire format: `_deliver_webhook` wraps the envelope in
  `{"text": <envelope>, "from": <sender>}` + signs over `timestamp\n<body>`
  (Content-Type: application/json). Raw bracketed body remains via
  `wire_format="raw"` (back-compat for hermes↔hermes peers).
- `mesh-peer-registry` (mesh_core) as a dependency — the shared protocol home.

### Changed
- `MESH_SIGN_TIMESTAMP` is now **default ON** (the timestamp is the
  replay-defense the canonical JSON wire demands); `MESH_SIGN_TIMESTAMP=0`
  opts out (raw back-compat). Receivers accept both legacy body-only and
  timestamp-prefixed signatures.
- Phase 5 cutover: hermes-mesh now uses `mesh_core` (mesh-peer-registry).

### Fixed
- Pre-existing `test_registry_send_signs_with_ed25519` now passes under the
  canonical timestamp contract (suite 136/136 green).

### Interop
- hermes-mesh ↔ diploid-agent/diploid-mesh (Phase 5) — verified by the
  hermetic dual-boot test (`test_hermes_interop.py`).

## [0.1.22] - 2026-08-27

### Changed
- Docs-only bump: README mesh-setup clarification (registry registration
  required, loopback host, mesh-to-DM routing, troubleshooting table).
