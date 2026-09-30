# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Fixed
- **Float transport silently dropped every message over Telegram's 4096-character cap.**
  `float.send()` posted the whole message in one `sendMessage`; above the cap Telegram answers
  HTTP 400 `message is too long` and the module logged only `HTTP <code> <reason>`, so the loss was
  invisible. Two silent-drop modes existed: over-cap, and empty text. Repeated live reproduction:
  5,000 chars → 400; 0 chars → 400 `message text is empty`; and **4,200 raw chars of `&` → 21,000
  after `html.escape` → 400**, i.e. a message under the RAW cap could still die because escaping
  expands the payload.
  The float now escapes once with `quote=False`, chunks the **escaped** string at 4000 (3994 when a
  part needs an `[i/n] ` prefix), never splits inside an `&…;` entity, prefixes `[i/n] ` when
  multi-part, sends at most 8 parts and then appends an explicit `… +N,NNN chars not floated`
  marker whose count is computed rather than estimated, skips empty/whitespace text without an HTTP
  call, and logs every failure at ERROR with the part index, Telegram's own `description`, the kind
  of failure (rejected / http / transport), and what was delivered versus not attempted.
- **The bot token could reach a log line.** `_http_error_detail` avoided `str(exc)` because it
  embeds the token-bearing URL, then returned `exc.reason` unredacted; a server or
  TLS-terminating proxy planting the URL in the reason phrase put the token in the log. `reason` is
  now redacted on that path too, and `_redact` coerces its arguments so a malformed config cannot
  raise out of `send()`.
- `send()` could raise `AttributeError` for a non-string text (the new empty-text guard ran before
  the `try`) — it now never raises for any input shape.
- A multi-part send could stall its caller: `float.send` is called synchronously from
  `session_relay`, and 8 sequential requests at a 10 s socket timeout is ~80 s worst case against
  ~10 s before. A 15 s cumulative wall budget now bounds the loop, and exhausting it is logged
  loudly rather than silently truncating.
- `_safe_cut` could return 0 for an entity at index 0, and the caller's fallback then hard-cut
  *inside* the entity. It now cuts just past the complete entity (unreachable at the production
  limit, but no longer a trap).

### Added
- `tests/test_float_chunking.py` — boundary (4000/4001 escaped, raw≠escaped), entity integrity,
  escape-expansion ceiling with an exactly-computed marker, empty/whitespace, redaction on all
  three failure paths, wall-budget exhaustion, and log-content assertions.

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
