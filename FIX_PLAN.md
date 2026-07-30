# hermes-mesh Fix Plan

This plan addresses issues found during a cold review of `hermes-mesh` and the interoperability gaps with `openclaw-mesh`.

## 1. Lazy-import `MeshAdapter` to avoid registration-time crashes

- **Problem**: `hermes_mesh/__init__.py` imports `MeshAdapter` at registration time. If `aiohttp` or the `gateway.*` modules are unavailable, `register()` raises before `check_mesh_requirements` can return `False`.
- **Files**: `hermes_mesh/__init__.py`
- **Fix**: Move the `from .adapter import MeshAdapter` import inside the `adapter_factory` lambda or a small factory function so it is only imported when the platform is actually instantiated.
- **Acceptance**: Registration no longer crashes when `gateway` modules are missing; `check_mesh_requirements` still gates adapter creation.

## 2. SSRF-validate URLs at registration time

- **Problem**: `handle_mesh_register` only checks `url.startswith(("http://", "https://"))`. Malicious or locally-routed URLs can be stored and later fail only on send.
- **Files**: `hermes_mesh/session_relay.py`
- **Fix**: Call `_validate_target_url(url, allow_loopback=...)` inside `handle_mesh_register` before writing the identity. Respect a config/env flag that allows loopback/private URLs for local testing.
- **Acceptance**: `mesh_register` rejects private/loopback URLs by default and accepts them only when explicitly allowed.

## 3. Cache fleet identity resolution

- **Problem**: `get_raw_agent_identity` and `list_agents` re-read YAML from disk on every call. Under frequent mesh traffic this is unnecessary I/O.
- **Files**: `hermes_mesh/identity.py`
- **Fix**: Add a small TTL cache (e.g. `functools.lru_cache` or a time-bounded dict) keyed by absolute path and file mtime. Invalidate when the mtime changes.
- **Acceptance**: Repeated `mesh_list` / `mesh_send` calls do not re-parse unchanged identity files; file edits are reflected within the TTL or on mtime change.

## 4. Broaden float credential sources

- **Problem**: `hermes_mesh/float.py` reads only environment variables. Users who configure Telegram in `platforms.mesh.extra` or a plugin config have no supported path.
- **Files**: `hermes_mesh/float.py`
- **Fix**: Accept an optional `config` dict passed from the adapter/tools and fall back through: config → `HERMES_TELEGRAM_BOT_TOKEN` → `A2A_TELEGRAM_BOT_TOKEN` → `TELEGRAM_BOT_TOKEN` (and same chain for chat id).
- **Acceptance**: Floats can be configured via config object as well as env vars.

## 5. Document the `[mesh]` envelope contract and consider legacy `[a2a]` support

- **Problem**: `openclaw-mesh` still uses `[a2a]`, causing the plugins to reject each other. Hermes is the source of truth for the new `[mesh]` format.
- **Files**: `README.md`, `SPEC.md`, optionally `hermes_mesh/adapter.py`
- **Fix**: Update docs to state clearly that the wire envelope is `[mesh]`. Optionally make `_MESH_ENVELOPE_RE` accept both `[mesh]` and `[a2a]` as a backward-compatible concession while openclaw catches up.
- **Acceptance**: The README explains that OpenClaw peers must be configured to send `[mesh]` and that Hermes still accepts `[a2a]` if the compatibility option is enabled.

## 6. Optional: add `mesh_deregister` tool

- **Problem**: There is no way to remove an identity at runtime once registered.
- **Files**: `hermes_mesh/__init__.py`, `hermes_mesh/session_relay.py`, `hermes_mesh/identity.py`
- **Fix**: Add `handle_mesh_deregister` and expose `mesh_deregister(name)`.
- **Acceptance**: Calling `mesh_deregister(name="britney")` removes the identity directory or file and it no longer appears in `mesh_list`.

## Execution order

1. SSRF validation in `mesh_register` (security, small change).
2. Lazy `MeshAdapter` import (robustness).
3. Identity caching (performance).
4. Float credential broadening (usability).
5. Doc/`[mesh]` contract and optional backward compat (interoperability).
6. Optional `mesh_deregister`.
