"""Closed-thread anchor registry for mesh terminal replies.

``reply=end`` closes a thread: the terminal message's ``task_id`` becomes an
anchor that is persisted to disk so replies referencing it are rejected by the
transport (``THREAD_CLOSED``) even across gateway restarts.

Registry file: ``~/.hermes/fleet/mesh/closed-threads.json`` (configurable via
``MESH_CLOSED_THREADS``). Append-only entries: ``{anchor_task_id, closed_at,
closed_by}`` — minimal, no message text. Writes are atomic (tmp file +
``os.replace``) mirroring the outbox persistence pattern.

Writes are serialized across gateway processes with ``fcntl.flock`` on a
sidecar ``.lock`` file so simultaneous terminal replies from different wives
never lose an anchor — the fleet runs multiple gateway processes (different
wives) sharing one registry on a single host's local FS, so a plain
``threading.Lock`` cannot serialize them. ``is_closed`` rehydrates the
in-memory snapshot whenever the registry file's mtime changes, so anchors
recorded by another process become visible without a restart.

FAIL-OPEN POLICY (intentional): the registry is best-effort bookkeeping. A
missing, corrupt, or unwritable registry must never brick messaging — a
terminal message still delivers normally (AC-2.3) and ``THREAD_CLOSED``
enforcement degrades to advisory. On corrupt or unreadable state a WARNING with
the marker "[mesh] closed-threads registry UNAVAILABLE — enforcement disabled"
is logged and enforcement is disabled.

Plain module-level functions: ``load`` / ``record`` / ``is_closed`` plus the
in-memory locked-flag store (``_LOCKED``).

This module converges on ``mesh_core.threads`` primitives for the heavy
lifting — file locking/hydration, atomic writes, corrupt-file backups, and
entry reading — while preserving the Hermes-specific default vault path,
fail-open logging, and module-level state that the existing tests patch.
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import mesh_core.threads as _core
from mesh_core.envelope import validate_envelope_token as _validate_token
from mesh_core.exceptions import EnvelopeError

from .common import validate_envelope_token
from .identity import _fleet_root

logger = logging.getLogger(__name__)

# In-memory locked-flag store: an anchor present here is a closed thread whose
# replies are rejected with THREAD_CLOSED.
_LOADED: bool = False
_LOCKED: set[str] = set()
# mtime of the registry file whose content is currently reflected in _LOCKED.
_MTIME: int | float | None = None

# Re-export the mesh_core write lock so callers/tests can see the same object.
_WRITE_LOCK = _core._WRITE_LOCK

# Distinct, greppable marker for the intentional fail-open state (F6).
_REGISTRY_UNAVAILABLE = (
    "[mesh] closed-threads registry UNAVAILABLE — enforcement disabled"
)


def _registry_path() -> Path:
    """Return the on-disk closed-threads registry path."""
    env = os.environ.get("MESH_CLOSED_THREADS")
    if env:
        return Path(env)
    return _fleet_root() / "mesh" / "closed-threads.json"


def _registry_lock_path(path: Path) -> Path:
    """Return the sidecar lock file used for cross-process serialization."""
    return _core._registry_lock_path(path)


def _registry_mtime(path: Path) -> int | float | None:
    """Return the registry file's mtime, or None if it does not exist."""
    return _core._registry_mtime(path)


def _registry_lock(path: Path):
    """Hold the registry lock across a read-merge-write critical section."""
    return _core._registry_lock(path)


def _hydrate(entries: list[dict], path: Path) -> None:
    """Install a fresh registry snapshot into the in-memory locked set."""
    global _LOCKED, _LOADED, _MTIME
    _LOCKED.clear()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        anchor = entry.get("anchor_task_id")
        if not isinstance(anchor, str) or not anchor:
            continue
        try:
            _LOCKED.add(_validate_token(anchor, "anchor"))
        except EnvelopeError:
            pass
    _LOADED = True
    _MTIME = _registry_mtime(path)


def _read_entries(path: Path | None = None) -> list[dict]:
    """Read registry entries from disk; tolerate a missing or corrupt file.

    Fail-open: on corrupt/unreadable state log the distinct UNAVAILABLE marker
    and return [] so messaging is never blocked (F6).
    """
    if path is None:
        path = _registry_path()
    entries, failed = _core._read_entries_strict(path)
    if failed:
        logger.warning(
            "%s: %s (corrupt or unreadable)",
            _REGISTRY_UNAVAILABLE,
            path,
        )
    return entries


def _write_entries(entries: list[dict], path: Path | None = None) -> None:
    """Atomically write registry entries (tmp file + os.replace)."""
    if path is None:
        path = _registry_path()
    _core._write_entries(entries, path)


def _backup_corrupt(path: Path) -> None:
    """Back up a corrupt registry file to ``<path>.corrupt-<ts>``.

    Called inside the flock critical section (``record``) so the backup name is
    unique and the original corrupt bytes are preserved before the fresh write
    clobbers the path (B6). Best-effort: on failure log loudly and continue —
    the subsequent fresh write is still attempted.
    """
    backup = _core._backup_corrupt(path)
    if backup:
        logger.warning(
            "[mesh] corrupt closed-threads registry %s backed up to %s",
            path,
            backup,
        )
    else:
        logger.warning(
            "[mesh] failed to back up corrupt closed-threads registry %s", path
        )


def load() -> list[dict]:
    """Load registry entries from disk into the locked set (restart rehydrate).

    Returns the persisted entries. Calling this after a gateway restart
    restores the closed-thread state (AC-5.1).
    """
    path = _registry_path()
    entries = _read_entries(path)
    _hydrate(entries, path)
    return entries


def record(anchor_task_id: str, closed_by: str) -> None:
    """Persist a closed-thread anchor (append-only, idempotent).

    Both fields are validated with the shared envelope-token validator so no
    injection characters can reach the registry file. The read-merge-write is
    serialized across processes with fcntl.flock (F1); the idempotency check
    re-reads the file under the lock so no duplicate rows accumulate (F5).
    """
    anchor = validate_envelope_token(anchor_task_id)
    by = validate_envelope_token(closed_by)
    path = _registry_path()
    with _registry_lock(path):
        # Fresh read under the cross-process lock: never trust the in-memory
        # snapshot for idempotency — another gateway process may have written
        # since we last hydrated.
        entries, failed = _core._read_entries_strict(path)
        if failed:
            # B6: never clobber unreadable state. Back up the corrupt file
            # inside the flock critical section so the original bytes survive
            # the fresh write below, then start from [].
            _backup_corrupt(path)
        for entry in entries:
            if entry.get("anchor_task_id") == anchor:
                _hydrate(entries, path)
                return
        entries.append(
            {"anchor_task_id": anchor, "closed_at": time.time(), "closed_by": by}
        )
        _write_entries(entries, path)
        _hydrate(entries, path)
    logger.info("[mesh] thread closed by terminal message %s (closed_by=%s)", anchor, by)


def is_closed(anchor_task_id: str | None) -> bool:
    """Return True when the anchor is a closed (locked) thread.

    ``None`` is never checked — the escape hatch is structural: a message
    without ``ref`` is never blocked. Callers must only pass a non-``None``
    ``ref`` here.

    Kept cheap on the hot path: one mtime ``stat`` per call; the on-disk file
    is only re-read when the mtime differs from the snapshot we hydrated (F2),
    so anchors recorded by other gateway processes are visible without a
    restart.
    """
    if anchor_task_id is None:
        return False
    path = _registry_path()
    # Locked read (F7): _hydrate clears+re-adds the in-memory set non-atomically,
    # so concurrent record()/hydrate could otherwise expose a transient empty
    # snapshot. Same GIL+flock discipline as writes.
    try:
        with _registry_lock(path):
            if not _LOADED:
                _hydrate(_read_entries(path), path)
                return anchor_task_id in _LOCKED
            if _registry_mtime(path) != _MTIME:
                _hydrate(_read_entries(path), path)
            return anchor_task_id in _LOCKED
    except (PermissionError, OSError) as exc:
        # B1 fail-open: the read path must never raise on lock acquisition — an
        # unwritable registry dir (lock sidecar O_CREAT denied) would otherwise
        # PermissionError every ref-bearing message and brick messaging. The
        # WRITE path (record) stays loud. Uncertainty -> False.
        logger.warning("%s: %s (%s)", _REGISTRY_UNAVAILABLE, path, exc)
        return False


def list_closed() -> list[str]:
    """Return all closed anchors."""
    path = _registry_path()
    if not _LOADED or _registry_mtime(path) != _MTIME:
        _hydrate(_read_entries(path), path)
    return sorted(_LOCKED)


def clear() -> None:
    """Clear the on-disk registry and the in-memory locked set."""
    path = _registry_path()
    with _registry_lock(path):
        if path.exists():
            try:
                path.unlink()
            except OSError:
                pass
    _LOCKED.clear()
    _LOADED = False
    _MTIME = None
