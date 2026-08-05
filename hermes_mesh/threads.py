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
in-memory locked-flag store (``_LOCKED``). Reuses ``common.py`` validators.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - POSIX-only feature
    fcntl = None  # type: ignore[assignment]

from .common import validate_envelope_token

logger = logging.getLogger(__name__)

# In-memory locked-flag store: an anchor present here is a closed thread whose
# replies are rejected with THREAD_CLOSED.
_LOCKED: set[str] = set()
_LOADED: bool = False
# mtime of the registry file whose content is currently reflected in _LOCKED.
_MTIME: int | float | None = None
# Intra-process guard; the cross-process guard is fcntl.flock on the lock file.
_WRITE_LOCK = threading.Lock()

# Distinct, greppable marker for the intentional fail-open state (F6).
_REGISTRY_UNAVAILABLE = "[mesh] closed-threads registry UNAVAILABLE — enforcement disabled"


def _registry_path() -> Path:
    """Return the on-disk closed-threads registry path."""
    env = os.environ.get("MESH_CLOSED_THREADS")
    if env:
        return Path(env)
    from .identity import _fleet_root

    return _fleet_root() / "mesh" / "closed-threads.json"


def _registry_lock_path(path: Path) -> Path:
    """Return the sidecar lock file used for cross-process serialization."""
    return Path(f"{path}.lock")


def _registry_mtime(path: Path) -> int | float | None:
    """Return the registry file's mtime, or None if it does not exist.

    Uses ``st_mtime_ns`` (full precision) when available so two writes in
    the same second are still distinguishable; the F2 mtime check only
    re-reads the file when this value changes.
    """
    try:
        st = path.stat()
    except OSError:
        return None
    ns = getattr(st, "st_mtime_ns", None)
    return ns if ns is not None else st.st_mtime


@contextmanager
def _registry_lock(path: Path):
    """Hold the registry lock across a read-merge-write critical section.

    Acquires the intra-process ``_WRITE_LOCK`` and, when fcntl is available,
    an exclusive ``flock`` on the sidecar lock file. The flock is what
    serializes the multiple fleet gateway processes that share one registry;
    it is held across the whole read-append-write so no anchor is lost.
    """
    lock_path = _registry_lock_path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o644)
    with _WRITE_LOCK:
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


def _hydrate(entries: list[dict], path: Path) -> None:
    """Install a fresh registry snapshot into the in-memory locked set."""
    global _LOCKED, _LOADED, _MTIME
    _LOCKED.clear()
    for entry in entries:
        anchor = entry.get("anchor_task_id")
        if isinstance(anchor, str) and anchor:
            _LOCKED.add(anchor)
    _LOADED = True
    _MTIME = _registry_mtime(path)


def _read_entries(path: Path | None = None) -> list[dict]:
    """Read registry entries from disk; tolerate a missing or corrupt file.

    Fail-open: on corrupt/unreadable state log the distinct UNAVAILABLE marker
    and return [] so messaging is never blocked (F6). Callers that then write
    re-hydrate from whatever they write.
    """
    if path is None:
        path = _registry_path()
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("%s: %s (%s)", _REGISTRY_UNAVAILABLE, path, exc)
        return []
    if not isinstance(data, list):
        logger.warning("%s: %s (malformed)", _REGISTRY_UNAVAILABLE, path)
        return []
    return [entry for entry in data if isinstance(entry, dict)]


def _write_entries(entries: list[dict], path: Path | None = None) -> None:
    """Atomically write registry entries (tmp file + os.replace)."""
    if path is None:
        path = _registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(
        dir=str(path.parent), prefix="closed-threads-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(entries, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


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
        entries = _read_entries(path)
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
    if not _LOADED:
        _hydrate(_read_entries(path), path)
        return anchor_task_id in _LOCKED
    if _registry_mtime(path) != _MTIME:
        _hydrate(_read_entries(path), path)
    return anchor_task_id in _LOCKED
