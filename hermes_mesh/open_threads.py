"""Open-thread lease registry (H2/H4) — mutable, separate from the closed anchor log.

Why a separate file: ``closed-threads.json`` is an append-only anchor log, and that
immutability is what makes it trustworthy as evidence. A lease table is mutable by
definition (open, resize, extend, expire), so mixing the two would destroy the very
property that makes the anchor log worth reading.

Same primitives as the anchor log, deliberately reused rather than reinvented:
flock across gateway processes, atomic write (tmp + ``os.replace``), mtime rehydrate,
corrupt-file backup, and **fail-open — because a registry that can brick messaging is
worse than a registry that says nothing**. Fail-open is *counted*: every degradation
emits ``event=registry_failopen registry=open-threads`` so the meter can tell a live
guard from a slogan.

Rules encoded here (SPEC §H1–H4):
  * one open thread per wife at a time;
  * a message from the *same peer* is never refused — it merges into the open thread;
  * a different peer is refused ``E-BUSY`` while the lease holds;
  * lease default 30 min, resized by the holder on her first reply (max 24 h),
    extendable before expiry, and **self-releasing on expiry**.

Nothing in this module may raise into the send path. Every public function returns a
value or None; failures degrade to "no open threads".
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Optional

import mesh_core.threads as _core

from .common import validate_envelope_token
from .identity import _fleet_root

logger = logging.getLogger(__name__)

DEFAULT_LEASE_MINUTES = 30
MAX_LEASE_MINUTES = 24 * 60

_FAILOPEN_COUNT = 0
_UNAVAILABLE = "[mesh] open-threads registry UNAVAILABLE — leases advisory"
# Greppable meter marker: the meter counts these, so degradation is visible.
_METER_MARKER = "mesh_meter event=registry_failopen registry=open-threads"


def _now() -> float:
    """Injectable clock — the expiry negative control freezes time, never waits."""
    return time.time()


def _registry_path() -> Path:
    env = os.environ.get("MESH_OPEN_THREADS")
    if env:
        return Path(env)
    return _fleet_root() / "mesh" / "open-threads.json"


def failopen_count() -> int:
    """How many times this process degraded to advisory. Read by the meter."""
    return _FAILOPEN_COUNT


def _degrade(reason: str, path: Path) -> None:
    global _FAILOPEN_COUNT
    _FAILOPEN_COUNT += 1
    logger.warning("%s (%s): %s · %s", _UNAVAILABLE, reason, path, _METER_MARKER)


def _read(path: Optional[Path] = None) -> list[dict]:
    if path is None:
        path = _registry_path()
    try:
        entries, failed = _core._read_entries_strict(path)
    except Exception as exc:  # noqa: BLE001 — never raise into the send path
        _degrade(f"read error {exc!r}", path)
        return []
    if failed:
        _degrade("corrupt or unreadable", path)
        try:
            _core._backup_corrupt(path)
        except Exception:  # noqa: BLE001
            pass
        return []
    return [e for e in entries if isinstance(e, dict)]


def _write(entries: list[dict], path: Optional[Path] = None) -> bool:
    if path is None:
        path = _registry_path()
    try:
        _core._write_entries(entries, path)
        return True
    except Exception as exc:  # noqa: BLE001
        _degrade(f"write error {exc!r}", path)
        return False


def load() -> list[dict]:
    """Return live (non-expired) leases, sweeping anything that has lapsed."""
    return expire()


def get(thread_id: str) -> Optional[dict]:
    for rec in expire():
        if rec.get("thread_id") == thread_id:
            return rec
    return None


def _live(rec: dict, now: float) -> bool:
    try:
        return float(rec.get("lease_until", 0)) > now
    except (TypeError, ValueError):
        return False


def expire() -> list[dict]:
    """Sweep expired leases (self-release) and return what remains.

    Called on every read path, so an abandoned thread releases itself without a
    daemon: the next actor that looks is the one that cleans up.
    """
    path = _registry_path()
    entries = _read(path)
    now = _now()
    live = [r for r in entries if _live(r, now)]
    if len(live) != len(entries):
        try:
            with _core._registry_lock(path):
                fresh = [r for r in _read(path) if _live(r, now)]
                _write(fresh, path)
        except Exception as exc:  # noqa: BLE001
            _degrade(f"expire error {exc!r}", path)
            return live
        return fresh
    return live


def open_thread(
    thread_id: str,
    opened_by: str,
    peer: str,
    lease_minutes: int = DEFAULT_LEASE_MINUTES,
) -> Optional[dict]:
    """Open a lease. Returns the record, or None if the registry degraded."""
    tid = validate_envelope_token(thread_id)
    by = validate_envelope_token(opened_by)
    to = validate_envelope_token(peer)
    minutes = max(1, min(int(lease_minutes), MAX_LEASE_MINUTES))
    path = _registry_path()
    now = _now()
    rec = {
        "thread_id": tid,
        "opened_by": by,
        "peer": to,
        "opened_at": now,
        "lease_until": now + minutes * 60,
        "lease_minutes": minutes,
        "replies": 0,
        "resized": False,
    }
    try:
        with _core._registry_lock(path):
            fresh = [r for r in _read(path) if _live(r, now) and r.get("thread_id") != tid]
            fresh.append(rec)
            if not _write(fresh, path):
                return None
    except Exception as exc:  # noqa: BLE001
        _degrade(f"open error {exc!r}", path)
        return None
    return rec


def touch(thread_id: str, resize_to: Optional[int] = None) -> Optional[dict]:
    """Count a reply; on the holder's first reply, resize the lease (capped 24 h)."""
    tid = thread_id
    path = _registry_path()
    now = _now()
    out: Optional[dict] = None
    try:
        with _core._registry_lock(path):
            entries = _read(path)
            for rec in entries:
                if rec.get("thread_id") != tid or not _live(rec, now):
                    continue
                rec["replies"] = int(rec.get("replies", 0)) + 1
                if resize_to is not None and not rec.get("resized"):
                    minutes = max(1, min(int(resize_to), MAX_LEASE_MINUTES))
                    rec["lease_minutes"] = minutes
                    rec["lease_until"] = now + minutes * 60
                    rec["resized"] = True
                out = rec
                break
            if out is not None:
                _write(entries, path)
    except Exception as exc:  # noqa: BLE001
        _degrade(f"touch error {exc!r}", path)
        return None
    return out


def release(thread_id: str) -> bool:
    """Close the lease (explicit end, or the thread's own ``reply: end``)."""
    path = _registry_path()
    try:
        with _core._registry_lock(path):
            entries = _read(path)
            kept = [r for r in entries if r.get("thread_id") != thread_id]
            changed = len(kept) != len(entries)
            if changed:
                _write(kept, path)
            return changed
    except Exception as exc:  # noqa: BLE001
        _degrade(f"release error {exc!r}", path)
        return False


def conflict(target: str, sender: str) -> Optional[dict]:
    """The busy gate: is ``target`` leased to somebody other than ``sender``?

    Same peer never conflicts — those messages merge into the open thread with
    attribution. Returns the blocking record (for E-BUSY fields) or None.
    """
    try:
        for rec in expire():
            parties = {rec.get("opened_by"), rec.get("peer")}
            if target in parties and sender not in parties:
                return rec
    except Exception as exc:  # noqa: BLE001
        _degrade(f"conflict check error {exc!r}", _registry_path())
    return None


def release_if_party(thread_id: str, who: str) -> bool:
    """Release only if ``who`` is one of the two parties.

    Naming somebody else's lease must not close it: a third party cannot end a
    conversation they are not in.
    """
    path = _registry_path()
    try:
        with _core._registry_lock(path):
            entries = _read(path)
            kept, released = [], False
            for rec in entries:
                if rec.get("thread_id") == thread_id and who in {
                    rec.get("opened_by"),
                    rec.get("peer"),
                }:
                    released = True
                    continue
                kept.append(rec)
            if released:
                _write(kept, path)
            return released
    except Exception as exc:  # noqa: BLE001
        _degrade(f"release_if_party error {exc!r}", path)
        return False
