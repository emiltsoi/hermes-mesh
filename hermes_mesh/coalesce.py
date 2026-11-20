"""Inbound mesh coalescing — the backpressure the transport never had.

Why this exists (2026-10-24): every mesh message spawned a turn, whether or not the envelope asked
for a reply. `action: info, reply: no` was read as "no cost", and it never was: arrival is the cost.
One seat measured 167 inbound messages in a day — 167 turns that were not work, on a day when the
fleet was trying to do something else. The loop then fed itself: each long reply earned a long reply.

Two rules, both applied at the receiver, because the receiver is the only party that can say what a
turn is worth:

  1. COALESCE — non-urgent traffic from one peer waits on disk and arrives as ONE turn carrying all
     of it, once the oldest pending item is older than the window (checked every 30 s). Ten
     informational messages cost one turn, not ten — and because the trigger is the OLDEST item's
     age rather than a stretch of quiet, a steadily-talking peer is still flushed roughly every
     tick. That is what prevents starvation: the window bounds the wait, it does not require silence.
  2. NEVER DELAY URGENT — an envelope that asks for action (`action: do`, or any `reply:` other than
     "no") flushes that peer's pending digest first, then arrives immediately. Order is preserved:
     the digest is always older than the urgent message that triggered it.

Nothing is dropped. Pending items live in a per-peer JSONL file under the seat's mesh state dir, so a
restart loses nothing, and every digest carries the path to the full text so a truncated item can be
read in full.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

DEFAULT_WINDOW_SECONDS = 600      # how long informational traffic waits for company
DEFAULT_MAX_ITEMS = 25            # a digest never grows past this; the rest stays on disk
DEFAULT_PREVIEW_CHARS = 700       # per item in the digest body


def _urgent(action: str, reply: str) -> bool:
    """An envelope that asks for something is never coalesced."""
    if (reply or "").strip().lower() not in {"", "no"}:
        return True
    return (action or "").strip().lower() == "do"


class Coalescer:
    """Per-peer pending queue with a time-based flush."""

    def __init__(
        self,
        root: str,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        max_items: int = DEFAULT_MAX_ITEMS,
        preview_chars: int = DEFAULT_PREVIEW_CHARS,
    ) -> None:
        self.root = root
        self.window_seconds = float(window_seconds)
        self.max_items = int(max_items)
        self.preview_chars = int(preview_chars)
        os.makedirs(self.root, exist_ok=True)
        self._migrate_legacy_archives()

    # -- storage ---------------------------------------------------------
    def _stem(self, peer: str) -> str:
        """Filesystem-safe, collision-free stem for a peer name.

        Sanitizing alone maps ``a b`` and ``a_b`` to the same file, merging two peers' mail under
        one attribution; when the name had to be mangled a short digest of the RAW peer is appended
        so distinct senders can never share a pending file. Clean names keep their readable stem —
        ``kore`` stays ``kore.jsonl`` — and a stem re-sanitized is itself, so the filename stems
        that ``peers()`` hands back resolve to the same file again.
        """
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in peer)
        if safe != peer:
            safe = f"{safe}.{hashlib.sha1(peer.encode('utf-8')).hexdigest()[:8]}"
        return safe

    def _path(self, peer: str) -> str:
        return os.path.join(self.root, f"{self._stem(peer)}.jsonl")

    def _archive_path(self, peer: str) -> str:
        """Where the most recently delivered batch is kept, readable by the digest's reader.

        Archives live in their own subdirectory, never beside the pending queues. A sibling name is
        not safe: ``foo.delivered`` is a valid sender, and its pending queue would then land on
        exactly the file that is ``foo``'s archive — ``foo``'s flush would destroy ``foo.delivered``'s
        mail, and ``peers()`` would hide it so it never flushed. A directory cannot be reached by any
        peer name, because no name may contain a path separator.
        """
        safe = self._stem(peer)
        arch_dir = os.path.join(self.root, ".delivered")
        os.makedirs(arch_dir, exist_ok=True)
        return os.path.join(arch_dir, f"{safe}.jsonl")

    def _migrate_legacy_archives(self) -> None:
        """Sweep pre-``.delivered/`` archives out of the pending directory, once, at construction.

        An earlier revision kept delivered batches beside the queues as ``<peer>.delivered.jsonl``.
        ``peers()`` must not name-filter that suffix — ``foo.delivered`` is a valid sender — so a
        leftover archive would be listed as a pending queue, re-digested once under a fabricated
        sender name, then cleared. Moving it under ``.delivered/`` is the only safe answer.
        Best-effort and idempotent: a file that will not move is logged and left behind, and
        construction never raises because of it.
        """
        suffix = ".delivered.jsonl"
        try:
            names = os.listdir(self.root)
        except OSError as exc:
            logger.warning(
                "[mesh] coalesce: cannot scan %s for legacy archives (%s)", self.root, exc
            )
            return
        for name in sorted(names):
            src = os.path.join(self.root, name)
            if not name.endswith(suffix) or not os.path.isfile(src):
                continue
            try:
                arch_dir = os.path.join(self.root, ".delivered")
                os.makedirs(arch_dir, exist_ok=True)
                os.replace(src, os.path.join(arch_dir, name[: -len(suffix)] + ".jsonl"))
            except OSError as exc:
                logger.warning(
                    "[mesh] coalesce: could not migrate legacy archive %s (%s)", name, exc
                )

    def _pending_lines(self, peer: str) -> list[str]:
        """Raw non-blank lines of the peer's pending file, malformed rows included."""
        path = self._path(peer)
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip()]

    def pending(self, peer: str) -> list[dict]:
        items: list[dict] = []
        for line in self._pending_lines(peer):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("[mesh] coalesce: skipping malformed pending line for %s", peer)
                continue
            # Valid JSON is not necessarily a row: "123" and "[1]" parse fine and then explode on
            # item.get() inside build_digest, which would abort the whole flush scan.
            if not isinstance(row, dict):
                logger.warning("[mesh] coalesce: skipping non-object pending row for %s", peer)
                continue
            items.append(row)
        return items

    def peers(self) -> list[str]:
        out = []
        for name in sorted(os.listdir(self.root)):
            # Archives live in the `.delivered/` subdirectory, so every `*.jsonl` beside the queues is
            # a pending queue. There must be NO name-based exclusion here: `foo.delivered` is a valid
            # sender, and filtering its suffix would hide its pending mail from every flush forever.
            if name.endswith(".jsonl") and os.path.isfile(os.path.join(self.root, name)):
                out.append(name[: -len(".jsonl")])
        return out

    def add(self, peer: str, item: dict) -> int:
        """Append one informational message. Returns the pending count for that peer."""
        item = dict(item)
        item.setdefault("received_at", time.time())
        with open(self._path(peer), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(item, ensure_ascii=False) + "\n")
        # The append already succeeded, so the recount is informational only: if it fails the
        # caller must still treat the message as coalesced, or it is delivered now AND in a digest.
        try:
            return len(self.pending(peer))
        except Exception:
            logger.warning("[mesh] coalesce: stored but could not recount pending for %s", peer)
            return -1

    def clear(self, peer: str) -> None:
        try:
            os.unlink(self._path(peer))
        except FileNotFoundError:
            pass

    # -- flush -----------------------------------------------------------
    def due(self, now: Optional[float] = None) -> list[str]:
        """Peers whose oldest pending item has waited past the window.

        Never raises: a file that cannot be read, or an oldest row whose ``received_at`` is not a
        number, skips that one peer with a warning. Letting it raise would abort the scan for every
        peer after it in listdir order, every flush cycle, forever.
        """
        now = time.time() if now is None else now
        out = []
        for peer in self.peers():
            try:
                items = self.pending(peer)
                if items and (now - float(items[0].get("received_at", now))) >= self.window_seconds:
                    out.append(peer)
            except Exception as exc:
                logger.warning("[mesh] coalesce: skipping peer %s during due() scan (%s)", peer, exc)
        return out

    def build_digest(self, peer: str) -> tuple[Optional[str], list[dict]]:
        """Return (body_text, items_taken). Items beyond max_items stay on disk."""
        items = self.pending(peer)
        if not items:
            return None, []
        taken = items[: self.max_items]
        held = len(items) - len(taken)
        hours = ""
        try:
            span = float(taken[-1]["received_at"]) - float(taken[0]["received_at"])
        except (TypeError, ValueError):
            span = 0.0
        if span >= 3600:
            hours = f" over {span / 3600:.1f}h"
        elif span >= 60:
            hours = f" over {span / 60:.0f}m"

        lines = [
            f"{len(taken)} message{'s' if len(taken) != 1 else ''} from {peer}{hours}, "
            f"not asking for a reply. Read them; nothing here needs an answer.",
            "",
        ]
        for i, item in enumerate(taken, 1):
            body = str(item.get("body", ""))
            if len(body) > self.preview_chars:
                body = body[: self.preview_chars].rstrip() + " […]"
            try:
                when = time.strftime("%H:%M:%S", time.localtime(float(item.get("received_at", 0))))
            except (TypeError, ValueError, OverflowError, OSError):
                when = "??:??:??"
            lines.append(f"--- [{i}] {when}  id={item.get('id', '?')}  action={item.get('action', 'info')}")
            lines.append(body)
            lines.append("")
        if held:
            lines.append(f"({held} more held on disk — {self._path(peer)})")
        # The delivered batch is archived by take(); this line must name THAT file, not the pending
        # queue, or it points at a path the same flush is about to delete.
        lines.append(
            f"(full text of these {len(taken)} kept at {self._archive_path(peer)} until the next flush)"
        )
        return "\n".join(lines), taken

    def take(self, peer: str, count: int) -> None:
        """Remove the first `count` items, rewriting what remains.

        The delivered batch is written to ``<peer>.delivered.jsonl`` first, so the path a digest
        names still holds the full text after the digest has been enqueued. Without this the
        footer pointed at a file the same call had just deleted.

        The rewrite carries raw lines, not re-parsed rows: `count` indexes parsed items, and a
        line that does not parse is neither taken nor counted — it is written back verbatim so a
        corrupt row is not destroyed by an unrelated flush.
        """
        taken: list[str] = []
        rest: list[str] = []
        seen = 0
        for line in self._pending_lines(peer):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                rest.append(line)
                continue
            # Only objects are rows. A line that parses as valid JSON but not an object is not an
            # item, is not counted toward `count`, and is written back verbatim like any other line
            # this method cannot interpret.
            if not isinstance(row, dict):
                rest.append(line)
                continue
            if seen < count:
                taken.append(line)
                seen += 1
            else:
                rest.append(line)
        if taken:
            archive = self._archive_path(peer)
            tmp_a = archive + ".tmp"
            with open(tmp_a, "w", encoding="utf-8") as fh:
                for line in taken:
                    fh.write(line + "\n")
            os.replace(tmp_a, archive)
        if not rest:
            self.clear(peer)
            return
        tmp = self._path(peer) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            for line in rest:
                fh.write(line + "\n")
        os.replace(tmp, self._path(peer))
