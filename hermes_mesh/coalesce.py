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
from urllib.parse import quote, unquote

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

    # -- storage ---------------------------------------------------------
    def _stem(self, peer: str) -> str:
        """Filesystem-safe, collision-free stem for a peer name.

        Sanitizing alone maps ``a b`` and ``a_b`` to the same file, merging two peers' mail under
        one attribution, and hashing only the names it mangled still lets a legal name land on a
        mangled one (``a b`` and ``a_b.<that-hash>`` shared a queue). Percent-encoding the RAW
        name is injective instead: every name maps to exactly one stem and unquote() recovers it,
        so no two senders can ever share a pending file.

        Injective per BYTE, that is — filesystems fold case, and on a case-insensitive host
        ``kore`` and ``Kore`` quote differently yet still land on one file. A short sha1 of the
        RAW name is appended unconditionally, so stems that fold together still differ in their
        suffix. Unreserved characters stay readable — ``kore`` stays ``kore.<hash>.jsonl`` — and
        ``peers()`` strips the suffix and unquotes back to the true name.
        """
        digest = hashlib.sha1(peer.encode("utf-8")).hexdigest()[:8]
        return f"{quote(peer, safe='')}.{digest}"

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
            # Stems are percent-encoded and carry a trailing `.<8 hex of sha1(raw name)>` —
            # strip the suffix, then unquote hands the caller back the true peer name so the
            # flush loop resolves the same file again. A stem whose tail is not a hash suffix
            # (a queue written by an older layout) keeps it — the decode stays lossless.
            if name.endswith(".jsonl") and os.path.isfile(os.path.join(self.root, name)):
                stem = name[: -len(".jsonl")]
                base, dot, suffix = stem.rpartition(".")
                if dot and len(suffix) == 8 and all(c in "0123456789abcdef" for c in suffix):
                    stem = base
                out.append(unquote(stem))
        return out

    def add(self, peer: str, item: dict) -> int:
        """Append one informational message. Returns the pending count for that peer."""
        item = dict(item)
        item.setdefault("received_at", time.time())
        path = self._path(peer)
        # A crash mid-append leaves a final line without its newline, and concatenating the
        # next append onto it corrupts BOTH lines — pending() then skips them forever. But
        # truncation is only right for a genuinely torn write: a write can flush the whole row
        # and die before the newline, and that fragment is good mail. Parse the tail after the
        # last newline — if it is complete JSON keep it and just mend the line end; only an
        # unparseable fragment is truncated away. Best-effort: a fault here must never refuse
        # the append itself.
        try:
            if os.path.getsize(path):
                with open(path, "rb+") as fh:
                    fh.seek(-1, os.SEEK_END)
                    if fh.read(1) != b"\n":
                        fh.seek(0)
                        data = fh.read()
                        cut = data.rfind(b"\n") + 1
                        try:
                            json.loads(data[cut:].decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            fh.truncate(cut)
                            logger.warning(
                                "[mesh] coalesce: dropped torn final line in %s", path
                            )
                        else:
                            fh.seek(0, os.SEEK_END)
                            fh.write(b"\n")
                            logger.warning(
                                "[mesh] coalesce: kept intact final row missing its newline in %s",
                                path,
                            )
        except OSError:
            pass
        with open(path, "a", encoding="utf-8") as fh:
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
        peer after it in listdir order, every flush cycle, forever. A stamp that is a number too
        big for float is not corrupt mail though — it degrades to 0, instantly due, rather than
        starving the peer forever.
        """
        now = time.time() if now is None else now
        out = []
        for peer in self.peers():
            try:
                items = self.pending(peer)
                if items:
                    try:
                        oldest = float(items[0].get("received_at", now))
                    except OverflowError:
                        oldest = 0.0
                    if (now - oldest) >= self.window_seconds:
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
            span = float(taken[-1].get("received_at")) - float(taken[0].get("received_at"))
        except (TypeError, ValueError, OverflowError):
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

        The delivered batch is written to the ``.delivered/`` archive first, so the path a
        digest names still holds the full text after the digest has been enqueued. Without
        this the footer pointed at a file the same call had just deleted.

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

    def restore(self, peer: str, items: Iterable[dict]) -> None:
        """Put a taken-but-undelivered batch back at the FRONT of the pending queue.

        A digest stranded in the inbox at shutdown is the one loss this feature must never
        have: take() already deleted its pending rows, so the batch is written back to disk
        where the next boot's flush finds it. Restored items lead the file — they are older
        than anything still pending — and the rewrite is atomic like take()'s.
        """
        lines = [json.dumps(item, ensure_ascii=False) for item in items]
        lines += self._pending_lines(peer)
        tmp = self._path(peer) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
        os.replace(tmp, self._path(peer))
