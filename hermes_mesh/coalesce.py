"""Inbound mesh coalescing — the backpressure the transport never had.

Why this exists (2026-10-24): every mesh message spawned a turn, whether or not the envelope asked
for a reply. `action: info, reply: no` was read as "no cost", and it never was: arrival is the cost.
One seat measured 167 inbound messages in a day — 167 turns that were not work, on a day when the
fleet was trying to do something else. The loop then fed itself: each long reply earned a long reply.

Two rules, both applied at the receiver, because the receiver is the only party that can say what a
turn is worth:

  1. COALESCE — non-urgent traffic from one peer waits on disk and arrives as ONE turn carrying all
     of it, after a quiet window. Ten informational messages cost one turn, not ten.
  2. NEVER DELAY URGENT — an envelope that asks for action (`action: do`, or any `reply:` other than
     "no") flushes that peer's pending digest first, then arrives immediately. Order is preserved:
     the digest is always older than the urgent message that triggered it.

Nothing is dropped. Pending items live in a per-peer JSONL file under the seat's mesh state dir, so a
restart loses nothing, and every digest carries the path to the full text so a truncated item can be
read in full.
"""

from __future__ import annotations

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

    # -- storage ---------------------------------------------------------
    def _path(self, peer: str) -> str:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in peer)
        return os.path.join(self.root, f"{safe}.jsonl")

    def pending(self, peer: str) -> list[dict]:
        path = self._path(peer)
        if not os.path.exists(path):
            return []
        items: list[dict] = []
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning("[mesh] coalesce: skipping malformed pending line for %s", peer)
        return items

    def peers(self) -> list[str]:
        out = []
        for name in sorted(os.listdir(self.root)):
            if name.endswith(".jsonl"):
                out.append(name[: -len(".jsonl")])
        return out

    def add(self, peer: str, item: dict) -> int:
        """Append one informational message. Returns the pending count for that peer."""
        item = dict(item)
        item.setdefault("received_at", time.time())
        with open(self._path(peer), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(item, ensure_ascii=False) + "\n")
        return len(self.pending(peer))

    def clear(self, peer: str) -> None:
        try:
            os.unlink(self._path(peer))
        except FileNotFoundError:
            pass

    # -- flush -----------------------------------------------------------
    def due(self, now: Optional[float] = None) -> list[str]:
        """Peers whose oldest pending item has waited past the window."""
        now = time.time() if now is None else now
        out = []
        for peer in self.peers():
            items = self.pending(peer)
            if items and (now - float(items[0].get("received_at", now))) >= self.window_seconds:
                out.append(peer)
        return out

    def build_digest(self, peer: str) -> tuple[Optional[str], list[dict]]:
        """Return (body_text, items_taken). Items beyond max_items stay on disk."""
        items = self.pending(peer)
        if not items:
            return None, []
        taken = items[: self.max_items]
        held = len(items) - len(taken)
        hours = ""
        span = float(taken[-1]["received_at"]) - float(taken[0]["received_at"])
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
            when = time.strftime("%H:%M:%S", time.localtime(float(item.get("received_at", 0))))
            lines.append(f"--- [{i}] {when}  id={item.get('id', '?')}  action={item.get('action', 'info')}")
            lines.append(body)
            lines.append("")
        if held:
            lines.append(f"({held} more held on disk — {self._path(peer)})")
        else:
            lines.append(f"(full text kept at {self._path(peer)} until the next flush)")
        return "\n".join(lines), taken

    def take(self, peer: str, count: int) -> None:
        """Remove the first `count` items, rewriting what remains."""
        items = self.pending(peer)
        rest = items[count:]
        if not rest:
            self.clear(peer)
            return
        tmp = self._path(peer) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            for item in rest:
                fh.write(json.dumps(item, ensure_ascii=False) + "\n")
        os.replace(tmp, self._path(peer))
