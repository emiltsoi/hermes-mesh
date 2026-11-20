"""Sixth-review fixes: case-folded filenames, intact rows missing a newline,
restore order across drained digests, in-flight digest recovery, and a huge
received_at.

Each test names the defect it pins. The adapter-level ones build the real
MeshAdapter on the gateway stubs: the bug lives in shipped ordering, so the
test must exercise shipped code.
"""
import asyncio
import hashlib
import importlib.util
import json
import os
import sys
import time

import pytest

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


def _module():
    path = os.path.join(_HERE, "hermes_mesh", "coalesce.py")
    spec = importlib.util.spec_from_file_location("mesh_coalesce_fix5_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def coal(tmp_path):
    m = _module()
    return m, m.Coalescer(str(tmp_path / "pending"), window_seconds=600, max_items=25, preview_chars=50)


def _make_adapter(tmp_path):
    """The real adapter, on the stub gateway, with coalescing enabled into a temp root."""
    from gateway.config import PlatformConfig
    from hermes_mesh.adapter import MeshAdapter

    return MeshAdapter(
        PlatformConfig(
            extra={
                "secret": "INSECURE_NO_AUTH",
                "agent_name": "testagent",
                "coalesce": {
                    "enabled": True,
                    "dir": str(tmp_path / "pending"),
                    "window_seconds": 600,
                },
            }
        )
    )


def test_case_folded_peer_names_get_distinct_files(coal):
    """G1: this host's filesystem folds case — 'kore' and 'Kore' used to land on one
    queue and one archive, merging two senders' mail. Every filename now carries a
    sha1 of the RAW name, so folded stems still differ — and peers() decodes each
    back to the exact original."""
    m, c = coal
    c.add("kore", {"id": "l1", "body": "lower"})
    c.add("Kore", {"id": "u1", "body": "upper"})

    assert c._path("kore") != c._path("Kore")
    assert c._archive_path("kore") != c._archive_path("Kore")
    # The suffix is hashed from the raw name, not the quoted form.
    stem = os.path.basename(c._path("kore"))
    assert hashlib.sha1("kore".encode("utf-8")).hexdigest()[:8] in stem

    assert [i["body"] for i in c.pending("kore")] == ["lower"]
    assert [i["body"] for i in c.pending("Kore")] == ["upper"]
    assert set(c.peers()) == {"kore", "Kore"}               # exact names, not stems


def test_add_keeps_a_complete_row_missing_its_newline(coal):
    """G2: a write that flushed the row but not its newline is complete mail, not a
    torn write — the old repair truncated everything after the last newline and
    destroyed it. Now the row gets its newline back and the append lands after it."""
    m, c = coal
    with open(c._path("yoyo"), "w", encoding="utf-8") as fh:
        fh.write('{"id": "g1", "body": "one"}')             # complete JSON, no newline
    c.add("yoyo", {"id": "g2", "body": "two"})
    assert [i["id"] for i in c.pending("yoyo")] == ["g1", "g2"]


def test_add_still_truncates_a_genuinely_torn_fragment(coal):
    """G2: only an unparseable fragment is torn — it is still dropped so the next
    append does not concatenate onto it."""
    m, c = coal
    c.add("yoyo", {"id": "g1", "body": "one"})
    with open(c._path("yoyo"), "a", encoding="utf-8") as fh:
        fh.write('{"id": "g9", "bo')                        # torn mid-key, no newline
    c.add("yoyo", {"id": "g2", "body": "two"})
    assert [i["id"] for i in c.pending("yoyo")] == ["g1", "g2"]
    assert "g9" not in open(c._path("yoyo"), encoding="utf-8").read()


def test_disconnect_restores_drained_digests_in_arrival_order(tmp_path):
    """G3: disconnect() drains stranded digests and restore() PREPENDS each one —
    replaying them in queue order inverted every peer's mail (newest first)."""
    adapter = _make_adapter(tmp_path)
    adapter._coalesce.add("peer_a", {"id": "a1", "action": "info", "reply": "no", "body": "one"})
    adapter._coalesce.add("peer_a", {"id": "a2", "action": "info", "reply": "no", "body": "two"})
    adapter._flush_coalesced("peer_a")                      # batch A -> inbox
    adapter._coalesce.add("peer_a", {"id": "b1", "action": "info", "reply": "no", "body": "three"})
    adapter._flush_coalesced("peer_a")                      # batch B -> inbox
    assert adapter._mesh_inbox.qsize() == 2
    asyncio.run(adapter.disconnect())
    assert [i["id"] for i in adapter._coalesce.pending("peer_a")] == ["a1", "a2", "b1"]


@pytest.mark.parametrize("swallow", [True, False])
def test_inflight_digest_is_restored_when_the_processor_is_cancelled(tmp_path, swallow):
    """G4: a digest dequeued and mid-turn when the processor is cancelled after the
    30s drain was neither delivered nor restored — the un-fixed sibling of the
    stranded batch disconnect() saves. Cancellation reaches the loop two ways:
    _process_mesh_event can propagate it or swallow it whole (its own except),
    and BOTH must put the batch back on disk AND let the loop actually die —
    otherwise the absorbed cancel leaves disconnect() waiting on a live task."""
    adapter = _make_adapter(tmp_path)
    adapter._coalesce.add("peer_a", {"id": "i1", "action": "info", "reply": "no", "body": "held"})
    adapter._flush_coalesced("peer_a")
    assert adapter._coalesce.pending("peer_a") == []        # take() already ran

    started = asyncio.Event()

    async def stuck(event):
        started.set()
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            if not swallow:
                raise

    adapter._process_mesh_event = stuck

    async def run():
        processor = asyncio.create_task(adapter._mesh_processor_loop())
        await asyncio.wait_for(started.wait(), timeout=5)   # mid-turn, event consumed
        processor.cancel()
        await asyncio.wait_for(processor, timeout=5)        # must end, not hang

    asyncio.run(run())
    assert [i["id"] for i in adapter._coalesce.pending("peer_a")] == ["i1"]


def test_build_digest_tolerates_a_huge_received_at(coal):
    """G5: float(10**400) raises OverflowError — not ValueError — and it escaped
    build_digest's guard, so one hostile timestamp broke that peer's digest
    forever."""
    m, c = coal
    with open(c._path("ada"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"id": "b0", "received_at": 10**400, "body": "hi"}) + "\n")
    body, taken = c.build_digest("ada")
    assert body is not None and len(taken) == 1
    # And due() must not starve the peer: an unreadable stamp degrades to 0, which
    # is always past the window — skipping the peer would strand its mail forever.
    assert "ada" in c.due()
