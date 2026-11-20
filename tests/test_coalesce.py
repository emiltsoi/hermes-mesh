"""Inbound coalescing — the backpressure rule, tested as a rule.

Pinned 2026-10-24 after one seat measured 167 inbound mesh messages in a day: every message spawned a
turn whether or not it asked for anything. These tests cover the decision (urgent vs not), the store,
the digest shape, the cap, and restart safety. They do not touch a gateway.
"""
import importlib.util
import json
import os
import time

import pytest

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _module():
    path = os.path.join(_HERE, "hermes_mesh", "coalesce.py")
    spec = importlib.util.spec_from_file_location("mesh_coalesce_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def coal(tmp_path):
    m = _module()
    return m, m.Coalescer(str(tmp_path / "pending"), window_seconds=600, max_items=25, preview_chars=50)


def test_urgent_is_never_coalesced():
    m, _ = _module(), None
    assert m._urgent("do", "no") is True
    assert m._urgent("info", "yes") is True
    assert m._urgent("info", "end") is True
    assert m._urgent("info", "no") is False
    assert m._urgent("info", "") is False


def test_informational_waits_then_arrives_once(coal):
    m, c = coal
    for i in range(5):
        c.add("kore", {"id": f"id{i}", "action": "info", "reply": "no", "body": "x" * 200})
    assert len(c.pending("kore")) == 5
    assert c.due() == []                      # inside the quiet window
    assert c.due(now=time.time() + 700) == ["kore"]

    body, taken = c.build_digest("kore")
    assert len(taken) == 5
    assert body.count("--- [") == 5
    assert "not asking for a reply" in body   # the digest must not invite an answer
    assert "nothing here needs an answer" in body
    assert "[…]" in body                      # long bodies are truncated, not lost
    assert c._archive_path("kore") in body     # the full text is named via the archive — the old
                                               # assertion pinned the PENDING file, which the flush
                                               # deletes; archives now live in their own directory
    # assertion pinned kore.jsonl, the pending file this same flush removes


def test_take_clears_and_overflow_keeps_the_rest(coal):
    m, c = coal
    for i in range(30):
        c.add("daji", {"id": f"d{i}", "action": "info", "reply": "no", "body": f"m{i}"})
    body, taken = c.build_digest("daji")
    assert len(taken) == 25                   # capped per turn
    c.take("daji", len(taken))
    assert len(c.pending("daji")) == 5        # nothing dropped
    assert "more held on disk" in body


def test_pending_survives_a_restart(coal, tmp_path):
    m, c = coal
    c.add("isa", {"id": "x1", "action": "info", "reply": "no", "body": "hello"})
    fresh = m.Coalescer(str(tmp_path / "pending"))
    assert len(fresh.pending("isa")) == 1


def test_empty_digest_is_none(coal):
    m, c = coal
    body, taken = c.build_digest("nobody")
    assert body is None and taken == []


def test_due_skips_a_corrupt_peer_and_scans_the_rest(coal):
    """F4: one corrupt pending file must not stall the whole fleet's scan."""
    m, c = coal
    # "aaa" sorts before "zzz" in listdir order — the corrupt file is hit FIRST.
    with open(c._path("aaa"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"id": "b0", "received_at": "not-a-number"}) + "\n")
    c.add("zzz", {"id": "g1", "action": "info", "reply": "no", "body": "hi", "received_at": 0})
    assert c.due(now=time.time()) == ["zzz"]


def test_build_digest_tolerates_a_non_numeric_received_at(coal):
    """F4: the same corrupt row that due() skips must not break digest building either."""
    m, c = coal
    with open(c._path("ada"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"id": "b0", "received_at": "never", "body": "hi"}) + "\n")
    body, taken = c.build_digest("ada")
    assert body is not None and len(taken) == 1


def test_peer_names_that_sanitize_alike_get_distinct_files(coal):
    """F7: 'a b' and 'a_b' both used to land in a_b.jsonl — merged mail, wrong attribution."""
    m, c = coal
    c.add("a b", {"id": "s1", "body": "spaces"})
    c.add("a_b", {"id": "s2", "body": "underscore"})
    assert c._path("a b") != c._path("a_b")
    assert c._archive_path("a b") != c._archive_path("a_b")
    assert [i["body"] for i in c.pending("a b")] == ["spaces"]
    assert [i["body"] for i in c.pending("a_b")] == ["underscore"]


def test_add_returns_minus_one_when_the_recount_fails(coal, monkeypatch):
    """F8: the append already happened, so a failed recount must not raise — the caller would
    fall through to direct delivery and the message would arrive now AND in a later digest."""
    m, c = coal

    def boom(peer):
        raise OSError("disk went away after the append")

    monkeypatch.setattr(c, "pending", boom)
    held = c.add("daji", {"id": "x1", "action": "info", "reply": "no", "body": "hi"})
    assert held == -1                       # non-raising: the caller treats it as coalesced
    monkeypatch.undo()
    assert len(c.pending("daji")) == 1      # and the item really is on disk


def test_take_preserves_malformed_lines(coal):
    """F10: a corrupt row must survive a rewrite triggered by an unrelated flush."""
    m, c = coal
    c.add("yoyo", {"id": "g1", "action": "info", "reply": "no", "body": "one"})
    with open(c._path("yoyo"), "a", encoding="utf-8") as fh:
        fh.write("{not json\n")
    c.add("yoyo", {"id": "g2", "action": "info", "reply": "no", "body": "two"})
    c.take("yoyo", 1)
    raw = open(c._path("yoyo"), encoding="utf-8").read()
    assert "{not json" in raw               # verbatim, not silently dropped
    assert [i["id"] for i in c.pending("yoyo")] == ["g2"]


def test_archive_never_collides_with_another_peers_pending(coal):
    """CRITICAL from the second review: `foo.delivered` is a valid sender, and its PENDING queue
    used to land on exactly the file that is `foo`'s ARCHIVE -- so foo's flush destroyed
    foo.delivered's mail and peers() hid it. Archives now live in their own directory."""
    m, c = coal
    c.add("foo", {"id": "a1", "action": "info", "reply": "no", "body": "for foo"})
    c.add("foo.delivered", {"id": "b1", "action": "info", "reply": "no", "body": "for the other peer"})

    assert c._path("foo.delivered") != c._archive_path("foo")

    body, taken = c.build_digest("foo")
    c.take("foo", len(taken))

    survivors = c.pending("foo.delivered")
    assert [i["id"] for i in survivors] == ["b1"]     # untouched by foo's flush
    assert "foo.delivered" in c.peers()               # and still visible to the flush loop


def test_non_object_json_rows_are_not_items(coal):
    """MAJOR from the second review: "123" parses as JSON but is not a row; it used to reach
    item.get() in build_digest and abort the entire flush scan."""
    m, c = coal
    c.add("isa", {"id": "o1", "action": "info", "reply": "no", "body": "real"})
    with open(c._path("isa"), "a", encoding="utf-8") as fh:
        fh.write("123\n[1]\nnull\n")

    assert [i["id"] for i in c.pending("isa")] == ["o1"]      # non-objects are not rows
    body, taken = c.build_digest("isa")                        # must not raise
    assert len(taken) == 1 and "real" in body

    c.take("isa", len(taken))
    raw = open(c._path("isa"), encoding="utf-8").read()
    assert "123" in raw and "[1]" in raw and "null" in raw     # preserved verbatim, like any junk row


def test_legacy_delivered_files_migrate_into_the_archive_dir(tmp_path):
    """MAJOR from the third review: archives used to live beside the queues as
    <peer>.delivered.jsonl, and peers() rightly refuses to name-filter that suffix (a
    'foo.delivered' sender is valid) — so a leftover archive would list as a pending queue and
    be re-digested once under a fabricated name. Construction sweeps them into .delivered/."""
    m = _module()
    root = tmp_path / "pending"
    root.mkdir()
    (root / "kore.delivered.jsonl").write_text(
        json.dumps({"id": "old1", "body": "archived"}) + "\n", encoding="utf-8"
    )
    c = m.Coalescer(str(root))
    moved = root / ".delivered" / "kore.jsonl"
    assert moved.exists()                                   # archive dir, never a sibling name
    assert not (root / "kore.delivered.jsonl").exists()
    assert "kore" not in c.peers()                          # not a pending queue
    assert c.pending("kore") == []                          # and no phantom items


def test_legacy_migration_is_best_effort(tmp_path):
    """An OSError on one file logs and continues: the unmovable archive is left behind rather
    than lost, the next legacy file still migrates, and construction never raises."""
    m = _module()
    root = tmp_path / "pending"
    root.mkdir()
    (root / "kore.delivered.jsonl").write_text('{"id": "a"}\n', encoding="utf-8")
    (root / "linda.delivered.jsonl").write_text('{"id": "b"}\n', encoding="utf-8")
    # A directory squatting on the target name forces an OSError on os.replace.
    blocker = root / ".delivered"
    blocker.mkdir()
    (blocker / "kore.jsonl").mkdir()
    c = m.Coalescer(str(root))
    assert (root / "kore.delivered.jsonl").exists()         # left behind, not lost
    assert (blocker / "linda.jsonl").is_file()              # the unblocked one still moved
    m.Coalescer(str(root))                                  # and a second construction is fine
