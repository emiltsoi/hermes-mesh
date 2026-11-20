"""The legacy-archive sweep is one-shot — disarmed by `.delivered/.migrated`.

CRITICAL from the fourth review: `_migrate_legacy_archives()` swept every root-level
`*.delivered.jsonl` on EVERY construction, but `foo.delivered` is a valid sender whose live
pending queue is exactly `foo.delivered.jsonl` — so a second construction moved the queue into
the archive dir, `peers()` lost the peer, and the peer's next flush overwrote the file. The
suffix cannot distinguish a legacy archive from a live queue, so the sweep runs once, on the
upgrade that introduces `.delivered/`, and the marker is what makes the layout unambiguous
after that.
"""
import importlib.util
import json
import os

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _module():
    path = os.path.join(_HERE, "hermes_mesh", "coalesce.py")
    spec = importlib.util.spec_from_file_location("mesh_coalesce_marker_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_live_queue_named_like_a_legacy_archive_survives_reconstruction(tmp_path):
    """T1: `foo.delivered` is a valid sender, and its pending queue is exactly the name the
    legacy sweep looks for. The first construction may sweep — the SECOND must not touch a
    queue planted in between, or the peer's mail is destroyed and peers() hides it."""
    m = _module()
    root = str(tmp_path / "pending")
    first = m.Coalescer(root)
    first.add("foo.delivered", {"id": "b1", "action": "info", "reply": "no", "body": "live mail"})

    second = m.Coalescer(root)
    assert [i["id"] for i in second.pending("foo.delivered")] == ["b1"]
    assert "foo.delivered" in second.peers()


def test_legacy_archive_still_migrates_and_writes_the_marker(tmp_path):
    """T2: the one-shot sweep still does its job — a genuine `<peer>.delivered.jsonl` present
    at the FIRST construction moves into `.delivered/` — and the marker recording that the
    layout is now unambiguous is written."""
    m = _module()
    root = tmp_path / "pending"
    root.mkdir()
    (root / "kore.delivered.jsonl").write_text(
        json.dumps({"id": "old1", "body": "archived"}) + "\n", encoding="utf-8"
    )
    m.Coalescer(str(root))
    assert (root / ".delivered" / "kore.jsonl").is_file()   # still moved
    assert not (root / "kore.delivered.jsonl").exists()
    assert (root / ".delivered" / ".migrated").is_file()    # the disarm itself


def test_marker_disarms_the_sweep_forever(tmp_path):
    """T3: with the marker present, a file that merely LOOKS like a legacy archive is left
    exactly where it is — after the one-time upgrade pass the layout is unambiguous and
    nothing at the root is ever moved by name again."""
    m = _module()
    root = tmp_path / "pending"
    m.Coalescer(str(root))                                   # first construction sweeps, marks
    assert (root / ".delivered" / ".migrated").is_file()

    (root / "late.delivered.jsonl").write_text(
        json.dumps({"id": "n1", "body": "planted after the sweep"}) + "\n", encoding="utf-8"
    )
    m.Coalescer(str(root))
    assert (root / "late.delivered.jsonl").is_file()         # untouched
    assert not (root / ".delivered" / "late.jsonl").exists()
