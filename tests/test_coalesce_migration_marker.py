"""The legacy-archive sweep is a deliberate one-shot — never automatic.

CRITICAL from the fourth review: `_migrate_legacy_archives()` swept every root-level
`*.delivered.jsonl` on EVERY construction, but `foo.delivered` is a valid sender whose live
pending queue is exactly `foo.delivered.jsonl`. The marker stopped later runs — but not the
FIRST construction, which still swept a live queue into the archive dir, hid the peer from
`peers()`, and let its next flush overwrite the file. The suffix cannot distinguish a legacy
archive from a live queue, so construction now moves nothing at all: the sweep only runs when
an operator calls `migrate_legacy_archives(root)` on a root known to predate `.delivered/`.

MAJOR from the fifth review: the marker lived inside `.delivered/` — purgeable — and was
written before a best-effort sweep, so `rm -rf .delivered` re-armed the migration while one
failed `os.replace` disarmed it forever. The marker now sits at the root as
`.migration-complete` and is written only when every move succeeded.
"""
import importlib.util
import json
import os
import shutil

_HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _module():
    path = os.path.join(_HERE, "hermes_mesh", "coalesce.py")
    spec = importlib.util.spec_from_file_location("mesh_coalesce_marker_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_construction_never_moves_a_live_queue(tmp_path):
    """F2: `foo.delivered` is a valid sender, and its pending queue is exactly the name the
    legacy sweep looks for — so even the FIRST construction on a pre-existing root must
    leave it in place and listed by peers()."""
    m = _module()
    root = tmp_path / "pending"
    root.mkdir()
    (root / "foo.delivered.jsonl").write_text(
        json.dumps({"id": "b1", "action": "info", "reply": "no", "body": "live mail"}) + "\n",
        encoding="utf-8",
    )
    c = m.Coalescer(str(root))
    assert (root / "foo.delivered.jsonl").is_file()          # unmoved
    assert not (root / ".delivered" / "foo.jsonl").exists()
    assert [i["id"] for i in c.pending("foo.delivered")] == ["b1"]
    assert "foo.delivered" in c.peers()


def test_explicit_migration_moves_legacy_archives_and_marks_at_root(tmp_path):
    """F2/F3: the operator-run sweep still does its job — a genuine `<peer>.delivered.jsonl`
    moves into `.delivered/` — and the marker recording the upgrade lives at the ROOT, so
    purging the archive dir cannot re-arm the sweep."""
    m = _module()
    root = tmp_path / "pending"
    root.mkdir()
    (root / "kore.delivered.jsonl").write_text(
        json.dumps({"id": "old1", "body": "archived"}) + "\n", encoding="utf-8"
    )
    assert m.migrate_legacy_archives(str(root)) == 1
    assert (root / ".delivered" / "kore.jsonl").is_file()    # still moved
    assert not (root / "kore.delivered.jsonl").exists()
    assert (root / ".migration-complete").is_file()          # marker at root, not in .delivered/

    # Purging .delivered/ must not re-arm the sweep.
    shutil.rmtree(root / ".delivered")
    (root / "late.delivered.jsonl").write_text(
        json.dumps({"id": "n1", "body": "planted after the sweep"}) + "\n", encoding="utf-8"
    )
    assert m.migrate_legacy_archives(str(root)) == 0         # considered done
    assert (root / "late.delivered.jsonl").is_file()         # untouched — a live queue by name


def test_failed_move_does_not_write_the_marker(tmp_path):
    """F3: one failed os.replace must not permanently disarm retry — the marker is written
    only when every move succeeded, so the next deliberate run retries the stranded file."""
    m = _module()
    root = tmp_path / "pending"
    root.mkdir()
    (root / "kore.delivered.jsonl").write_text('{"id": "a"}\n', encoding="utf-8")
    blocker = root / ".delivered"
    blocker.mkdir()
    (blocker / "kore.jsonl").mkdir()                          # forces the os.replace to fail
    m.migrate_legacy_archives(str(root))
    assert not (root / ".migration-complete").exists()       # failure must not disarm retry

    shutil.rmtree(blocker / "kore.jsonl")
    assert m.migrate_legacy_archives(str(root)) == 1         # retry completes the move
    assert (blocker / "kore.jsonl").is_file()
    assert (root / ".migration-complete").is_file()
