"""A third party must never be able to close a conversation they are not in.

Found by Kore (2026-10-31) while porting N1–N10 to openclaw-mesh. She read the Hermes source and
spotted that the delivery-FAILURE path released with a bare `release(task_id)` while the success
path correctly used `release_if_party(tid, from_agent)`.

Why it matters, traced end to end:

1. `task_id` is caller-supplied (`session_relay.py:620`), validated only as an envelope token.
2. `claim()` appends whatever `thread_id` it is given with NO uniqueness check
   (`open_threads.py:332-342`), so a second live record can share an id with an existing lease.
3. `release(thread_id)` deletes EVERY record carrying that id (`open_threads.py:212-221`).

So a sender who passes a colliding `task_id` and then has a delivery fail closes the victim's live
thread as a side effect. `release_if_party` exists precisely to prevent this and says so in its
docstring — the failure path simply never adopted it.

These tests pin the mechanic rather than the call site, because the failure path has no harness: the
relay's webhook retries are not exercised anywhere in this suite.
"""
import json
import os
import pathlib

import pytest

from hermes_mesh import open_threads


@pytest.fixture()
def registry(tmp_path, monkeypatch):
    path = tmp_path / "open-threads.json"
    monkeypatch.setenv("MESH_OPEN_THREADS", str(path))
    yield path


def _records(path):
    if not path.exists():
        return []
    return json.loads(path.read_text())


def test_claim_permits_a_colliding_thread_id(registry):
    """Documents the precondition: the id space is not unique, by design or by omission."""
    victim = open_threads.claim("shared-id", "zero", "linda")
    assert victim["ok"] is True

    attacker = open_threads.claim("shared-id", "daji", "lilith")
    assert attacker["ok"] is True, "claim() accepted a duplicate id — the collision is real"

    ids = [r["thread_id"] for r in _records(registry)]
    assert ids.count("shared-id") == 2, f"expected two live records sharing the id, got {ids}"


def test_third_party_cannot_close_someone_elses_lease(registry):
    """The invariant the failure path used to violate."""
    open_threads.claim("shared-id", "zero", "linda")
    open_threads.claim("shared-id", "daji", "lilith")   # colliding id, different pair

    released = open_threads.release_if_party("shared-id", "daji")
    assert released is True, "the attacker's own record should have been released"

    survivors = {(r["opened_by"], r["peer"]) for r in _records(registry)}
    assert ("zero", "linda") in survivors, (
        "a third party's failed send closed zero<->linda's live thread"
    )
    assert ("daji", "lilith") not in survivors


def test_bare_release_is_the_hazard_this_guards_against(registry):
    """Why the relay must never call `release` on a caller-supplied id.

    Not an aspiration: this asserts the destructive behaviour of the function the failure path
    used, so that removing it is a visible change rather than a silent one.
    """
    open_threads.claim("shared-id", "zero", "linda")
    open_threads.claim("shared-id", "daji", "lilith")

    open_threads.release("shared-id")

    remaining = [r for r in _records(registry) if r["thread_id"] == "shared-id"]
    assert remaining == [], "bare release() removes every record sharing the id — victims included"


def test_relay_never_releases_by_bare_thread_id():
    """Structural guard on the CALL SITE — the actual defect Kore found.

    The mechanic is sound (`release_if_party` is correct); the bug was the relay reaching for the
    id-only function on its failure path. A behavioural harness for that path does not exist, so
    this asserts the call itself: no bare `_open_threads.release(` may appear in the relay.
    """
    repo = pathlib.Path(__file__).resolve().parent.parent
    src = (repo / "hermes_mesh" / "session_relay.py").read_text()
    offenders = [
        f"{i}: {line.strip()}"
        for i, line in enumerate(src.splitlines(), 1)
        if "_open_threads.release(" in line and "_open_threads.release_if_party(" not in line
    ]
    assert not offenders, (
        "session_relay releases by thread id alone; a third party can close a conversation:\n  "
        + "\n  ".join(offenders)
    )


def test_the_guard_can_actually_fail(tmp_path):
    """Kore's correction: a check that cannot fail on the broken state is not a check.

    The first version read a RELATIVE path, so running it from the repo was always green and
    running it anywhere else inspected the wrong tree — including a seat that still carried the
    defect. This pins the detector itself against a synthetic broken file.
    """
    broken = tmp_path / "session_relay.py"
    broken.write_text("        _open_threads.release(task_id)\n")

    lines = broken.read_text().splitlines()
    offenders = [
        f"{i}: {ln.strip()}"
        for i, ln in enumerate(lines, 1)
        if "_open_threads.release(" in ln and "_open_threads.release_if_party(" not in ln
    ]
    assert offenders == ["1: _open_threads.release(task_id)"], (
        "the detector failed to see the exact defect it exists to find"
    )


def test_guard_path_is_absolute_not_cwd_dependent():
    """The regression that produced the false 'green' in the first place."""
    repo = pathlib.Path(__file__).resolve().parent.parent
    assert (repo / "hermes_mesh" / "session_relay.py").is_file(), (
        "the guard resolved a path that does not exist from this CWD"
    )
