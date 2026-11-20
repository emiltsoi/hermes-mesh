"""Inbound coalescing — the backpressure rule, tested as a rule.

Pinned 2026-10-24 after one seat measured 167 inbound mesh messages in a day: every message spawned a
turn whether or not it asked for anything. These tests cover the decision (urgent vs not), the store,
the digest shape, the cap, and restart safety. They do not touch a gateway.
"""
import importlib.util
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
    assert "kore.jsonl" in body               # and the full text is named


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
