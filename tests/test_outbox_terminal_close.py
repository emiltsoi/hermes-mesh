"""A25–A28: a terminator handed to the outbox must not read closed until it lands.

Spec: ``fleet/shared/specs/mesh-thread-gate-port-spec.md`` §14.3/§14.4.

The outbox is a retry queue, not a delivery.  With ``MESH_OUTBOX_ENABLED=1`` a
failed ``reply:end`` is queued; the thread must stay open for the whole retry
window, be promoted only when the reaper actually delivers the close, and stay
open if the item is dead-lettered.  A28 is the negative control: a live attempt
that is in progress must still read closed, so A25 cannot be "fixed" by making
``is_closed()`` ignore pending closes.
"""
import json
import time
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from hermes_mesh import outbox, threads
from hermes_mesh.session_relay import handle_mesh_send

_TERM = "a25-a28-term"


@pytest.fixture(autouse=True)
def _isolated_mesh_state(tmp_path, monkeypatch):
    """Keep every registry/outbox read and write inside this test."""
    monkeypatch.setenv("MESH_AGENT_NAME", "sender")
    monkeypatch.setenv("MESH_OUTBOX_ENABLED", "1")
    monkeypatch.setenv("MESH_OUTBOX_PATH", str(tmp_path / "outbox"))
    monkeypatch.setenv("MESH_OUTBOX_MAX_ATTEMPTS", "5")
    monkeypatch.setenv("MESH_OUTBOX_BACKOFF", "0")
    monkeypatch.setenv("MESH_CLOSED_THREADS", str(tmp_path / "mesh" / "closed-threads.json"))
    monkeypatch.setenv("MESH_DSN_ENABLED", "1")
    monkeypatch.setenv("MESH_DSN_RATE_LIMIT", "1000")

    threads._LOCKED.clear()
    threads._LOADED = False
    threads._MTIME = None
    yield
    threads._LOCKED.clear()
    threads._LOADED = False
    threads._MTIME = None


@contextmanager
def _relay(deliver):
    """Run the real relay with only the transport boundary stubbed."""
    with (
        patch("hermes_mesh.auth.resolve_target", return_value=("http://target.invalid/mesh", None)),
        patch("hermes_mesh.auth.resolve_sender", return_value=("signing-material", None)),
        patch("hermes_mesh.session_relay._deliver_webhook", side_effect=deliver),
        patch("hermes_mesh.session_relay._float.send"),
    ):
        yield


def _send_terminal(task_id=_TERM, ref=None):
    args = {
        "message": "closing the thread",
        "agent": "target",
        "action": "info",
        "reply": "end",
        "task_id": task_id,
    }
    if ref is not None:
        args["ref"] = ref
    return handle_mesh_send(args)


def _queued_items():
    root = outbox._outbox_root()
    if not root.is_dir():
        return []
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(root.glob("*.json"))]


def _fail(*_args, **_kwargs):
    return (None, "unreachable")


def test_a25_failed_terminal_with_outbox_leaves_thread_open_and_queued():
    """A25: delivery fails at outbox=1 -> open thread + retryable item."""
    with _relay(_fail):
        result = _send_terminal("a25-term", ref="a25-parent")

    assert result.get("status") == "queued for outbox retry", result
    assert threads.is_closed("a25-term") is False

    items = _queued_items()
    assert len(items) == 1
    item = items[0]
    assert item["anchor"] == "a25-term", "the terminal anchor did not travel with the item"
    assert item["ref"] == "a25-parent", "ref is the thread reference, not the terminal anchor"
    assert item["attempt"] == 0
    assert item["next_retry"] <= time.time() + 1


def test_a26_redelivery_promotes_the_close():
    """A26: the reaper's confirmed delivery is what closes the thread."""
    with _relay(_fail):
        _send_terminal("a26-term")

    # Attribution: the thread is open before the reaper runs; only the actual
    # re-delivery can be responsible for the close afterwards.
    assert threads.is_closed("a26-term") is False

    def _succeed(*_args, **_kwargs):
        return ("redelivered", None)

    with _relay(_succeed):
        stats = outbox.retry_outbox()

    assert stats == {"retried": 1, "delivered": 1}, stats
    assert threads.is_closed("a26-term") is True
    assert outbox.outbox_count() == 0


def test_a27_dead_letter_leaves_thread_open_and_emits_notice():
    """A27: exhausted retries must not close; the sender hears the close failed."""
    notices = []

    def _fail_message_succeed_dsn(url, body, signing_material, **kwargs):
        is_dsn = (kwargs.get("extra_headers") or {}).get("X-Mesh-DSN") == "1" or "[mesh-dsn]" in body
        if is_dsn:
            notices.append(body)
            return ("dsn-delivered", None)
        return (None, "unreachable")

    with _relay(_fail_message_succeed_dsn):
        _send_terminal("a27-term")
        stats = outbox.retry_outbox(max_attempts=1)

    assert stats == {"retried": 1, "delivered": 0}, stats
    assert threads.is_closed("a27-term") is False

    dead = list(outbox._dead_letter_root().glob("*.json"))
    assert len(dead) == 1, dead
    assert outbox.outbox_count() == 0

    assert notices, "no delivery-failure notice was actually sent"
    assert "[mesh-dsn]" in notices[0]
    assert "[reason:dead-letter]" in notices[0]
    assert "a27-term" in notices[0]


def test_a28_successful_first_attempt_is_closed_from_the_moment_delivery_begins():
    """A28: negative control — the in-flight window stays closed on success."""
    seen = {}

    def _deliver_and_observe(url, body, signing_material, **kwargs):
        seen["closed_during_delivery"] = threads.is_closed("a28-term")
        return ("live-delivery", None)

    with _relay(_deliver_and_observe):
        result = _send_terminal("a28-term")

    assert result.get("status") == "delivered", result
    assert seen.get("closed_during_delivery") is True, (
        "the terminal thread was not closed while its delivery was in flight"
    )
    assert threads.is_closed("a28-term") is True
