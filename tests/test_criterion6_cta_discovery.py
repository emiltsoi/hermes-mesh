"""Criterion 6: discovery without failure.

A wife who has never read the schema closes a thread correctly, prompted by
what the interface shows her, with **no refusal in the loop**.

The CTA is taken from the real adapter path (``_handle_mesh`` ->
``_build_event`` -> ``_format_display_text``), never hand-written.  The caller
is simulated by reading only the rendered CTA: the bracket names the peer and
the action, and ``· thread=<id>`` names the lease argument.  The closing verb
(``reply=end``) is the caller's intent, not a schema lookup — the fleet already
teaches the verb; the parameter this test is about is the address.

If the CTA stops rendering ``thread=<id>``, ``_cta_arguments`` fails before any
``mesh_send`` call, which is what the mutation check exercises.
"""
from __future__ import annotations

import asyncio
import itertools
import json
import os
import pathlib
import re
import time
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gateway.config import PlatformConfig
from hermes_mesh import open_threads as ot
from hermes_mesh import threads
from hermes_mesh.adapter import MeshAdapter
from hermes_mesh.session_relay import handle_mesh_send


@pytest.fixture(autouse=True)
def _isolated_mesh_state(tmp_path, monkeypatch):
    """Never touch a real fleet registry, closed-thread log, or outbox."""
    monkeypatch.setenv("MESH_OPEN_THREADS", str(tmp_path / "open-threads.json"))
    monkeypatch.setenv("MESH_CLOSED_THREADS", str(tmp_path / "closed-threads.json"))
    monkeypatch.setenv("MESH_AGENT_NAME", "zero")
    monkeypatch.setenv("MESH_OUTBOX_ENABLED", "0")
    monkeypatch.setenv("MESH_DSN_ENABLED", "0")
    monkeypatch.setenv("MESH_WEBHOOK_ALLOW_LOOPBACK", "1")
    threads._LOCKED.clear()
    threads._LOADED = False
    threads._MTIME = None
    yield
    threads._LOCKED.clear()
    threads._LOADED = False
    threads._MTIME = None


@contextmanager
def _relay():
    """Run the real relay; stub only target/sender resolution and the wire."""
    ids = itertools.count(1)

    def deliver(*_args, **_kwargs):
        return f"delivery-{next(ids)}", None

    with (
        patch(
            "hermes_mesh.auth.resolve_target",
            return_value=("http://target.invalid/mesh", None),
        ),
        patch(
            "hermes_mesh.auth.resolve_sender",
            return_value=("signing-material", None),
        ),
        patch("hermes_mesh.session_relay._deliver_webhook", side_effect=deliver),
        patch("hermes_mesh.session_relay._float.send"),
    ):
        yield


def _adapter() -> MeshAdapter:
    return MeshAdapter(
        PlatformConfig(
            extra={
                "secret": "INSECURE_NO_AUTH",
                "agent_name": "linda",
                "target_session": "telegram:dm:123",
            }
        )
    )


def _request(envelope: str):
    request = MagicMock()
    request.read = AsyncMock(
        return_value=json.dumps(
            {"from": "zero", "text": envelope}, sort_keys=True
        ).encode()
    )
    request.headers = {"X-Mesh-Timestamp": str(time.time())}
    return request


def _envelope(lease_id: str) -> str:
    return (
        f"[mesh][from:zero][to:LINDA][id:{lease_id}]"
        f"[action:info][reply:yes] hello"
    )


_BRACKET = re.compile(
    r"\[Reply via mesh to (?P<agent>[^ ]+) — "
    r"action: (?P<action>[^,]+), reply: (?P<reply>[^\]]+)\]"
)
_PARAM = re.compile(r"· thread=(?P<thread>[^\s\]]+)")
_LABEL = re.compile(r"· thread (?P<thread>[^\s\]]+)")


def _cta_arguments(text: str) -> dict:
    """Read the CTA the way a reader would by eye — no schema knowledge.

    The bracket supplies the peer and action.  The lease argument is the token
    after ``· thread=``; the old label form is rejected explicitly so a revert
    cannot quietly parse.
    """
    bracket = _BRACKET.search(text)
    assert bracket is not None, f"no reply CTA in rendered header: {text!r}"

    param = _PARAM.search(text)
    assert param is not None, (
        "CTA does not teach the argument form '· thread=<id>': "
        f"{text!r}"
    )
    assert _LABEL.search(text) is None, (
        "CTA still teaches the label form '· thread <id>': "
        f"{text!r}"
    )

    arguments = bracket.groupdict()
    arguments["thread"] = param.group("thread")
    return arguments


def _refusal_kind(result: dict) -> str | None:
    """Classify a tool result that refused, without assuming one error shape."""
    if not isinstance(result, dict):
        return "non-dict result"
    blob = json.dumps(result, sort_keys=True, default=str)
    for marker in ("E-BUSY", "THREAD_CLOSED", "unknown argument"):
        if marker in blob:
            return marker
    if result.get("error"):
        return "other-error"
    return None


def test_criterion6_closes_from_the_cta_with_zero_refusals(monkeypatch):
    # This test supplies half its input, and names which half.
    #
    # 1. Derived from the CTA: the address — the `· thread=<id>` argument and
    #    the thread id itself.  This is the half criterion 6 measures.
    #
    # 2. Supplied by the caller, NOT derived from the CTA: the closing verb
    #    `reply=end`.  The CTA renders `reply: yes` on every inbound and never
    #    mentions `end`.
    #
    # 3. That is correct rather than a gap: "`thread=` is required to address a
    #    lease; `end` is a judgment.  Advertising the terminal verb on every
    #    message would train reflexive closes, and a thread closed by reflex
    #    loses the work inside it.  The verb belongs to the discipline; the
    #    parameter belongs to the interface."
    #
    # 4. The verb is separately proven: a schema-unread reader produced
    #    `reply=end` correctly and failed only on the address, which is why the
    #    asymmetry is empirical rather than argued.
    refusals: list[dict] = []

    def call(arguments: dict) -> dict:
        result = handle_mesh_send(arguments)
        kind = _refusal_kind(result)
        if kind is not None:
            refusals.append({"kind": kind, "result": result})
        return result

    # 1 · open a real lease through the real send path.  zero -> linda.
    with _relay():
        opened = call(
            {
                "agent": "linda",
                "message": "opening a lease",
                "action": "info",
                "reply": "yes",
            }
        )
    assert opened.get("delivery") == "delivered", opened
    lease_id = opened["task_id"]
    assert ot.get(lease_id) is not None, "fixture did not create a live lease"

    # 2 · the delivered message linda actually sees, rendered by the adapter.
    adapter = _adapter()
    response = asyncio.run(adapter._handle_mesh(_request(_envelope(lease_id))))
    assert response.status == 202, response.status
    event = adapter._mesh_inbox.get_nowait()
    assert event is not None
    cta_text = event.text

    # 3 · read the CTA, not the schema.
    derived = _cta_arguments(cta_text)
    assert derived["agent"] == "zero", derived
    assert derived["action"] == "info", derived
    assert derived["thread"] == lease_id, derived

    # The CTA states the sender's requested reply ("yes") — asserted so the
    # split is visible.  The caller's intent is to close; `end` is the closing
    # verb the fleet already teaches.  The address — the thing this test is
    # about — comes only from the CTA.
    assert derived["reply"] == "yes", derived
    closing = {
        "agent": derived["agent"],
        "message": "closing this thread",
        "action": derived["action"],
        "reply": "end",
        "thread": derived["thread"],
    }

    # 4 · linda calls the tool with what the CTA taught her.
    monkeypatch.setenv("MESH_AGENT_NAME", "linda")
    with _relay():
        closed = call(closing)

    # 5 · the property: release present, refusal count zero.
    assert refusals == [], f"refusal(s) in the loop: {refusals!r}"
    assert closed.get("delivery") == "delivered", closed
    payload = closed["lease_released"]
    assert payload["released"] is True, payload
    assert payload["reason"] == "released", payload
    assert payload["registry"] == str(
        pathlib.Path(os.environ["MESH_OPEN_THREADS"]).resolve()
    ), payload
    assert ot.get(lease_id) is None, "the lease is still live after the release"
    assert closed.get("error") is None, closed


def test_schema_description_quotes_the_parameter_form():
    """The schema and the envelope must use one word, not two syntaxes."""
    from hermes_mesh import register

    tools = {}

    class _Ctx:
        def register_tool(self, *, name, schema, handler, toolset=None):
            tools[name] = schema

        def register_platform(self, **_kwargs):
            pass

    register(_Ctx())
    description = tools["mesh_send"]["parameters"]["properties"]["thread"][
        "description"
    ]
    assert "· thread=<id>" in description, description
    assert "· thread <id>" not in description, description
