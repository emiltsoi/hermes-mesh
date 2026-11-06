"""Acceptance tests for the `thread` lease address (SPEC §4.1).

Six arms, each exercising the real handler with only the transport boundary
stubbed:

1. unknown key in ``args`` is refused with the near miss named (reproducer);
   the framework-injection guard proves the check never validates kwargs/merged;
2. ``thread`` releases the lease it names (reproducer);
3. ``ref`` still releases exactly as at base (guard — green before and after);
4. a real E-BUSY refusal carries a call shape that the tool accepts on replay
   (reproducer);
5. ``lease_released`` reports one of four exact facts on every release path
   (reproducer), including the silent writable-tempdir/missing-file case;
6. the initial ``lease_released`` binding is ``None`` (claimless), while a
   genuine registry read failure still reports ``registry-unavailable`` (G2
   pair);
7. the key is absent *entirely* on every non-``end`` reply, across all four
   registry states × reply yes/no × delivered/failed/queued (P5);
8. an undelivered terminator reports ``None`` — no outcome — at both failure
   arms, never ``{"released": False, ...}`` (P1/P3 on the never-attempted path).

The mutation runs are in the build report, not here. These tests are named so
each mechanism can be removed and the corresponding arm goes red.
"""
import ast
import inspect
import itertools
import json
import os
import pathlib
import sys
import textwrap
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from hermes_mesh import open_threads as ot
from hermes_mesh import threads
from hermes_mesh.session_relay import handle_mesh_send


@pytest.fixture(autouse=True)
def _isolated_mesh_state(tmp_path, monkeypatch):
    """Never touch a real fleet registry, closed-thread log, or outbox."""
    monkeypatch.setenv("MESH_OPEN_THREADS", str(tmp_path / "open-threads.json"))
    monkeypatch.setenv("MESH_CLOSED_THREADS", str(tmp_path / "closed-threads.json"))
    monkeypatch.setenv("MESH_AGENT_NAME", "zero")
    monkeypatch.setenv("MESH_OUTBOX_ENABLED", "0")
    monkeypatch.setenv("MESH_DSN_ENABLED", "0")
    monkeypatch.setenv("MESH_DSN_RATE_LIMIT", "1000")
    threads._LOCKED.clear()
    threads._LOADED = False
    threads._MTIME = None
    yield
    threads._LOCKED.clear()
    threads._LOADED = False
    threads._MTIME = None


def _open_threads_path() -> pathlib.Path:
    return pathlib.Path(os.environ["MESH_OPEN_THREADS"])


def _write_registry(entries) -> pathlib.Path:
    path = _open_threads_path()
    path.write_text(json.dumps(entries), encoding="utf-8")
    return path


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


def _send(**overrides):
    args = {
        "message": "hello",
        "agent": "linda",
        "action": "info",
        "reply": "no",
    }
    args.update(overrides)
    return handle_mesh_send(args)


def _open_lease(agent="linda"):
    result = _send(agent=agent, reply="yes", message="opening a lease")
    assert result.get("delivery") == "delivered", result
    rows = [
        r
        for r in ot.load()
        if r.get("opened_by") == "zero" and r.get("peer") == agent
    ]
    assert len(rows) == 1, rows
    return rows[0]["thread_id"]


def _assert_release(result, released, reason):
    """Assert the measured fact, including the §4.1 registry path."""
    payload = result["lease_released"]
    assert payload["released"] is released, payload
    assert payload["reason"] == reason, payload
    assert payload["registry"] == str(_open_threads_path().resolve()), payload
    return payload


def _parse_call(shape):
    """Parse the executable ``mesh_send(...)`` string a refusal carries."""
    tree = ast.parse(shape, mode="eval")
    call = tree.body
    assert isinstance(call, ast.Call)
    assert isinstance(call.func, ast.Name) and call.func.id == "mesh_send"
    return {kw.arg: ast.literal_eval(kw.value) for kw in call.keywords}


# ── Arm 1 ────────────────────────────────────────────────────────────────────


def test_arm1_unknown_arg_in_args_is_refused_with_near_miss():
    with _relay():
        result = handle_mesh_send(
            {
                "agent": "linda",
                "message": "hello",
                "action": "info",
                "reply": "no",
                "thred": "lease-id",
            }
        )

    assert "error" in result, result
    assert "'thred'" in result["error"], result
    assert "'thread'" in result["error"], result
    assert result["did_you_mean"] == "thread"


def test_arm1_framework_injected_kwargs_do_not_trip_the_guard():
    """THE TRAP: validate args only, never kwargs/merged.

    Positional ``args`` plus the context the framework injects on every call,
    including a future key this plugin does not know. The send must succeed.
    """
    with _relay():
        result = handle_mesh_send(
            {"message": "hello", "agent": "linda", "action": "info", "reply": "no"},
            task_id="framework-task-id",
            session_id="framework-session-id",
            user_task="the user's prompt",
            tool_call_id="call-1",
            harness_context="a future injected key",
        )

    assert result.get("delivery") == "delivered", result
    assert "error" not in result, result


# ── Arm 2 ────────────────────────────────────────────────────────────────────


def test_arm2_thread_releases_the_lease_it_names():
    with _relay():
        lease_id = _open_lease()
        result = _send(reply="end", thread=lease_id, message="closing it")

    assert result.get("delivery") == "delivered", result
    _assert_release(result, True, "released")
    assert all(r["thread_id"] != lease_id for r in ot.load()), ot.load()


def test_arm2_thread_wins_when_ref_is_also_present():
    """`thread` is the identity; `ref` must not be used as a fallback then."""
    with _relay():
        thread_lease = _open_lease("linda")
        ref_lease = _open_lease("britney")
        result = _send(
            agent="linda",
            reply="end",
            thread=thread_lease,
            ref=ref_lease,
            message="thread wins",
        )

    _assert_release(result, True, "released")
    ids = {r["thread_id"] for r in ot.load()}
    assert thread_lease not in ids
    assert ref_lease in ids, "ref was promoted to a fallback despite an explicit thread"


# ── Arm 3 (guard: green on base and after the change) ────────────────────────


def test_arm3_ref_release_is_unchanged():
    with _relay():
        lease_id = _open_lease()
        result = _send(reply="end", ref=lease_id, message="closing by ref")

    assert result.get("delivery") == "delivered", result
    assert all(r["thread_id"] != lease_id for r in ot.load()), ot.load()


def test_arm3_delivery_id_fallback_is_preserved():
    """The stubbed wire returns `delivery-1`; a lease keyed by it must release."""
    ot.open_thread("delivery-1", "zero", "linda", lease_minutes=30)

    with _relay():
        result = _send(reply="end", message="closing by delivery id")

    assert result.get("delivery") == "delivered", result
    assert all(r["thread_id"] != "delivery-1" for r in ot.load()), ot.load()


def test_arm3_task_id_fallback_is_preserved():
    ot.open_thread("term-task-id", "zero", "linda", lease_minutes=30)

    with _relay():
        result = _send(reply="end", task_id="term-task-id", message="closing by task")

    assert result.get("delivery") == "delivered", result
    assert all(r["thread_id"] != "term-task-id" for r in ot.load()), ot.load()


# ── Arm 4 ────────────────────────────────────────────────────────────────────


def test_arm4_recipient_busy_refusal_replays():
    """The fixture seed: a real recipient-busy E-BUSY, parsed and replayed."""
    ot.open_thread("lease-daji-kore", "daji", "kore", lease_minutes=30)

    with _relay():
        refused = _send(agent="kore", reply="yes", message="are you free?")

    assert refused.get("error") == "E-BUSY", refused
    assert refused.get("reason") == "recipient-busy", refused
    assert "thread=" in refused["executable"]
    parsed = _parse_call(refused["executable"])
    assert parsed["thread"] == "lease-daji-kore"
    assert parsed["agent"] == "kore"

    with _relay():
        replayed = handle_mesh_send(parsed)

    assert replayed.get("delivery") == "delivered", replayed
    assert "error" not in replayed, replayed


def test_arm4_cap_refusal_replays_and_closes_your_own_thread():
    with _relay():
        for peer in ("linda", "britney", "ada"):
            assert (
                _send(agent=peer, reply="yes", message="open").get("delivery")
                == "delivered"
            )
        refused = _send(agent="kore", reply="yes", message="fourth thread")

    assert refused.get("error") == "E-BUSY", refused
    assert refused.get("reason") == "too-many-open", refused
    parsed = _parse_call(refused["executable"])
    assert parsed["reply"] == "end"
    assert parsed["thread"] in refused["threads"]
    assert "thread=" in refused["executable"]

    with _relay():
        replayed = handle_mesh_send(parsed)

    assert replayed.get("delivery") == "delivered", replayed
    _assert_release(replayed, True, "released")
    assert all(r["thread_id"] != parsed["thread"] for r in ot.load()), ot.load()


# ── Arm 5 — four facts, driven separately ────────────────────────────────────


def test_arm5_released_true():
    """Fixture 1: caller is a party, lease exists."""
    with _relay():
        lease_id = _open_lease()
        result = _send(reply="end", thread=lease_id)

    _assert_release(result, True, "released")
    assert "lease_release_reason" not in result


def test_arm5_not_a_party():
    """Fixture 2: lease exists, caller is not a party. Never true."""
    ot.open_thread("lease-daji-linda", "daji", "linda", lease_minutes=30)

    with _relay():
        result = _send(
            agent="linda",
            reply="end",
            thread="lease-daji-linda",
            message="not mine to close",
        )

    assert result.get("delivery") == "delivered", result
    _assert_release(result, False, "not-a-party")
    assert any(
        r["thread_id"] == "lease-daji-linda" for r in ot.load()
    ), "a non-party closed the lease"


def test_arm5_no_such_lease():
    """Fixture 3: readable registry, no entry with that thread_id."""
    _write_registry([])

    with _relay():
        result = _send(reply="end", thread="lease-that-does-not-exist")

    _assert_release(result, False, "no-such-lease")


def test_arm5_missing_explicit_registry_is_unavailable():
    """Fixture 4: MESH_OPEN_THREADS names a missing file in a WRITABLE tempdir.

    This is the silent case: no read degradation, no counter movement, no file.
    It must not be reported as an empty fleet.
    """
    path = _open_threads_path()
    assert not path.exists()
    assert os.access(path.parent, os.W_OK)

    with _relay():
        result = _send(reply="end", thread="lease-that-does-not-exist")

    _assert_release(result, False, "registry-unavailable")
    assert not path.exists(), "the missing-path check must not create the registry"


def test_arm5_corrupt_registry_is_unavailable():
    """failed=True (exists but unreadable) is an unavailable registry, not empty."""
    _open_threads_path().write_text("{not json", encoding="utf-8")

    with _relay():
        result = _send(reply="end", thread="lease-any")

    _assert_release(result, False, "registry-unavailable")


def test_arm5_swallowed_exception_still_reports_unavailable():
    """Bookkeeping may not break delivery, but it must not report `released`."""
    _write_registry([])

    with _relay():
        with patch(
            "hermes_mesh.open_threads.release_if_party_status",
            side_effect=RuntimeError("registry exploded"),
        ):
            result = _send(reply="end", thread="lease-any")

    assert result.get("delivery") == "delivered", result
    _assert_release(result, False, "registry-unavailable")


def test_arm5_derived_absent_path_is_no_such_lease(tmp_path, monkeypatch):
    """SPEC §4.1: absent DERIVED path is a fresh fleet, not a config fault."""
    monkeypatch.delenv("MESH_OPEN_THREADS")
    monkeypatch.setenv("MESH_VAULT_PATH", str(tmp_path / "fleet"))

    result = ot.release_if_party_status("lease-any", "zero")

    assert result == {"released": False, "reason": "no-such-lease"}
    assert not (tmp_path / "fleet" / "mesh" / "open-threads.json").exists()


# ── Schema ───────────────────────────────────────────────────────────────────


def test_schema_declares_thread_as_its_own_parameter():
    from hermes_mesh import register

    tools = {}

    class _Ctx:
        def register_tool(self, *, name, schema, handler, toolset=None):
            tools[name] = schema

        def register_platform(self, **_kwargs):
            pass

    register(_Ctx())

    props = tools["mesh_send"]["parameters"]["properties"]
    assert "thread" in props
    assert "lease" in props["thread"]["description"].lower()
    assert "message" in props["ref"]["description"].lower()


# ── Arm 5d — registry path is a fact, not an optional decoration ─────────────


def test_arm5_registry_path_raise_keeps_the_key_and_says_null():
    """A raise in registry_path() must not erase the field it was filling.

    The release fact is measured before the path is labelled.  If labelling
    fails, the label is ``None`` (we tried and got nothing); the field itself
    remains present.  A response that drops the key says "this build does not
    have the field", which is a different and false claim.
    """
    with _relay():
        lease_id = _open_lease()
        with patch(
            "hermes_mesh.open_threads.registry_path",
            side_effect=RuntimeError("cannot resolve registry path"),
        ):
            result = _send(reply="end", thread=lease_id)

    assert result.get("delivery") == "delivered", result
    payload = result.get("lease_released")
    assert payload is not None, result
    assert "registry" in payload, (
        "registry key is ABSENT when registry_path() raises; "
        f"a consumer cannot tell 'unsupported' from 'unavailable': {payload!r}"
    )
    assert payload["registry"] is None, payload
    # The measured release fact is unaffected by the failed label lookup.
    assert payload["released"] is True, payload
    assert payload["reason"] == "released", payload


# ── G2 — a default may not carry a claim ─────────────────────────────────────


def _default_before_release_try(**overrides):
    """Observe ``lease_released`` immediately after its initial binding.

    The default is unreachable through today's responses (every early return
    writes its own value, and the delivered path overwrites it), which is
    precisely why a response-only assertion cannot see the trap.  Trace the
    binding while driving a real send, then read it at the first line of the
    release ``try`` — after the assignment, before anything is attempted.
    """
    function = ast.parse(
        textwrap.dedent(inspect.getsource(handle_mesh_send))
    ).body[0]
    default = next(
        node
        for node in function.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "lease_released"
            for target in node.targets
        )
    )
    release_try = next(
        node
        for node in function.body
        if isinstance(node, ast.Try) and node.lineno > default.lineno
    )
    first_line = handle_mesh_send.__code__.co_firstlineno
    read_line = first_line + release_try.lineno - 1
    observed = {}
    previous = sys.gettrace()

    def tracer(frame, event, _arg):
        if frame.f_code is not handle_mesh_send.__code__:
            return None
        if event == "line" and frame.f_lineno == read_line:
            observed["value"] = frame.f_locals["lease_released"]
            return None
        return tracer

    sys.settrace(tracer)
    try:
        with _relay():
            response = _send(**overrides)
    finally:
        sys.settrace(previous)

    assert observed, "the initial lease_released binding was never observed"
    return observed["value"], response


def test_no_claim_before_attempt_on_a_plain_reply():
    """A ``reply=yes`` delivery never reaches the release block.

    Nothing was requested from the registry, so the response may not report
    ``registry-unavailable``.  The initial binding must not carry that cause
    either, and it may not claim ``released: False`` — one early return inside
    the release ``try`` would ship a fabricated failure as measured fact.
    """
    default, result = _default_before_release_try(
        reply="yes", message="opening a lease"
    )

    assert result.get("delivery") == "delivered", result
    assert "lease_released" not in result, result
    assert "registry-unavailable" not in repr(result.get("lease_released")), result
    assert default is None, (
        "the pre-attempt lease_released default must be `None` — 'no outcome "
        "reported' — not an object that claims a release failed before one was "
        f"attempted: {default!r}"
    )


def test_genuine_unreadable_registry_still_reports_registry_unavailable():
    """Deleting the default must not delete the outcome.

    The registry exists and is corrupt — a real read failure, not an absent
    path and not a skipped release.  The response must still name it.
    """
    path = _open_threads_path()
    path.write_text("{not json", encoding="utf-8")
    assert path.exists()

    with _relay():
        result = _send(reply="end", thread="lease-that-does-not-exist")

    assert result.get("delivery") == "delivered", result
    payload = result["lease_released"]
    assert payload["released"] is False, payload
    assert payload["reason"] == "registry-unavailable", payload
    assert payload["registry"] == str(path.resolve()), payload


# ── Property — the field is structural, not conditional on the outcome ──────


@pytest.mark.parametrize(
    "outcome",
    [
        "delivered-success",
        "delivery-failure",
        "registry-unreadable",
        "not-a-party",
        "no-such-lease",
        "release-path-raises",
    ],
)
def test_property_every_end_response_carries_lease_released(outcome):
    """`"lease_released" in response` for every reply=end outcome.

    The field's presence is the interface; its value is the measurement.  A
    consumer must never have to infer "this build has no such field" from a
    key that only appears when the release happened to go well.
    """
    expected = None
    with _relay():
        if outcome == "delivered-success":
            lease_id = _open_lease()
            result = _send(reply="end", thread=lease_id)
            expected = (True, "released")
        elif outcome == "delivery-failure":
            with patch(
                "hermes_mesh.session_relay._deliver_webhook",
                return_value=(None, "wire down"),
            ):
                result = _send(reply="end", thread="lease-any")
        elif outcome == "registry-unreadable":
            # The autouse fixture points MESH_OPEN_THREADS at an absent file
            # inside a writable tempdir: explicit config, silent read.
            result = _send(reply="end", thread="lease-any")
            expected = (False, "registry-unavailable")
        elif outcome == "not-a-party":
            ot.open_thread("lease-daji-linda", "daji", "linda", lease_minutes=30)
            result = _send(
                agent="linda", reply="end", thread="lease-daji-linda"
            )
            expected = (False, "not-a-party")
        elif outcome == "no-such-lease":
            _write_registry([])
            result = _send(reply="end", thread="lease-that-does-not-exist")
            expected = (False, "no-such-lease")
        else:  # release-path-raises
            _write_registry([])
            with patch(
                "hermes_mesh.open_threads.release_if_party_status",
                side_effect=RuntimeError("release path exploded"),
            ):
                result = _send(reply="end", thread="lease-any")
            expected = (False, "registry-unavailable")

    assert "lease_released" in result, (
        f"{outcome}: reply=end response has no lease_released field: {result!r}"
    )
    if expected is not None:
        payload = result["lease_released"]
        assert payload["released"] is expected[0], (outcome, payload)
        assert payload["reason"] == expected[1], (outcome, payload)


# ── P2/P5 — the key exists iff the reply is a terminator ─────────────────────

# The four reason tokens, each named by the registry state that produces it.
# The state is arranged even for a non-end reply, which never reads a lease:
# that is exactly the claim — nothing was asked, so nothing may be reported.
_REASON_STATES = (
    "released",
    "no-such-lease",
    "not-a-party",
    "registry-unavailable",
)


def _arrange(reason):
    """Build the registry state ``reason`` names; return the send overrides.

    ``reply=yes`` claims the door, and the busy gate refuses a claim when the
    recipient is the peer of somebody else's live lease. Every case therefore
    carries a live ``zero -> linda`` thread so the claim merges into it —
    otherwise ``not-a-party`` would be refused before the wire and its absence
    assertion would hold for the wrong reason.
    """
    if reason == "released":
        return {"thread": _open_lease()}
    if reason == "no-such-lease":
        _write_registry([])
        return {"thread": "lease-that-does-not-exist"}
    if reason == "not-a-party":
        _open_lease()  # gate pass only; this thread is not the one addressed
        ot.open_thread("lease-daji-linda", "daji", "linda", lease_minutes=30)
        return {"agent": "linda", "thread": "lease-daji-linda"}
    # registry-unavailable: the autouse fixture names an ABSENT file inside a
    # writable tempdir — the silent read that must never read as an empty
    # fleet. No lease is opened here: opening one would create the very file
    # whose absence is the state under test.
    return {"thread": "lease-that-does-not-exist"}


@pytest.mark.parametrize("queued", [False, True])
def test_undelivered_terminal_reports_no_outcome(queued, tmp_path, monkeypatch):
    """P1/P3: a terminator that never left the box reports ``None``.

    The release block runs only after a real delivery, so on both failure arms
    nothing was asked of any lease and no cause was measured. ``None`` says
    exactly that. ``{"released": False, "reason": None}`` says the release
    FAILED — an outcome that never happened, sitting one early return away from
    being shipped as fact.
    """
    with _relay():
        if queued:
            monkeypatch.setenv("MESH_OUTBOX_ENABLED", "1")
            monkeypatch.setenv("MESH_OUTBOX_PATH", str(tmp_path / "outbox"))
        with patch(
            "hermes_mesh.session_relay._deliver_webhook",
            return_value=(None, "wire down"),
        ):
            result = _send(reply="end", thread="lease-any")

    assert "lease_released" in result, result
    assert result["lease_released"] is None, (
        "an undelivered terminator fabricated a release outcome: "
        f"{result['lease_released']!r}"
    )


@pytest.mark.parametrize("reason", _REASON_STATES)
def test_absence_matrix_states_still_report_their_reason_on_an_end(reason):
    """The matrix's states are real: each still yields its token on ``end``.

    Without this, four unrecognised environments would look like four covered
    reasons and the absence arm would be asserting over arrangements it never
    made.
    """
    with _relay():
        result = _send(reply="end", **_arrange(reason))

    payload = result.get("lease_released")
    assert isinstance(payload, dict), (reason, result)
    assert payload["released"] is (reason == "released"), (reason, payload)
    assert payload["reason"] == reason, (reason, payload)
    assert "registry" in payload, (reason, payload)


@pytest.mark.parametrize("reason", _REASON_STATES)
@pytest.mark.parametrize("reply", ["yes", "no"])
@pytest.mark.parametrize("transport", ["delivered", "failed", "queued"])
def test_property_non_end_reply_carries_no_lease_released(
    reason, reply, transport, tmp_path, monkeypatch
):
    """P2: on a non-``end`` reply the key is absent *entirely*.

    Nothing was asked of any lease, so there is neither a report to carry nor a
    ``None`` to stand for a missing one. This is the direction a happy-path
    read cannot see — the assignments are already gated, so the only way the
    key appears is a gate that stopped gating. Hence the mutant in the report.
    """
    with _relay():
        overrides = _arrange(reason)
        if transport == "queued":
            monkeypatch.setenv("MESH_OUTBOX_ENABLED", "1")
            monkeypatch.setenv("MESH_OUTBOX_PATH", str(tmp_path / "outbox"))
        if transport == "delivered":
            result = _send(reply=reply, **overrides)
        else:
            with patch(
                "hermes_mesh.session_relay._deliver_webhook",
                return_value=(None, "wire down"),
            ):
                result = _send(reply=reply, **overrides)

    label = f"reason={reason} reply={reply} transport={transport}"
    # The case must be a real send response — never a refusal or a validation
    # error, which carry no lease_released for reasons of their own.
    if transport == "delivered":
        assert result.get("delivery") == "delivered", (label, result)
    elif transport == "failed":
        assert "failed after" in str(result.get("error")), (label, result)
    else:
        assert result.get("status") == "queued for outbox retry", (label, result)
    assert "lease_released" not in result, (
        f"{label}: lease_released present on a non-end reply: {result!r}"
    )
