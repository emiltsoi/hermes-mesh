"""Tests for mesh terminal reply (reply=end) — FR-1 through FR-6.

Maps to the sealed spec (mesh-terminal-reply-2026-08-05):
- FR-1 reply enum gains "end" (AC-1.1, AC-1.2)
- FR-2 terminal thread semantics (AC-2.1 sender records, AC-2.2 recipient
  records, AC-2.3 delivers normally)
- FR-3 outbound guard -> THREAD_CLOSED before delivery (AC-3.1, AC-3.2)
- FR-4 inbound guard -> THREAD_CLOSED to sender (AC-4.1)
- FR-5 anchor registry persisted / restart-survival / escape hatch (AC-5.1, AC-5.2)
- FR-6 back-compat / receive tolerance (AC-6.1)
"""
import asyncio
import json
import os
import re
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hermes_mesh import auth as mesh_auth
from hermes_mesh import threads
from hermes_mesh.adapter import MeshAdapter
from hermes_mesh.session_relay import handle_mesh_send
from gateway.config import PlatformConfig


@pytest.fixture(autouse=True)
def _isolate_registry(tmp_path, monkeypatch):
    """Isolate the registry to a per-test temp file.

    MESH_VAULT_PATH is set in the shell, so `_fleet_root()` ignores the
    conftest HERMES_HOME swap; pin MESH_CLOSED_THREADS to a fresh path instead
    and clear the module-level locked set so no state leaks between tests.
    """
    monkeypatch.setenv(
        "MESH_CLOSED_THREADS",
        str(tmp_path / "mesh" / "closed-threads.json"),
    )
    threads._LOCKED.clear()
    threads._LOADED = False
    yield
    threads._LOCKED.clear()
    threads._LOADED = False


def _identity(name, url="http://127.0.0.1:8645/mesh/receive", public_key="test-public-key-pem"):
    return {
        "id": name,
        "name": name,
        "transports": {
            "hermes_webhook": {
                "url": url,
                "auth": {"public_key": public_key},
            },
        },
    }


@contextmanager
def _send_context(tmp_path, deliver_result=("delivery-123", None), deliver_side_effect=None):
    """Patch the mesh_send delivery path, exposing the deliver/float mocks.

    ``deliver_result`` is the fixed return value; ``deliver_side_effect``, when
    given, overrides it (used by the AC-6.3 degrade tests).
    """
    sender_private, _ = mesh_auth.load_or_generate_keypair(
        "sender",
        extra={"private_key_path": str(tmp_path / "sender.pem")},
    )

    def _raw(name):
        if name == "target":
            return _identity("target")
        return None

    deliver_kwargs = (
        {"side_effect": deliver_side_effect}
        if deliver_side_effect is not None
        else {"return_value": deliver_result}
    )

    with (
        patch.dict(os.environ, {"MESH_AGENT_NAME": "sender"}),
        patch("hermes_mesh.identity.get_raw_agent_identity", side_effect=_raw),
        patch("hermes_mesh.auth.resolve_sender", return_value=(sender_private, None)),
        patch(
            "hermes_mesh.session_relay._deliver_webhook", **deliver_kwargs
        ) as mock_deliver,
        patch("hermes_mesh.session_relay._float.send") as mock_float,
    ):
        yield mock_deliver, mock_float


def _make_adapter(secret="INSECURE_NO_AUTH", agent_name="ada", target_session="telegram:dm:123"):
    return MeshAdapter(
        PlatformConfig(
            extra={
                "secret": secret,
                "agent_name": agent_name,
                "target_session": target_session,
            }
        )
    )


def _make_request(body, headers=None):
    request = MagicMock()
    request.read = AsyncMock(return_value=json.dumps(body, sort_keys=True).encode())
    request.headers = headers or {"X-Mesh-Timestamp": str(time.time())}
    return request


def _envelope(sender="ada", recipient="ADA", msg_id="testid-123", action="do",
              reply="yes", ref=None, body="hello"):
    header = (
        f"[mesh][from:{sender}][to:{recipient}][id:{msg_id}]"
        f"[action:{action}][reply:{reply}]"
    )
    if ref:
        header += f"[ref:{ref}]"
    return f"{header} {body}"


def _run(coro):
    return asyncio.run(coro)


def _spawn_recorders(anchors, start_file):
    """Spawn one subprocess per anchor; each records on the start-file signal.

    Proves cross-process serialization: the children share the registry file
    via fcntl.flock on the sidecar lock file (a threading.Lock is per-process
    and cannot guard across processes).
    """
    repo_root = os.path.dirname(os.path.dirname(threads.__file__))
    code = (
        "import os, sys, time\n"
        "from hermes_mesh import threads\n"
        "start = sys.argv[1]\n"
        "for _ in range(10000):\n"
        "    if os.path.exists(start):\n"
        "        break\n"
        "    time.sleep(0.001)\n"
        "threads.record(sys.argv[2], closed_by='child')\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    procs = []
    for anchor in anchors:
        procs.append(
            subprocess.Popen(
                [sys.executable, "-c", code, str(start_file), anchor],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        )
    return procs


class TestFR1_ReplyEnum:
    """FR-1: envelope enum extension."""

    def test_reply_end_validates_and_delivers_like_no(self, tmp_path):
        """AC-1.1: reply=end delivers, reply_expected=false."""
        with _send_context(tmp_path) as (mock_deliver, mock_float):
            result = handle_mesh_send({
                "message": "goodbye friend",
                "agent": "target",
                "action": "info",
                "reply": "end",
            })
        assert result.get("status") == "delivered"
        assert result.get("reply_expected") is False
        body = mock_deliver.call_args[0][1]
        assert "[reply:end]" in body
        assert "goodbye friend" in body
        mock_float.assert_called_once()

    def test_reply_end_uses_custom_task_id(self, tmp_path):
        with _send_context(tmp_path) as (mock_deliver, _):
            result = handle_mesh_send({
                "message": "goodbye",
                "agent": "target",
                "action": "info",
                "reply": "end",
                "task_id": "bye-123",
            })
        assert result.get("task_id") == "bye-123"
        body = mock_deliver.call_args[0][1]
        assert "[id:bye-123]" in body
        assert "[reply:end]" in body

    def test_invalid_reply_rejected_with_exact_error(self):
        """AC-1.2: invalid reply -> existing error-dict shape."""
        result = handle_mesh_send({
            "message": "hi",
            "agent": "target",
            "action": "info",
            "reply": "maybe",
        })
        assert result == {
            "error": "Invalid reply 'maybe'; must be 'yes', 'no', or 'end'",
        }

    def test_schema_enum_includes_end_and_documents_terminal(self):
        """FR-1 AC-1.1: the mesh_send tool schema accepts reply=end and documents it."""
        import hermes_mesh

        captured = {}

        class _Ctx:
            def register_tool(self, name, toolset, schema, handler):
                captured[schema["name"]] = schema

            def register_platform(self, **kwargs):
                pass

        hermes_mesh.register(_Ctx())
        reply = captured["mesh_send"]["parameters"]["properties"]["reply"]
        assert reply["enum"] == ["yes", "no", "end"]
        assert "terminal" in reply["description"]
        assert "THREAD_CLOSED" in reply["description"]


class TestFR2_TerminalSemantics:
    """FR-2: terminal thread semantics."""

    def test_sender_records_anchor_at_send_time(self, tmp_path):
        """AC-2.1: sender gateway records the terminal anchor (persisted)."""
        with _send_context(tmp_path):
            result = handle_mesh_send({
                "message": "goodbye",
                "agent": "target",
                "action": "info",
                "reply": "end",
            })
        assert threads.is_closed(result["task_id"]) is True

    def test_recipient_records_anchor_on_receive(self):
        """AC-2.2: recipient gateway records the anchor when reply=end parsed."""
        adapter = _make_adapter()
        text = _envelope(reply="end", msg_id="term-abc", body="goodbye from ada")
        req = _make_request({"from": "ada", "text": text})
        resp = _run(adapter._handle_mesh(req))
        assert resp.status == 202
        assert threads.is_closed("term-abc") is True

    def test_terminal_message_delivers_full_content(self):
        """AC-2.3: terminal message delivers normally, full goodbye content."""
        adapter = _make_adapter()
        text = _envelope(reply="end", msg_id="term-full", body="full goodbye content")
        req = _make_request({"from": "ada", "text": text})
        resp = _run(adapter._handle_mesh(req))
        assert resp.status == 202
        assert not adapter._mesh_inbox.empty()
        event = adapter._mesh_inbox.get_nowait()
        assert "full goodbye content" in event.text
        assert event.metadata["mesh"]["reply"] == "end"


class TestFR3_OutboundGuard:
    """FR-3: replying gateway rejects ref == closed anchor BEFORE delivery."""

    def test_reply_to_closed_thread_rejected_exact_shape(self, tmp_path):
        """AC-3.1: exact error-dict shape; AC-3.2: no webhook sent."""
        threads.record("term-1", closed_by="ada")
        with _send_context(tmp_path) as (mock_deliver, mock_float):
            result = handle_mesh_send({
                "message": "hello",
                "agent": "target",
                "action": "info",
                "reply": "no",
                "ref": "term-1",
            })
        assert result == {
            "error": "THREAD_CLOSED: thread closed by terminal message term-1",
            "hint": "open a new message (no ref) to reach target",
        }
        mock_deliver.assert_not_called()
        mock_float.assert_not_called()


class TestFR4_InboundGuard:
    """FR-4: sender-of-end gateway rejects inbound ref == closed anchor."""

    def test_inbound_ref_to_closed_anchor_rejected(self):
        """AC-4.1: exact error-dict shape (mirrors the sender-side test); no delivery."""
        threads.record("term-1", closed_by="ada")
        adapter = _make_adapter()
        text = _envelope(reply="no", ref="term-1", msg_id="m1", body="late reply")
        req = _make_request({"from": "ada", "text": text})
        resp = _run(adapter._handle_mesh(req))
        assert resp.status == 400
        payload = json.loads(resp.body)
        assert payload == {
            "error": "THREAD_CLOSED: thread closed by terminal message term-1",
            "hint": "open a new message (no ref) to reach ada",
        }
        assert adapter._mesh_inbox.empty()


class TestFR5_Registry:
    """FR-5: anchor registry persisted, atomic, restart-survival, escape hatch."""

    def test_registry_atomic_write_and_content(self):
        threads.record("anchor-1", closed_by="ada")
        path = threads._registry_path()
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert len(data) == 1
        assert data[0]["anchor_task_id"] == "anchor-1"
        assert data[0]["closed_by"] == "ada"
        assert "closed_at" in data[0]
        # atomic write leaves no temp files behind
        assert [p.name for p in path.parent.iterdir() if p.name.endswith(".tmp")] == []

    def test_registry_survives_restart(self):
        """AC-5.1: closed state persists across a simulated gateway restart."""
        threads.record("anchor-restart", closed_by="ada")
        # Simulate a fresh process: drop in-memory state, reload from disk.
        threads._LOCKED.clear()
        threads._LOADED = False
        assert threads.is_closed("anchor-restart") is True
        entries = threads.load()
        assert any(e["anchor_task_id"] == "anchor-restart" for e in entries)

    def test_registry_path_env_override(self, tmp_path, monkeypatch):
        """MESH_CLOSED_THREADS overrides the default registry path."""
        custom = tmp_path / "custom" / "closed-threads.json"
        monkeypatch.setenv("MESH_CLOSED_THREADS", str(custom))
        threads.record("anchor-env", closed_by="ada")
        assert custom.exists()

    def test_record_is_idempotent(self):
        threads.record("anchor-dup", closed_by="ada")
        threads.record("anchor-dup", closed_by="bob")
        data = json.loads(threads._registry_path().read_text(encoding="utf-8"))
        assert len([e for e in data if e["anchor_task_id"] == "anchor-dup"]) == 1

    def test_is_closed_never_checks_without_ref(self):
        """AC-5.2: no ref is never checked — the escape hatch is structural."""
        assert threads.is_closed(None) is False


class TestFR6_BackCompatAndEscapeHatch:
    """FR-6 back-compat and the structural escape hatch."""

    def test_adapter_accepts_reply_end(self):
        adapter = _make_adapter()
        text = _envelope(reply="end", msg_id="term-new")
        req = _make_request({"from": "ada", "text": text})
        resp = _run(adapter._handle_mesh(req))
        assert resp.status == 202

    def test_adapter_unknown_reply_still_rejected_with_warning(self, caplog):
        """AC-6.1: unknown reply values unchanged — warning preserved, no crash."""
        adapter = _make_adapter()
        text = _envelope(reply="maybe")
        req = _make_request({"from": "ada", "text": text})
        with caplog.at_level("WARNING", logger="hermes_mesh.adapter"):
            resp = _run(adapter._handle_mesh(req))
        assert resp.status == 400
        assert "Invalid envelope reply" in caplog.text

    def test_escape_hatch_new_message_without_ref_delivers(self, tmp_path):
        """AC-5.2: a new message (no ref) after end is delivered normally."""
        threads.record("term-1", closed_by="ada")
        with _send_context(tmp_path) as (mock_deliver, _):
            result = handle_mesh_send({
                "message": "important news",
                "agent": "target",
                "action": "info",
                "reply": "no",
            })
        assert result.get("status") == "delivered"
        mock_deliver.assert_called_once()
        body = mock_deliver.call_args[0][1]
        assert "important news" in body
        assert "[ref:" not in body

    def test_escape_hatch_inbound_without_ref_after_end_delivers(self):
        threads.record("term-1", closed_by="ada")
        adapter = _make_adapter()
        text = _envelope(reply="no", msg_id="m2", body="news without ref")
        req = _make_request({"from": "ada", "text": text})
        resp = _run(adapter._handle_mesh(req))
        assert resp.status == 202
        assert not adapter._mesh_inbox.empty()

class TestCrossProcessAndDegrade:
    """Review fixes (F1-F5, F7, F9) and their tests (F10)."""

    def test_simultaneous_record_keeps_every_anchor(self, tmp_path):
        """F1/F10(a): concurrent record() from separate processes loses no anchor.

        The guard is fcntl.flock on the sidecar lock file, serializing the
        read-merge-write across real processes (a threading.Lock is per-process
        and cannot prove this). Four subprocesses race; all four anchors must
        survive and each must appear exactly once.
        """
        start_file = tmp_path / "go"
        anchors = ["race-a", "race-b", "race-c", "race-d"]
        procs = _spawn_recorders(anchors, start_file)
        start_file.write_text("go")
        for proc, anchor in zip(procs, anchors):
            out, err = proc.communicate(timeout=60)
            assert proc.returncode == 0, f"{anchor} failed: {err.decode()}"
        data = json.loads(threads._registry_path().read_text(encoding="utf-8"))
        recorded = [entry["anchor_task_id"] for entry in data]
        for anchor in anchors:
            assert recorded.count(anchor) == 1, f"anchor {anchor} lost/dup: {recorded}"
        assert threads.is_closed("race-a") is True

    def test_self_close_guard_fires_before_record(self, tmp_path):
        """F10(c): reply=end with ref==closed-anchor is rejected and NOT re-recorded."""
        threads.record("term-1", closed_by="ada")
        path = threads._registry_path()
        before = path.read_text(encoding="utf-8")
        with _send_context(tmp_path) as (mock_deliver, mock_float):
            result = handle_mesh_send({
                "message": "goodbye",
                "agent": "target",
                "action": "info",
                "reply": "end",
                "ref": "term-1",
            })
        assert result == {
            "error": "THREAD_CLOSED: thread closed by terminal message term-1",
            "hint": "open a new message (no ref) to reach target",
        }
        mock_deliver.assert_not_called()
        mock_float.assert_not_called()
        after = path.read_text(encoding="utf-8")
        assert before == after
        assert len(json.loads(after)) == 1

    def test_is_closed_rehydrates_from_external_writer(self):
        """F2/F10(e): anchors written by another process are visible without restart."""
        threads.record("local-1", closed_by="ada")
        assert threads._LOADED is True
        # Simulate another gateway process writing directly to the shared registry.
        path = threads._registry_path()
        data = json.loads(path.read_text(encoding="utf-8"))
        data.append({"anchor_task_id": "ext-1", "closed_at": time.time(), "closed_by": "bob"})
        path.write_text(json.dumps(data), encoding="utf-8")
        assert threads.is_closed("ext-1") is True
        assert threads.is_closed("local-1") is True
