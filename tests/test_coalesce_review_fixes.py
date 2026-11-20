"""Fifth-review fixes: injective stems, torn appends, missing timestamps, shutdown losses.

Each test names the defect it pins. The adapter-level ones build the real MeshAdapter on the
gateway stubs: the bug lives in shipped ordering, so the test must exercise shipped code.
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
    spec = importlib.util.spec_from_file_location("mesh_coalesce_fix4_under_test", path)
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


class _FakeRequest:
    """Just enough of aiohttp's Request for _handle_mesh."""

    def __init__(self, body: bytes):
        self._body = body
        self.headers = {"X-Mesh-Timestamp": str(time.time())}

    async def read(self) -> bytes:
        return self._body


def test_stem_is_injective_and_peers_round_trip(coal):
    """F1: 'a b' used to mangle to 'a_b.<sha1-of-'a b'>', which a peer literally named
    'a_b.<that hash>' then shared a queue and archive with — two senders, one file. The
    stem must collide with NO legal name, and peers() must decode both exactly."""
    m, c = coal
    collision = f"a_b.{hashlib.sha1('a b'.encode('utf-8')).hexdigest()[:8]}"
    c.add("a b", {"id": "s1", "body": "spaces"})
    c.add(collision, {"id": "s2", "body": "legal name"})
    assert c._path("a b") != c._path(collision)
    assert c._archive_path("a b") != c._archive_path(collision)
    assert [i["body"] for i in c.pending("a b")] == ["spaces"]
    assert [i["body"] for i in c.pending(collision)] == ["legal name"]
    assert set(c.peers()) == {"a b", collision}              # decoded, not the stored stems


def test_digest_survives_a_row_without_received_at(coal):
    """F4: a valid JSON object lacking received_at raised KeyError inside build_digest —
    one '{}' row killed the peer's whole digest, and its other pending mail with it."""
    m, c = coal
    c.add("isa", {"id": "g1", "action": "info", "reply": "no", "body": "real"})
    with open(c._path("isa"), "a", encoding="utf-8") as fh:
        fh.write("{}\n")
    body, taken = c.build_digest("isa")
    assert body is not None and len(taken) == 2
    assert "--- [2]" in body                                 # the {} row is in the digest too


def test_add_repairs_a_torn_final_line(coal):
    """F5: a crash mid-append leaves a line without its newline; the next append used to
    concatenate onto it and pending() skipped BOTH forever. The fragment is already
    unrecoverable — truncate it so the new message is not lost with it."""
    m, c = coal
    c.add("yoyo", {"id": "g1", "action": "info", "reply": "no", "body": "one"})
    with open(c._path("yoyo"), "a", encoding="utf-8") as fh:
        fh.write('{"id": "tor')                              # torn fragment, no trailing newline
    c.add("yoyo", {"id": "g2", "action": "info", "reply": "no", "body": "two"})
    assert [i["id"] for i in c.pending("yoyo")] == ["g1", "g2"]
    raw = open(c._path("yoyo"), encoding="utf-8").read()
    assert '{"id": "tor' not in raw                          # dropped, not merged into g2's line


def test_handler_refuses_work_while_closing(tmp_path):
    """F6: aiohttp still serves after disconnect() posts the inbox sentinel, so an envelope
    accepted during shutdown lives only in memory and dies with the process. While closing
    the handler must refuse — a 503 the sender's retry can redeliver from, nothing stored,
    nothing enqueued."""
    adapter = _make_adapter(tmp_path)
    adapter._closing = True
    body = json.dumps({
        "text": "[mesh][from:peer_a][to:testagent][id:m1][action:info][reply:no]\nhello",
        "from": "peer_a",
    }).encode()
    resp = asyncio.run(adapter._handle_mesh(_FakeRequest(body)))
    assert resp.status == 503
    assert adapter._mesh_inbox.qsize() == 0                  # not queued behind the sentinel
    assert adapter._coalesce.pending("peer_a") == []         # and not stored either


def test_disconnect_recovers_a_stranded_digest(tmp_path):
    """F7: a digest cancelled behind a long turn is dropped after take() already deleted its
    pending rows — and archives are never rescanned. disconnect() must drain the inbox and
    put a stranded batch back on disk for the next boot."""
    adapter = _make_adapter(tmp_path)
    adapter._coalesce.add("peer_a", {"id": "i1", "action": "info", "reply": "no", "body": "one"})
    adapter._coalesce.add("peer_a", {"id": "i2", "action": "info", "reply": "no", "body": "two"})
    adapter._flush_coalesced("peer_a")
    assert adapter._mesh_inbox.qsize() == 1                  # minted, never consumed
    assert adapter._coalesce.pending("peer_a") == []         # take() already ran
    asyncio.run(adapter.disconnect())
    assert [i["id"] for i in adapter._coalesce.pending("peer_a")] == ["i1", "i2"]
    assert "peer_a" in adapter._coalesce.peers()             # the next boot's flush finds it
