"""Failing-first tests for mesh delivery budget + token scorer (A19-A24).

Wave ``2026-11-01-mesh-delivery-budget`` · WO-20261101-1.

Every test below drives a **real** local HTTP server through the real
``_pinned_request`` path. Mocking ``_pinned_request`` would bypass
``resp.read()`` -> ``raise``, which is exactly the line that discards the proof
of arrival, so a mocked test would pass without testing the defect.

The semantic core (Kore's caution, and the whole incident):

    A timeout means we do not know. A 409-duplicate means it landed.

They have opposite remedies. ``A20`` and ``A21`` are a pair on purpose: A20
alone teaches a sender to accept every refusal, A21 alone teaches it to reject
every one. A sender passing both has learned to read the token, not the code.
``A23``/``A24`` add the field-ordering trap: our own door's *refusal* carries a
``delivery_id`` and its *receipt* does not, so keying on the id gets both
answers wrong at once.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hermes_mesh import auth as mesh_auth
from hermes_mesh import session_relay
from hermes_mesh.session_relay import _deliver_webhook

ENVELOPE = "[mesh][from:sender][to:target][id:m1][action:info][reply:no] hello"


class _Peer:
    """A local peer whose answer is scripted: (status, payload, sleep_s)."""

    def __init__(self) -> None:
        self.status = 200
        self.payload: dict = {"delivery_id": "x"}
        self.sleep_s = 0.0
        self.requests = 0
        self._lock = threading.Lock()
        peer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802 - http.server API
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                with peer._lock:
                    peer.requests += 1
                if peer.sleep_s:
                    import time as _t

                    _t.sleep(peer.sleep_s)
                body = json.dumps(peer.payload).encode()
                self.send_response(peer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/mesh/receive"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture()
def peer():
    p = _Peer()
    try:
        yield p
    finally:
        p.close()


@pytest.fixture()
def sender_key(tmp_path):
    private_pem, _public_pem = mesh_auth.load_or_generate_keypair(
        "sender", extra={"private_key_path": str(tmp_path / "sender.pem")}
    )
    return private_pem


@pytest.fixture(autouse=True)
def _fast_retry(monkeypatch):
    """Keep retry pacing out of the assertions; the budget, not the backoff, is under test."""
    monkeypatch.setenv("MESH_WEBHOOK_ALLOW_LOOPBACK", "1")
    monkeypatch.setattr(session_relay, "_DELIVERY_BACKOFF", 0.01)


def _send(peer, sender_key):
    return _deliver_webhook(peer.url, ENVELOPE, sender_key, allow_loopback=True, sender="sender")


def test_a19_slow_peer_inside_total_budget_is_delivered(peer, sender_key):
    """A peer slower than total/retries but faster than total must succeed.

    Pre-fix attempt 0 receives 10/3 ~= 3.33 s, so a 4.0 s peer is unreachable by
    construction and every later attempt fails *because the message arrived*.
    """
    peer.status = 200
    peer.payload = {"delivery_id": "x"}
    peer.sleep_s = 4.0

    delivery_id, error = _send(peer, sender_key)

    assert error is None, f"a 4.0s peer must be deliverable inside a 10s budget, got {error!r}"
    assert delivery_id == "x"


def test_a20_duplicate_refusal_is_a_delivery(peer, sender_key):
    """409 duplicate is the strongest proof of arrival, and must not be retried."""
    peer.status = 409
    peer.payload = {"status": "duplicate", "delivery_id": "abc"}

    delivery_id, error = _send(peer, sender_key)

    assert error is None, f"409 duplicate must be DELIVERED, got {error!r}"
    assert delivery_id in ("abc", None, "unknown")
    assert peer.requests == 1, f"a duplicate must not be retried, saw {peer.requests} requests"


def test_a21_busy_refusal_is_not_a_delivery(peer, sender_key):
    """503 busy is a refusal, never arrival. The inverse of A20, deliberately."""
    peer.status = 503
    peer.payload = {"status": "busy"}

    delivery_id, error = _send(peer, sender_key)

    assert error is not None, "503 busy must never be reported as delivered"
    assert error == "busy", f"expected 'busy', got {error!r}"
    assert delivery_id is None


def test_a22_unknown_token_is_not_arrival(peer, sender_key):
    """A token from neither list, on a code that elsewhere means duplicate."""
    peer.status = 409
    peer.payload = {"status": "thread-busy"}

    delivery_id, error = _send(peer, sender_key)

    assert error is not None, "an unknown token must not be treated as arrival"
    assert error == "unconfirmed", f"expected 'unconfirmed', got {error!r}"
    assert delivery_id is None


def test_a23_id_on_a_refusal_is_not_proof_of_arrival(peer, sender_key):
    """Our own door: 503 busy *carries* a delivery_id. It is still a refusal."""
    peer.status = 503
    peer.payload = {"status": "busy", "delivery_id": "abc"}

    delivery_id, error = _send(peer, sender_key)

    assert error is not None, (
        "a refusal carrying a delivery_id must not be marked delivered -- "
        "that loses a QueueFull message with a success report"
    )
    assert delivery_id is None


def test_a24_receipt_without_id_is_still_delivered(peer, sender_key):
    """Our own duplicate answer is 200 {"status":"duplicate"} -- no id at all."""
    peer.status = 200
    peer.payload = {"status": "duplicate"}

    delivery_id, error = _send(peer, sender_key)

    assert error is None, f"a duplicate receipt without an id is a delivery, got {error!r}"
    assert delivery_id is not None
