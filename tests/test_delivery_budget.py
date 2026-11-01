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
        self.sleep_after_first: float | None = None
        self.slow_count: int | None = None
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
                    index = peer.requests
                # `sleep_after_first` lets a test make the peer swallow leading
                # requests and answer later ones immediately -- the only shape that
                # exercises the deadline extension. `slow_count` says HOW MANY
                # leading requests are swallowed, and it must be set whenever the
                # extension is under test: `_resolve_target_url` returns loopback
                # twice, so `_pinned_request` sends TWO requests per attempt and a
                # single slow request would be answered by the duplicate.
                delay = peer.sleep_s
                if peer.slow_count is not None:
                    if index > peer.slow_count:
                        delay = peer.sleep_after_first or 0.0
                elif index > 1 and peer.sleep_after_first is not None:
                    delay = peer.sleep_after_first
                if delay:
                    import time as _t

                    _t.sleep(delay)
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

    Pre-fix attempt 0 receives 10/3 ~= 3.33 s, so a peer that accepts after that
    threshold is unreachable on the only attempt with enough budget and every
    later attempt fails *because the message arrived*.

    The sleep is 8.0 s and not 4.0 s on purpose, and the number comes from
    measurement rather than arithmetic.

    ``_pinned_request`` tries **every** resolved IP with the full ``timeout``, and
    ``_resolve_target_url`` currently returns loopback **twice**
    (``[IPv4Address('127.0.0.1'), IPv4Address('127.0.0.1')]``), so one attempt's
    wall clock is ~2x its nominal window: a 3.33 s window blocked for 6.67 s and a
    1.56 s window for 3.13 s (measured). A 4.0 s peer is therefore served by the
    divided schedule's own doubling, and a 6.0 s peer likewise -- both survive the
    budget mutation and prove nothing.

    8.0 s sits outside ``2 * total/retries`` (6.67 s) and inside ``2 * total``
    (20 s), so the divided schedule cannot reach it however the retries fall,
    while first-attempt-full delivers it on attempt 0.
    """
    peer.status = 200
    peer.payload = {"delivery_id": "x"}
    peer.sleep_s = 8.0

    delivery_id, error = _send(peer, sender_key)

    assert error is None, f"an 8.0s peer must be deliverable inside a 10s budget, got {error!r}"
    assert delivery_id == "x"


def test_a20_duplicate_refusal_is_a_delivery(peer, sender_key):
    """409 duplicate is the strongest proof of arrival, and must not be retried."""
    peer.status = 409
    peer.payload = {"status": "duplicate", "delivery_id": "abc"}

    delivery_id, error = _send(peer, sender_key)

    assert error is None, f"409 duplicate must be DELIVERED, got {error!r}"
    # Not `in ("abc", None, "unknown")`: that disjunction accepts every way of
    # failing to read the id, so a build that read `abc`, one that defaulted to
    # "unknown" and one that gave up with None would all pass. The peer's body
    # says `abc` and the code returns it, so the claim is the exact value.
    assert delivery_id == "abc", (
        f"the id must be READ from the duplicate body, not defaulted; got {delivery_id!r}"
    )
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


def test_a25_deadline_extension_rescues_the_retries(peer, sender_key, monkeypatch):
    """The once-only extension is the difference between a retry and a formality.

    This is the test A19 cannot be. Post-fix, attempt 0 takes the whole timeout,
    so it never fails against a merely-slow peer and the extension is never
    exercised -- deleting the extension leaves A19 green. The extension only
    earns its place when attempt 0 gets *no answer at all*: without it the
    remaining budget is already spent and the retries return ``unconfirmed``
    without ever being tried.

    The peer swallows the first request entirely and answers the second
    immediately, so the only thing under test is whether attempt 1 happens.
    """
    monkeypatch.setattr(session_relay, "_DELIVERY_TIMEOUT", 2)
    peer.status = 200
    peer.payload = {"delivery_id": "x"}
    peer.sleep_s = 5.0
    peer.sleep_after_first = 0.0
    # One, not two. This was 2 while `_resolve_host` returned every address twice
    # and one attempt therefore made two requests; the de-duplication condition
    # makes an attempt a single request, so swallowing one is exactly one attempt
    # and swallowing two would swallow attempt 1 as well and fail a correct build.
    peer.slow_count = 1

    delivery_id, error = _send(peer, sender_key)

    assert peer.requests >= 2, (
        "attempt 1 was never tried: without the extension the deadline is "
        f"already spent after attempt 0 (saw {peer.requests} request(s))"
    )
    assert error is None, f"the extension must let attempt 1 succeed, got {error!r}"
    assert delivery_id == "x"


def test_a26_resolution_yields_distinct_addresses():
    """One address must mean one attempt, or the budget's arithmetic is fiction.

    ``getaddrinfo`` without ``type``/``proto`` returns one entry per socket kind,
    so every address appears twice::

        getaddrinfo('127.0.0.1')  -> ['127.0.0.1', '127.0.0.1']
        getaddrinfo('localhost')  -> ['127.0.0.1', '127.0.0.1', '::1', '::1']

    ``_pinned_request`` gives **each** entry the full timeout, so a duplicate here
    doubles the wall clock of every attempt and asks a timed-out peer twice -- a
    duplicate generator sitting inside the fix for duplicates. This asserts the
    property rather than the argument: ``type=`` and ``proto=`` each fix it alone,
    and a defensive de-duplication fixes it too, so the test names the invariant
    and lets the implementation choose how to hold it.
    """
    for host in ("127.0.0.1", "localhost"):
        try:
            addrs = session_relay._resolve_host(host)
        except ValueError:
            continue  # host not resolvable on this box: not this test's subject
        assert addrs, f"{host} resolved to nothing"
        assert len(addrs) == len(set(addrs)), (
            f"{host} returned duplicate addresses {addrs}; every duplicate gives one "
            "more full-timeout connection attempt, so the delivery budget doubles"
        )


