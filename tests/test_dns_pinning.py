"""DNS pinning across delivery retries.

Wave ``2026-11-03-experiment-2-dns-pinning`` · SPEC AC1–AC5.

The property:

    Given:  a host that resolves to address A on the first lookup,
            and would resolve to B on a second lookup
    When:   one delivery is attempted, the first attempt fails,
            and the retry loop runs
    Then:   every attempt dials A
    And:    B is never dialled

Why it matters: the delivery path validates the resolved address against the
loopback/private-range policy *and* dials it. If the hostname were re-resolved
per attempt, the validation would apply to the address the attacker showed us
first and the connection to the address they showed us second -- a rebind walks
straight past the SSRF guard between attempt 0 and attempt 1.

Instrumentation: this records the addresses **handed to the dialer**
(``_pinned_request``) on every attempt, and never counts calls to
``_resolve_host``. The call count is an implementation detail a legitimate
refactor may change (resolve once and thread the result differently, and the
guarantee still holds); the recording is the observable guarantee. A test that
asserted ``_resolve_host`` was called exactly once would break when the code is
improved, and would not notice a second resolution path added beside it.
"""

from __future__ import annotations

import ipaddress
import socket

import pytest

from hermes_mesh import auth as mesh_auth
from hermes_mesh import session_relay
from hermes_mesh.session_relay import _deliver_webhook

ENVELOPE = "[mesh][from:sender][to:target][id:m1][action:info][reply:no] hello"

# A name that only the fake resolver knows. It never reaches real DNS.
REBIND_HOST = "rebind.pinned.invalid"

# The address the first lookup returns, and the one the second lookup returns
# if -- and only if -- the delivery resolves the hostname a second time.
FIRST_IP = ipaddress.ip_address("127.0.0.1")
REBOUND_IP = ipaddress.ip_address("127.0.0.2")


@pytest.fixture()
def dead_port():
    """A loopback port with nothing listening: ``connect()`` is refused at once.

    Bound and released, so the port is free and the kernel answers with a reset
    rather than a dropped SYN (a bound-but-unlistening socket on macOS makes
    ``connect`` hang until the attempt timeout, which would cost seconds per
    retry). If another process grabs the port in the microseconds between, the
    connection is either refused or answered by a stranger whose non-JSON reply
    fails the same attempt -- the retry happens either way and the addresses
    dialled are unaffected, so this test does not turn on the race.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture()
def rebinding_dns(monkeypatch):
    """Make ``getaddrinfo`` answer ``FIRST_IP`` first and ``REBOUND_IP`` after.

    Only ``REBIND_HOST`` is faked; every other lookup (including the numeric
    IPs the dialer resolves on its way to a socket) is passed through to the
    real resolver, so the dial itself is genuine. The fake accepts and ignores
    ``args``/``kwargs`` on purpose -- asserting that ``type=``/``proto=`` were
    passed would be asserting the implementation, not the property.
    """
    real_getaddrinfo = socket.getaddrinfo
    lookups: list[str] = []

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host != REBIND_HOST:
            return real_getaddrinfo(host, port, *args, **kwargs)
        answer = REBOUND_IP if lookups else FIRST_IP
        lookups.append(str(answer))
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (str(answer), port or 0),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return lookups


@pytest.fixture()
def dialled(monkeypatch):
    """Record the address list each attempt hands to ``_pinned_request``."""
    attempts: list[list] = []
    real_pinned_request = session_relay._pinned_request

    def recording_pinned_request(
        url, body, headers, timeout, allow_loopback, resolved_ip_objs=None
    ):
        attempts.append(list(resolved_ip_objs or []))
        return real_pinned_request(
            url,
            body,
            headers,
            timeout,
            allow_loopback=allow_loopback,
            resolved_ip_objs=resolved_ip_objs,
        )

    monkeypatch.setattr(session_relay, "_pinned_request", recording_pinned_request)
    return attempts


@pytest.fixture()
def sender_key(tmp_path):
    private_pem, _public_pem = mesh_auth.load_or_generate_keypair(
        "sender", extra={"private_key_path": str(tmp_path / "sender.pem")}
    )
    return private_pem


@pytest.fixture(autouse=True)
def _fast_retry(monkeypatch):
    """Keep retry pacing out of the assertions; the pinning, not the backoff, is under test.

    The timeout is bounded because a rebind that *does* take effect sends an
    attempt to an address nothing answers on, and the wall clock of a failing
    build must not be the developer's problem.
    """
    monkeypatch.setenv("MESH_WEBHOOK_ALLOW_LOOPBACK", "1")
    monkeypatch.setattr(session_relay, "_DELIVERY_BACKOFF", 0.01)
    monkeypatch.setattr(session_relay, "_DELIVERY_TIMEOUT", 2)


def test_dns_rebind_between_attempts_never_moves_the_pinned_delivery(
    dead_port, sender_key, rebinding_dns, dialled
):
    """One delivery, one resolution: a mid-delivery DNS change must not take effect.

    Attempt 0 is refused (dead port), so the retry loop runs with the DNS now
    answering ``REBOUND_IP``. Every attempt must still dial ``FIRST_IP``.
    """
    url = f"http://{REBIND_HOST}:{dead_port}/mesh/receive"

    delivery_id, error = _deliver_webhook(
        url, ENVELOPE, sender_key, allow_loopback=True, sender="sender"
    )

    # The port is dead by construction, so no delivery can succeed; the delivery
    # result is not the subject here, only what was dialled on the way.
    assert delivery_id is None
    assert error is not None

    assert len(dialled) >= 2, (
        "the retry never ran, so this test would pass vacuously: a rebind can "
        f"only be observed across two attempts, saw {len(dialled)}"
    )

    flat = [ip for attempt in dialled for ip in attempt]
    rebound_attempts = [
        index + 1 for index, attempt in enumerate(dialled) if REBOUND_IP in attempt
    ]
    assert not rebound_attempts, (
        f"the rebound address {REBOUND_IP} was dialled on attempt(s) "
        f"{rebound_attempts} of {len(dialled)}: the hostname was re-resolved "
        "mid-delivery, so a DNS change between attempts redirected the retry -- "
        f"the exact rebind the pinning exists to stop. Attempts: {dialled}"
    )

    first_attempt = set(dialled[0])
    later_attempts = [set(attempt) for attempt in dialled[1:]]
    assert all(attempt == first_attempt for attempt in later_attempts), (
        "every attempt in one delivery must dial the same address; attempt 1 "
        f"dialled {sorted(map(str, first_attempt))} but later attempts dialled "
        f"{[sorted(map(str, attempt)) for attempt in later_attempts]}"
    )

    assert first_attempt == {FIRST_IP}, (
        f"the delivery must dial the address from the first lookup ({FIRST_IP}); "
        f"it dialled {[str(ip) for ip in flat]}"
    )
