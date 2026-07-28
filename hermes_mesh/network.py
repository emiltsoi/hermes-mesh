"""Loopback and local-address classification for binding vs. target hosts.

The distinction matters:

* ``is_loopback_bind_host`` is used when deciding whether an adapter may bind
  to a host. Binding to ``0.0.0.0`` or ``::`` means *all* interfaces, so those
  are not loopback. Only ``127.0.0.1``/``::1``/``localhost`` are safe for
  loopback-only binding.

* ``is_local_target_host`` is used when validating a URL *target*. It treats
  bracketed IPv6, plain loopback/private IPs, and the common shorthand
  ``0.0.0.0`` as a local target so callers can decide to allow loopback
  delivery. IPv6 unspecified (``::``) is still excluded because it is not a
  valid remote target.
"""
from __future__ import annotations

import ipaddress


def _strip_brackets(host: str) -> str:
    """Remove surrounding ``[`` ``]`` from bracketed IPv6 literals."""
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def is_loopback_bind_host(host: str | None) -> bool:
    """Return True when `host` binds only to the local machine.

    ``0.0.0.0`` and ``::`` are *not* loopback; they mean every interface.
    """
    if not host:
        return False
    return host.strip().lower() in {"127.0.0.1", "localhost", "::1"}


def is_local_target_host(host: str) -> bool:
    """Return True when `host` is a known local/loopback/private endpoint.

    Literal IPs are classified with ``ipaddress``; hostnames must be loopback
    literals to avoid treating an attacker-controlled public domain as local.
    ``0.0.0.0`` is accepted as a local target (common testing shorthand) but
    ``::`` is not — it is the unspecified address and cannot be connected to.
    """
    host = (host or "").lower().strip()
    if not host:
        return False
    if host in {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}:
        return True
    host = _strip_brackets(host)
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local)
