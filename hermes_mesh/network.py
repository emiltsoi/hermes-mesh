"""Loopback and local-address classification for binding vs. target hosts.

These helpers are re-exported from ``mesh_core.network`` with identical
semantics so both packages share one source of truth.
"""
from __future__ import annotations

from mesh_core.network import is_local_target_host, is_loopback_bind_host

__all__ = ["is_local_target_host", "is_loopback_bind_host"]
