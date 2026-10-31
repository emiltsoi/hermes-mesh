class TestSessionSelector:
    """Session-selector 0.1.8: [session] + [from_session] tokens, session_map
    routing, and reply metadata. Backward-compatible with bare envelopes."""

    @staticmethod
    def _make_adapter(secret="INSECURE_NO_AUTH", agent_name="ada",
                      target_session="telegram:dm:123", session_map=None, host=None):
        from hermes_mesh.adapter import MeshAdapter
        from gateway.platforms.base import PlatformConfig
        extra = {
            "secret": secret,
            "agent_name": agent_name,
            "target_session": target_session,
            "host": host,
        }
        if session_map:
            extra["session_map"] = session_map
        return MeshAdapter(PlatformConfig(extra=extra))

    @staticmethod
    def _make_request(body, headers):
        from unittest.mock import MagicMock, AsyncMock
        import json
        request = MagicMock()
        request.read = AsyncMock(return_value=json.dumps(body, sort_keys=True).encode())
        request.headers = headers
        return request

    @staticmethod
    def _envelope(sender="ada", recipient="ADA", msg_id="testid-123", action="do",
                  reply="yes", ref=None, session=None, from_session=None, body="hello"):
        header = f"[mesh][from:{sender}][to:{recipient}][id:{msg_id}]"
        if session:
            header += f"[session:{session}]"
        if from_session:
            header += f"[from_session:{from_session}]"
        header += f"[action:{action}][reply:{reply}]"
        if ref:
            header += f"[ref:{ref}]"
        return f"{header} {body}"

    @staticmethod
    def _run(coro):
        import asyncio
        return asyncio.run(coro)

    def test_parse_envelope_with_session_tokens(self):
        adapter = self._make_adapter()
        text = self._envelope(session="review", from_session="chat")
        parsed, err = adapter._parse_envelope(text)
        assert err is None
        assert parsed["session"] == "review"
        assert parsed["from_session"] == "chat"

    def test_parse_envelope_without_session_tokens_backward_compatible(self):
        adapter = self._make_adapter()
        text = self._envelope()
        parsed, err = adapter._parse_envelope(text)
        assert err is None
        assert parsed["session"] is None
        assert parsed["from_session"] is None

    def test_session_map_routes_to_mapped_session(self):
        adapter = self._make_adapter(
            target_session="telegram:dm:default",
            session_map={"review": "telegram:dm:review123"},
        )
        text = self._envelope(sender="linda", session="review")
        parsed, err = adapter._parse_envelope(text)
        event, _ = adapter._build_event(
            {}, parsed["sender"], parsed["recipient"], parsed["msg_id"],
            parsed["action"], parsed["reply"], parsed["ref"], parsed["body_text"],
            session=parsed["session"], from_session=parsed["from_session"],
        )
        assert event is not None
        # The mapped session's chat id must be the source's chat id.
        assert event.source.chat_id == "review123", (
            f"session_map routing failed: chat_id={event.source.chat_id}"
        )

    def test_unmapped_session_falls_back_to_target_session(self):
        adapter = self._make_adapter(
            target_session="telegram:dm:default",
            session_map={"review": "telegram:dm:review123"},
        )
        text = self._envelope(sender="linda", session="unknown-session")
        parsed, err = adapter._parse_envelope(text)
        event, _ = adapter._build_event(
            {}, parsed["sender"], parsed["recipient"], parsed["msg_id"],
            parsed["action"], parsed["reply"], parsed["ref"], parsed["body_text"],
            session=parsed["session"], from_session=parsed["from_session"],
        )
        assert event is not None
        assert event.source.chat_id == "default", "unmapped session should fall back"

    def test_absent_session_uses_target_session(self):
        adapter = self._make_adapter(target_session="telegram:dm:default")
        text = self._envelope(sender="linda")
        parsed, err = adapter._parse_envelope(text)
        event, _ = adapter._build_event(
            {}, parsed["sender"], parsed["recipient"], parsed["msg_id"],
            parsed["action"], parsed["reply"], parsed["ref"], parsed["body_text"],
            session=parsed["session"], from_session=parsed["from_session"],
        )
        assert event is not None
        assert event.source.chat_id == "default", "absent session should use target_session"

    def test_session_tokens_carried_in_event_metadata(self):
        from hermes_mesh import adapter as _adapter_mod
        import pytest
        if _adapter_mod._CORE_BINDS_PLATFORM:
            pytest.skip("core refuses non-empty event metadata (2026-10+); see TestCorePortability")
        adapter = self._make_adapter()
        text = self._envelope(sender="linda", session="review", from_session="chat")
        parsed, err = adapter._parse_envelope(text)
        event, _ = adapter._build_event(
            {}, parsed["sender"], parsed["recipient"], parsed["msg_id"],
            parsed["action"], parsed["reply"], parsed["ref"], parsed["body_text"],
            session=parsed["session"], from_session=parsed["from_session"],
        )
        assert event.metadata["mesh"]["session"] == "review"
        assert event.metadata["mesh"]["from_session"] == "chat"

    def test_invalid_session_token_rejected(self):
        adapter = self._make_adapter()
        # A # in a session name violates the token alphabet.
        text = self._envelope(sender="linda", session="rev#iew")
        parsed, err = adapter._parse_envelope(text)
        assert err is not None, "invalid session token must be rejected"


class TestCorePortability:
    """The plugin must run on both cores.

    Upstream 2026-10 removed ``_platform`` from ``build_source()`` and began refusing non-empty
    ``event.metadata`` on native events. Both behaviours are probed at import, so the old core keeps
    its exact contract and the new core gets the shape it accepts. These tests pin both sides of
    each gate — the flag is monkeypatched, so neither depends on which core is installed.
    """

    @staticmethod
    def _adapter(target_session="telegram:dm:123"):
        from hermes_mesh.adapter import MeshAdapter
        from gateway.platforms.base import PlatformConfig
        return MeshAdapter(PlatformConfig(extra={
            "secret": "INSECURE_NO_AUTH", "agent_name": "ada",
            "target_session": target_session, "host": None,
        }))

    @staticmethod
    def _build(adapter):
        return adapter._build_event(
            {}, "ada", "ADA", "mid-1", "info", "no", None, "hello",
            session=None, from_session=None,
        )

    def test_routed_source_omits_platform_on_new_core(self, monkeypatch):
        from hermes_mesh import adapter as mod
        ad = self._adapter()
        seen = {}

        def spy(**kw):
            seen.update(kw)
            kw.pop("_platform", None)
            return ad.__class__.build_source(ad, **kw)

        monkeypatch.setattr(ad, "build_source", spy)
        monkeypatch.setattr(mod, "_CORE_BINDS_PLATFORM", True)
        monkeypatch.setattr(mod, "_ROUTED_BINDING", False, raising=False)
        event, err = self._build(ad)

        assert err is None
        assert "_platform" not in seen, "new core WITHOUT the routed carry must not stamp"
        assert seen["chat_id"] == "123", "routed target still rides on chat_id"

    def test_routed_source_stamps_platform_on_new_core_with_the_carry(self, monkeypatch):
        """Third generation case: a new core carrying ROUTED_PLATFORM_BINDING accepts the stamp.

        Without this case the two above can both pass while the carry core — the only core the
        fleet is about to run — silently stays mesh-keyed.
        """
        from hermes_mesh import adapter as mod
        ad = self._adapter()
        seen = {}

        def spy(**kw):
            seen.update(kw)
            kw.pop("_platform", None)
            return ad.__class__.build_source(ad, **kw)

        monkeypatch.setattr(ad, "build_source", spy)
        monkeypatch.setattr(mod, "_CORE_BINDS_PLATFORM", True)
        monkeypatch.setattr(mod, "_ROUTED_BINDING", True, raising=False)
        event, err = self._build(ad)

        assert err is None
        stamped = seen.get("_platform")
        assert stamped is not None, "carry core must stamp the routed platform; nothing was passed"
        assert "telegram" in str(getattr(stamped, "value", stamped)).lower(), (
            f"carry core must stamp telegram, saw {stamped!r}")

    def test_routed_source_stamps_platform_on_old_core(self, monkeypatch):
        from hermes_mesh import adapter as mod
        ad = self._adapter()
        seen = {}

        def spy(**kw):
            seen.update(kw)
            kw.pop("_platform", None)
            return ad.__class__.build_source(ad, **kw)

        monkeypatch.setattr(ad, "build_source", spy)
        monkeypatch.setattr(mod, "_CORE_BINDS_PLATFORM", False)
        event, err = self._build(ad)

        assert err is None
        assert seen["_platform"].value == "telegram", "old core keeps the routed stamp"

    def test_no_event_metadata_when_core_refuses_it(self, monkeypatch):
        from hermes_mesh import adapter as mod
        ad = self._adapter()
        monkeypatch.setattr(mod, "_CORE_BINDS_PLATFORM", True)
        event, err = self._build(ad)
        assert err is None
        assert "mesh" not in event.metadata, "new core refuses non-empty metadata"

    def test_authorization_is_upstream_declared(self):
        ad = self._adapter()
        assert ad.authorization_is_upstream is True


class TestRoutedPlatformDeclaration:
    """The declaration the core carry reads must exist, and must be a real collection.

    Core-side tests set ``delivers_as_platforms`` on a stub adapter, so nothing in this repo
    noticed if the real MeshAdapter lost it — the plugin suite could be green while the
    fleet's routed delivery silently degraded to mesh-keyed sessions. Found by Britney's
    mutation M1 (plugin side), 2026-10-31. A survivor that is a missing test is still a hole.
    """

    def test_mesh_adapter_declares_telegram(self):
        from hermes_mesh.adapter import MeshAdapter, _ROUTED_BINDING  # noqa: F401
        from gateway.config import Platform

        declared = getattr(MeshAdapter, "delivers_as_platforms", None)
        assert declared is not None, "the routed-platform declaration is gone — the carry reads it"
        assert isinstance(declared, (set, frozenset)), (
            f"must be a real collection; the core refuses a bare string, got {type(declared)!r}")
        assert Platform("telegram") in declared, "must name the platform the fleet actually routes to"

    def test_the_probe_is_a_bool_not_a_throw(self):
        """A missing sentinel on the old core must read False, never raise at import."""
        from hermes_mesh import adapter as adapter_mod

        assert isinstance(adapter_mod._ROUTED_BINDING, bool)

    def test_stamp_condition_covers_both_generations(self):
        """Old core OR carry core -> stamp. New core without the carry -> no stamp (mesh-keyed)."""
        from hermes_mesh import adapter as adapter_mod

        def stamps(core_binds_platform, routed_binding):
            return (not core_binds_platform) or routed_binding

        assert stamps(core_binds_platform=False, routed_binding=False) is True   # old core
        assert stamps(core_binds_platform=True, routed_binding=True) is True     # carry core
        assert stamps(core_binds_platform=True, routed_binding=False) is False   # new core alone
