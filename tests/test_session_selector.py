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
