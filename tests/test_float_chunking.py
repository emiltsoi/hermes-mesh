"""Tests for Telegram float chunking, truncation and failure logging.

All tests are offline: the HTTP call (``urllib.request.urlopen``) is patched.
"""
import io
import json
import re
import urllib.error
from unittest.mock import patch

from hermes_mesh import float as float_module


CFG = {
    "telegram_bot_token": "test-token-abc",
    "telegram_default_chat_id": "123456",
}

_PREFIX_RE = re.compile(r"^\[\d+/\d+\] ")
_SUFFIX_RE = re.compile(r"… \+\d[\d,]* chars not floated$")


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _capture(payloads, body=b'{"ok": true}'):
    """Return a fake urlopen that records request payloads and succeeds."""

    def fake_urlopen(req, timeout=None):
        payloads.append(json.loads(req.data.decode()))
        return _FakeResponse(body)

    return fake_urlopen


def _content(part: str, truncated: bool = False) -> str:
    """Strip the part marker, and (only when truncation happened) the suffix.

    The truncation suffix is appended only to the last part of a message that
    exceeded the ceiling. Stripping it unconditionally would corrupt a payload
    that legitimately ends with text shaped like ``… +N chars not floated``,
    making round-trip assertions vacuous — so callers opt in explicitly.
    """
    text = _PREFIX_RE.sub("", part)
    if truncated:
        text = _SUFFIX_RE.sub("", text)
    return text


def _entities_closed(part: str) -> bool:
    """True when every '&' in `part` is closed by a ';' in the same part."""
    idx = 0
    while True:
        amp = part.find("&", idx)
        if amp == -1:
            return True
        semi = part.find(";", amp)
        if semi == -1:
            return False
        idx = semi + 1


class TestEmptyAndShort:
    def test_empty_text_skips_with_no_http_call(self, caplog):
        with patch("hermes_mesh.float.urllib.request.urlopen") as mock_open:
            with caplog.at_level("DEBUG", logger="hermes_mesh.float"):
                float_module.send("", config=CFG)
        mock_open.assert_not_called()
        assert "empty or whitespace-only" in caplog.text

    def test_whitespace_only_skips_with_no_http_call(self, caplog):
        with patch("hermes_mesh.float.urllib.request.urlopen") as mock_open:
            with caplog.at_level("DEBUG", logger="hermes_mesh.float"):
                float_module.send("  \n\t  ", config=CFG)
        mock_open.assert_not_called()
        assert "empty or whitespace-only" in caplog.text

    def test_short_message_is_one_part_without_marker(self):
        payloads = []
        with patch("hermes_mesh.float.urllib.request.urlopen", _capture(payloads)):
            float_module.send("hello world", config=CFG)
        assert len(payloads) == 1
        assert payloads[0]["text"] == "hello world"


class TestChunkBoundary:
    def test_exactly_4000_escaped_is_one_part(self):
        text = "a" * 4000
        payloads = []
        with patch("hermes_mesh.float.urllib.request.urlopen", _capture(payloads)):
            float_module.send(text, config=CFG)
        assert len(payloads) == 1
        assert payloads[0]["text"] == text

    def test_4001_escaped_is_two_parts(self):
        text = "a" * 4001
        payloads = []
        with patch("hermes_mesh.float.urllib.request.urlopen", _capture(payloads)):
            float_module.send(text, config=CFG)
        assert len(payloads) == 2
        assert payloads[0]["text"].startswith("[1/2] ")
        assert payloads[1]["text"].startswith("[2/2] ")
        # The marker counts toward the escaped budget.
        assert all(len(p["text"]) <= 4000 for p in payloads)
        # Nothing is lost: content concatenates back to the escaped input.
        assert "".join(_content(p["text"]) for p in payloads) == text

    def test_800_ampersands_escaped_4000_is_one_part(self):
        # raw != escaped: 800 '&' -> 4000 escaped chars, right at the budget.
        text = "&" * 800
        assert len(float_module.html.escape(text, quote=False)) == 4000
        payloads = []
        with patch("hermes_mesh.float.urllib.request.urlopen", _capture(payloads)):
            float_module.send(text, config=CFG)
        assert len(payloads) == 1
        assert payloads[0]["text"] == "&amp;" * 800

    def test_801_ampersands_escaped_4005_is_two_parts(self):
        # raw != escaped: 801 '&' -> 4005 escaped chars, one over the budget.
        text = "&" * 801
        assert len(float_module.html.escape(text, quote=False)) == 4005
        payloads = []
        with patch("hermes_mesh.float.urllib.request.urlopen", _capture(payloads)):
            float_module.send(text, config=CFG)
        assert len(payloads) == 2
        assert payloads[0]["text"].startswith("[1/2] ")
        assert payloads[1]["text"].startswith("[2/2] ")
        for p in payloads:
            assert len(p["text"]) <= 4000
            assert _entities_closed(p["text"])
        assert "".join(_content(p["text"]) for p in payloads) == "&amp;" * 801


class TestEscapeExpansion:
    def test_quotes_are_not_escaped(self):
        text = "a \"b\" <c> & d'e"
        payloads = []
        with patch("hermes_mesh.float.urllib.request.urlopen", _capture(payloads)):
            float_module.send(text, config=CFG)
        assert len(payloads) == 1
        assert payloads[0]["text"] == "a \"b\" &lt;c&gt; &amp; d'e"
        assert "&quot;" not in payloads[0]["text"]
        assert "&#x27;" not in payloads[0]["text"]

    def test_ampersands_expand_then_chunk(self):
        # 4200 raw chars -> 21000 escaped chars, far over the 4096 cap. Quotes
        # are not escaped (quote=False), so only '&' expands here.
        text = "&" * 4200
        assert len(float_module.html.escape(text, quote=False)) == 21000
        payloads = []
        with patch("hermes_mesh.float.urllib.request.urlopen", _capture(payloads)):
            float_module.send(text, config=CFG)
        assert len(payloads) > 1
        for p in payloads:
            assert len(p["text"]) <= 4000
            assert _entities_closed(p["text"])
        # Every escaped '&amp;' survives across the parts.
        joined = "".join(_content(p["text"]) for p in payloads)
        assert joined == "&amp;" * 4200


class TestEntityBoundary:
    def test_split_never_lands_inside_entity(self):
        # Position 3994 falls inside '&amp;' (starts at 3992). A naive hard
        # split would strand '&am' / 'p;' across the boundary.
        text = "a" * 3992 + "&" + "b" * 200
        payloads = []
        with patch("hermes_mesh.float.urllib.request.urlopen", _capture(payloads)):
            float_module.send(text, config=CFG)
        assert len(payloads) == 2
        for p in payloads:
            assert _entities_closed(p["text"]), p["text"]
        # The full entity lands intact at the head of the second part.
        assert "&amp;" in _content(payloads[1]["text"])
        # Reassembled escaped payload is exact.
        assert "".join(_content(p["text"]) for p in payloads) == float_module.html.escape(
            text, quote=False
        )


class TestEntityIntegrityGuarantee:
    def test_safe_cut_makes_progress_on_leading_entity(self):
        # When the entity starts at index 0 and its ';' is past the limit, the
        # old _safe_cut returned 0 and the chunker hard-cut inside the entity.
        cut = float_module._safe_cut("&amp;xyz", 1)
        assert cut > 0
        assert cut == len("&amp;")

    def test_small_limits_never_split_entities(self):
        escaped = "&amp;&lt;&gt;data&amp;"
        for limit in range(1, 9):
            parts = float_module._chunk_escaped(escaped, limit)
            assert "".join(parts) == escaped
            for p in parts:
                assert _entities_closed(p), (limit, p)


class TestTruncationCeiling:
    def test_80000_chars_is_eight_parts_plus_marker(self):
        text = "a" * 80000
        payloads = []
        with patch("hermes_mesh.float.urllib.request.urlopen", _capture(payloads)):
            float_module.send(text, config=CFG)
        assert len(payloads) == 8
        for i, p in enumerate(payloads, start=1):
            assert p["text"].startswith(f"[{i}/8] ")
            assert len(p["text"]) <= 4000
        last = payloads[-1]["text"]
        match = re.search(r"\+([\d,]+) chars not floated$", last)
        assert match is not None, last
        reported = int(match.group(1).replace(",", ""))
        floated_raw = sum(
            len(_content(p["text"], truncated=True)) for p in payloads
        )
        assert reported == 80000 - floated_raw
        assert reported > 0

    def test_40000_ampersands_raw_differs_from_escaped(self):
        # raw 40,000 -> escaped 200,000: exercises _raw_count_for_escaped's
        # raw-vs-escaped distinction and the suffix budget under expansion.
        text = "&" * 40000
        assert len(float_module.html.escape(text, quote=False)) == 200000
        payloads = []
        with patch("hermes_mesh.float.urllib.request.urlopen", _capture(payloads)):
            float_module.send(text, config=CFG)
        assert len(payloads) == 8
        for i, p in enumerate(payloads, start=1):
            assert p["text"].startswith(f"[{i}/8] ")
            assert len(p["text"]) <= 4000
            assert _entities_closed(p["text"])
        last = payloads[-1]["text"]
        match = re.search(r"\+([\d,]+) chars not floated$", last)
        assert match is not None, last
        reported = int(match.group(1).replace(",", ""))
        floated_escaped = sum(
            len(_content(p["text"], truncated=True)) for p in payloads
        )
        # Every cut lands on an entity boundary, so the floated content is a
        # whole number of '&amp;' units and converts exactly back to raw chars.
        assert floated_escaped % len("&amp;") == 0
        floated_raw = floated_escaped // len("&amp;")
        assert reported == 40000 - floated_raw
        assert reported > 0

    def test_truncation_is_visible_in_the_log(self, caplog):
        with patch("hermes_mesh.float.urllib.request.urlopen", _capture([])):
            with caplog.at_level("WARNING", logger="hermes_mesh.float"):
                float_module.send("a" * 80000, config=CFG)
        assert "truncated" in caplog.text.lower()
        assert "max 8" in caplog.text
        assert "not floated" in caplog.text


class TestFailureLogging:
    def _http_error(self, description: str):
        body = json.dumps({"ok": False, "description": description}).encode()
        return urllib.error.HTTPError(
            "https://api.telegram.org/bottest-token-abc/sendMessage",
            400,
            "Bad Request",
            {},
            io.BytesIO(body),
        )

    def test_json_body_description_is_logged_and_send_does_not_raise(self, caplog):
        with patch("hermes_mesh.float.urllib.request.urlopen") as mock_open:
            mock_open.side_effect = self._http_error("Bad Request: message is too long")
            with caplog.at_level("ERROR", logger="hermes_mesh.float"):
                float_module.send("hello", config=CFG)  # must not raise
        assert "part 1/1" in caplog.text
        assert "Bad Request: message is too long" in caplog.text
        assert "test-token-abc" not in caplog.text

    def test_later_part_failure_reports_earlier_delivery(self, caplog):
        calls = {"n": 0}

        def fake_urlopen(req, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                return _FakeResponse(b'{"ok": true}')
            raise self._http_error("Bad Request: message is too long")

        with patch("hermes_mesh.float.urllib.request.urlopen", fake_urlopen):
            with caplog.at_level("ERROR", logger="hermes_mesh.float"):
                float_module.send("a" * 4001, config=CFG)  # must not raise
        assert calls["n"] == 2
        assert "part 2/2 failed" in caplog.text
        assert "parts 1-1 delivered" in caplog.text
        assert "test-token-abc" not in caplog.text

    def test_non_json_http_error_logs_status_and_reason(self, caplog):
        err = urllib.error.HTTPError(
            "https://api.telegram.org/bottest-token-abc/sendMessage",
            500,
            "Internal Server Error",
            {},
            io.BytesIO(b"<html>oops</html>"),
        )
        with patch("hermes_mesh.float.urllib.request.urlopen") as mock_open:
            mock_open.side_effect = err
            with caplog.at_level("ERROR", logger="hermes_mesh.float"):
                float_module.send("hello", config=CFG)
        assert "part 1/1" in caplog.text
        assert "HTTP 500 Internal Server Error" in caplog.text

    def test_429_stops_after_logging_part_index(self, caplog):
        err = urllib.error.HTTPError(
            "https://api.telegram.org/bottest-token-abc/sendMessage",
            429,
            "Too Many Requests",
            {},
            io.BytesIO(b'{"ok":false,"description":"Too Many Requests: retry after 3"}'),
        )
        with patch("hermes_mesh.float.urllib.request.urlopen") as mock_open:
            mock_open.side_effect = err
            with caplog.at_level("ERROR", logger="hermes_mesh.float"):
                float_module.send("a" * 8000, config=CFG)
        # First part fails -> only one call attempted, no hammering.
        assert mock_open.call_count == 1
        assert "part 1/3" in caplog.text
        assert "rate limited" in caplog.text

    def test_non_json_error_states_remaining_not_attempted(self, caplog):
        # F5: a mid-stream failure must say the remainder was not attempted.
        err = urllib.error.HTTPError(
            "https://api.telegram.org/bottest-token-abc/sendMessage",
            400,
            "Bad Request",
            {},
            io.BytesIO(b"<html>oops</html>"),
        )
        with patch("hermes_mesh.float.urllib.request.urlopen") as mock_open:
            mock_open.side_effect = err
            with caplog.at_level("ERROR", logger="hermes_mesh.float"):
                float_module.send("a" * 8000, config=CFG)
        assert "part 1/3" in caplog.text
        assert "not attempted" in caplog.text

    def test_http_error_reason_phrase_is_redacted(self, caplog):
        # F1: a server-supplied reason phrase can carry the token-bearing URL.
        reason = "https://api.telegram.org/bottest-token-abc/sendMessage"
        err = urllib.error.HTTPError(
            "https://api.telegram.org/bottest-token-abc/sendMessage",
            400,
            reason,
            {},
            io.BytesIO(b""),
        )
        with patch("hermes_mesh.float.urllib.request.urlopen") as mock_open:
            mock_open.side_effect = err
            with caplog.at_level("ERROR", logger="hermes_mesh.float"):
                float_module.send("hello", config=CFG)
        assert "part 1/1" in caplog.text
        assert "HTTP 400" in caplog.text
        assert "<redacted>" in caplog.text
        assert "test-token-abc" not in caplog.text

    def test_200_ok_false_is_reported_as_rejected(self, caplog):
        # F5: a Telegram rejection (200/ok:false) is not a transport failure.
        with patch(
            "hermes_mesh.float.urllib.request.urlopen",
            _capture([], body=b'{"ok": false, "description": "Bad Request: chat not found"}'),
        ):
            with caplog.at_level("ERROR", logger="hermes_mesh.float"):
                float_module.send("hello", config=CFG)
        assert "rejected" in caplog.text
        assert "chat not found" in caplog.text
        assert "not attempted" in caplog.text

    def test_transport_failure_is_labeled_transport(self, caplog):
        with patch("hermes_mesh.float.urllib.request.urlopen") as mock_open:
            mock_open.side_effect = OSError("connection reset")
            with caplog.at_level("ERROR", logger="hermes_mesh.float"):
                float_module.send("a" * 4001, config=CFG)
        assert "transport" in caplog.text
        assert "not attempted" in caplog.text

    def test_429_log_does_not_duplicate_http_429(self, caplog):
        # F5: reason-only 429 used to log 'HTTP 429 rate limited: HTTP 429 ...'.
        err = urllib.error.HTTPError(
            "https://api.telegram.org/bottest-token-abc/sendMessage",
            429,
            "Too Many Requests",
            {},
            io.BytesIO(b""),
        )
        with patch("hermes_mesh.float.urllib.request.urlopen") as mock_open:
            mock_open.side_effect = err
            with caplog.at_level("ERROR", logger="hermes_mesh.float"):
                float_module.send("hello", config=CFG)
        assert "rate limited" in caplog.text
        assert caplog.text.count("HTTP 429") == 1


class TestSendNeverRaises:
    def test_non_str_text_does_not_raise(self, caplog):
        with patch("hermes_mesh.float.urllib.request.urlopen") as mock_open:
            with caplog.at_level("ERROR", logger="hermes_mesh.float"):
                float_module.send(12345, config=CFG)  # must not raise
        mock_open.assert_not_called()
        assert "text must be str" in caplog.text

    def test_non_str_bot_token_does_not_raise(self, caplog):
        cfg = {"telegram_bot_token": 123456789, "telegram_default_chat_id": "123456"}
        with patch("hermes_mesh.float.urllib.request.urlopen") as mock_open:
            mock_open.side_effect = Exception(
                "failed: https://api.telegram.org/bot123456789/sendMessage"
            )
            with caplog.at_level("ERROR", logger="hermes_mesh.float"):
                float_module.send("hello", config=cfg)  # must not raise
        assert "part 1/1" in caplog.text
        assert "123456789" not in caplog.text
        assert "<redacted>" in caplog.text

    def test_malformed_config_does_not_raise(self, caplog):
        with patch("hermes_mesh.float.urllib.request.urlopen") as mock_open:
            with caplog.at_level("ERROR", logger="hermes_mesh.float"):
                float_module.send("hello", config="not-a-dict")  # must not raise
        mock_open.assert_not_called()
        assert "credentials" in caplog.text


class TestSendWallBudget:
    def test_exhausted_budget_stops_further_parts_loudly(self, caplog):
        # F4: a clock jump past the cumulative budget must abort the loop
        # before issuing any part and say so, rather than stalling.
        ticks = iter([0.0, 100.0, 100.0, 100.0])
        with patch(
            "hermes_mesh.float.time.monotonic",
            side_effect=lambda: next(ticks),
        ), patch("hermes_mesh.float.urllib.request.urlopen") as mock_open:
            with caplog.at_level("ERROR", logger="hermes_mesh.float"):
                float_module.send("a" * 4001, config=CFG)
        mock_open.assert_not_called()
        assert "part 1/2" in caplog.text
        assert "budget exhausted" in caplog.text
        assert "remaining parts not attempted" in caplog.text


# INVARIANT: no chunker may silently drop or duplicate a byte — the parts
# rebuild the input exactly, or as an explicit prefix when truncation was
# declared. Named as a first-class claim so a search for the round-trip
# property (reconstruct / unescape / prefix) finds it instead of having to
# infer it from assertions scattered across the tests above.
class TestPartsReconstructOriginal:
    """The round-trip property, asserted once across every case class."""

    @staticmethod
    def _send(text: str) -> list[dict]:
        payloads: list[dict] = []
        with patch("hermes_mesh.float.urllib.request.urlopen", _capture(payloads)):
            float_module.send(text, config=CFG)
        return payloads

    def test_parts_reconstruct_the_original_input_exactly(self):
        # 1. Short / single part: the lone payload is the escaped text and the
        #    parts rejoin to the input.
        text = "hello world"
        payloads = self._send(text)
        assert len(payloads) == 1
        assert payloads[0]["text"] == float_module.html.escape(text, quote=False)
        assert "".join(_content(p["text"]) for p in payloads) == text

        # 2. Exact multiple of the multipart budget (4000 minus the widest
        #    "[8/8] " marker = 3994) and one char over it.
        for text in ("a" * (3994 * 2), "a" * (3994 * 2 + 1)):
            payloads = self._send(text)
            # No truncation here, so there is no suffix to strip.
            assert not _SUFFIX_RE.search(payloads[-1]["text"])
            assert "".join(_content(p["text"]) for p in payloads) == text

        # 3. Escape expansion: raw != escaped. The rejoin is the escaped input,
        #    and unescaping it recovers the raw input byte-for-byte.
        for text in ("&" * 801, "&" * 4200):
            escaped = float_module.html.escape(text, quote=False)
            payloads = self._send(text)
            assert not _SUFFIX_RE.search(payloads[-1]["text"])
            joined = "".join(_content(p["text"]) for p in payloads)
            assert joined == escaped
            assert float_module.html.unescape(joined) == text

        # 4. A cut that would land mid-entity: position 3994 falls inside the
        #    '&amp;' starting at 3992. No part may end on a dangling '&', and
        #    unescaping the rejoin is byte-identical to the input.
        text = "a" * 3992 + "&" + "b" * 200
        payloads = self._send(text)
        assert not _SUFFIX_RE.search(payloads[-1]["text"])
        joined = "".join(_content(p["text"]) for p in payloads)
        assert joined == float_module.html.escape(text, quote=False)
        assert float_module.html.unescape(joined) == text
        for p in payloads:
            assert _entities_closed(p["text"]), p["text"]
            assert not _content(p["text"]).endswith("&")

        # 5. Over the 8-part ceiling: truncation is declared, so the marker is
        #    appended *inside* the final part. Strip it only because truncation
        #    actually happened (and assert the marker is present): stripping it
        #    unconditionally would also strip content that legitimately ends
        #    like the marker, making the prefix check vacuous.
        text = "a" * 80000
        payloads = self._send(text)
        assert len(payloads) == float_module._MAX_PARTS
        marker = re.search(r"\+([\d,]+) chars not floated$", payloads[-1]["text"])
        assert marker is not None, payloads[-1]["text"]
        reported = int(marker.group(1).replace(",", ""))
        prefix = "".join(_content(p["text"], truncated=True) for p in payloads)
        assert text.startswith(prefix)
        assert reported == len(text) - len(prefix)
