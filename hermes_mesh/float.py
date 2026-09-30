"""Telegram float transport for Hermes mesh.

Fire-and-forget notification to the sender's Telegram DM. Best-effort —
failures are logged and swallowed; the tool result is the source of truth.

Credential chain (highest to lowest priority):
  1. config dict passed to send() / configure()
  2. Env var chain: HERMES_TELEGRAM_BOT_TOKEN → TELEGRAM_BOT_TOKEN
"""
from __future__ import annotations

import html
import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)


# Telegram rejects sendMessage text longer than 4096 characters. We stay under
# that with headroom. The limit applies to the ESCAPED text we actually put on
# the wire, not the raw input, so every length below is measured post-escape.
_CHUNK_LIMIT = 4000
# Hard ceiling on parts. Beyond this we float a head plus an explicit marker
# saying how many raw characters were dropped — never silently.
_MAX_PARTS = 8
_TRUNCATION_UNIT = "chars"
# Per-request socket timeout.
_HTTP_TIMEOUT_S = 10.0
# Cumulative wall-clock budget for one send(), across every part. Before
# chunking there was exactly one request with a 10s socket timeout; chunking
# can now issue up to _MAX_PARTS requests, so without a loop-level bound a slow
# Telegram endpoint could stall a synchronous mesh_send for ~80s. 15s keeps the
# worst case close to the old single-request behaviour while still letting a
# normal multi-part message finish.
_SEND_WALL_BUDGET_S = 15.0


# Module-level config set by the platform adapter from config.extra.
_config: dict[str, Any] = {}


def configure(config: dict[str, Any] | None) -> None:
    """Set module-level float config (usually platforms.mesh.extra)."""
    global _config
    _config = dict(config) if config else {}


def _resolve_credentials(config: dict[str, Any] | None = None) -> tuple[str, str]:
    """Resolve bot_token and chat_id from config then env vars.

    Returns ("", "") if absent.
    """
    cfg = config if config is not None else _config
    bot = (
        cfg.get("telegram_bot_token")
        or cfg.get("bot_token")
        or os.getenv("HERMES_TELEGRAM_BOT_TOKEN")
        or os.getenv("TELEGRAM_BOT_TOKEN", "")
    )
    chat = (
        cfg.get("telegram_default_chat_id")
        or cfg.get("chat_id")
        or os.getenv("HERMES_TELEGRAM_DEFAULT_CHAT_ID")
        or os.getenv("TELEGRAM_HOME_CHANNEL", "")
    )
    return bot, chat


def _redact(text: Any, secret: Any) -> str:
    """Replace occurrences of `secret` in `text` with a placeholder.

    Both arguments are coerced to ``str``: this helper is called from inside
    exception handlers, and a non-string secret (e.g. an int parsed from
    config) must never be able to raise and escape ``send()``.
    """
    text = str(text)
    if not secret:
        return text
    return text.replace(str(secret), "<redacted>")


def _marker_len(total: int) -> int:
    """Width of the widest ``[i/total] `` prefix for `total` parts."""
    return len(f"[{total}/{total}] ")


def _safe_cut(s: str, limit: int) -> int:
    """Return a positive index that does not split an HTML entity.

    The escaped payload contains only complete ``&...;`` entities. Cutting
    inside one would leave an ``&``-fragment dangling at the end of a part, so
    back the cut up to the entity's opening ``&``. If that ``&`` is at index 0
    (the entity starts the string and runs past ``limit``), there is no
    entity-safe cut at or before ``limit``; cut just after the complete entity
    instead. Escaped entities are at most 5 characters, so this only exceeds
    ``limit`` when the limit itself is tiny, and it never splits an entity and
    always makes progress (the result is > 0 for any non-empty ``s`` and
    positive ``limit``).
    """
    if limit >= len(s):
        return len(s)
    cut = limit
    amp = s.rfind("&", 0, cut)
    if amp != -1:
        semi = s.find(";", amp)
        if semi == -1 or semi >= cut:
            if amp > 0:
                cut = amp
            elif semi != -1:
                # Entity begins at index 0 and its ';' is at/after the limit:
                # no entity-safe cut exists at or before the limit. Cut after
                # the whole entity so it stays intact.
                cut = semi + 1
            # else: an unterminated '&' at index 0 (only possible for input
            # not produced by html.escape) — fall through with cut = limit.
    return cut


def _next_cut(s: str, limit: int) -> int:
    """Pick the next boundary in `s`, preferring paragraph/newline/space."""
    if len(s) <= limit:
        return len(s)
    for sep in ("\n\n", "\n", " "):
        idx = s.rfind(sep, 0, limit)
        if idx != -1:
            return _safe_cut(s, idx + len(sep))
    return _safe_cut(s, limit)


def _chunk_escaped(escaped: str, limit: int) -> list[str]:
    """Split already-escaped text into pieces nominally of at most `limit` chars.

    A piece never splits an HTML entity. Since ``_safe_cut`` keeps an entity
    whole even when a single entity is longer than ``limit``, a piece can exceed
    ``limit`` only in that degenerate tiny-limit case (entities are at most 5
    characters). It also guarantees an entity-aligned, positive cut, so the
    guard below is defensive only: it preserves forward progress if that
    invariant is ever broken rather than spinning forever.
    """
    if limit <= 0:
        raise ValueError("chunk limit must be positive")
    parts: list[str] = []
    start = 0
    length = len(escaped)
    while start < length:
        cut = _next_cut(escaped[start:], limit)
        if cut <= 0:
            # Defensive: never stall on a pathological boundary.
            cut = min(limit, length - start)
        parts.append(escaped[start:start + cut])
        start += cut
    return parts


def _raw_count_for_escaped(text: str, escaped_len: int) -> int:
    """Count raw input chars that produce `escaped_len` escaped characters.

    Our cuts always land on an entity boundary, so `escaped_len` falls exactly
    between escape units and the count is exact, never an estimate.
    """
    total = 0
    raw = 0
    for ch in text:
        unit = html.escape(ch, quote=False)
        if total + len(unit) > escaped_len:
            break
        total += len(unit)
        raw += 1
    return raw


def _truncation_suffix(raw_remaining: int) -> str:
    """Marker naming how many RAW input characters could not be floated."""
    return f"… +{raw_remaining:,} {_TRUNCATION_UNIT} not floated"


def _build_parts(text: str, escaped: str) -> tuple[list[str], int, int]:
    """Split escaped text into Telegram-sized parts, adding markers.

    Returns ``(parts, total, dropped_raw)``. A single part is returned
    marker-free. Multiple parts are prefixed ``[i/n] ``. If more than
    ``_MAX_PARTS`` parts would be needed, the first ``_MAX_PARTS`` are returned,
    the last one carries an explicit marker naming the raw characters that were
    not floated, and ``dropped_raw`` is that count (0 when nothing was dropped).
    """
    if len(escaped) <= _CHUNK_LIMIT:
        return [escaped], 1, 0

    marker_only_limit = _CHUNK_LIMIT - _marker_len(_MAX_PARTS)
    base = _chunk_escaped(escaped, marker_only_limit)

    if len(base) <= _MAX_PARTS:
        total = len(base)
        return [f"[{i}/{total}] {p}" for i, p in enumerate(base, 1)], total, 0

    # Over the ceiling: send the first _MAX_PARTS. Reserve room for the widest
    # possible truncation marker when deciding how much of the last part fits,
    # so the final payload never exceeds the per-part budget either.
    total = _MAX_PARTS
    head = base[:_MAX_PARTS]
    raw_total = len(text)
    max_suffix = len(_truncation_suffix(raw_total))
    last_limit = marker_only_limit - max_suffix
    if last_limit < 1:
        last_limit = 1
    if len(head[-1]) > last_limit:
        cut = _safe_cut(head[-1], last_limit)
        if cut <= 0:
            cut = min(last_limit, len(head[-1]))
        head[-1] = head[-1][:cut]

    floated_escaped = sum(len(p) for p in head)
    floated_raw = _raw_count_for_escaped(text, floated_escaped)
    remaining_raw = raw_total - floated_raw

    parts = [f"[{i}/{total}] {p}" for i, p in enumerate(head, 1)]
    parts[-1] += _truncation_suffix(remaining_raw)
    return parts, total, remaining_raw


def _http_error_detail(exc: urllib.error.HTTPError, bot: Any) -> str:
    """Extract Telegram's own description from an HTTPError body when present.

    Never uses ``repr(exc)``: its string form embeds the request URL, which
    contains the bot token. Both the description and the fallback status/reason
    phrase are passed through ``_redact`` — a server-supplied reason phrase can
    equally carry the token-bearing URL.
    """
    body = ""
    try:
        raw = exc.read()
        if raw:
            body = raw.decode("utf-8", errors="replace")
    except Exception:
        body = ""
    if body:
        try:
            parsed = json.loads(body)
            description = parsed.get("description") if isinstance(parsed, dict) else None
            if description:
                return _redact(str(description), bot)
        except (ValueError, TypeError):
            pass
    return _redact(f"HTTP {exc.code} {exc.reason}", bot)


def _log_part_failure(
    log: logging.Logger, idx: int, total: int, detail: str, kind: str = "transport"
) -> None:
    """Log a part failure, naming what was delivered and what was skipped.

    ``kind`` distinguishes a Telegram rejection (HTTP 200 with ``ok:false``)
    from an HTTP or transport failure, so the operator can tell which happened.
    """
    remaining = total - idx
    if idx > 1:
        log.error(
            "Float part %d/%d failed (%s): %s; parts 1-%d delivered, "
            "%d remaining not attempted",
            idx, total, kind, detail, idx - 1, remaining,
        )
    else:
        log.error(
            "Float part %d/%d failed (%s): %s; no parts delivered, "
            "%d remaining not attempted",
            idx, total, kind, detail, remaining,
        )


def send(text: str, sender_name: str = "hermes-agent", config: dict[str, Any] | None = None) -> None:
    """Send a float message to the sender's Telegram DM.

    Args:
        text: The message text to send (already padded with mesh header).
        sender_name: The calling agent's name (for diagnostics, not delivery).
        config: Optional config dict with telegram_bot_token / telegram_default_chat_id.
    """
    try:
        bot, chat = _resolve_credentials(config)
    except Exception:
        # A malformed config must never escape: the float is best-effort.
        logger.error("Float delivery error: could not resolve Telegram credentials")
        return
    if not bot or not chat:
        logger.debug("Float skipped: missing Telegram credentials (bot=%s, chat=%s)",
                     bool(bot), bool(chat))
        return

    if not isinstance(text, str):
        # text.strip() would raise on a non-str; the old code only caught this
        # because html.escape ran inside the try. Keep send() exception-free.
        logger.error("Float delivery error: text must be str, got %s", type(text).__name__)
        return
    if not text.strip():
        logger.debug("Float skipped: empty or whitespace-only text")
        return

    # NOTE: Telegram's HTTP API requires the bot token in the request path.
    # This is a residual limitation of Telegram itself; traffic between the
    # gateway and Telegram is HTTPS, but proxies/TLS inspection that terminate
    # the connection can still observe the token. We redact it from logs below.
    url = f"https://api.telegram.org/bot{bot}/sendMessage"
    try:
        # Escape exactly once. quote=False is safe here because the payload is
        # element text, never an attribute value: quotes carry no markup
        # meaning, and escaping them would only inflate the payload further
        # toward Telegram's cap. All chunk length math is on this escaped form.
        escaped = html.escape(text, quote=False)
        parts, total, dropped_raw = _build_parts(text, escaped)
    except Exception as e:
        logger.error("Float delivery error: %s", _redact(str(e), bot))
        return

    if dropped_raw:
        # Make truncation visible to the operator, not only in the Telegram
        # body: over-ceiling messages silently report total=_MAX_PARTS.
        logger.warning(
            "Float message truncated at ceiling: sent %d parts (max %d), "
            "%s %s not floated",
            total, _MAX_PARTS, f"{dropped_raw:,}", _TRUNCATION_UNIT,
        )

    # Bound the whole loop, not just each request: up to _MAX_PARTS sequential
    # requests could otherwise stall a synchronous mesh_send. Each request's
    # socket timeout is clamped to the remaining budget so the total stays
    # bounded, and exhausting the budget stops further parts loudly.
    deadline = time.monotonic() + _SEND_WALL_BUDGET_S
    for idx, part in enumerate(parts, start=1):
        remaining_budget = deadline - time.monotonic()
        if remaining_budget <= 0:
            logger.error(
                "Float send aborted at part %d/%d: %.0fs wall budget exhausted "
                "after %d part(s) delivered; remaining parts not attempted",
                idx, total, _SEND_WALL_BUDGET_S, idx - 1,
            )
            return
        payload = {
            "chat_id": chat,
            "text": part,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(
                req, timeout=min(_HTTP_TIMEOUT_S, remaining_budget)
            ) as resp:
                body = resp.read().decode()
                result = json.loads(body)
                if not result.get("ok"):
                    # A 200 with ok=false is a Telegram rejection, distinct
                    # from a transport failure. Report it loudly and stop
                    # rather than hammering the API for the remaining parts.
                    detail = _redact(str(result.get("description", "unknown")), bot)
                    _log_part_failure(logger, idx, total, detail, kind="rejected")
                    return
                logger.debug("Float part %d/%d sent to %s: %d chars", idx, total, chat, len(part))
        except urllib.error.HTTPError as e:
            # Includes 429: log with the part index and stop. Never retry.
            # HTTPError may include the full URL (with the secret bot token) in
            # its string form, so only the (redacted) status/reason/description
            # is logged.
            detail = _http_error_detail(e, bot)
            if e.code == 429:
                # Avoid 'HTTP 429 rate limited: HTTP 429 ...' duplication when
                # the detail already carries the status line.
                prefix = f"HTTP {e.code} "
                if detail.startswith(prefix):
                    detail = detail[len(prefix):]
                detail = f"HTTP 429 rate limited: {detail}"
            _log_part_failure(logger, idx, total, detail, kind="http")
            return
        except Exception as e:
            _log_part_failure(
                logger, idx, total, _redact(str(e), bot), kind="transport"
            )
            return
