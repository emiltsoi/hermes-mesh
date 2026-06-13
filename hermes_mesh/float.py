"""Telegram float transport for Hermes mesh.

Fire-and-forget notification to the sender's Telegram DM. Best-effort —
failures are logged and swallowed; the tool result is the source of truth.

Env var chain: HERMES_TELEGRAM_BOT_TOKEN → A2A_TELEGRAM_BOT_TOKEN → TELEGRAM_BOT_TOKEN
"""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)


def _resolve_credentials() -> tuple[str, str]:
    """Resolve bot_token and chat_id from env vars. Returns ("", "") if absent."""
    bot = (
        os.getenv("HERMES_TELEGRAM_BOT_TOKEN")
        or os.getenv("A2A_TELEGRAM_BOT_TOKEN")
        or os.getenv("TELEGRAM_BOT_TOKEN", "")
    )
    chat = (
        os.getenv("HERMES_TELEGRAM_DEFAULT_CHAT_ID")
        or os.getenv("A2A_TELEGRAM_DEFAULT_CHAT_ID")
        or os.getenv("TELEGRAM_HOME_CHANNEL", "")
    )
    return bot, chat


def send(text: str, sender_name: str = "hermes-agent") -> None:
    """Send a float message to the sender's Telegram DM.

    Args:
        text: The message text to send (already padded with mesh header).
        sender_name: The calling agent's name (for diagnostics, not delivery).
    """
    bot, chat = _resolve_credentials()
    if not bot or not chat:
        logger.debug("Float skipped: missing Telegram credentials (bot=%s, chat=%s)",
                     bool(bot), bool(chat))
        return

    url = f"https://api.telegram.org/bot{bot}/sendMessage"
    payload = {
        "chat_id": chat,
        "text": text,
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
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode()
            result = json.loads(body)
            if not result.get("ok"):
                logger.debug("Float delivery failed: %s", result.get("description", "unknown"))
            else:
                logger.debug("Float sent to %s: %d chars", chat, len(text))
    except Exception as e:
        logger.debug("Float delivery error: %s", e)
