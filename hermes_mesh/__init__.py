"""Hermes Mesh — session-aware fleet relay plugin.

Registers a single tool: a2a_send_session_message.
Does NOT re-implement standard A2A — delegates to the upstream
Hermes A2A platform adapter for discover/call/serve.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

__all__ = ["register"]


def check_requirements() -> bool:
    """Mesh depends on Hermes core — always loadable."""
    return True


def validate_config(config) -> bool:
    """No required config — everything is env-var or vault-driven."""
    return True


def register(ctx) -> None:
    """Register the a2a_send_session_message tool with Hermes."""
    try:
        from .session_relay import handle_send_session_message

        ctx.register_tool(
            name="a2a_send_session_message",
            description=(
                "Send a one-way message through a target Hermes gateway into "
                "its configured platform session context. Auto-pads "
                "[a2a][from:<self>][to:<agent>][id:<uuid>][action:<action>]"
                "[reply:<reply>] header. Returns delivery status."
            ),
            handler=handle_send_session_message,
            toolset="a2a",
            parameters={
                "message": {
                    "type": "string",
                    "description": "The message body to send (header is auto-padded)",
                    "required": True,
                },
                "agent": {
                    "type": "string",
                    "description": "Name of the target Hermes mesh peer (e.g. daji, yoyo)",
                    "required": True,
                },
                "action": {
                    "type": "string",
                    "enum": ["do", "info"],
                    "description": "do (recipient should take action) | info (log/acknowledge)",
                    "default": "do",
                },
                "reply": {
                    "type": "string",
                    "enum": ["yes", "no"],
                    "description": "yes (sender expects reply) | no (fire-and-forget)",
                    "default": "yes",
                },
                "ref": {
                    "type": "string",
                    "description": "Optional message ID being replied to (for threading)",
                },
                "task_id": {
                    "type": "string",
                    "description": "Optional task ID override (auto-generated if omitted)",
                },
            },
        )
        logger.info("Hermes Mesh: registered a2a_send_session_message tool")
    except Exception:
        logger.warning("Hermes Mesh: failed to register tool", exc_info=True)
