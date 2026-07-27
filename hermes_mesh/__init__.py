"""Hermes Mesh — session-aware fleet relay plugin.

Registers tools: mesh_list, mesh_register, mesh_send.
Does NOT re-implement standard A2A — delegates to the upstream
Hermes A2A platform adapter for discover/call/serve.
"""
from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

__all__ = ["register"]


def validate_config(config) -> bool:
    """Require a mesh HMAC secret (or INSECURE_NO_AUTH for loopback testing)."""
    if config is None or not hasattr(config, "extra"):
        logger.error("Hermes Mesh: missing platform config")
        return False
    secret = config.extra.get("secret", "")
    if not secret:
        logger.error(
            "Hermes Mesh: platforms.mesh.extra.secret is required; "
            "use INSECURE_NO_AUTH only on loopback for local testing"
        )
        return False
    return True


def _json_dump_handler(handler):
    """Wrap a handler that returns a dict so the tool registry sees a JSON string."""
    def wrapper(*args, **kwargs):
        result = handler(*args, **kwargs)
        if isinstance(result, dict):
            return json.dumps(result)
        return result
    return wrapper


def register(ctx) -> None:
    """Register the mesh tools and platform adapter with Hermes."""
    from .session_relay import handle_mesh_list, handle_mesh_register, handle_mesh_send

    ctx.register_tool(
        name="mesh_list",
        toolset="mesh",
        schema={
            "name": "mesh_list",
            "description": "List all agents registered in the fleet mesh vault.",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
        handler=_json_dump_handler(handle_mesh_list),
    )

    ctx.register_tool(
        name="mesh_register",
        toolset="mesh",
        schema={
            "name": "mesh_register",
            "description": (
                "Register or update an agent identity in the fleet mesh vault. "
                "Requires name, url, and secret."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Agent name (defaults to MESH_AGENT_NAME env var)",
                    },
                    "url": {
                        "type": "string",
                        "description": "Hermes webhook URL for this agent",
                    },
                    "secret": {
                        "type": "string",
                        "description": "Shared HMAC secret for this agent",
                    },
                    "role": {
                        "type": "string",
                        "description": "Role description",
                        "default": "agent",
                    },
                    "description": {
                        "type": "string",
                        "description": "Human-readable agent description",
                        "default": "",
                    },
                    "overwrite": {
                        "type": "boolean",
                        "description": "Overwrite existing identity",
                        "default": False,
                    },
                },
                "required": ["url", "secret"],
            },
        },
        handler=_json_dump_handler(handle_mesh_register),
    )

    ctx.register_tool(
        name="mesh_send",
        toolset="mesh",
        schema={
            "name": "mesh_send",
            "description": (
                "Send a one-way message through a target Hermes gateway into "
                "its configured platform session context. Auto-pads "
                "[mesh][from:<self>][to:<agent>][id:<uuid>][action:<action>]"
                "[reply:<reply>] header. Returns delivery status."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "The message body to send (header is auto-padded)",
                    },
                    "agent": {
                        "type": "string",
                        "description": "Name of the target Hermes mesh peer (e.g. daji, yoyo)",
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
                "required": ["message", "agent"],
            },
        },
        handler=_json_dump_handler(handle_mesh_send),
    )
    logger.info("Hermes Mesh: registered mesh tools")

    from .adapter import MeshAdapter, check_mesh_requirements

    ctx.register_platform(
        name="mesh",
        label="Hermes Mesh",
        adapter_factory=lambda cfg: MeshAdapter(cfg),
        check_fn=check_mesh_requirements,
        validate_config=validate_config,
        emoji="🕸️",
    )
    logger.info("Hermes Mesh: registered mesh platform adapter")
