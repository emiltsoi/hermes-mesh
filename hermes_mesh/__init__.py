"""Hermes Mesh — session-aware fleet relay plugin.

Registers tools: mesh_list, mesh_register, mesh_send, mesh_deregister, mesh_sync, mesh_publish.
Does NOT re-implement standard A2A — delegates to the upstream
Hermes A2A platform adapter for discover/call/serve.
"""
from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

__all__ = ["register"]


def validate_config(config) -> bool:
    """Require a mesh auth sentinel (or INSECURE_NO_AUTH for loopback testing)."""
    if config is None or not hasattr(config, "extra"):
        logger.error("Hermes Mesh: missing platform config")
        return False
    secret = config.extra.get("secret", "")
    if not secret:
        logger.error(
            "Hermes Mesh: platforms.mesh.extra.secret is required as an auth-enable sentinel; "
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


def _mesh_adapter_factory(cfg):
    """Lazily import MeshAdapter only when the platform is instantiated."""
    from .adapter import MeshAdapter

    return MeshAdapter(cfg)


def check_mesh_requirements() -> bool:
    """Check if mesh adapter dependencies are available, fail-closed."""
    try:
        from .adapter import check_mesh_requirements as _check

        return _check()
    except Exception:
        return False


def register(ctx) -> None:
    """Register the mesh tools and platform adapter with Hermes."""
    from .session_relay import (
        handle_mesh_deregister,
        handle_mesh_health,
        handle_mesh_list,
        handle_mesh_publish,
        handle_mesh_refresh_identities,
        handle_mesh_register,
        handle_mesh_send,
        handle_mesh_sync,
    )

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
                "Register or update an agent identity in the local mesh cache. "
                "Requires name and url. If public_key is omitted, an Ed25519 "
                "keypair is generated automatically."
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
                    "public_key": {
                        "type": "string",
                        "description": "Optional Ed25519 public key PEM. If omitted, one is generated.",
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
                    "dry_run": {
                        "type": "boolean",
                        "description": "Validate the request without writing",
                        "default": False,
                    },
                    "bulk": {
                        "type": "array",
                        "description": "Bulk register multiple agents at once",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string", "description": "Agent name"},
                                "url": {"type": "string", "description": "Hermes webhook URL"},
                                "public_key": {"type": "string", "description": "Optional Ed25519 public key PEM"},
                                "role": {"type": "string", "description": "Role"},
                                "description": {"type": "string", "description": "Description"},
                            },
                            "required": ["name", "url"],
                        },
                    },
                },
                "required": ["url"],
            },
        },
        handler=_json_dump_handler(handle_mesh_register),
    )

    ctx.register_tool(
        name="mesh_health",
        toolset="mesh",
        schema={
            "name": "mesh_health",
            "description": (
                "Return mesh health and metrics summary."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
        handler=_json_dump_handler(handle_mesh_health),
    )

    ctx.register_tool(
        name="mesh_refresh_identities",
        toolset="mesh",
        schema={
            "name": "mesh_refresh_identities",
            "description": (
                "Clear the identity cache and force the next lookup to read from disk."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
        handler=_json_dump_handler(handle_mesh_refresh_identities),
    )

    ctx.register_tool(
        name="mesh_deregister",
        toolset="mesh",
        schema={
            "name": "mesh_deregister",
            "description": (
                "Deregister an agent from the fleet mesh vault or registry. "
                "Requires name."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Agent name (defaults to MESH_AGENT_NAME env var)",
                    },
                },
                "required": [],
            },
        },
        handler=_json_dump_handler(handle_mesh_deregister),
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
                        "description": (
                            "REQUIRED. Semantics: info = log/acknowledge, no work "
                            "needed — use unless you need work done. do = recipient "
                            "should take action. Prefer info; reserve do for real work."
                        ),
                    },
                    "reply": {
                        "type": "string",
                        "enum": ["yes", "no", "end"],
                        "description": (
                            "REQUIRED. Semantics: no = fire-and-forget, no response "
                            "needed — use unless you need a response. yes = sender "
                            "expects a reply. end = terminal reply, closes the thread; "
                            "replies referencing its task_id are rejected THREAD_CLOSED. "
                            "Prefer no; reserve yes for genuine questions and end for closure."
                        ),
                    },
                    "ref": {
                        "type": "string",
                        "description": "Optional message ID being replied to (for threading)",
                    },
                    "task_id": {
                        "type": "string",
                        "description": "Optional task ID override (auto-generated if omitted)",
                    },
                    "session": {
                        "type": "string",
                        "description": "Optional target session name (session-selector 0.1.8). Routes to the receiver's mapped platform session; absent = the receiver's default (target_session).",
                    },
                    "from_session": {
                        "type": "string",
                        "description": "Optional originating session name (session-selector 0.1.8). The reply copies this as its session — use when replying to a message that carried [from_session:...].",
                    },
                },
                "required": ["message", "agent", "action", "reply"],
            },
        },
        handler=_json_dump_handler(handle_mesh_send),
    )

    ctx.register_tool(
        name="mesh_sync",
        toolset="mesh",
        schema={
            "name": "mesh_sync",
            "description": (
                "Sync one or all peer identities from the mesh-peer-registry to the local cache. "
                "If name is omitted, all peers are synced."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Optional agent name to sync",
                    },
                    "registry_url": {
                        "type": "string",
                        "description": "Optional registry URL override",
                    },
                },
            },
        },
        handler=_json_dump_handler(handle_mesh_sync),
    )

    ctx.register_tool(
        name="mesh_publish",
        toolset="mesh",
        schema={
            "name": "mesh_publish",
            "description": "Publish the local agent's identity to the mesh-peer-registry.",
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
                    "ttl": {
                        "type": "integer",
                        "description": "Optional TTL in seconds for registry entries",
                    },
                    "registry_url": {
                        "type": "string",
                        "description": "Optional registry URL override",
                    },
                },
                "required": ["url"],
            },
        },
        handler=_json_dump_handler(handle_mesh_publish),
    )
    logger.info("Hermes Mesh: registered mesh tools")

    ctx.register_platform(
        name="mesh",
        label="Hermes Mesh",
        adapter_factory=_mesh_adapter_factory,
        check_fn=check_mesh_requirements,
        validate_config=validate_config,
        emoji="🕸️",
    )
    logger.info("Hermes Mesh: registered mesh platform adapter")
