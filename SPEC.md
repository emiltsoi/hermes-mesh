# hermes-mesh — SPEC

## What

Session-aware mesh relay for Hermes fleet agents. Builds on top of the
[standard Hermes A2A platform adapter](https://github.com/NousResearch/hermes-agent)
to add fleet-specific session routing, identity resolution, and gateway float.

**The standard A2A plugin handles:** discover, call, serve Agent Cards, JSON-RPC,
bearer auth, injection filters, audit logging.

**hermes-mesh adds:** `a2a_send_session_message` — route a message into another
fleet agent's live gateway session with full sender context preserved.

## Why

Standard A2A is request/response — fine for one-shot jobs, inadequate for
conversational fleet coordination. When an agent dispatches to another
mid-conversation, the recipient needs to know:

- Who asked (sender identity)
- What message they're responding to (threading)
- What action to take (CTA: do/info)
- Whether a reply is expected

The mesh layer provides this context through a structured message header and
gateway hook delivery that routes into the target agent's active session.

## Architecture

```
Caller Agent
  └─ a2a_send_session_message(agent="britney", message="...")
       │
       ├─ 1. Resolve target identity from fleet vault
       │     (hermes_root/profiles/<name>/a2a/vault.yaml)
       │
       ├─ 2. Build padded message with mesh metadata header:
       │     [a2a][from:linda][to:britney][id:uuid][action:do][reply:yes]
       │
       ├─ 3. HMAC-SHA256 sign + POST to target's hermes_webhook endpoint
       │
       └─ 4. Float: echo to sender's Telegram DM for visibility
```

## Fleet Identity Store

Agents are resolved from the vault:

```
$HERMES_HOME/fleet/a2a/agents/
  ├── britney/
  │   └── identity.yaml   ← name, transports.hermes_webhook.{url, auth.secret}
  ├── linda/
  │   └── identity.yaml
  └── ...
```

Each `identity.yaml`:
```yaml
id: linda
name: linda
description: Software Architect
transports:
  hermes_webhook:
    protocol: hermes-webhook
    url: http://127.0.0.1:8080/webhook
    auth:
      type: hmac-sha256
      secret: ${LINDA_WEBHOOK_SECRET}
```

## CTA Protocol

The mesh uses a 2D CTA (Call To Action) embedded in the message header:

| Field | Values | Meaning |
|-------|--------|---------|
| `action` | `do` | Recipient should take action |
|         | `info` | Informational — log or acknowledge |
| `reply`  | `yes` | Sender expects a reply |
|          | `no`  | Fire-and-forget |

## Scope Boundaries

**IN:** Session relay, fleet identity resolution, gateway hook float, CTA protocol
**OUT:** Standard A2A (discover, call, serve), JSON-RPC framing, Agent Cards, SSE,
push notifications, worker spawning, bearer auth, injection filters, rate limiting

Standard A2A is handled by the upstream Hermes A2A platform adapter.
This plugin is a mesh layer on top — it depends on that adapter but does not
re-implement it.

## Dependencies

- Hermes Agent with A2A platform adapter enabled
- Python stdlib + pyyaml + cryptography (Ed25519 identity signing)
- No external HTTP libraries (uses `urllib`)
