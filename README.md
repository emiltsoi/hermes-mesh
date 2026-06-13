# hermes-mesh

**Session-aware mesh relay for Hermes fleet agents.**

Standard A2A is request/response — fine for one-shot jobs, inadequate for
conversational fleet coordination. `hermes-mesh` adds session-preserving
communication: when one agent dispatches to another, the recipient knows
who asked, what they're responding to, and what action to take.

## What it does

One tool: `a2a_send_session_message`

```
Caller: a2a_send_session_message(agent="britney", message="Review this plan")
  │
  ├─ 1. Resolves Britney's identity from the fleet vault
  ├─ 2. Pads [a2a][from:linda][to:britney][id:uuid][action:do][reply:yes]
  ├─ 3. HMAC signs + POSTs to Britney's gateway webhook
  └─ 4. Echoes to sender's Telegram DM for visibility
```

Britney's gateway receives the message, routes it into her active session,
and she sees it as an inbound A2A trigger with full sender context.

## What it does NOT do

This plugin is a **mesh layer**, not a full A2A implementation. Standard A2A
operations (discover, call, serve, JSON-RPC, Agent Cards) are handled by the
[upstream Hermes A2A platform adapter](https://github.com/NousResearch/hermes-agent).

## Install

```bash
pip install hermes-mesh
```

Or from source:

```bash
git clone https://github.com/emiltsoi/hermes-mesh.git
cd hermes-mesh
pip install -e .
```

## Configure

### 1. Enable the A2A platform adapter in Hermes

The standard A2A plugin must be enabled — `hermes-mesh` builds on it.

### 2. Set up fleet identity

Each agent needs an identity in `$HERMES_HOME/fleet/a2a/agents/<name>/identity.yaml`:

```yaml
id: britney
name: britney
description: Principal SWE — Orchestrator
transports:
  hermes_webhook:
    protocol: hermes-webhook
    url: http://127.0.0.1:8081/webhook
    auth:
      type: hmac-sha256
      secret: ${BRITNEY_WEBHOOK_SECRET}
```

### 3. Environment

```bash
export A2A_AGENT_NAME=linda          # Who the sender is
export TELEGRAM_BOT_TOKEN=...         # For float delivery
export TELEGRAM_HOME_CHANNEL=...      # Where floats go
```

## CTA Protocol

Messages carry a 2D Call To Action in the header:

| Field  | Values | Meaning |
|--------|--------|---------|
| action | `do`   | Recipient should take action |
|        | `info` | Informational — acknowledge |
| reply  | `yes`  | Sender expects a reply |
|        | `no`   | Fire-and-forget |

## Relationship to hermes-agent-a2a

`hermes-mesh` replaces the mesh functionality of the now-archived
[hermes-agent-a2a](https://github.com/emiltsoi/hermes-agent-a2a) plugin.
Standard A2A (discover, call, serve, Agent Cards, JSON-RPC, security) is
now provided natively by the upstream Hermes A2A platform adapter.

The old plugin's `a2a_send_session_message` is the genesis of this project —
a focused, dependency-light extraction of the only unique feature the old
plugin had that the upstream standard doesn't cover.

## License

MIT — see [LICENSE](LICENSE).
