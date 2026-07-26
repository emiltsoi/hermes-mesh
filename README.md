# hermes-mesh

**Agent-to-agent session relay for Hermes fleet agents.**

Standard A2A is request/response — fine for one-shot jobs, inadequate for
conversational fleet coordination. `hermes-mesh` adds session-preserving
communication: when one agent dispatches to another, the recipient knows
who asked, what they're responding to, and what action to take.

## Tools

- `mesh_list` — list all agents in the fleet mesh vault.
- `mesh_register` — register or update an agent identity in the fleet mesh vault.
- `mesh_send` — send a session-preserving message to another fleet agent.

```
Caller: mesh_send(agent="britney", message="Review this plan")
  │
  ├─ 1. Resolves Britney's identity from the fleet vault
  ├─ 2. Pads [mesh][from:linda][to:britney][id:uuid][action:do][reply:yes]
  ├─ 3. HMAC-SHA256 signs with the sender's own secret
  └─ 4. POSTs to Britney's mesh adapter endpoint
```

Britney's gateway receives the message on its `mesh` platform adapter,
routes it into her active session, and she sees it as an inbound mesh
trigger with full sender context.

`mesh_send` returns `{"state": "completed", "status": "delivered", ...}` on
success, with `message_id` and `task_id` populated.

## What it does NOT do

This plugin is a **mesh layer**, not a full A2A implementation. Standard A2A
operations (discover, call, serve, JSON-RPC, Agent Cards) are handled by the
[hermes-agent-a2a plugin](https://github.com/emiltsoi/hermes-agent-a2a), which
provides Google A2A 1.0 compliance. The upstream `hermes-agent` core does not
provide A2A support.

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

### 1. Enable the mesh platform adapter

Add `hermes-mesh` to `plugins.enabled` and enable the `mesh` platform in
`config.yaml`:

```yaml
plugins:
  enabled:
    - hermes-mesh

platforms:
  mesh:
    enabled: true
    extra:
      port: 8744
      secret: <mesh-adapter-hmac-secret>
      route: receive          # listens on /mesh/receive
      agent_name: agent0      # local agent name
      target_session: "telegram:dm:<chat_id>"  # optional session routing
```

Each agent's gateway should listen on its own mesh port. The default port
is `8645`.

### 2. Set up fleet identity

Each agent needs an identity in `$HERMES_HOME/fleet/mesh/agents/<name>/identity.yaml`
(legacy `fleet/a2a/agents` is also checked, but `hermes-mesh` targets use the
mesh adapter URL):

```yaml
id: britney
name: britney
description: Principal SWE — Orchestrator
transports:
  hermes_webhook:
    protocol: hermes-webhook
    url: http://127.0.0.1:8745/mesh/receive
    auth:
      type: hmac-sha256
      secret: <britney-mesh-adapter-secret>
```

The `hermes_webhook.url` must point at the target agent's mesh adapter
endpoint (`/mesh/<route>`). The `hermes_webhook.auth.secret` is the
**target's** adapter secret; messages are signed with the **sender's**
own secret for per-agent HMAC authentication.

### 3. Register local agents

You can also register identities at runtime:

```bash
mesh_register(name="britney", url="http://127.0.0.1:8745/mesh/receive", secret="...", role="agent")
```

### 4. Environment

```bash
export MESH_AGENT_NAME=linda            # Who the sender is
export MESH_WEBHOOK_DELIVERY_RETRIES=3  # Delivery retry count
export MESH_WEBHOOK_DELIVERY_BACKOFF=1  # Initial retry backoff in seconds
export MESH_WEBHOOK_DELIVERY_TIMEOUT=5  # Per-attempt timeout
export TELEGRAM_BOT_TOKEN=...           # For float delivery
export TELEGRAM_HOME_CHANNEL=...        # Where floats go
```

`A2A_*` names (`A2A_AGENT_NAME`, `A2A_WEBHOOK_DELIVERY_RETRIES`, etc.) are
still accepted as fallbacks for backward compatibility.

## CTA Protocol

Messages carry a 2D Call To Action in the header:

| Field  | Values | Meaning |
|--------|--------|---------|
| action | `do`   | Recipient should take action |
|        | `info` | Informational — acknowledge |
| reply  | `yes`  | Sender expects a reply |
|        | `no`   | Fire-and-forget |

## Relationship to hermes-agent-a2a

`hermes-mesh` replaces the mesh functionality of the now-archived `hermes-agent-a2a` plugin.
Standard A2A (discover, call, serve, Agent Cards, JSON-RPC, security) is
provided by the [hermes-agent-a2a plugin](https://github.com/emiltsoi/hermes-agent-a2a);
the upstream `hermes-agent` core does not include A2A support.

The old plugin's `a2a_send_session_message` is the genesis of this project —
a focused, dependency-light extraction of the only unique feature the old
plugin had that the upstream standard doesn't cover.

## License

MIT — see [LICENSE](LICENSE).
