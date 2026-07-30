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
      secret: true            # auth-enable sentinel; HMAC keys are per-agent in the fleet vault
      route: receive          # listens on /mesh/receive
      agent_name: agent0      # local agent name
      target_session: "telegram:dm:<chat_id>"  # optional session routing
      telegram_bot_token: "..."            # optional: source for float messages
      telegram_default_chat_id: "..."     # optional: source for float messages
```

Each agent's gateway should listen on its own mesh port. The default port
is `8645`.

### 2. Set up fleet identity

Each agent needs an identity in `$HERMES_HOME/fleet/mesh/agents/<name>/identity.yaml`:

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

Mesh delivery is one-way inbound into the target agent's session. If the
agent generates a reply, the platform `send()` call is intentionally a
no-op; the agent must explicitly call `mesh_send(agent="...", message="...")`
to send a response back through the mesh.

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
export MESH_REGISTER_ALLOW_LOOPBACK=0   # Set to 1 to let mesh_register store loopback URLs
export MESH_IDENTITY_CACHE_TTL=1.0      # Identity YAML cache TTL in seconds
```



## Envelope format

Every `mesh_send` carries a `[mesh]` header on the wire:

```text
[mesh][from:<sender>][to:<recipient>][id:<uuid>][action:<do|info>][reply:<yes|no>] ...
```

The `[mesh]` prefix is the canonical format. All mesh peers, including OpenClaw, must send `[mesh]` envelopes.

## Use Cases

All of these patterns are powered by `mesh_send` — the session relay tool that delivers a message into a target agent's live conversation context with full thread continuity. No polling, no separate worker process, no context loss.

### Background agents that wake on schedule

You want an agent to do work while you're not watching — poll a feed, check a system, prepare a daily briefing. Most agent frameworks solve this with a separate daemon or polling loop.

The Hermes mesh approach: the agent's session *is* the ambient worker. A cron job fires `mesh_send` → routes into the agent's live session → agent wakes with full context intact → acts → replies via the mesh.

```
Cron tick fires
     │
     ▼
mesh_send → agent's live session
     │
     ▼
Agent session wakes. Full conversation history available.
Agent reads the mesh message, acts, replies.
     │
     ▼
Reply routes back through the mesh to the caller.
```

No separate worker daemon. No polling. The agent was sleeping — its session was idle. The schedule woke it via `mesh_send`. When it finishes, it goes back to sleep. The session persists so the next wake has full context from the previous run.

What this enables: daily digests compiled by 7am, monitoring agents that alert only on change, background research that accumulates context over days and delivers when ready.

### Specialist chain — humans curate, agents specialize

A complex task needs architecture thinking, domain discovery, and implementation planning. You could throw it all at one agent, but specialists are better.

The Hermes mesh approach: talk to three different agents in sequence via `mesh_send`, each building full context independently. When you reach execution, you have three expert perspectives — not one confused generalist.

```
You → mesh_send → Isa (Discovery)
     ← structured findings with full codebase context

You → mesh_send → Britney (Architecture)
     ← architecture proposal grounded in Isa's actual findings

You → mesh_send → Linda (Design Review)
     ← signed-off design with coupling and failure mode analysis

You → Merge all three perspectives → Claude Code executes with full specialist context
```

Each agent maintained a fully-persistent session. Isa's context is complete — she was inside the codebase, she knows what she found and what she dismissed. Britney responds to Isa's actual findings. Linda reviews the real architecture, not a paraphrase. All routing happens via `mesh_send` through the mesh — the user never leaves their own interface.

The human is the curator: deciding which specialist to consult, in what order, when to stop prep and start executing.

What this enables: multi-domain tasks handled by actual specialists rather than a single LLM acting as all of them, quality-gated workflows where each specialist signs off before the next stage, reduced hallucination because each specialist's claims are grounded in their own exploration.

### Specialist injection — agents loop in specialists mid-chain

During any relay chain, an agent can pull in a specialist via `mesh_send` without restarting or losing context. The chain pauses, the specialist responds, their output flows back in, the chain continues.

```
Britney → mesh_send → Linda (design review)
    │
    Linda detects a coupling issue that spans Isa's domain
    │
    Linda → mesh_send → Isa: "What's the import graph for module X?"
    Isa responds with the graph
    │
    Linda folds Isa's data into the review
    Linda → mesh_send → Britney: "Approved, with one routing change"
```

The human didn't know to call Isa — Linda did it because the mesh discipline says: wrong domain, route first. No context loss, no chain restart, no paraphrase. The specialist consultation is invisible to the caller.

What this enables: agents that self-correct by consulting the right specialist when they hit a domain boundary, chains that get smarter as they run without human intervention, context that flows through the right expert regardless of who initiated the chain.

### Parallel specialist prep — all at once, not one at a time

Same result as the specialist chain, but run in parallel instead of sequence. All three calls to `mesh_send` fire simultaneously — each agent works in isolation with a complete session, none waiting for the others.

```
You → mesh_send → Isa (discovery)    ─┐
You → mesh_send → Britney (arch)     ─┤
You → mesh_send → Linda (review)     ─┘
     All three act in parallel
     │
     ▼
You receive three independent, fully-contextual responses
Merge → Claude Code executes
```

Each agent had an uninterrupted, complete session. None of them know about the others until you merge the outputs. The context never got diluted by multitasking — every specialist worked in isolation and delivered a finished result.

What this enables: same quality as sequential specialist prep in a fraction of the time, agents that work at their own pace without blocking each other, human curator assembles the final output from complete specialist perspectives rather than watching a generalist try to do three things at once.

## The Mesh: Session-Aware Fleet Messaging

This is the main thing that makes Hermes fleets different from standard A2A.

**Standard A2A is orchestration:** one agent delegates a task to another, gets a result back, continues. The relationship is client → worker. Context doesn't persist between turns.

**Hermes mesh is teamwork:** agents hold conversations across sessions, preserve sender context (sender name, message ID being replied to), and route replies through the mesh by convention. Britney can ask Linda a question mid-dispatch and get a threaded reply back — when both agents follow the mesh discipline documented below.

`mesh_send` is the mesh bridge. The envelope carries sender context — sender name and the message ID being replied to — so the recipient's LLM sees exactly who asked and what they're responding to. Thread continuity within the mesh is preserved by agent discipline, not protocol enforcement: agents agree to route replies through `mesh_send` back to the sender. This is intentional — convention-based coordination lets agents exercise judgment rather than follow mechanical rules. The fleet's organic interactions (escalation instead of reflex-loop, context-aware routing) emerge from this flexibility.

**In a multi-owner or adversarial deployment, this model is insufficient.** A protocol-level mechanism would be needed. `X-Fleet-Hops` (for 1-1 task exchange) could address reflexive loops there; mesh multi-party discussions have no loop problem since each agent routes independently.

This is not a webhook relay. It's a session-to-session handoff where the envelope does the routing work.

**What this enables:**
- Agents that work as a team, not just a delegation chain
- Cross-fleet coordination without either side needing to know internal topology
- Thread-preserving conversations between agents that outlive a single task
- Mesh discipline: domain routing, reply accountability, full context preserved

**Google A2A support** is provided by the separate [hermes-agent-a2a](https://github.com/emiltsoi/hermes-agent-a2a) plugin for external A2A JSON-RPC onboarding. The mesh session relay is a separate transport layer.

### Mesh Discipline: The CTA Protocol

Every `mesh_send` carries a **CTA** (Call To Action) that tells the recipient what to do with it:

| Field | Values | Meaning |
|-------|--------|---------|
| `action` | `do` \| `info` | `do`: act on this message. `info`: log/acknowledge only |
| `reply` | `yes` \| `no` | `yes`: sender expects a reply. `no`: fire-and-forget |

**Combinations:**
- `action=do + reply=yes`: take action, then reply with result
- `action=do + reply=no`: act on it, no reply needed
- `action=info + reply=yes`: acknowledge and reply when done processing
- `action=info + reply=no`: acknowledge only, no reply needed

**Reply rule:** All mesh replies use `mesh_send` back to the originating peer — not a plain Telegram DM or platform DM. Plain DMs break thread continuity. The mesh handles the return path.

**Agent prompt for mesh discipline:**

> When you receive a mesh message:
> 1. Read the CTA — `action` tells you what to do, `reply` tells you whether to respond
> 2. If `reply=yes`: respond via `mesh_send` back to the sender, using the same message ID as a reference (`ref` field)
> 3. Never reply via plain Telegram DM or platform DM — always route through the mesh so the reply carries your full context and reaches the correct thread
> 4. If you need to route the message to another agent first (wrong domain), do so immediately — don't hold it
> 5. If the CTA is ambiguous, reply=yes is the safe default

**Example — Britney dispatches to Linda:**

```python
mesh_send(
    message="Linda, review PR #123 before I merge. Link: https://github.com/...",
    agent="linda",
    action="do",
    reply="yes"
)
# Linda's session receives it attributed to Britney.
# Linda's reply routes back through the mesh to Britney's session.
```

**Example — Linda acknowledges without replying:**

```python
mesh_send(
    message="Routing to Britney — she owns SWE dispatch.",
    agent="britney",
    action="info",
    reply="no"
)
# Britney receives the update; Linda has already forwarded.
```

### Session Float via Webhook Delivery

The primary session relay mechanism is webhook delivery: `mesh_send` POSTs the `[mesh]` envelope to the target agent's `hermes_webhook` URL (e.g. `http://.../mesh/receive`), HMAC-SHA256 signed with the **sender's** own secret. The target gateway receives the webhook on its `mesh` platform adapter and routes it into the configured session. This works without any extra hook handler registered.

`hermes-mesh` also sends a best-effort Telegram float to the sender's `TELEGRAM_HOME_CHANNEL` when `TELEGRAM_BOT_TOKEN` is set. The float is fire-and-forget; the tool result reflects the webhook delivery status, not the float.

## Relationship to hermes-agent-a2a

`hermes-mesh` and `hermes-agent-a2a` are separate plugins.
Standard A2A (discover, call, serve, Agent Cards, JSON-RPC, security) is
provided by the [hermes-agent-a2a plugin](https://github.com/emiltsoi/hermes-agent-a2a);
the upstream `hermes-agent` core does not include A2A support.

`hermes-mesh` carries the `[mesh][from:...][to:...]` envelope, per-agent HMAC
authentication, and the `fleet/mesh/agents` vault. The two identity stores
are now fully independent.

## OpenClaw interoperability

Hermes agents are not the only mesh participants. The companion
[openclaw-mesh](https://github.com/emiltsoi/openclaw-mesh) plugin turns an
OpenClaw agent into a full mesh peer using the same vault format, envelope
format, and HMAC scheme.

A Hermes agent can `mesh_send(agent="emts", message="...")` and an OpenClaw
agent receives the full `[mesh]` envelope with sender identity, action, reply
intent, and thread id. Replies flow back the same way. Both agents keep the
session context — who asked, what they asked for, and whether a reply is
expected — across the Hermes/OpenClaw boundary.

## Testing

`hermes-mesh` is a Hermes plugin and its adapter imports `gateway.*` modules from the
`hermes-agent` package. When running the test suite outside the agent repository, add
the `hermes-agent` source tree to `PYTHONPATH`:

```bash
PYTHONPATH=/path/to/hermes-mesh:/path/to/hermes-agent pytest tests/test_mesh.py -q
```

For example, with a default install:

```bash
PYTHONPATH=/home/emil/CascadeProjects/hermes-mesh:/home/emil/.hermes/hermes-agent \
  pytest tests/test_mesh.py -q
```

This coupling is expected while the project remains a plugin rather than a
standalone library.

## License

MIT — see [LICENSE](LICENSE).
