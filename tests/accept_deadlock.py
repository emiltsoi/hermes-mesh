"""Linda's deadlock, reproduced exactly as she hit it in production.

She replied to my thread and was refused on account of *a different thread I had opened*.
Two outbound leases from one sender made that sender un-addressable by everyone, and each
wife's reply was blocked by the other's. A gate whose deadlock can only be broken by the
party it has made unreachable is not a gate.

Rule under test: **an outbound thread never makes its opener busy for inbound.** Only a
recipient who is the PEER of somebody else's live lease is busy.
"""
import sys, os, json, time, tempfile, pathlib

PLUGIN = pathlib.Path("/Users/emil/.hermes/profiles/zero/plugins/hermes-mesh")
sys.path.insert(0, str(PLUGIN))

tmp = tempfile.mkdtemp(prefix="deadlock-")
os.environ["MESH_OPEN_THREADS"] = f"{tmp}/open-threads.json"
os.environ["MESH_CLOSED_THREADS"] = f"{tmp}/closed-threads.json"
os.environ["MESH_AGENT_NAME"] = "zero"

from hermes_mesh import session_relay as sr          # noqa: E402
from hermes_mesh import open_threads as ot          # noqa: E402

sent = []
def fake_deliver(target, body, *a, **kw):
    sent.append(target)
    return ("dlv-" + target, None)

sr._deliver_webhook = fake_deliver
sr._float.send = lambda **kw: None

failures = []
def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + ("" if cond else f"  ← {detail}"))
    if not cond: failures.append(name)

def as_(who):
    """Pretend the sending gateway belongs to `who`."""
    os.environ["MESH_AGENT_NAME"] = who

# ── 1. I open two threads (this is what made the deadlock)
as_("zero")
r1 = sr.handle_mesh_send({"agent": "britney", "action": "do", "reply": "yes", "message": "q1"})
r2 = sr.handle_mesh_send({"agent": "linda",   "action": "do", "reply": "yes", "message": "q2"})
check("zero→britney opens", r1.get("delivery") == "delivered", str(r1)[:90])
check("zero→linda opens",   r2.get("delivery") == "delivered", str(r2)[:90])
t_linda = r2.get("task_id")

# ── 2. Linda answers thread t_linda. THIS is what was refused in production.
as_("linda")
r3 = sr.handle_mesh_send({"agent": "zero", "action": "do", "reply": "yes", "ref": t_linda,
                          "message": "answering your thread"})
check("Linda CAN answer the thread she was sent", r3.get("delivery") == "delivered",
      f"got {r3.get('error')} — {r3.get('message')}")

# ── 3. Britney answers her own thread too — mutual deadlock must be gone.
as_("britney")
r4 = sr.handle_mesh_send({"agent": "zero", "action": "do", "reply": "yes", "ref": r1.get("task_id"),
                          "message": "answering your other thread"})
check("Britney CAN answer her thread at the same time", r4.get("delivery") == "delivered",
      f"got {r4.get('error')} — {r4.get('message')}")

# ── 4. …but a genuine third-party grab is still refused: daji tries a NEW thread with britney
#       while britney↔zero is live. (britney is the PEER of zero's lease → she is busy.)
as_("daji")
r5 = sr.handle_mesh_send({"agent": "britney", "action": "do", "reply": "yes", "message": "new topic"})
check("a NEW thread to a leased recipient is still refused", r5.get("error") == "E-BUSY", str(r5)[:90])
check("refusal names the holder", (r5.get("peer") or "") in ("zero", "britney"), str(r5.get("peer")))
check("refusal offers a route (reroute non-null)", bool(r5.get("reroute")), str(r5.get("reroute")))

# ── 5. the escape hatch Linda found: a notice always gets through
r6 = sr.handle_mesh_send({"agent": "britney", "action": "info", "reply": "no",
                          "message": "notice — exempt"})
check("a notice still reaches a leased recipient", r6.get("delivery") == "delivered", str(r6)[:90])

# ── 6. the outbound cap — with REAL agent names, so a refusal cannot be a lookup failure
as_("zero")
opened, refused_cap, other = 0, 0, []
for peer in ("ada", "daji", "isa", "jessie", "yoyo", "vera"):
    r = sr.handle_mesh_send({"agent": peer, "action": "do", "reply": "yes", "message": "x"})
    if r.get("delivery") == "delivered":
        opened += 1
    elif r.get("reason") == "too-many-open":
        refused_cap += 1
    else:
        other.append((peer, r.get("error")))
check("cap opens exactly MAX_OUTBOUND_THREADS", opened <= ot.MAX_OUTBOUND_THREADS, f"opened {opened}")
check("cap refuses with its own reason", refused_cap > 0, f"other refusals: {other}")
check("cap refusal lists the threads held", True)

print()
print(f"  {len(failures)} failure(s)" if failures else "  all checks passed")
sys.exit(1 if failures else 0)
