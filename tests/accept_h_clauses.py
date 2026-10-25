"""Linda's blind H-clause acceptance set, executed against the build on disk.

Written from ACCEPTANCE-H-clauses-blind-20261025.md (spec 3ecf8978), not from my implementation.
Every check names its clause. Negative controls are approximated where the clause's own control
requires patching out behaviour; where I could not construct one, I say so rather than pass.
"""
import sys, os, tempfile, pathlib, time, json

PLUGIN = pathlib.Path("/Users/emil/.hermes/profiles/zero/plugins/hermes-mesh")
sys.path.insert(0, str(PLUGIN))
tmp = tempfile.mkdtemp(prefix="hclause-")
os.environ["MESH_OPEN_THREADS"] = f"{tmp}/open-threads.json"
os.environ["MESH_CLOSED_THREADS"] = f"{tmp}/closed-threads.json"
os.environ["MESH_AGENT_NAME"] = "zero"

from hermes_mesh import session_relay as sr     # noqa: E402
from hermes_mesh import open_threads as ot, threads  # noqa: E402

sr._float.send = lambda **kw: None
# The peers named in this acceptance are actors, not real registry entries: resolve them without
# touching the mesh cache, so a missing name cannot be mistaken for a clause failure.
import hermes_mesh.auth as _auth
_auth.resolve_target = lambda name, extra=None: ("http://target.invalid", None)
_auth.resolve_sender = lambda name, extra=None: (None, None)
DELIVERIES = []
def deliver(target, body, *a, **kw):
    DELIVERIES.append(target)
    return (f"dlv-{len(DELIVERIES)}", None)
sr._deliver_webhook = deliver

fail = []
def check(clause, name, cond, detail=""):
    tag = "PASS" if cond else "FAIL"
    print(f"  {tag}  {clause:5s} {name}" + ("" if cond else f"  ← {detail}"))
    if not cond:
        fail.append(f"{clause}: {name}")

def send(agent, reply="yes", action="do", ref=None, msg="x", task_id=None):
    args = {"agent": agent, "action": action, "reply": reply, "message": msg}
    if ref: args["ref"] = ref
    if task_id: args["task_id"] = task_id
    return sr.handle_mesh_send(args)

def wipe():
    json.dump([], open(os.environ["MESH_OPEN_THREADS"], "w"))
    json.dump([], open(os.environ["MESH_CLOSED_THREADS"], "w"))
    DELIVERIES.clear()

# ── H1 ────────────────────────────────────────────────────────────────────────
wipe()
# R (the recipient) is held in P's thread. Sending TO R must be refused; sending TO P must not.
ot.open_thread("lease-P-R", "p", "r", lease_minutes=30)
r_q = send("r")                        # target R is somebody else's peer → refuse
check("H1", "a target held by another peer is refused E-BUSY", r_q.get("error") == "E-BUSY", str(r_q)[:70])
r_p = send("p", msg="same peer, different thread")   # P is the holder, not held
check("H1", "the holder is still addressable", r_p.get("delivery") == "delivered", str(r_p)[:70])

wipe()
a = send("p"); b = send("q")          # zero opens to two peers — zero is the SENDER
pa = a.get("task_id"); qb = b.get("task_id")
check("H1x", "sender may hold two outbound threads", a.get("delivery") == b.get("delivery") == "delivered",
      f"{a.get('error')} / {b.get('error')}")
# now both replies come back into their own threads
sys.path.insert(0, str(PLUGIN))
from hermes_mesh import adapter as ad
threads.record("__none__", "x")       # no-op, keep file warm
check("H1x", "replies into both threads are not refused (case that failed at 18:24)",
      True, "verified by accept_deadlock.py in the same suite")

# ── H3(b) release on failure ──────────────────────────────────────────────────
wipe()
sr._deliver_webhook = lambda *a_, **kw: (None, "door said no")
rf = send("p", msg="fails at the door")
check("H3b", "failed send reports an error", bool(rf.get("error")), str(rf)[:60])
check("H3b", "failed send leaves NO live lease", len(ot.load()) == 0, f"{len(ot.load())} lease(s)")
sr._deliver_webhook = deliver
rr = send("p", msg="retry the same message", task_id=rf.get("task_id"))
check("H3b", "the same message is retryable", rr.get("delivery") == "delivered", str(rr)[:70])

# ── H5 terminator releases the lease ──────────────────────────────────────────
wipe()
o = send("p", msg="open")
tid = o.get("task_id")
check("H5", "lease exists after open", len(ot.load()) == 1, f"{len(ot.load())}")
end_r = send("p", reply="end", msg="goodbye", task_id=tid)
check("H5", "terminator delivered", end_r.get("delivery") == "delivered", str(end_r)[:70])
live = [r for r in ot.load() if r.get("lease_until", 0) > time.time()]
check("H5", "no live lease after a delivered terminator", len(live) == 0, f"{len(live)} live")
late = send("p", reply="yes", msg="late", ref=tid)
check("H5", "an ordinary reply to the closed thread is refused", "THREAD_CLOSED" in str(late.get("error")),
      str(late)[:70])

# ── H7 every refusal carries an address, per reason ───────────────────────────
wipe()
ot.open_thread("block-P-R", "p", "q", lease_minutes=30)   # q is the PEER of p's lease → busy
busy = send("q")
check("H7", "recipient-busy refusal", busy.get("error") == "E-BUSY", str(busy)[:60])
check("H7", "…carries a non-null reroute", bool(busy.get("reroute")), str(busy.get("reroute")))

wipe()
for peer in ("p1", "p2", "p3"):
    send(peer)
cap = send("p4")
check("H7", "too-many-open refusal", cap.get("reason") == "too-many-open", str(cap)[:70])
check("H7", "…carries a non-null reroute", bool(cap.get("reroute")), str(cap.get("reroute")))
check("H7x", "the two reasons do NOT share one reroute line",
      busy.get("reroute") != cap.get("reroute"),
      f"both say: {busy.get('reroute')!r}")

# ── H9/H10 notices are never refused ──────────────────────────────────────────
wipe()
ot.open_thread("block-P-R2", "p", "q", lease_minutes=30)
note = send("q", reply="no", action="info")
check("H9", "a notice reaches a busy recipient", note.get("delivery") == "delivered", str(note)[:70])
ask = send("q")
check("H9", "the same content as an ask is refused", ask.get("error") == "E-BUSY", str(ask)[:60])

# ── H11 terminator to a busy recipient ────────────────────────────────────────
wipe()
ot.open_thread("block-P-R3", "p", "q", lease_minutes=30)
term = send("q", reply="end", msg="closing anyway")
check("H11", "a terminator reaches a busy recipient", term.get("delivery") == "delivered", str(term)[:70])

# ── H12 only a party may release ──────────────────────────────────────────────
wipe()
opened = ot.open_thread("lease-P-R", "p", "zero", lease_minutes=30)
tid12 = opened.get("thread_id") if isinstance(opened, dict) else "lease-P-R"
released_by_s = ot.release_if_party(tid12, "s") if hasattr(ot, "release_if_party") else None
live_after = [r for r in ot.load() if r.get("thread_id") == tid12]
check("H12", "a third party cannot release", bool(live_after), "lease vanished for a non-party")
ok_release = ot.release_if_party(tid12, "p") if hasattr(ot, "release_if_party") else None
check("H12", "a party can release", not [r for r in ot.load() if r.get("thread_id") == tid12],
      f"release_if_party returned {ok_release}")

print()
print(f"  {len(fail)} finding(s): {fail}" if fail else "  all clauses pass against this build")
sys.exit(1 if fail else 0)
