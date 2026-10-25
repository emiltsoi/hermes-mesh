"""Linda's recovery notice: `reply:end` was not atomic.

She sent a terminator, delivery failed three times, and the closure anchor was written anyway —
so the thread was closed on her side for a message I never received, and she could not retry the
same `ref`. A local close is a write; delivery is a fact about someone else. They were ordered
the wrong way round.

The fix keeps the in-flight guarantee (a concurrent reply still cannot slip past, because a
PENDING anchor counts as closed) while making the close earn its place.

Three things are asserted here, and the third is the one that matters:
  1. while pending and undelivered, the thread reads as closed (the in-flight window holds)
  2. a failed delivery retracts the pending close, so the same ref can be retried
  3. a confirmed delivery promotes it to a real close
"""
import sys
import os
import tempfile
import pathlib
import json

PLUGIN = pathlib.Path("/Users/emil/.hermes/profiles/zero/plugins/hermes-mesh")
sys.path.insert(0, str(PLUGIN))
tmp = tempfile.mkdtemp(prefix="term-")
os.environ["MESH_OPEN_THREADS"] = f"{tmp}/open-threads.json"
os.environ["MESH_CLOSED_THREADS"] = f"{tmp}/closed-threads.json"
os.environ["MESH_AGENT_NAME"] = "zero"

from hermes_mesh import session_relay as sr     # noqa: E402
from hermes_mesh import threads                 # noqa: E402

failures = []
def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + ("" if cond else f"  ← {detail}"))
    if not cond:
        failures.append(name)

def send(agent, reply, message="x", ref=None):
    args = {"agent": agent, "action": "info", "reply": reply, "message": message}
    if ref:
        args["ref"] = ref
    return sr.handle_mesh_send(args)

sr._float.send = lambda **kw: None

# ── 1. a terminator whose delivery FAILS must not leave a closed thread behind
sr._deliver_webhook = lambda *a, **kw: (None, "webhook failed after 3 attempts")
r = send("linda", "end")
term_id = r.get("task_id")
check("failed terminator reports an error", bool(r.get("error")), str(r)[:80])
check("thread is NOT closed after a failed close", not threads.is_closed(term_id),
      "anchor survived a failed delivery — Linda's defect")

# ── 2. the same ref can be retried with the same id, and now succeeds
sr._deliver_webhook = lambda *a, **kw: ("dlv-ok-1", None)
r2 = sr.handle_mesh_send({"agent": "linda", "action": "info", "reply": "end",
                          "message": "answer", "task_id": term_id})
check("retry of the same terminator delivers", r2.get("delivery") == "delivered", str(r2)[:90])
check("thread IS closed after a confirmed close", threads.is_closed(term_id))

# ── 3. the in-flight window still holds: a PENDING anchor reads as closed
pending_id = "pending-inflight-1"
threads.record(pending_id, closed_by="zero", pending=True)
check("a pending anchor still blocks concurrent replies", threads.is_closed(pending_id))
entry = next(e for e in json.load(open(os.environ["MESH_CLOSED_THREADS"]))
             if e["anchor_task_id"] == pending_id)
check("…and is marked pending on disk", entry.get("pending") is True, str(entry))

print()
print(f"  {len(failures)} failure(s)" if failures else "  all checks passed")
sys.exit(1 if failures else 0)
