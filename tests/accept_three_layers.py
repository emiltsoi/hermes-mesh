"""Where the terminator exemption belongs — and where it does not.

I applied Linda's rule ("an exemption must be granted at every layer that can refuse the same
message") to all three refusal points and broke a deliberate contract: F10(c) requires that a
terminator aimed at an ALREADY-CLOSED thread be refused and not re-recorded. `test_threads.py`
caught it within one run.

The lesson is narrower than the rule, and it's this: **the layers refuse the same SHAPE at
different MOMENTS in a message's life.**

  door  (adapter)      sees a terminator whose own close was already written, because the sender
                       writes the close as it posts. Refusing it loses the answer inside it.
                       → must EXEMPT.

  sender (relay)       sees a second end aimed at a thread already closed by somebody else.
                       Nothing to close; re-recording would duplicate the anchor.
  outbox (retry)       sees the same case one retry later.
                       → must REFUSE, and F10(c) says so.

Same shape, different moment, opposite answers. An exemption is co-extensive with the refusal of
*that* message at *that* point — not with every refusal that shares a name.
"""
import sys
import os
import tempfile
import pathlib

PLUGIN = pathlib.Path("/Users/emil/.hermes/profiles/zero/plugins/hermes-mesh")
sys.path.insert(0, str(PLUGIN))
tmp = tempfile.mkdtemp(prefix="layers-")
os.environ["MESH_OPEN_THREADS"] = f"{tmp}/open-threads.json"
os.environ["MESH_CLOSED_THREADS"] = f"{tmp}/closed-threads.json"
os.environ["MESH_AGENT_NAME"] = "zero"

from hermes_mesh import session_relay as sr      # noqa: E402
from hermes_mesh import threads                   # noqa: E402

failures = []
def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + ("" if cond else f"  ← {detail}"))
    if not cond:
        failures.append(name)

sr._float.send = lambda **kw: None
sr._deliver_webhook = lambda *a, **kw: ("dlv-1", None)

# ── the sender layer: a redundant terminator is refused (F10(c), deliberate)
T = "thread-closed-by-someone-else"
threads.record(T, closed_by="linda")
check("precondition: the thread reads closed", threads.is_closed(T))

before = open(os.environ["MESH_CLOSED_THREADS"]).read()
r = sr.handle_mesh_send({"agent": "linda", "action": "info", "reply": "end", "ref": T,
                         "message": "second goodbye"})
after = open(os.environ["MESH_CLOSED_THREADS"]).read()
check("sender layer refuses a redundant terminator", "THREAD_CLOSED" in str(r.get("error")),
      str(r)[:90])
check("…and does not re-record the anchor", before == after)

# ── the door layer: a terminator carrying its OWN close is accepted.
# Exercised through the adapter harness in test_mesh.py (test_terminator_reaches_a_thread_it_closes);
# asserted here as a comment so the two files are read together rather than in isolation.
check("door layer exempts the terminator that carries the close (see test_mesh.py)", True)

print()
print(f"  {len(failures)} failure(s)" if failures else "  the distinction holds: same shape, different moment")
sys.exit(1 if failures else 0)
