"""H3 acceptance — the busy gate, exercised through handle_mesh_send itself.

Direction matters and is easy to get backwards (v1 of this test did): the gate asks
"is the RECIPIENT already in an open thread with somebody else?" — so the refusal is
produced by the SENDER's gateway, before anything leaves the box. Nothing is queued.

Not a static grep and not a copy of the logic: the real tool handler, with only the
webhook transport stubbed.
"""
import os, sys, tempfile, pathlib

PLUGIN = pathlib.Path("/Users/emil/.hermes/profiles/zero/plugins/hermes-mesh")
sys.path.insert(0, str(PLUGIN))

tmp = tempfile.mkdtemp(prefix="busy-")
os.environ["MESH_OPEN_THREADS"] = str(pathlib.Path(tmp) / "open-threads.json")
os.environ["MESH_CLOSED_THREADS"] = str(pathlib.Path(tmp) / "closed-threads.json")
os.environ["MESH_AGENT_NAME"] = "zero"

from hermes_mesh import session_relay as sr          # noqa: E402
from hermes_mesh import open_threads as ot          # noqa: E402

NOW = [2_000_000.0]
ot._now = lambda: NOW[0]

SENT = []
def fake_deliver(target, body, *a, **kw):
    SENT.append((target, body))
    return "delivery-id-" + str(len(SENT)), None
sr._deliver_webhook = fake_deliver
sr._float.send = lambda **kw: None

cases = []
def check(n, ok): cases.append((n, bool(ok)))

def send(agent, reply="yes", ref=None, message="hello"):
    args = {"agent": agent, "action": "do", "reply": reply, "message": message}
    if ref:
        args["ref"] = ref
    return sr.handle_mesh_send(args)

# 1 · an ordinary send opens a lease between me and the recipient
r1 = send("linda")
check("first send delivered", r1.get("delivery") == "delivered")
check("lease opened", len(ot.load()) == 1)
LINDA_LEASE = ot.load()[0]["thread_id"]

# 2 · I may send again to the same peer (merge, never refused)
r2 = send("linda", message="and another thing")
check("same peer allowed", r2.get("delivery") == "delivered")

# 3 · THE GATE: daji is leased to kore, so daji is busy for everyone else
ot.open_thread("lease-daji-kore", "daji", "kore", lease_minutes=30)
before = len(SENT)
r3 = send("daji")
check("busy recipient refused", r3.get("error") == "E-BUSY")
check("nothing left the box", len(SENT) == before)
check("E-BUSY carries fields",
      all(k in r3 for k in ("thread_id", "peer", "opened_at", "lease_until")))
check("E-BUSY names the other party", r3.get("peer") == "kore")
check("E-BUSY states it is not lost", "neither delivered nor lost" in r3.get("note", ""))

# 4 · a NOTICE is exempt — the board must never go silent because a wife is talking
r4 = send("daji", reply="no", message="board notice")
check("notice exempt from gate", r4.get("delivery") == "delivered")

# 5 · an end is NEVER refused by the gate — and it cannot close somebody else's lease
r5 = send("daji", reply="end", ref="lease-daji-kore")
check("end exempt from gate", r5.get("delivery") == "delivered")
check("third party cannot close a lease", any(r["thread_id"] == "lease-daji-kore" for r in ot.load()))

# 6 · a party ending her own thread releases it
r6 = send("linda", reply="end", ref=LINDA_LEASE)
check("own end delivered", r6.get("delivery") == "delivered")
check("own lease released", all(r["thread_id"] != LINDA_LEASE for r in ot.load()))

# 6 · expiry frees a busy recipient without anybody ending anything
ot.open_thread("lease-vera-kore", "vera", "kore", lease_minutes=30)
r7 = send("vera")
check("busy before expiry", r7.get("error") == "E-BUSY")
NOW[0] += 31 * 60
r8 = send("vera")
check("reachable after expiry", r8.get("delivery") == "delivered")
print("  [dbg] r8 =", r8)
print("  [dbg] leases =", [(x["thread_id"], x["opened_by"], x["peer"]) for x in ot.load()])

fails = [n for n, ok in cases if not ok]
for n, ok in cases:
    print(("  PASS  " if ok else "  FAIL  ") + n)
print(f"\n  {len(cases)-len(fails)}/{len(cases)} passed · sends attempted: {len(SENT)}")
sys.exit(1 if fails else 0)
