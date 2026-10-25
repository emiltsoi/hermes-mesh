"""H3 acceptance, the only one that could have caught the check-then-act race:

two REAL processes race for the same recipient, N iterations. Assertion per iteration:
exactly one lease exists, exactly one sender was refused E-BUSY, exactly one delivered.

A sequential suite cannot observe a race; this one runs concurrently on purpose.
"""
import json, os, subprocess, sys, tempfile, pathlib

PLUGIN = pathlib.Path("/Users/emil/.hermes/profiles/zero/plugins/hermes-mesh")
WORKER = pathlib.Path("/Users/emil/.hermes/profiles/zero/cache/scratch/race_worker.py")
PY = sys.executable
N = 10
TARGET = "vera"
SENDERS = ("zero", "britney")

tmp = tempfile.mkdtemp(prefix="race-")
REG = pathlib.Path(tmp) / "open-threads.json"

env = dict(os.environ)
env["MESH_OPEN_THREADS"] = str(REG)
env["MESH_CLOSED_THREADS"] = str(pathlib.Path(tmp) / "closed-threads.json")
env["PYTHONPATH"] = "/Users/emil/.hermes/hermes-agent"

def leases():
    if not REG.exists():
        return []
    try:
        return json.loads(REG.read_text() or "[]")
    except Exception:
        return []

bad = []
for i in range(N):
    REG.write_text("[]")
    procs = [
        subprocess.Popen([PY, str(WORKER), s, TARGET], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for s in SENDERS
    ]
    out = []
    for p in procs:
        line = p.communicate()[0].strip().splitlines()
        out.append(json.loads(line[-1]) if line else {"error": "no-output"})

    held = leases()
    busy = [o for o in out if o.get("error") == "E-BUSY"]
    ok = [o for o in out if o.get("delivery") == "delivered"]
    good = len(held) == 1 and len(busy) == 1 and len(ok) == 1
    if not good:
        bad.append((i, len(held), len(busy), len(ok), out))
    print(f"  iter {i:2d}  leases={len(held)}  E-BUSY={len(busy)}  delivered={len(ok)}  "
          + ("PASS" if good else "FAIL"))

print(f"\n  {N-len(bad)}/{N} iterations atomic")
if bad:
    for b in bad[:3]:
        print("   FAILED:", b)
sys.exit(1 if bad else 0)
