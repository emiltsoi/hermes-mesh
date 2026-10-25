"""Acceptance tests for H2/H4 — open-thread leases, against the REAL module.

Runs entirely in a temp registry (MESH_OPEN_THREADS), never the live file.
Time is frozen, never waited: Linda's negative control says prove expiry by
moving the clock, not by sleeping.
"""
import os
import sys
import json
import pathlib
import tempfile
import importlib

PLUGIN = pathlib.Path("/Users/emil/.hermes/profiles/zero/plugins/hermes-mesh")
sys.path.insert(0, str(PLUGIN))

tmp = tempfile.mkdtemp(prefix="openthreads-")
REG = pathlib.Path(tmp) / "open-threads.json"
os.environ["MESH_OPEN_THREADS"] = str(REG)

from hermes_mesh import open_threads as ot  # noqa: E402

cases = []
def check(name, ok): cases.append((name, bool(ok)))

T1, T2, T3 = ("aaaaaaaa-0000-0000-0000-000000000001",
              "aaaaaaaa-0000-0000-0000-000000000002",
              "aaaaaaaa-0000-0000-0000-000000000003")

# frozen clock
NOW = [1_000_000.0]
ot._now = lambda: NOW[0]

# 1 · open → visible
rec = ot.open_thread(T1, "zero", "linda", lease_minutes=30)
check("open returns record", rec and rec["thread_id"] == T1)
check("get finds it", ot.get(T1) is not None)
check("lease is 30 min", abs(rec["lease_until"] - (NOW[0] + 1800)) < 1)

# 2 · same peer never conflicts
check("same-peer: no conflict", ot.conflict("linda", "zero") is None)
check("same-peer reversed: no conflict", ot.conflict("zero", "linda") is None)

# 3 · a third party is refused
block = ot.conflict("linda", "daji")
check("third-party: conflict", block is not None and block["thread_id"] == T1)
check("E-BUSY fields present",
      block and all(k in block for k in ("thread_id", "peer", "opened_at", "lease_until")))

# 4 · first reply resizes, second does not
ot.touch(T1, resize_to=120)
r = ot.get(T1)
check("resize applied", abs(r["lease_until"] - (NOW[0] + 7200)) < 1 and r["resized"])
ot.touch(T1, resize_to=600)
r = ot.get(T1)
check("no second resize", abs(r["lease_until"] - (NOW[0] + 7200)) < 1)

# 5 · resize is capped at 24 h
ot2 = ot.open_thread(T2, "zero", "kore", lease_minutes=30)
ot.touch(T2, resize_to=99_999)
r2 = ot.get(T2)
check("cap at 24h", r2["lease_minutes"] == 1440)
ot.release(T2)
check("release removes", ot.get(T2) is None)

# 6 · NEGATIVE CONTROL — an abandoned thread self-releases when time moves.
#     Uses a thread that was never resized: T1 was legitimately extended to 2 h above.
T4 = "aaaaaaaa-0000-0000-0000-000000000004"
ot.open_thread(T4, "zero", "isa", lease_minutes=30)
check("abandoned: alive at t+29m", (NOW.__setitem__(0, NOW[0] + 29 * 60), ot.get(T4))[1] is not None)
check("resized thread still alive at t+31m (correct)", ot.get(T1) is not None)
NOW[0] += 2 * 60
check("abandoned: gone at t+31m", ot.get(T4) is None)
check("abandoned: swept from disk", all(r["thread_id"] != T4 for r in json.loads(REG.read_text())))
check("abandoned: no longer blocks", ot.conflict("isa", "daji") is None)

# 7 · fail-open on a corrupt registry, and the degradation is COUNTED
before = ot.failopen_count()
REG.write_text("{not json at all")
check("corrupt: load degrades to []", ot.load() == [])
check("corrupt: no exception, no block", ot.conflict("linda", "daji") is None)
check("corrupt: failopen counted", ot.failopen_count() > before)
check("corrupt: backup written", any(p.name.startswith("open-threads.json.corrupt")
                                     for p in pathlib.Path(tmp).iterdir()))

# 8 · atomic write leaves no tmp litter
ot.open_thread(T3, "zero", "vera", lease_minutes=5)
litter = [p.name for p in pathlib.Path(tmp).iterdir() if ".tmp" in p.name]
check("no tmp litter", litter == [])
check("registry is valid json again", isinstance(json.loads(REG.read_text()), list))

fails = [n for n, ok in cases if not ok]
for n, ok in cases:
    print(("  PASS  " if ok else "  FAIL  ") + n)
print(f"\n  {len(cases)-len(fails)}/{len(cases)} passed")
sys.exit(1 if fails else 0)
