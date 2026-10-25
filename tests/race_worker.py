"""Race worker: one real process attempting one send. Used by test_h3_race.py.

Deliberately holds the claim for a moment (sleep inside the stubbed transport) so the
window between claim and delivery is wide enough for a second process to hit it —
which is exactly the window a sequential test can never open.
"""
import os
import sys
import json
import time
import pathlib

PLUGIN = pathlib.Path("/Users/emil/.hermes/profiles/zero/plugins/hermes-mesh")
sys.path.insert(0, str(PLUGIN))

os.environ["MESH_AGENT_NAME"] = sys.argv[1]          # sender
target = sys.argv[2]                                  # recipient

from hermes_mesh import session_relay as sr           # noqa: E402

def slow_deliver(t, body, *a, **kw):
    time.sleep(0.25)                                  # the window
    return "delivery-" + os.getpid().__str__(), None

sr._deliver_webhook = slow_deliver
sr._float.send = lambda **kw: None

# NEGATIVE CONTROL: reproduce the pre-fix check-then-act sequence through the real
# relay path. If the race test still passes under this, the test is decorative.
if os.environ.get("RACE_LEGACY") == "1":
    from hermes_mesh import open_threads as _ot
    def legacy_claim(thread_id, opened_by, peer, lease_minutes=30):
        blocker = _ot.conflict(peer, opened_by)     # read, no lock held
        if blocker:
            return {"ok": False, "blocker": blocker}
        time.sleep(0.05)                            # the gap the lock used to close
        return {"ok": True, "lease": _ot.open_thread(thread_id, opened_by, peer)}  # act, later
    _ot.claim = legacy_claim

res = sr.handle_mesh_send({"agent": target, "action": "do", "reply": "yes", "message": "race"})
print(json.dumps({"sender": sys.argv[1], "error": res.get("error"), "delivery": res.get("delivery")}))
