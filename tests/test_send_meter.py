"""The send meter — can the fraction be measured at all?

Britney's finding: "mesh_send completed (0.93s)" records timing only, so the number of
messages that EXPECTED an answer was never measurable and any reply:yes fraction was an
impression. This test asserts the meter line exists, carries the four fields, and fires
on all three outcomes — the denominator the gate's coverage depends on.
"""
import logging, sys, pathlib, tempfile

PLUGIN = pathlib.Path("/Users/emil/.hermes/profiles/zero/plugins/hermes-mesh")
sys.path.insert(0, str(PLUGIN))

tmp = tempfile.mkdtemp(prefix="meter-")
import os
os.environ["MESH_OPEN_THREADS"] = f"{tmp}/open-threads.json"
os.environ["MESH_CLOSED_THREADS"] = f"{tmp}/closed-threads.json"
os.environ["MESH_AGENT_NAME"] = "zero"

from hermes_mesh import session_relay as sr  # noqa: E402


def main():

    class Grab(logging.Handler):
        def __init__(self):
            super().__init__(); self.lines = []
        def emit(self, record):
            self.lines.append(record.getMessage())

    grab = Grab()
    sr.logger.addHandler(grab)
    sr.logger.setLevel(logging.INFO)

    failures = []
    total = [0]
    def check(name, cond, detail=""):
        total[0] += 1
        print(f"  {'PASS' if cond else 'FAIL'}  {name}{'' if cond else '  ← ' + detail}")
        if not cond: failures.append(name)

    # ── delivered
    sr._deliver_webhook = lambda *a, **kw: ("dlv-1", None)
    sr._float.send = lambda **kw: None
    sr.handle_mesh_send({"agent": "britney", "action": "do", "reply": "yes", "message": "x"})
    line = next((l for l in grab.lines if "outcome=delivered" in l), "")
    check("delivered line exists", bool(line), str(grab.lines[-2:]))
    check("carries agent=", "agent=britney" in line, line)
    check("carries action=", "action=do" in line, line)
    check("carries reply=", "reply=yes" in line, line)
    check("carries thread=", "thread=" in line and "thread=-" not in line, line)

    # ── refused (a third party already holds the recipient)
    import json, time
    rows = json.load(open(os.environ["MESH_OPEN_THREADS"]))
    rows.append({"thread_id": "planted-1", "opened_by": "daji", "peer": "vera",
                 "opened_at": time.time(), "lease_until": time.time() + 900,
                 "lease_minutes": 30, "replies": 0, "resized": False})
    json.dump(rows, open(os.environ["MESH_OPEN_THREADS"], "w"))
    res = sr.handle_mesh_send({"agent": "vera", "action": "do", "reply": "yes", "message": "x"})
    check("refusal returned", res.get("error") == "E-BUSY", str(res)[:80])
    check("refused line logged", any("outcome=refused" in l for l in grab.lines), str(grab.lines[-2:]))
    check("refused names the thread", any("thread=planted-1" in l for l in grab.lines), "")

    # ── the meter must not perturb a notice (exempt, still logged as delivered)
    sr.handle_mesh_send({"agent": "britney", "action": "info", "reply": "no", "message": "x"})
    check("notice logged with reply=no",
          any("reply=no" in l and "outcome=delivered" in l for l in grab.lines), "")

    print()
    print(f"  {total[0] - len(failures)}/{total[0]} passed" + (f" · FAILURES: {failures}" if failures else ""))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
