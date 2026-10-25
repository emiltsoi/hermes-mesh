"""Acceptance test for H1: the thread id must reach the delivered header.

Imports the REAL adapter from the installed plugin — never a copy — and exercises the
header renderer directly. A copy would prove the copy, which is the failure class this
whole thread exists to kill.
"""
import sys
import pathlib

PLUGIN = pathlib.Path("/Users/emil/.hermes/profiles/zero/plugins/hermes-mesh")
sys.path.insert(0, str(PLUGIN))

from hermes_mesh.adapter import MeshAdapter  # noqa: E402

fmt = MeshAdapter._format_display_text
A = "11111111-1111-1111-1111-111111111111"
B = "22222222-2222-2222-2222-222222222222"
REF = "99999999-9999-9999-9999-999999999999"

cases = []

# 1 · single message, normal CTA — id present AND copy-ready in the CTA
h = fmt("linda", "hello", "do", "yes", [A])
cases.append(("single: thread tag", f"[thread:{A}]" in h))
cases.append(("single: id beside the CTA", f"· thread {A}" in h))
cases.append(("single: order", h.startswith("⬡ [Mesh from:linda] [thread:")))

# 2 · closed thread — no ref hint, because no reply is owed
h = fmt("linda", "bye", "do", "end", [A])
cases.append(("end: thread tag", f"[thread:{A}]" in h))
cases.append(("end: no ref in cta", "ref:" not in h))
cases.append(("end: says closed", "thread closed by sender" in h))

# 3 · merged delivery — N ids, and the wife is told to choose
h = fmt("linda", "two things", "do", "yes", [A, B])
cases.append(("merged: both ids", f"[thread:{A}]" in h and f"[thread:{B}]" in h))
# merged: no single id is offered beside the CTA — the header lists them all and the
# wife names which she answers; nothing is guessed for her.
case_merged_no_single = not any(f"· thread {i}" in h for i in (A, B))
cases.append(("merged: no guess", case_merged_no_single))

# 4 · a reply carries the parent it answers
h = fmt("linda", "re", "do", "yes", [B], ref=A)
cases.append(("ref: parent shown", f"[re:{A}]" in h))
cases.append(("ref: own id too", f"[thread:{B}]" in h))

# 5 · no id at all (defensive) — must not emit an empty tag
h = fmt("linda", "bare", "do", "yes", [])
cases.append(("bare: no empty tag", "[thread:]" not in h))

# 6 · the old format must be gone
h = fmt("linda", "x", "do", "yes", [A])
cases.append(("old shape gone", h.count("[Mesh from:linda]") == 1 and "[thread:" in h))

fails = [n for n, ok in cases if not ok]
for n, ok in cases:
    print(("  PASS  " if ok else "  FAIL  ") + n)
print()
print(f"  {len(cases)-len(fails)}/{len(cases)} passed")
print("  sample:", fmt("linda", "body text here", "do", "yes", [A]))
print("  merged:", fmt("linda", "body text here", "do", "yes", [A, B]))
sys.exit(1 if fails else 0)
