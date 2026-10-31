#!/usr/bin/env python3
"""Sweep every seat for a bare `release(...)` on the delivery-failure path.

Kore's correction (2026-10-31): the in-repo structural guard read a RELATIVE path, so it inspected
whichever tree pytest ran from — green in the repo, green over a broken seat. The seats are
independent directory copies (distinct inodes), not symlinks, and `hermes plugins` has no sync, so
a fix reaches a seat only when someone copies `hermes_mesh/` into it. That is a deploy, not a
reboot. This script is the instrument for that question.

Two FALSE GREENS were then found in the first version of this script, both caught by Kore with
negative controls, both fixed here and pinned by the controls in `--self-test`:

  1. The needle was literal (`_open_threads.release(`), so a seat importing `open_threads as ot`
     and calling `ot.release(task_id)` — same defect, same third-party close — printed FIXED and
     exited 0. The sweep certified by spelling. It now matches any call to a function named
     `release`, qualified or bare, with `release_if_party` exempt.
  2. A seat shipping `plugins/hermes-mesh` with no `session_relay.py` hit `continue` and vanished
     from the denominator, so a rename or path move turned lost coverage into a *passing fraction*.
     Every seat directory found is now accounted for, and an unreadable seat is a SKIP that fails
     the sweep.

A gate that cannot fail on the broken state is not a gate. Both controls must print PASS before
this script is trusted to certify a deploy.

    python3 scripts/fleet-bare-release-sweep.py [--root DIR] [--self-test]
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tempfile

DEFAULT_ROOT = pathlib.Path("/Volumes/External/fleet/profiles")

# A call to a function named exactly `release`, qualified (`ot.release(`, `_open_threads.release(`)
# or bare (`release(`). `release_if_party(` does not match: the name continues into `_if_party`
# before the paren, so the correct form is exempt by construction as well as by SAFE.
RELEASE_CALL = re.compile(r"(?<!def )\brelease\s*\(")
SAFE = "release_if_party"


def offenders_in(text: str) -> list[str]:
    """Lines that call release() without the party check."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue                                    # a comment is not a call
        m = RELEASE_CALL.search(line)
        if not m:
            continue
        if SAFE in line[max(0, m.start() - 40):m.end()]:
            continue                                    # release_if_party( — correct form
        out.append(f"{i}: {stripped}")
    return out


def sweep(root: pathlib.Path) -> tuple[list[tuple[str, str, list[str]]], int]:
    """Return (per-seat verdicts, number of seat dirs found)."""
    seat_dirs = sorted(root.glob("*/plugins/hermes-mesh"))
    results = []
    for seat_dir in seat_dirs:
        seat = seat_dir.parent.parent.name
        relay = seat_dir / "hermes_mesh" / "session_relay.py"
        if not relay.is_file():
            # Never silently dropped: a seat we cannot read is a coverage hole, not a pass.
            results.append((seat, "SKIP", [f"no session_relay.py under {relay.parent}"]))
            continue
        found = offenders_in(relay.read_text(errors="replace"))
        results.append((seat, "BARE" if found else "FIXED", found))
    return results, len(seat_dirs)


def _write_seat(root: pathlib.Path, seat: str, body: str | None) -> None:
    d = root / seat / "plugins" / "hermes-mesh" / "hermes_mesh"
    d.mkdir(parents=True, exist_ok=True)
    if body is not None:
        (d / "session_relay.py").write_text(body)


def self_test() -> int:
    """Both false greens reproduced. Each must FAIL the sweep, or the gate is decoration."""
    failures: list[str] = []

    def expect(label: str, body: str | None, want_rc: int) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            _write_seat(root, "victim",
                        "        _open_threads.release_if_party(task_id, from_agent)\n")
            _write_seat(root, "subject", body)
            results, found = sweep(root)
            clean = all(v == "FIXED" for _, v, _ in results) and len(results) == found
            rc = 0 if clean else 1
            ok = rc == want_rc
            if not ok:
                failures.append(label)
            print(f"  [{'PASS' if ok else 'FAIL'}] {label}: rc={rc} (want {want_rc}) "
                  f"— {[(s, v) for s, v, _ in results]}")

    expect("alias `ot.release(task_id)` is caught", "        ot.release(task_id)\n", 1)
    expect("bare `release(task_id)` is caught", "        release(task_id)\n", 1)
    expect("`release_if_party(...)` is NOT flagged",
           "        _open_threads.release_if_party(task_id, from_agent)\n", 0)
    expect("a seat with no relay does not vanish from the denominator", None, 1)
    expect("a comment mentioning release( is not a call",
           "        # never call release(task_id) here\n"
           "        _open_threads.release_if_party(task_id, from_agent)\n", 0)

    print(f"\n  self-test: {'ALL CONTROLS BEHAVE' if not failures else 'FAILED — ' + str(failures)}")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(DEFAULT_ROOT))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()

    root = pathlib.Path(args.root)
    if not root.is_dir():
        print(f"sweep: root not found: {root}")
        return 2

    results, seats_found = sweep(root)
    if not seats_found:
        print(f"sweep: no seat ships hermes-mesh under {root}")
        return 2

    bare = [r for r in results if r[1] == "BARE"]
    skips = [r for r in results if r[1] == "SKIP"]
    for seat, verdict, ev in results:
        print(f"  {verdict:5} {seat}" + (f"  ← {ev[0]}" if ev else ""))

    print(f"\n  seats found: {seats_found} · accounted for: {len(results)}")
    if len(results) != seats_found:
        print(f"  DENOMINATOR MISMATCH — {seats_found - len(results)} seat(s) vanished")
        return 2
    print(f"  {len(results) - len(bare) - len(skips)}/{len(results)} seats carry the "
          f"party-checked release")

    if bare:
        print(f"  {len(bare)} seat(s) still release by id alone on a failed delivery:")
        for seat, _, ev in bare:
            for line in ev:
                print(f"    {seat}: {line}")
    if skips:
        print(f"  {len(skips)} seat(s) unreadable — the fraction does not mean what it looks like:")
        for seat, _, ev in skips:
            print(f"    {seat}: {ev[0]}")
    return 1 if (bare or skips) else 0


if __name__ == "__main__":
    sys.exit(main())
