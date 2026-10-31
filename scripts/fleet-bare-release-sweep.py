#!/usr/bin/env python3
"""Sweep every seat for the bare `release(task_id)` on the delivery-failure path.

Kore's correction (2026-10-31): the in-repo structural guard reads a RELATIVE path, so it inspects
whichever tree pytest happens to run from. Run in the repo it is green; run against a deployed seat
that still carries the defect it stays green too, because it never looks there. A guard scoped to
the fix's own directory shores up the fixed copy and says nothing about the fleet.

The seats are independent directory copies (distinct inodes), not symlinks, and `hermes plugins`
has no sync step — so a restart reloads whatever the seat directory already holds. A fix reaches a
seat only when someone copies `hermes_mesh/` into it. That is a deploy, not a reboot.

This script is the instrument for that question. Exit 1 if ANY seat still carries the defect.

    python3 scripts/fleet-bare-release-sweep.py [--root /Volumes/External/fleet/profiles]
"""
from __future__ import annotations

import argparse
import pathlib
import sys

DEFAULT_ROOT = pathlib.Path("/Volumes/External/fleet/profiles")
BAD = "release_if_party(task_id, from_agent)"          # the fixed form
NEEDLE = "_open_threads.release("                      # the bare form


def sweep(root: pathlib.Path) -> list[tuple[str, str, list[str]]]:
    """Return (seat, verdict, evidence) for every seat that ships the plugin."""
    results = []
    for seat_dir in sorted(root.glob("*/plugins/hermes-mesh")):
        relay = seat_dir / "hermes_mesh" / "session_relay.py"
        if not relay.is_file():
            continue
        seat = seat_dir.parent.parent.name
        lines = relay.read_text(errors="replace").splitlines()
        offenders = [
            f"{i}: {ln.strip()}"
            for i, ln in enumerate(lines, 1)
            if NEEDLE in ln and BAD not in ln
        ]
        if offenders:
            results.append((seat, "BARE", offenders))
        else:
            results.append((seat, "FIXED", []))
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(DEFAULT_ROOT))
    args = ap.parse_args()
    root = pathlib.Path(args.root)
    if not root.is_dir():
        print(f"sweep: root not found: {root}")
        return 2

    results = sweep(root)
    if not results:
        print(f"sweep: no seat ships hermes-mesh under {root}")
        return 2

    bare = [r for r in results if r[1] == "BARE"]
    for seat, verdict, ev in results:
        print(f"  {verdict:5} {seat}" + (f"  ← {ev[0]}" if ev else ""))
    print(f"\n  {len(results) - len(bare)}/{len(results)} seats carry the party-checked release")
    if bare:
        print(f"  {len(bare)} seat(s) still open a third party's thread on a failed delivery:")
        for seat, _, ev in bare:
            for line in ev:
                print(f"    {seat}: {line}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
