"""Require EVIDENCE that the type gate ran in this job. Mandatory CI step.

The gate step writes a receipt (``scripts/type_gate.py``); this step demands it.
If the gate step did not execute — ``true ||``, a shell function, a subshell,
``if false; then``, an alternate shell — there is no receipt and this fails the
build, without anyone having predicted the spelling.

WHAT THIS PROVES, stated honestly because the previous version overclaimed. This
is an ACCIDENT AND STALENESS detector, not a forgery detector. An independent
review hand-wrote a receipt naming a checker that does not exist and this check
accepted it. It refuses:

* a MISSING receipt — the gate step did not run;
* a STALE one — the recorded config digest must equal the SHA-256 of
  ``mypy.ini`` as it is right now, so a receipt describing an earlier or weaker
  config cannot stand in for the config that is shipping;
* a REPLAYED one — in CI the recorded run identity must match this run's, so a
  receipt restored from a cache, carried over from another run, or committed to
  the tree is refused even if the config is unchanged;
* one that names NO checker, or too few files.

It does NOT refuse a receipt written by someone who can edit the workflow or the
gate script: every value available to the gate step is available to a forging
step in the same workflow. See ``scripts/type_gate.py`` for why nothing inside
this repository can close that, and for what does the real work instead
(``test_a_planted_union_defect_still_fails_the_gate``, which plants a defect and
runs the gate script itself).

Run: python scripts/check_type_gate_receipt.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from type_gate import (
    CONFIG,
    MINIMUM_CHECKED_FILES,
    RECEIPT,
    config_digest,
    run_identity,
)


def main() -> int:
    if not RECEIPT.exists():
        print(
            f"NO TYPE-GATE RECEIPT at {RECEIPT.name}. The gate step did not "
            "execute in this job. A step that is PRESENT and did not RUN is "
            "exactly the bypass this check exists for — do not 'fix' it by "
            "committing a receipt; make the gate step actually run.",
            file=sys.stderr,
        )
        return 1

    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))

    recorded = receipt.get("config_sha256")
    actual = config_digest()
    if recorded != actual:
        print(
            f"STALE TYPE-GATE RECEIPT: it records config sha256 {recorded} but "
            f"{CONFIG.name} is {actual}. The receipt is from a run against a "
            "different config than the one shipping.",
            file=sys.stderr,
        )
        return 1

    # Replay: in CI the run identity must be THIS run. Absent locally (every
    # field empty), where there is no run to be confused with.
    here = run_identity()
    if any(here.values()):
        recorded_run = receipt.get("run") or {}
        if recorded_run != here:
            print(
                f"REPLAYED TYPE-GATE RECEIPT: it records run {recorded_run!r} but "
                f"this run is {here!r}. A receipt from another run — cached, "
                "committed, or carried over — is not evidence that the gate ran "
                "here.",
                file=sys.stderr,
            )
            return 1

    if not str(receipt.get("mypy", "")).strip():
        print("TYPE-GATE RECEIPT names no checker.", file=sys.stderr)
        return 1

    checked = receipt.get("checked_files", 0)
    if not isinstance(checked, int) or checked < MINIMUM_CHECKED_FILES:
        print(
            f"TYPE-GATE RECEIPT reports {checked} file(s) checked, floor is "
            f"{MINIMUM_CHECKED_FILES}.",
            file=sys.stderr,
        )
        return 1

    print(
        f"type gate receipt OK: {receipt['mypy']} on python {receipt['python']} "
        f"checked {checked} files against {CONFIG.name}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
