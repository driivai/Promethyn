"""Require EVIDENCE that the type gate ran in this job. Mandatory CI step.

This is the half of the execution proof that cannot be spelled around. The gate
step writes a receipt (``scripts/type_gate.py``); this step demands it. If the
gate step did not execute — ``true ||``, a shell function, a subshell, ``if
false; then``, an alternate shell, anything at all — there is no receipt and
this fails the build. Nobody has to have predicted the spelling.

It also refuses a STALE receipt: the recorded config digest must equal the
SHA-256 of ``mypy.ini`` on disk right now, so a receipt from an earlier, weaker
config (or one committed to the repository) cannot stand in for a run against
the config that is actually shipping.

Run: python scripts/check_type_gate_receipt.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from type_gate import CONFIG, MINIMUM_CHECKED_FILES, RECEIPT, config_digest


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
