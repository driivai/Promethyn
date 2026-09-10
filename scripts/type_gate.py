"""Run the whole-tree type gate and leave EVIDENCE that it ran.

An independent review turned the gate off in CI with one line::

    run: true || python -m mypy --config-file mypy.ini

That step contains the gate command, carries no ``if:``, no
``continue-on-error`` and none of the four escapes the old guard blacklisted —
and mypy never runs. Exit zero, build green, nothing checked. The guard was
looking for *presence*, and presence is not execution.

The blacklist could be extended (``true ||`` today, then ``false &&``, a shell
function, a subshell, ``if false; then``, an alternate shell, a rewritten
``$SHELL``) and it would still only refuse what somebody thought of. So the CI
step runs THIS instead, and it emits a receipt: a JSON file naming the checker
version, the interpreter, the number of files actually checked, and the SHA-256
of the config that was used. A separate, mandatory CI step (``check_type_gate_
receipt.py``) then requires that receipt to exist and to match the config on
disk.

WHAT THE RECEIPT IS, AND IS NOT. An earlier version of this file claimed: "A
step that did not execute writes no receipt, and the build fails — no matter how
the non-execution was spelled." That sentence was false and is deleted. An
independent review hand-wrote a receipt naming a checker that does not exist,
python 0.0.0, 100000 files and a 1970 timestamp, and the check accepted it: only
the config digest binds, and anyone can compute that from the file on disk.

The receipt is an ACCIDENT AND STALENESS DETECTOR, not a forgery detector.

  It DOES catch: a gate step that silently stopped running; a receipt left over
  from a previous run, restored from a cache, or committed to the tree (the run
  identity below and the config digest both change); a config edited after the
  run it claims to describe.

  It does NOT catch: anyone who can edit the workflow or this script. They can
  add a step that writes whatever receipt they like. Nothing inside this
  repository can prevent that — every binding available to this step (the runner
  env ``GITHUB_RUN_ID``/``RUN_ATTEMPT``/``SHA``, ``GITHUB_TOKEN``, any secret) is
  equally available to a forging step in the same workflow, and the only
  constructions that would not be — a checking workflow running from the base
  branch — require ``pull_request_target``, which hands a write token to
  untrusted head code and is not a trade this repository will make.

  What actually catches a weakened gate is
  ``test_a_planted_union_defect_still_fails_the_gate``, which plants a real
  defect and runs THIS SCRIPT: weakening the config, the flags, or this body
  turns it red. The receipt is belt to that braces.

Two further properties the receipt carries, both of which have already failed
in this repository once:

* **The checked-file count is pinned to a floor.** A gate whose scope silently
  shrank — ``files`` narrowed, a directory moved out from under it — reports
  ``Success`` over what is left. ``MINIMUM_CHECKED_FILES`` makes that fail.
* **A clean run must actually say so.** Only ``Success: no issues found in N
  source files`` is accepted. mypy exiting zero for some other reason (nothing
  to check, an internal short-circuit) is refused.

Run: python scripts/type_gate.py
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONFIG = REPO / "mypy.ini"
RECEIPT = REPO / "type-gate-receipt.json"

#: The tree's real size at the last deliberate update, and the tolerance below
#: it. A review pointed out that a floor of 230 against 244 real files let 14
#: files of scope vanish unnoticed — a floor with that much slack is barely a
#: floor. The tolerance is now small and explicit.
#:
#: THE RULE FOR UPDATING IT: when the tree legitimately grows, raise
#: ``EXPECTED_CHECKED_FILES`` to the new observed count in the same change that
#: grows it. Never lower it to accommodate a narrowing — a smaller tree passing
#: is not this tree passing. The tolerance absorbs a file or two in flight; it is
#: not a budget for removing directories.
EXPECTED_CHECKED_FILES = 255
CHECKED_FILE_TOLERANCE = 2
MINIMUM_CHECKED_FILES = EXPECTED_CHECKED_FILES - CHECKED_FILE_TOLERANCE

_SUCCESS = re.compile(r"^Success: no issues found in (\d+) source files?$", re.MULTILINE)


def config_digest() -> str:
    return hashlib.sha256(CONFIG.read_bytes()).hexdigest()


def run_identity() -> dict[str, str]:
    """What the RUNNER says about this run. Absent locally, present in CI.

    Recorded so a receipt from a different run — cached, committed, or left over
    — is distinguishable from this one. Not a forgery binding: every one of these
    is exported to every step (see the module docstring).
    """

    return {
        key.lower(): os.environ.get(key, "")
        for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA", "GITHUB_JOB")
    }


def main() -> int:
    probe = subprocess.run(
        [sys.executable, "-m", "mypy", "--version"],
        capture_output=True, text=True, cwd=REPO,
    )
    if probe.returncode != 0:
        # Previously unchecked, and its result recorded as "" — a receipt that
        # named no checker at all. The main run below would still have failed,
        # but the receipt would have carried a blank where the evidence goes.
        print(
            "[type-gate] FAILED — could not run mypy at all:\n" + probe.stderr,
            file=sys.stderr,
        )
        return 1
    version = probe.stdout.strip()
    if not version:
        print(
            "[type-gate] FAILED — mypy reported no version; refusing to write a "
            "receipt that names no checker.",
            file=sys.stderr,
        )
        return 1
    # Printed before the run so the log says which checker produced the result.
    # pyproject allows a RANGE of mypy versions; #87 was green on 2.3.1 while an
    # independent review's 1.20.2 reported a real defect, and nothing in the log
    # said which checker had spoken.
    print(f"[type-gate] {version}")
    print(f"[type-gate] python {platform.python_version()}")
    print(f"[type-gate] config {CONFIG.name} sha256={config_digest()[:16]}")

    result = subprocess.run(
        [sys.executable, "-m", "mypy", "--config-file", str(CONFIG)],
        capture_output=True, text=True, cwd=REPO,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)

    if result.returncode != 0:
        print("[type-gate] FAILED — the tree does not type-check", file=sys.stderr)
        return 1

    match = _SUCCESS.search(result.stdout)
    if match is None:
        print(
            "[type-gate] FAILED — mypy exited 0 without reporting a clean run over "
            "any files. A gate that checks nothing reports success too.",
            file=sys.stderr,
        )
        return 1

    checked = int(match.group(1))
    if checked < MINIMUM_CHECKED_FILES:
        print(
            f"[type-gate] FAILED — only {checked} file(s) checked, floor is "
            f"{MINIMUM_CHECKED_FILES}. The gate's scope shrank; a smaller tree "
            "passing is not the same as this tree passing.",
            file=sys.stderr,
        )
        return 1

    RECEIPT.write_text(
        json.dumps(
            {
                "mypy": version,
                "python": platform.python_version(),
                "checked_files": checked,
                "config_sha256": config_digest(),
                "finished_at": time.time(),
                "run": run_identity(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"[type-gate] OK — {checked} files checked; receipt written to {RECEIPT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
