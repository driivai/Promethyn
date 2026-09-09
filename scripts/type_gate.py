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
disk. A step that did not execute writes no receipt, and the build fails — no
matter how the non-execution was spelled.

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
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONFIG = REPO / "mypy.ini"
RECEIPT = REPO / "type-gate-receipt.json"

#: A floor, not an equality: adding modules is ordinary, and losing them is the
#: failure this catches. Set to 230 when the gate was widened from src alone
#: (127 files) to src + scripts + tests (244) — leaving it at the old 120 would
#: have let the gate lose the whole of tests/ and still report success. Raise it
#: deliberately when the tree grows; never lower it to accommodate a narrowing.
MINIMUM_CHECKED_FILES = 230

_SUCCESS = re.compile(r"^Success: no issues found in (\d+) source files?$", re.MULTILINE)


def config_digest() -> str:
    return hashlib.sha256(CONFIG.read_bytes()).hexdigest()


def main() -> int:
    version = subprocess.run(
        [sys.executable, "-m", "mypy", "--version"],
        capture_output=True, text=True, cwd=REPO,
    ).stdout.strip()
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
