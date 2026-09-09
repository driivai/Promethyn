"""Run the type gate against the DECLARED FLOOR of the supported mypy range.

``pyproject.toml`` declares a range (``mypy>=N``); ``constraints.txt`` pins one
version and CI installs under it. So every build exercised exactly the newest
checker in the range — and #87 was green that way while an independent review,
running 1.20.2 (also inside the declared range), reported a real ``union-attr``
defect in ``sandbox/namespace.py`` that CI could not see. "Green" meant "green
on one checker we happened to pin", and nothing said so.

This closes that: it reads the floor out of ``pyproject.toml``, installs the
project's pinned closure into a throwaway venv with ONLY the checker moved to
the floor, and runs the same config. A diagnostic only the floor reports fails
the build here, instead of surfacing in somebody else's review.

The closure matters. An earlier version installed mypy and the type stubs alone,
so third-party imports degraded to ``Any`` at the floor while being real in the
main run — same config, different environment, and therefore a weaker check
wearing the same name. Now the only variable between the two jobs is the
checker.

The floor is a claim about what this project supports. Raise it deliberately —
never to make a diagnostic go away. The version that found the defect must stay
inside the range, or the range is being used as a silencer.

Run: python scripts/type_gate_floor.py
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PYPROJECT = REPO / "pyproject.toml"
CONFIG = REPO / "mypy.ini"

_FLOOR = re.compile(r'"mypy>=([0-9][0-9.]*)"')


def floor_constraints(floor: str, into: Path) -> Path:
    """``constraints.txt`` with the mypy pin replaced by the declared floor.

    The venv used to get ``mypy=={floor}`` and the type stubs and NOTHING ELSE —
    no ``psycopg``, no ``cryptography``, no ``pytest``. With
    ``ignore_missing_imports = True`` those imports degrade to ``Any`` at the
    floor while being real in the main run, so the two jobs were checking
    different things and a review observed that "the job proves less than it
    appears to".

    Installing the real pinned closure with only the checker moved to the floor
    makes the environments match: same packages, same versions, one different
    checker — which is the single variable this job exists to vary.
    """

    text = (REPO / "constraints.txt").read_text(encoding="utf-8")
    swapped, n = re.subn(r"^mypy==.*$", f"mypy=={floor}", text, count=1, flags=re.MULTILINE)
    if n != 1:
        raise SystemExit(
            "constraints.txt no longer carries exactly one 'mypy==' pin; this "
            "check cannot construct the floor environment"
        )
    path = into / "constraints-floor.txt"
    path.write_text(swapped, encoding="utf-8")
    return path


def declared_floor() -> str:
    match = _FLOOR.search(PYPROJECT.read_text(encoding="utf-8"))
    if match is None:
        raise SystemExit(
            "pyproject.toml no longer declares a mypy floor as \"mypy>=N\"; this "
            "check cannot tell what the supported range is"
        )
    return match.group(1)


def main() -> int:
    floor = declared_floor()
    print(f"[type-gate-floor] declared floor: mypy>={floor}")

    with tempfile.TemporaryDirectory(prefix="prom-mypy-floor-") as tmp:
        venv = Path(tmp) / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        python = venv / "bin" / "python"
        constraints = floor_constraints(floor, Path(tmp))
        print(f"[type-gate-floor] installing the pinned closure with mypy=={floor}")
        subprocess.run(
            [str(python), "-m", "pip", "install", "--quiet",
             "-e", str(REPO) + "[dev]", "-c", str(constraints)],
            check=True, cwd=REPO,
        )
        subprocess.run([str(python), "-m", "mypy", "--version"], check=True, cwd=REPO)
        result = subprocess.run(
            [str(python), "-m", "mypy", "--config-file", str(CONFIG)],
            cwd=REPO, capture_output=True, text=True,
        )

    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode != 0:
        print(
            f"[type-gate-floor] FAILED at mypy=={floor}. The tree type-checks on "
            "the pinned checker but not on the floor of the range this project "
            "declares it supports. Fix the EXPRESSION, or raise the floor "
            "deliberately — never to make the diagnostic go away.",
            file=sys.stderr,
        )
        return 1
    print(f"[type-gate-floor] OK at mypy=={floor}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
