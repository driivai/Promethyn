"""Run the type gate against the DECLARED FLOOR of the supported mypy range.

``pyproject.toml`` declares a range (``mypy>=N``); ``constraints.txt`` pins one
version and CI installs under it. So every build exercised exactly the newest
checker in the range — and #87 was green that way while an independent review,
running 1.20.2 (also inside the declared range), reported a real ``union-attr``
defect in ``sandbox/namespace.py`` that CI could not see. "Green" meant "green
on one checker we happened to pin", and nothing said so.

This closes that: it reads the floor out of ``pyproject.toml``, installs exactly
that version into a throwaway venv (the pinned closure is untouched), and runs
the same config. A diagnostic only the floor reports fails the build here,
instead of surfacing in somebody else's review.

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


def declared_type_stubs() -> list[str]:
    """The ``types-*`` pins from ``constraints.txt``.

    The floor venv has to mirror what a developer installing ``.[dev]`` at the
    floor would have. Without the stubs, the floor reports "Library stubs not
    installed" — a diagnostic about the venv, not about the code, which would
    make this job noise and get it switched off.
    """

    text = (REPO / "constraints.txt").read_text(encoding="utf-8")
    return re.findall(r"^(types-[A-Za-z0-9._-]+==[0-9][^\s]*)$", text, re.MULTILINE)


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
        stubs = declared_type_stubs()
        print(f"[type-gate-floor] type stubs: {stubs or '(none pinned)'}")
        subprocess.run(
            [str(python), "-m", "pip", "install", "--quiet", f"mypy=={floor}", *stubs],
            check=True,
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
