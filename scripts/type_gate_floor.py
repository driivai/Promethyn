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
wearing the same name.

WHAT "THE SAME CLOSURE" DOES AND DOES NOT MEAN. This file used to say "the only
variable between the two jobs is the checker". That was too strong, and a review
was right to say so: ``constraints.txt`` CONSTRAINS a resolution, it does not
REQUEST packages. A different mypy declares different requirements — mypy 2.x
pulls ``librt`` and ``ast_serialize``, mypy 1.x does not — so the floor
environment can legitimately differ by more than one distribution, and asserting
otherwise would be a claim nobody had checked.

So it is checked instead of claimed. This job builds BOTH environments — the
pinned closure as shipped, and the pinned closure with the checker at the floor —
and requires every difference between them to be OWNED BY THE CHECKER: mypy
itself, or anything in mypy's own TRANSITIVE requirement closure, read from each
environment's metadata rather than from a list. The delta is printed on every
run; today it is::

    ast-serialize: pinned=0.9.0  floor=absent
    librt:         pinned=0.15.0 floor=absent
    mypy:          pinned=2.3.1  floor=1.11.0
    pathspec:      pinned=1.1.1  floor=absent

— mypy 2.3.1 requires ``librt``, which requires ``ast_serialize`` and
``pathspec``; mypy 1.11.0 requires none of them. Any distribution outside that
closure fails the job, because a diagnostic that appears at the floor could then
be attributed to something other than the checker version. That is the property
the old sentence was reaching for, in the form that can be verified.

The reference environment is built here rather than being the interpreter this
script runs on: on a developer's machine that interpreter carries whatever else
is installed, and the claim is about the pinned closure.

The floor is a claim about what this project supports. Raise it deliberately —
never to make a diagnostic go away. The version that found the defect must stay
inside the range, or the range is being used as a silencer.

Run: python scripts/type_gate_floor.py
"""

from __future__ import annotations

import json
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

    Installing the real pinned closure with the checker moved to the floor makes
    the environments match as closely as a resolution can: same pins, one
    different checker. It does not make them IDENTICAL — see the module
    docstring, and ``compare_environments``, which measures the residual delta
    rather than asserting there is none.
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


#: Emitted inside each environment: what is installed, and the checker's own
#: TRANSITIVE dependency closure. Both are read from the environment's own
#: metadata, so neither is a list somebody maintained — which matters, because
#: the delta is exactly what nobody predicts. Measured: mypy 2.3.1 brings
#: ``librt``, and ``librt`` brings ``ast_serialize`` and ``pathspec``; a
#: direct-requirements-only version of this probe called those two unexplained.
_PROBE = """
import json, sys
from importlib import metadata

def canonical(name):
    return name.strip().lower().replace("_", "-").replace(".", "-")

installed = {canonical(d.metadata["Name"]): d.version
             for d in metadata.distributions() if d.metadata["Name"]}

def dependencies(name):
    try:
        requires = metadata.requires(name) or []
    except metadata.PackageNotFoundError:
        return set()
    out = set()
    for spec in requires:
        spec = spec.split(";")[0].split("(")[0].split("[")[0]
        head = spec.split("=")[0].split("<")[0].split(">")[0].split("!")[0].split("~")[0]
        if head.strip():
            out.add(canonical(head))
    return out

owned, frontier = set(), ["mypy"]
while frontier:
    current = frontier.pop()
    for dependency in dependencies(current):
        if dependency not in owned:
            owned.add(dependency)
            frontier.append(dependency)
json.dump({"installed": installed, "checker_owned": sorted(owned)}, sys.stdout)
"""


def _pinned_environment(venv: Path, constraints: Path, label: str) -> Path:
    """A throwaway venv holding ``pip install -e .[dev] -c <constraints>``."""

    print(f"[type-gate-floor] installing {label}")
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    python = venv / "bin" / "python"
    subprocess.run(
        [str(python), "-m", "pip", "install", "--quiet",
         "-e", str(REPO) + "[dev]", "-c", str(constraints)],
        check=True, cwd=REPO,
    )
    return python


def _environment(python: str | Path) -> dict:
    probe = subprocess.run(
        [str(python), "-c", _PROBE], capture_output=True, text=True, check=True,
    )
    return json.loads(probe.stdout)


def compare_environments(reference: dict, floor: dict) -> tuple[list[str], list[str]]:
    """Split the two environments' difference into checker-owned and everything
    else.

    The claim this replaces was that there IS no difference. There can be: a
    different mypy declares different requirements, and ``constraints.txt``
    constrains a resolution rather than requesting packages. What must hold is
    the narrower, checkable thing — that every difference belongs to the checker.

    Returns ``(permitted, unexplained)``. Anything in ``unexplained`` means the
    two jobs are not running the same check, and the floor job is measuring
    something other than the checker version.
    """

    owned = {"mypy"} | set(reference["checker_owned"]) | set(floor["checker_owned"])
    permitted: list[str] = []
    unexplained: list[str] = []
    for name in sorted(set(reference["installed"]) | set(floor["installed"])):
        here = reference["installed"].get(name)
        there = floor["installed"].get(name)
        if here == there:
            continue
        difference = f"{name}: pinned={here or 'absent'} floor={there or 'absent'}"
        (permitted if name in owned else unexplained).append(difference)
    return permitted, unexplained


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
        # TWO environments, both built here. The reference is deliberately NOT
        # this interpreter: on a developer's machine that is whatever else is
        # installed, and the claim under test is about the PINNED CLOSURE, so the
        # reference has to be the pinned closure itself — same command, same
        # constraints file, unmodified.
        floor_python = _pinned_environment(
            Path(tmp) / "floor", floor_constraints(floor, Path(tmp)),
            f"the pinned closure with mypy=={floor}",
        )
        reference_python = _pinned_environment(
            Path(tmp) / "reference", REPO / "constraints.txt",
            "the pinned closure as shipped",
        )
        subprocess.run([str(floor_python), "-m", "mypy", "--version"], check=True, cwd=REPO)

        permitted, unexplained = compare_environments(
            _environment(reference_python), _environment(floor_python)
        )
        print(
            "[type-gate-floor] checker-owned differences between the two "
            f"environments: {permitted or 'none'}"
        )
        if unexplained:
            print(
                "[type-gate-floor] FAILED — the floor environment differs from "
                f"the pinned one in package(s) the checker does not own: {unexplained}. "
                "The two jobs are then not running the same check, and a "
                "diagnostic that appears at the floor cannot be attributed to "
                "the checker version. Pin the difference in constraints.txt.",
                file=sys.stderr,
            )
            return 1

        result = subprocess.run(
            [str(floor_python), "-m", "mypy", "--config-file", str(CONFIG)],
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
