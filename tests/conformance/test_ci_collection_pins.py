"""The workflow's collection pins are checkable HERE, not only in CI.

Several CI steps pin how many tests a module must contribute — ``expected =
{"test_coverage_enforcement": 33, ...}`` — so that a proof which stops being
collected fails the build instead of passing silently. The pin is load-bearing
and it is also, by construction, a number kept in a second place: it lives in
``.github/workflows/ci.yml`` and nowhere else, so a locally green suite says
nothing about whether it still matches.

Measured, this sprint: a full local run reported ``2419 passed, 23 skipped`` on
three interpreters, and the very next CI run refused all three matrix jobs on
``AssertionError: ('test_policy_enforcement_regression', 20, 19)`` — two tests
had been added to pinned modules and the pins had not moved. Nothing the author
could run locally could have seen it.

This closes that gap the way the repository closes gaps: the workflow is the
source, this test is the reader. It parses each pinned step out of ci.yml,
collects the files that step runs (one ``--collect-only`` pass for all of them),
and compares. A pin that no longer matches fails here, in the suite the author
runs, with the same message CI would print.

Named limits, each a test below:

* It compares COLLECTION, not outcomes. The workflow's steps also assert zero
  skips, failures and errors; those need the run, and the run is CI's job.
* It reads the two pin SHAPES the workflow uses — a per-module mapping and a
  bare ``assert len(cases) == N`` total. A step that invents a third shape is
  invisible to the parser, which is why the set of pinned steps is itself
  pinned: a new one has to be added here deliberately.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"

#: Every step whose ``run`` script carries a collection pin this guard can
#: read. Enumerated rather than discovered, in both directions: a pinned step
#: the parser stops seeing (a reworded assertion, a deleted heredoc) is a VOID
#: GUARD and fails here, and a newly pinned step has to be listed deliberately.
PINNED_STEPS = (
    "Opened substrate proofs (exact collection, zero skips)",
    "Config attestation proofs (exact collection, zero skips)",
    "PROD-FIX-1 proofs (approval expiry, attestation chronology, hostname taxonomy)",
    "PROD-FIX-2 proofs (F8 — no secret reaches a public string)",
    "PHASE-1.2a proofs (requirement coverage enforced before fusion)",
    "PHASE-1.2b proofs (the unbound-judgment route is closed)",
    "PHASE-1.2 CHECKPOINT 3 proofs (advisory evidence cannot satisfy)",
    "PHASE-1.2c Checkpoint B execution-descriptor proofs",
    "PHASE-1.2c authorization record and pinned-hold proofs",
    "Linux opened-store and lock mount integration (must run, zero skips)",
)

_TEST_PATH = re.compile(r"tests/[\w./-]+\.py")


class Pin:
    """One step's pin: the files it runs, and what it demands of them."""

    def __init__(self, step: str, files: tuple[str, ...], per_module: dict[str, int], total: int | None):
        self.step = step
        self.files = files
        self.per_module = per_module
        self.total = total

    @property
    def readable(self) -> bool:
        return bool(self.files) and (bool(self.per_module) or self.total is not None)


def _heredoc_bodies(script: str) -> list[str]:
    """The Python bodies of ``python - <<'PY' ... PY`` blocks in a run script."""

    bodies: list[str] = []
    current: list[str] | None = None
    for line in script.splitlines():
        if current is None:
            if line.strip().startswith("python - <<'PY'"):
                current = []
            continue
        if line.strip() == "PY":
            bodies.append("\n".join(current))
            current = None
            continue
        current.append(line)
    return bodies


def _pin_from_body(body: str) -> tuple[dict[str, int], int | None]:
    """Read the two shapes: an ``expected`` mapping and/or a bare total.

    ``ast`` rather than a regular expression, because the mappings carry
    comments explaining every number and a text scan would have to skip them.
    """

    per_module: dict[str, int] = {}
    total: int | None = None
    tree = ast.parse(body)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "expected" for t in node.targets
        ):
            if isinstance(node.value, ast.Dict):
                for key, value in zip(node.value.keys, node.value.values):
                    if not isinstance(key, ast.Constant) or not isinstance(value, ast.Constant):
                        continue
                    if isinstance(key.value, str) and isinstance(value.value, int):
                        per_module[key.value] = value.value
        if isinstance(node, ast.Assert) and isinstance(node.test, ast.Compare):
            call = node.test.left
            comparator = node.test.comparators[0] if node.test.comparators else None
            is_len_cases = (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "len"
                and len(call.args) == 1
                and isinstance(call.args[0], ast.Name)
                and call.args[0].id == "cases"
            )
            if is_len_cases and isinstance(comparator, ast.Constant) and isinstance(comparator.value, int):
                total = comparator.value
    return per_module, total


def _pins() -> dict[str, Pin]:
    job = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["build"]
    pins: dict[str, Pin] = {}
    for step in job["steps"]:
        name, script = step.get("name"), step.get("run")
        if not name or not script or "python -m pytest" not in script:
            continue
        files = tuple(dict.fromkeys(_TEST_PATH.findall(script)))
        per_module: dict[str, int] = {}
        total: int | None = None
        for body in _heredoc_bodies(script):
            body_modules, body_total = _pin_from_body(body)
            per_module.update(body_modules)
            total = body_total if body_total is not None else total
        pin = Pin(name, files, per_module, total)
        if pin.readable:
            pins[name] = pin
    return pins


def _collected(paths: tuple[str, ...]) -> dict[str, int]:
    """Collected test count per file, one pytest pass for all of them."""

    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *paths],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert proc.returncode == 0, f"collection failed:\n{proc.stdout[-4000:]}\n{proc.stderr[-2000:]}"
    counts: dict[str, int] = {path: 0 for path in paths}
    for line in proc.stdout.splitlines():
        if "::" not in line:
            continue
        path = line.split("::", 1)[0].strip()
        if path in counts:
            counts[path] += 1
    empty = [path for path, count in counts.items() if count == 0]
    assert not empty, f"no tests collected from {empty}; the pin would be read against nothing"
    return counts


def mismatches(pin: Pin, per_file: dict[str, int]) -> list[str]:
    """Every way this pin disagrees with what was collected, in CI's words.

    Pure, so the planted-defect test below drives the same comparison the real
    check drives — a guard whose failing branch is never executed is a guard
    that has never been shown to fail.
    """

    observed = {Path(path).stem: count for path, count in per_file.items() if path in pin.files}
    found = []
    for module, expected in pin.per_module.items():
        actual = observed.get(module)
        if actual != expected:
            found.append(f"{pin.step}: ({module!r}, {actual}, {expected})")
    if pin.total is not None:
        actual_total = sum(observed.values())
        if actual_total != pin.total:
            found.append(f"{pin.step}: total collected {actual_total}, pinned {pin.total}")
    return found


@pytest.fixture(scope="module")
def pins() -> dict[str, Pin]:
    return _pins()


@pytest.fixture(scope="module")
def per_file(pins: dict[str, Pin]) -> dict[str, int]:
    paths = tuple(dict.fromkeys(path for pin in pins.values() for path in pin.files))
    return _collected(paths)


def test_every_collection_pin_in_the_workflow_matches_what_pytest_collects(pins, per_file):
    """The load-bearing check: the numbers in ci.yml, against this tree."""

    found = [line for pin in pins.values() for line in mismatches(pin, per_file)]
    assert not found, (
        "ci.yml collection pins are stale; CI will refuse every matrix job:\n  "
        + "\n  ".join(found)
        + "\n\nMove the pin in .github/workflows/ci.yml in the same change that "
        "added or removed the tests, and say why in the comment beside it."
    )


def test_the_pinned_steps_are_exactly_the_ones_this_guard_reads(pins):
    """Void-guard control, both directions.

    A step that carries a pin the parser cannot read is a number nothing checks
    until CI refuses; a step listed here that no longer pins anything is this
    test watching an empty room.
    """

    assert tuple(sorted(pins)) == tuple(sorted(PINNED_STEPS)), (
        "the set of readable collection pins moved:\n"
        f"  parsed but not listed: {sorted(set(pins) - set(PINNED_STEPS))}\n"
        f"  listed but not parsed: {sorted(set(PINNED_STEPS) - set(pins))}"
    )


def test_each_pinned_step_names_files_and_a_number(pins):
    """Neither half alone is a pin: files with no number check nothing, and a
    number with no files is checked against nothing."""

    for pin in pins.values():
        assert pin.files, f"{pin.step}: a pin with no test files"
        assert pin.per_module or pin.total is not None, f"{pin.step}: files with no pin"
        for path in pin.files:
            assert (REPO / path).is_file(), f"{pin.step}: pinned path {path} does not exist"


def test_a_pin_that_is_one_too_low_is_REPORTED_and_the_true_pin_is_not(pins, per_file):
    """The positive control beside the refusal.

    The comparison is driven twice over the real collection: once with a
    deliberately wrong number, which must be reported in the shape CI prints,
    and once with the number as committed, which must be silent. Without the
    second half this test would pass just as well if the comparison reported
    everything.
    """

    real = pins["PHASE-1.2a proofs (requirement coverage enforced before fusion)"]
    assert mismatches(real, per_file) == [], "the committed pin should be silent"

    understated = Pin(real.step, real.files, dict(real.per_module), real.total)
    understated.per_module["test_policy_enforcement_regression"] -= 1
    reported = mismatches(understated, per_file)
    assert len(reported) == 1 and "'test_policy_enforcement_regression'" in reported[0], reported


def test_the_named_limit_this_guard_does_NOT_see_skips_failures_or_errors(pins):
    """Every pinned step also asserts that nothing skipped, failed or errored.

    That assertion needs the RUN, and the run is CI's. This guard reads
    collection only — so a proof that is collected and then skips is invisible
    here and visible there. Stated as a passing test so the boundary cannot be
    mistaken for coverage it does not have.
    """

    text = WORKFLOW.read_text(encoding="utf-8")
    for step in PINNED_STEPS:
        assert step in text
    assert text.count('for t in ("skipped", "failure", "error")') >= len(PINNED_STEPS) - 1

    tracker = (REPO / "docs" / "OPEN-GAPS.md").read_text(encoding="utf-8")
    assert re.search(r"^## G12\b", tracker, re.M), "docs/OPEN-GAPS.md has no entry G12"
