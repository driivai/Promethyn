"""Every proof selector a mutation runner names must be a test that exists.

WHY THIS MODULE EXISTS. A mutation runner names its proof by STRING. Rename the
test and the string still parses, still looks right in review, and selects
nothing — pytest reports no summary, the runner cannot measure a baseline, and
the row proves nothing. Measured on this branch: renaming
``test_an_unreachable_component_reads_as_not_applicable_not_as_a_refusal`` left
``receipt_classification_proofs.py`` pointing at a name that no longer existed,
and the three-version matrix went red on all three Pythons at
``RuntimeError: baseline invalid: ...: (no summary)``.

The runner refusing was correct — a mutation that would silently not apply is a
proof of nothing presented as a proof of safety. What was missing is anything
that says so BEFORE CI: this is a cross-file reference with no compiler and no
import to break.

So the selectors are DERIVED from each runner's own source and checked against
the test names that exist, both read from the tree. Neither side is a list
anyone maintains.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]


def _test_names() -> set[str]:
    """Every test function name in the tree."""

    names: set[str] = set()
    for path in (REPO / "tests").rglob("test_*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                names.add(node.name)
    return names


def _runner_selectors() -> dict[str, set[str]]:
    """Every string a runner uses that LOOKS like a proof selector.

    A string literal beginning ``test_`` inside a runner is either a selector or
    a mutation payload naming one; both must exist, so no distinction is drawn.
    """

    found: dict[str, set[str]] = {}
    for path in sorted((REPO / "scripts").glob("*_proofs.py")):
        selectors = {
            node.value
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith("test_")
            and "::" not in node.value
            and "/" not in node.value
            and node.value.isidentifier()
        }
        if selectors:
            found[path.name] = selectors
    return found


#: The proof runners that carry selector strings, and the total they carry.
#: Observed at base ce16a19 on 2026-09-19.
RUNNERS_CARRYING_SELECTORS = frozenset({
    "composed_message_revert_proofs.py",
    "floor_sweep_proofs.py",
    "matrix_agreement_proofs.py",
    "reachability_build_proofs.py",
    "receipt_classification_proofs.py",
    "spend_proofs.py",
})
#: NOTE, because it bit twice while this pin was being written: the floor-sweep
#: runner PROVES this pin and also FEEDS it — its rows name test functions as
#: bare strings, so editing the runner moves the number it is proving. Re-measure
#: after any edit to ``scripts/floor_sweep_proofs.py``; do not reason about it.
TOTAL_SELECTORS = 106


def test_the_runner_population_is_not_empty():
    """Doctrine #8: an instrument that finds nothing reads as a pass."""

    # MEMBERSHIP for the runners, because WHICH runners carry selectors is the
    # property: ``>= 1`` against five permitted four to stop carrying them and
    # still read as a pass, which is precisely "it stopped seeing them rather
    # than that they stopped existing" going undetected.
    # NOTE, measured: ``_runner_selectors`` drops runners with no selectors
    # (``if selectors``), so five here is a filtered view of the seventeen
    # ``scripts/*_proofs.py`` on disk. The filtered set is what this pin
    # governs, and the disk-vs-workflow population is pinned separately below.
    runners = _runner_selectors()
    assert set(runners) == RUNNERS_CARRYING_SELECTORS, (
        f"runners carrying selectors are {sorted(runners)}, pinned "
        f"{sorted(RUNNERS_CARRYING_SELECTORS)}"
    )
    # A COUNT for the selectors: the property is that the sweep still sees a
    # substantial body of them, and their individual spellings are already
    # asserted to exist as collected tests by the tests below. ``> 20`` against
    # 91 was slack of 71.
    assert sum(len(v) for v in runners.values()) == TOTAL_SELECTORS, (
        f"{sum(len(v) for v in runners.values())} selectors, pinned "
        f"{TOTAL_SELECTORS} — this sweep found a different number, which means "
        "it stopped seeing them or they stopped existing; both need answering"
    )


def test_every_proof_runner_on_disk_is_run_by_the_workflow_and_every_one_the_workflow_runs_exists():
    """The runner population, both ways round.

    F-9 found two of seventeen ``scripts/*_proofs.py`` that no CI step ran —
    the class of instrument nothing required to keep reddening. The glob is
    the convention; the workflow is what runs. Derived from both and compared
    exactly, so a runner added without a step, or a step naming a runner that
    was renamed away, is a red line here and not a finding for a later sprint
    (doctrine #11, OPEN-GAPS G53: measured 17 == 17 when written).
    """

    workflow = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    run_by_workflow = set(re.findall(r"python scripts/(\w+_proofs\.py)", workflow))
    on_disk = {path.name for path in (REPO / "scripts").glob("*_proofs.py")}
    assert on_disk, "no proof runners found at all"
    assert on_disk == run_by_workflow, (
        f"on disk but not run by ci.yml: {sorted(on_disk - run_by_workflow)}; "
        f"run by ci.yml but not on disk: {sorted(run_by_workflow - on_disk)}"
    )


@pytest.mark.parametrize("runner", sorted(_runner_selectors()))
def test_every_selector_a_runner_names_is_a_test_that_exists(runner):
    """Per runner, so a failure names the file to fix."""

    existing = _test_names()
    missing = sorted(_runner_selectors()[runner] - existing)
    assert missing == [], (
        f"{runner} names proof selectors that no longer exist: {missing}. "
        "A renamed test leaves the string valid and the row measuring nothing; "
        "point it at the test that replaced it, or delete the row."
    )
