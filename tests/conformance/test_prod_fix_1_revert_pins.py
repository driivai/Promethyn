"""The PROD-FIX-1 revert runner is pinned: drift in EITHER direction FAILs.

Same discipline as the F11, PROM-FIX-B, substrate, PIH-4a and TYPE-GATE pin
tests. Loads ``scripts/prod_fix_1_revert_proofs.py`` as a module and proves,
without executing pytest inside pytest: the mutation list is exactly the pinned
size with distinct names; every mutation's edit target still exists in the
function it rewrites (a vanished target is a proof that has silently stopped
executing); each selection is non-empty and names a test file that exists; and
the enforcement refuses a shortfall AND an excess.

It also checks the property specific to this sprint: every mutation must remove
an ADMISSION BOUNDARY, a CLOCK RULE, an ORDERING REFUSAL or a HOSTNAME
NORMALISATION — the four things PROD-FIX-1 added. A runner whose mutations no
longer remove one of those is measuring nothing.
"""

from __future__ import annotations

import importlib.util
import inspect
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "prod_fix_1_revert_proofs.py"


@pytest.fixture(scope="module")
def runner():
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        spec = importlib.util.spec_from_file_location("prod_fix_1_revert_proofs", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(REPO / "scripts"))
    return module


def test_the_runner_is_pinned_and_every_target_still_exists(runner):
    assert (runner.EXPECTED_REVERTS, runner.EXPECTED_CALL_FAILURES) == (14, 23)
    plan = runner.mutations()
    assert len(plan) == runner.EXPECTED_REVERTS
    assert len({name for name, *_ in plan}) == len(plan), "duplicate mutation names"
    for name, function, edits, test_file, selection in plan:
        assert (REPO / test_file).exists(), f"{name}: {test_file} does not exist"
        assert selection.strip(), f"{name}: empty -k selection"
        text = textwrap.dedent(inspect.getsource(function))
        for old, _new in edits:
            assert old in text, (
                f"{name}: revert target vanished from {function.__qualname__}: "
                f"{old!r} — this proof would no longer execute"
            )


def test_every_mutation_removes_something_prod_fix_1_added(runner):
    """Each ``old`` must be one of the four things this sprint installed, and
    each ``new`` must remove it. A mutation that merely edits text proves
    nothing about the fix."""

    installed = (
        "deadline.admit()",          # an admission boundary
        "elapsed_remaining <= 0",    # the elapsed arm
        "wall_remaining <= 0",       # the wall arm
        "opened_elapsed = read_elapsed()",  # the sampling ORDER
        "remaining <= self.uncertainty_s",  # the declared clock uncertainty
        "if not trust_utc:",         # the UTC trust refusal
        "MINIMUM_TIMEOUT_MS",        # the never-zero timeout floor
        "newest_record(records)",    # the P-1 ambiguity refusal
        "len(distinct) > 1",
        "normalize_host(",           # the P-2 normalisation
    )
    for name, _function, edits, _test_file, _selection in runner.mutations():
        for old, new in edits:
            assert any(marker in old for marker in installed), (
                f"{name}: the reverted text is not something PROD-FIX-1 added: "
                f"{old!r}"
            )
            assert old != new, f"{name}: the mutation changes nothing"


def test_a_shortfall_or_an_excess_fails_the_runner(runner):
    reverts, failures = runner.EXPECTED_REVERTS, runner.EXPECTED_CALL_FAILURES
    runner.enforce_expected(reverts, failures)
    for caught, observed in (
        (reverts - 1, failures),
        (reverts + 1, failures),
        (reverts, failures - 1),
        (reverts, failures + 1),
        (0, 0),
    ):
        with pytest.raises(AssertionError, match="drifted"):
            runner.enforce_expected(caught, observed)


def test_the_runner_covers_all_three_findings(runner):
    """A runner that drifted into covering only the easy one would still print a
    reassuring number."""

    files = {test_file for _, _, _, test_file, _ in runner.mutations()}
    assert files == {runner.F7, runner.P1, runner.P2}, files


def test_the_runner_states_its_own_limit(runner):
    """A count says nothing about semantic coverage, and the runner is editable
    by whoever edits the code it guards. Both must be said where the assurance
    is described."""

    doc = runner.__doc__ or ""
    for claim in (
        "does NOT prove\nthe mutation set is complete",
        "semantic\ncoverage",
        "Nor is it externally anchored",
    ):
        assert claim in doc, f"the runner no longer states: {claim!r}"
