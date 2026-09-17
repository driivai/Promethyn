"""The Checkpoint-B mutation plan is named, live, and pinned both ways."""
from __future__ import annotations

import importlib.util
import inspect
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "phase_1_2c_checkpoint_b_revert_proofs.py"


@pytest.fixture(scope="module")
def runner():
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        spec = importlib.util.spec_from_file_location("checkpoint_b_reverts", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(REPO / "scripts"))
    return module


def test_mutation_plan_and_observed_failure_count_are_pinned(runner):
    # 6 / 7 -> 8 / 9 at close-out: the two R3 mutations above.
    assert (runner.EXPECTED_REVERTS, runner.EXPECTED_CALL_FAILURES) == (8, 9)
    plan = runner.mutations()
    assert len(plan) == runner.EXPECTED_REVERTS
    assert len({name for name, *_ in plan}) == len(plan)


#: Rows whose property is carried by more than one mechanism (G44).
PINNED_COMPANION_ROWS = {"selected-profile-injection-unwired"}


def test_every_mutation_target_and_selection_is_live(runner):
    for row in runner.mutations():
        name, function, edits, test_file, selection = row[:5]
        companions = row[5] if len(row) > 5 else ()
        assert (REPO / test_file).is_file(), name
        assert selection.strip(), name
        source = textwrap.dedent(inspect.getsource(inspect.unwrap(function)))
        for old, replacement in edits:
            assert old in source, f"{name}: mutation target disappeared"
            assert old != replacement, f"{name}: mutation is a no-op"
        for companion, old, replacement in companions:
            companion_source = textwrap.dedent(inspect.getsource(inspect.unwrap(companion)))
            assert old in companion_source, f"{name}: companion target disappeared"
            assert old != replacement, f"{name}: companion mutation is a no-op"


def test_the_rows_carrying_a_companion_edit_are_pinned(runner):
    """A companion edit neuters a SECOND mechanism so the named one is isolated.
    Which rows need one is a claim about how many mechanisms carry each
    property, so it is pinned by name: adding one silently would hide that a
    proof had stopped isolating its mechanism (G44), and dropping one would put
    the proof back to passing for the wrong reason."""

    carrying = {row[0] for row in runner.mutations() if len(row) > 5 and row[5]}
    assert carrying == PINNED_COMPANION_ROWS


def test_shortfall_and_excess_are_both_refused(runner):
    expected = (runner.EXPECTED_REVERTS, runner.EXPECTED_CALL_FAILURES)
    runner.enforce_expected(*expected)
    for observed in (
        (expected[0] - 1, expected[1]),
        (expected[0] + 1, expected[1]),
        (expected[0], expected[1] - 1),
        (expected[0], expected[1] + 1),
    ):
        with pytest.raises(AssertionError, match="drifted"):
            runner.enforce_expected(*observed)


def test_mutations_cover_every_named_load_bearing_join(runner):
    names = {name for name, *_ in runner.mutations()}
    assert names == {
        "re-resolve-replaced-by-redigest",
        "action-class-comparison-removed",
        "attempt-id-comparison-removed",
        "hold-admission-check-removed",
        # R3's reproduction, added at close-out. The descriptor check above
        # refuses a ROUTED decision lacking the seam proof; these two are what
        # stop a FAIL reaching a hold at all, and what stops the validated
        # action being swapped after the gate saw it. An earlier report named
        # "hold-admission-check-removed" as R3's reproduction — measured, it
        # reddens hold_admission_refuses and leaves the FAIL test passing, so
        # that naming was wrong.
        "routed-outcome-check-removed",
        "hold-action-substitution-check-removed",
        "hold-pinned-policy-comparison-removed",
        "selected-profile-injection-unwired",
    }
