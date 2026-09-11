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
    assert (runner.EXPECTED_REVERTS, runner.EXPECTED_CALL_FAILURES) == (6, 7)
    plan = runner.mutations()
    assert len(plan) == runner.EXPECTED_REVERTS
    assert len({name for name, *_ in plan}) == len(plan)


def test_every_mutation_target_and_selection_is_live(runner):
    for name, function, edits, test_file, selection in runner.mutations():
        assert (REPO / test_file).is_file(), name
        assert selection.strip(), name
        source = textwrap.dedent(inspect.getsource(function))
        for old, replacement in edits:
            assert old in source, f"{name}: mutation target disappeared"
            assert old != replacement, f"{name}: mutation is a no-op"


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
        "hold-policy-re-resolution-removed",
        "selected-profile-injection-unwired",
    }
