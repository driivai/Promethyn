"""The PROM-FIX-B revert runner is pinned: fewer executed reversions than
pinned FAIL, the same discipline as the F11 runners.

Loads ``scripts/fix_b_revert_proofs.py`` as a module and proves, without
executing pytest inside pytest: the mutation list is exactly the pinned
size with distinct names; every mutation's edit target still exists in the
function it rewrites (a vanished target is a proof that would stop
executing); each selection is non-empty; and the enforcement refuses a
shortfall and an excess on either count.
"""

from __future__ import annotations

import importlib.util
import inspect
import textwrap
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "fix_b_revert_proofs.py"


@pytest.fixture(scope="module")
def runner():
    spec = importlib.util.spec_from_file_location("fix_b_revert_proofs", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_runner_is_pinned_and_every_target_still_exists(runner):
    assert (runner.EXPECTED_REVERTS, runner.EXPECTED_CALL_FAILURES) == (12, 133)
    plan = runner.mutations()
    assert len(plan) == runner.EXPECTED_REVERTS
    assert len({name for name, *_ in plan}) == len(plan), "duplicate mutation names"
    for name, function, edits, test_file, selection in plan:
        assert Path(test_file).exists() and selection.strip()
        text = textwrap.dedent(inspect.getsource(function))
        for old, _new in edits:
            assert old in text, f"{name}: revert target vanished from {function.__qualname__}: {old!r}"


def test_a_shortfall_or_an_excess_fails_the_runner(runner):
    reverts, failures = runner.EXPECTED_REVERTS, runner.EXPECTED_CALL_FAILURES
    runner.enforce_expected(reverts, failures)
    for caught, observed in ((reverts - 1, failures), (0, 0), (reverts, failures - 1), (reverts + 1, failures), (reverts, failures + 1)):
        with pytest.raises(AssertionError, match="drifted"):
            runner.enforce_expected(caught, observed)
