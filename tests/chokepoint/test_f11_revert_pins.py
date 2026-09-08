"""The F11 revert runners are pinned: fewer executed reversions than pinned FAIL.

A mutation runner that silently ran zero (or fewer) mutations and exited 0 is
the void-guard shape this repository exists to catch, and until PROM-F11's
close-out both runners printed whatever count they happened to run. They now
carry the counts from the checkpoint-2b and checkpoint-3 reports as
assertions, checked before the run (mutation list size) and after it
(call-phase failures), and CI runs both. This test loads the two scripts as
modules and proves, without executing pytest inside pytest:

1. each mutation list is exactly the pinned size, with distinct names;
2. every mutation's edit target still exists in the function it rewrites (a
   vanished target is a proof that would stop executing);
3. the enforcement refuses a shortfall and an excess, on either count.
"""

from __future__ import annotations

import importlib.util
import inspect
import textwrap
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def reconcile():
    return load("f11_reconcile_revert_proofs")


@pytest.fixture(scope="module")
def source():
    return load("f11_source_revert_proofs")


def _targets_still_exist(name: str, function, edits) -> None:
    text = textwrap.dedent(inspect.getsource(function))
    for old, _new in edits:
        assert old in text, f"{name}: revert target vanished from {function.__qualname__}: {old!r}"


def test_reconcile_runner_is_pinned_to_the_checkpoint_3_counts(reconcile):
    assert (reconcile.EXPECTED_REVERTS, reconcile.EXPECTED_CALL_FAILURES) == (43, 72)
    plan = reconcile.mutations()
    assert len(plan) == reconcile.EXPECTED_REVERTS
    assert len({name for name, _, _ in plan}) == len(plan), "duplicate mutation names"
    for name, changes, selection in plan:
        assert selection.strip()
        for function, edits in changes:
            _targets_still_exist(name, function, edits)


def test_source_runner_is_pinned_to_the_checkpoint_2b_counts(source):
    assert (source.EXPECTED_REVERTS, source.EXPECTED_CALL_FAILURES) == (15, 21)
    plan = source.mutations()
    assert len(plan) == source.EXPECTED_REVERTS
    assert len({name for name, _, _, _ in plan}) == len(plan), "duplicate mutation names"
    for name, function, edits, selection in plan:
        assert selection.strip()
        _targets_still_exist(name, function, edits)


@pytest.mark.parametrize("runner", ["reconcile", "source"])
def test_a_shortfall_or_an_excess_fails_the_runner(runner, request):
    module = request.getfixturevalue(runner)
    reverts, failures = module.EXPECTED_REVERTS, module.EXPECTED_CALL_FAILURES
    module.enforce_expected(reverts, failures)  # the pinned pair passes
    for caught, observed in (
        (reverts - 1, failures),
        (0, 0),
        (reverts, failures - 1),
        (reverts + 1, failures),
        (reverts, failures + 1),
    ):
        with pytest.raises(AssertionError, match="drifted"):
            module.enforce_expected(caught, observed)
