"""The TYPE-GATE revert runner is pinned: any drift in either direction FAILs,
the same discipline as the F11, PROM-FIX-B, substrate and PIH-4a runners.

Loads ``scripts/type_gate_revert_proofs.py`` as a module and proves, without
executing pytest inside pytest: the mutation list is exactly the pinned size
with distinct names; every mutation's edit target still exists in the function
it rewrites (a vanished target is a proof that has silently stopped executing);
each selection is non-empty and names a test file that exists; and the
enforcement refuses a shortfall AND an excess on either count.

It additionally checks the property specific to this sprint: every mutation
reintroduces a shape TYPE-GATE forbids. A revert runner whose mutations no
longer break the union narrowing is measuring nothing.
"""

from __future__ import annotations

import importlib.util
import inspect
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "type_gate_revert_proofs.py"


@pytest.fixture(scope="module")
def runner():
    # The runner imports the shared harness by module name, as the other
    # per-sprint runners do; scripts/ is on the path when it runs as a script.
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        spec = importlib.util.spec_from_file_location("type_gate_revert_proofs", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(REPO / "scripts"))
    return module


def test_the_runner_is_pinned_and_every_target_still_exists(runner):
    assert (runner.EXPECTED_REVERTS, runner.EXPECTED_CALL_FAILURES) == (12, 17)
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


def test_every_mutation_actually_removes_a_union_narrowing(runner):
    """The mutations must reintroduce a forbidden shape, not merely edit text.

    Each ``old`` either narrows the union (``isinstance(..., Unavailable)``, or
    the ``missing`` list the ensemble/k-sample levers build from it), and each
    ``new`` removes that narrowing.
    """

    for name, _function, edits, _test_file, _selection in runner.mutations():
        for old, new in edits:
            narrows = "Unavailable" in old or "if missing:" in old
            assert narrows, f"{name}: the reverted line does not narrow the union: {old!r}"
            assert "Unavailable" not in new or "getattr" in new, (
                f"{name}: the mutation still narrows the union, so it reverts "
                f"nothing: {new!r}"
            )


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


def test_the_runner_drives_the_behavioural_crash_tests(runner):
    """The proofs must run against the tests that drive a REAL Unavailable
    through the real consumer — not against a unit test of the narrowing
    itself, which would prove only that the branch exists."""

    crash_tests = REPO / "tests/conformance/test_unavailable_consumers_do_not_crash.py"
    assert crash_tests.exists()
    for name, _function, _edits, test_file, _selection in runner.mutations():
        assert (REPO / test_file) == crash_tests, (
            f"{name} is proved against {test_file}, not the behavioural suite"
        )
