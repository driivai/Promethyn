"""Exact pins and live mutation targets for the opened-substrate proofs."""

import importlib.util
import inspect
import textwrap
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def proof_runner():
    script = Path(__file__).resolve().parents[2] / "scripts" / "substrate_revert_proofs.py"
    spec = importlib.util.spec_from_file_location("substrate_revert_proofs", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with pytest.MonkeyPatch.context() as patch:
        patch.syspath_prepend(str(script.parent))
        spec.loader.exec_module(module)
    return module


def test_opened_substrate_proofs_are_pinned_and_targets_exist(proof_runner):
    assert (proof_runner.EXPECTED_REVERTS, proof_runner.EXPECTED_CALL_FAILURES) == (16, 38)
    plan = proof_runner.mutations()
    assert len(plan) == proof_runner.EXPECTED_REVERTS
    assert len({name for name, *_ in plan}) == len(plan)
    for name, function, edits, test_file, selection in plan:
        assert Path(test_file).exists() and selection.strip()
        source = textwrap.dedent(inspect.getsource(function))
        for old, _new in edits:
            assert old in source, f"{name}: target disappeared"


def test_opened_substrate_pin_shortfall_and_excess_refuse(proof_runner):
    count, failed = proof_runner.EXPECTED_REVERTS, proof_runner.EXPECTED_CALL_FAILURES
    proof_runner.enforce_expected(count, failed)
    for pair in ((0, 0), (count - 1, failed), (count + 1, failed),
                 (count, failed - 1), (count, failed + 1)):
        with pytest.raises(AssertionError, match="drifted"):
            proof_runner.enforce_expected(*pair)
