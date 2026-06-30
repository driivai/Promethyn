"""Operability coverage for the "nothing to verify" case (F3), with parity.

Originally RED-by-design; now green. A task with no test cases cannot be
verified, so the runner returns ABSTAIN (a genuine "no opinion") rather than
FAIL (a confident failure). The parity tests pin that this change touches *only*
the empty-cases path: every non-empty verdict, and the example benchmark's
rates, are unchanged. See ``docs/shakeout-report.md`` (F3).
"""

from __future__ import annotations

import pytest

from prometheus_protocol import Config, build_orchestrator
from prometheus_protocol._examples.python_functions import build_benchmark
from prometheus_protocol.core.models import Case, Task, Verdict
from prometheus_protocol.verifier.runner import SubprocessVerifier


def test_empty_cases_task_abstains():
    task = Task(id="t/f", entry_point="f", prompt="x", split="train", cases=())
    evidence = SubprocessVerifier(memory_mb=0).verify(
        code="def f(x):\n    return x\n", task=task
    )
    assert evidence.verdict == Verdict.ABSTAIN
    # ABSTAIN is not a pass...
    assert evidence.passed is False
    # ...and it carries no case count to mistake for a failure.
    assert evidence.total == 0


def test_empty_cases_abstain_creates_no_calibration_sample():
    # Routed through the bank, an empty-cases ABSTAIN yields an ABSTAIN judgment
    # and records nothing for calibration (no usable evidence).
    from prometheus_protocol.verifier.bank import VerifierBank
    from prometheus_protocol.verifier.store import InMemoryTrustStore

    task = Task(id="t/f", entry_point="f", prompt="x", split="train", cases=())
    verifier = SubprocessVerifier(memory_mb=0)
    evidence = verifier.verify(code="def f(x):\n    return x\n", task=task)

    store = InMemoryTrustStore()
    bank = VerifierBank(store)
    bank.register(verifier.verifier_id, verifier.tier)
    judgment = bank.judge([evidence])

    assert judgment.verdict == Verdict.ABSTAIN
    stats = store.get(verifier.verifier_id)
    assert (stats.tp, stats.fn, stats.tn, stats.fp) == (0, 0, 0, 0)


@pytest.mark.parametrize("n_cases", [1, 2, 3])
def test_nonempty_cases_keep_their_verdict(n_cases):
    # PARITY: a correct solution stays PASS and a wrong one stays FAIL for any
    # non-empty case set — the F3 change does not perturb real verdicts.
    cases = tuple(Case(args=(i,), expected=i) for i in range(n_cases))
    task = Task(id="t/f", entry_point="f", prompt="x", split="train", cases=cases)

    good = SubprocessVerifier(memory_mb=0).verify(
        code="def f(x):\n    return x\n", task=task
    )
    assert good.verdict == Verdict.PASS

    bad = SubprocessVerifier(memory_mb=0).verify(
        code="def f(x):\n    return x + 1\n", task=task
    )
    assert bad.verdict == Verdict.FAIL


def test_example_benchmark_rates_unchanged(tmp_path):
    # PARITY: every example task has cases, so F3 cannot move their verdicts; the
    # documented held-out baseline rate must still reproduce exactly.
    bench = build_benchmark()
    orch = build_orchestrator(
        Config(
            registry_dir=tmp_path / "skills",
            ledger_path=":memory:",
            verifier_memory_mb=0,
        )
    )
    assert orch.baseline(bench.heldout).pass_rate == 0.4
