"""Conformance for the confidence-composition measurement.

Three things must hold before the study's numbers mean anything:

1. the calibration ARITHMETIC is correct — scripted inputs with a hand-computed
   expected calibration table / false-confidence / discrimination / ECE, so the
   measurement is proven before it is trusted;
2. a composed confidence CANNOT grant authority — it is a pure number that never
   reaches the gate, and a high composed value does not let a non-authoritative
   (soft) action execute; the gate still decides;
3. the Hearth is byte-identical to main — the study adds a module and a
   benchmark, and changes no trusted-core file.

The behavioural instrument checks that EXECUTE SQL ground truth need the
isolation runtime (skip without it, FAIL under PROM_REQUIRE_SANDBOX=1); the
arithmetic and no-authority checks need no runtime.
"""

from __future__ import annotations

import math
import os
import subprocess

import pytest

from prometheus_protocol.core.models import (
    ACTION_PYTHON_CODE,
    ExecutableAction,
    Tier,
    Verdict,
)
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.executor import SandboxExecutor
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import OUTCOME_BLOCK
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.orchestration import (
    ActionGateway,
    AgentStep,
    Workflow,
    WorkflowRuntime,
)
from prometheus_protocol.orchestration import composition as comp
from prometheus_protocol.orchestration.demo import ScriptedAgent, ScriptedGrader
from prometheus_protocol.sandbox import NamespaceSandbox
from prometheus_protocol.verifier.bank import VerifierBank

from prometheus_protocol.benchmarks.chain_eval import (
    Bucket,
    calibration_table,
    discrimination,
    expected_calibration_error,
    false_confidence,
)

_REQUIRE = (os.environ.get("PROM_REQUIRE_SANDBOX", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}


def _require_runtime() -> None:
    if not NamespaceSandbox.available():
        reason = "namespace isolation runtime (unprivileged user namespaces) unavailable"
        if _REQUIRE:
            pytest.fail(f"PROM_REQUIRE_SANDBOX=1 but {reason}")
        pytest.skip(reason)


# --------------------------------------------------------------------------
# 1. the calibration arithmetic is correct (fixture-verified)
# --------------------------------------------------------------------------

# A scripted set with a hand-computed expected analysis.
_COMPOSED = [0.10, 0.30, 0.30, 0.50, 0.70, 0.70, 0.90, 0.90, 0.90, 1.00]
_CORRECT = [False, False, True, True, True, False, True, True, False, True]


def test_calibration_table_matches_hand_computed():
    table = calibration_table(_COMPOSED, _CORRECT, n_buckets=5)
    # (n, n_correct, mean_composed, frac_correct) per bucket, hand-computed.
    expected = [
        (1, 0, 0.10, 0.0),                 # [0.0,0.2)
        (2, 1, 0.30, 0.5),                 # [0.2,0.4)
        (1, 1, 0.50, 1.0),                 # [0.4,0.6)
        (2, 1, 0.70, 0.5),                 # [0.6,0.8)
        (4, 3, 0.925, 0.75),               # [0.8,1.0]  (includes the 1.00)
    ]
    assert len(table) == 5
    for bk, (n, nc, meanc, frac) in zip(table, expected):
        assert bk.n == n and bk.n_correct == nc
        assert math.isclose(bk.mean_composed, meanc, abs_tol=1e-9)
        assert bk.frac_correct is not None
        assert math.isclose(bk.frac_correct, frac, abs_tol=1e-9)


def test_expected_calibration_error_matches_hand_computed():
    table = calibration_table(_COMPOSED, _CORRECT, n_buckets=5)
    ece = expected_calibration_error(table, total=len(_COMPOSED))
    # 0.01 + 0.04 + 0.05 + 0.04 + 0.07 = 0.21
    assert math.isclose(ece, 0.21, abs_tol=1e-9)


def test_false_confidence_matches_hand_computed():
    # composed >= 0.80 -> the four in the top bucket (T,T,F,T): 1 of 4 wrong.
    n_high, n_wrong, rate = false_confidence(_COMPOSED, _CORRECT, threshold=0.80)
    assert (n_high, n_wrong) == (4, 1)
    assert math.isclose(rate, 0.25, abs_tol=1e-9)
    # composed >= 0.95 -> only the 1.00 (correct): 0 wrong.
    n_high2, n_wrong2, rate2 = false_confidence(_COMPOSED, _CORRECT, threshold=0.95)
    assert (n_high2, n_wrong2) == (1, 0)
    assert rate2 == 0.0
    # threshold above every value -> no chains clear it, rate is None (not 0).
    assert false_confidence(_COMPOSED, _CORRECT, threshold=1.01) == (0, 0, None)


def test_discrimination_matches_hand_computed():
    mc, mw, sep = discrimination(_COMPOSED, _CORRECT)
    assert math.isclose(mc, 4.30 / 6, abs_tol=1e-9)   # mean composed over correct
    assert math.isclose(mw, 2.00 / 4, abs_tol=1e-9)   # mean composed over incorrect
    assert math.isclose(sep, 4.30 / 6 - 2.00 / 4, abs_tol=1e-9)


def test_empty_bucket_reports_no_fraction_not_zero():
    # A calibration bucket with no members must report frac_correct None, never a
    # misleading 0% (0% correct reads as "always wrong", not "no data").
    table = calibration_table([0.9, 0.9], [True, True], n_buckets=5)
    empty = table[0]  # [0.0,0.2) has no members
    assert empty.n == 0 and empty.frac_correct is None


# --------------------------------------------------------------------------
# 2. the composition rules are pure hypotheses that cannot authorize
# --------------------------------------------------------------------------


def test_rules_are_pure_numbers_in_range_with_expected_ordering():
    confs = [0.9, 0.7, 0.8]
    tiers = [Tier.HARD, Tier.HARD, Tier.HARD]
    vals = {name: rule(confs, tiers) for name, rule in comp.RULES.items()}
    for v in vals.values():
        assert 0.0 <= v <= 1.0
    # product <= min <= mean for confidences in [0, 1].
    assert vals["product"] <= vals["min"] <= vals["mean"] + 1e-12
    assert math.isclose(vals["min"], 0.7, abs_tol=1e-9)
    assert math.isclose(vals["product"], 0.9 * 0.7 * 0.8, abs_tol=1e-9)
    assert math.isclose(vals["mean"], 0.8, abs_tol=1e-9)
    # weakest_link_length = min - 0.02*(N-1)
    assert math.isclose(vals["weakest_link_length"], 0.7 - 0.02 * 2, abs_tol=1e-9)


def test_tier_weighted_caps_soft_but_never_hard():
    # A SOFT step's confidence is capped at the measured SOFT reliability ceiling;
    # a HARD step's is untouched. Only ever lowers, never raises.
    ceiling = comp.SOFT_RELIABILITY_CEILING
    hard = comp.tier_weighted_rule([0.95, 0.95], [Tier.HARD, Tier.HARD])
    soft = comp.tier_weighted_rule([0.95, 0.95], [Tier.HARD, Tier.SOFT])
    assert math.isclose(hard, 0.95 * 0.95, abs_tol=1e-9)
    assert math.isclose(soft, 0.95 * ceiling, abs_tol=1e-9)
    assert soft < hard  # the soft cap lowered it


def test_composition_module_holds_no_execution_capability():
    """The composition module imports nothing from the gate/executor/controller:
    a composed number is a summary, structurally unable to reach the world."""

    forbidden = {
        "ExecutionController", "ActionGate", "PromotionGate", "SandboxExecutor",
        "ActionGateway", "ExecutableAction",
    }
    assert not (set(vars(comp)) & forbidden), "composition must hold no action capability"
    for name in ("execute", "approve", "submit", "route_action"):
        assert not hasattr(comp, name)


def test_high_composed_confidence_cannot_execute_a_soft_action():
    """The decisive property: a composed number never reaches the gate. A chain
    whose composed confidence is HIGH still cannot execute a non-authoritative
    (soft) action — the gate blocks it on its own per-step judgment."""

    ledger = SqliteLedger(":memory:")
    controller = ExecutionController(
        gate=ActionGate(escalate_below=0.75, route_high_risk=True),
        executor=SandboxExecutor(),
        ledger=ledger,
    )
    runtime = WorkflowRuntime(
        bank=VerifierBank(), gateway=ActionGateway(controller.submit), ledger=ledger,
    )
    action = ExecutableAction(kind=ACTION_PYTHON_CODE, code="print('should not run')")
    wf = Workflow(workflow_id="authz-wf", steps=(
        AgentStep("h1", ScriptedAgent("h1", "ok"), ScriptedGrader("hg1", Tier.HARD), task="t"),
        AgentStep("h2", ScriptedAgent("h2", "ok"), ScriptedGrader("hg2", Tier.HARD), task="t"),
        AgentStep("h3", ScriptedAgent("h3", "ok"), ScriptedGrader("hg3", Tier.HARD), task="t"),
        AgentStep(
            "softact",
            ScriptedAgent("softact", "do", action=action, risk_class="low"),
            ScriptedGrader("soft-grader", Tier.SOFT),
            task="t", depends_on=("h1", "h2", "h3"),
        ),
    ))
    run = runtime.run(wf)

    confidences = [s.confidence for s in run.steps]
    tiers = [s.tier for s in run.steps]
    # The chain "looks" confident: mean composition is high (three HARD@~0.95).
    mean_composed = comp.mean_rule(confidences, tiers)
    assert mean_composed >= 0.80, mean_composed
    # min (the honest floor) correctly surfaces the weak soft step.
    assert comp.min_rule(confidences, tiers) <= 0.51

    # Yet the soft action is BLOCKED, and nothing executed — the composed number
    # granted no authority.
    softact = next(s for s in run.steps if s.step_id == "softact")
    assert softact.outcome == OUTCOME_BLOCK
    assert ledger.executions() and all(not e["executed"] for e in ledger.executions())
    assert run.executed_subject_ids == ()


# --------------------------------------------------------------------------
# 3. behavioural instrument checks (need the isolation runtime)
# --------------------------------------------------------------------------


def test_instrument_is_sound_references_selfverify_and_wrong_fails():
    _require_runtime()
    from prometheus_protocol.benchmarks.chain_eval import instrument_self_check

    lines: list[str] = []
    assert instrument_self_check(out=lines.append), "\n".join(lines)


def test_chain_ground_truth_is_executed_not_labelled():
    _require_runtime()
    from prometheus_protocol.benchmarks.chain_eval import run_chain
    from prometheus_protocol.benchmarks.chain_items import CHAINS
    from prometheus_protocol.verifier.sql import SqlVerifier

    verifier = SqlVerifier()
    # An all-correct chain executes correct; a designed-wrong chain executes wrong.
    ac = next(c for c in CHAINS if c.scenario == "all_correct")
    cw = next(c for c in CHAINS if c.scenario in ("compound", "confident_wrong"))
    assert run_chain(ac, verifier).correct is True
    assert run_chain(cw, verifier).correct is False


# --------------------------------------------------------------------------
# 4. the Hearth is byte-identical to main
# --------------------------------------------------------------------------

_HEARTH_FILES = (
    "src/prometheus_protocol/verifier/bank.py",
    "src/prometheus_protocol/verifier/aggregate.py",
    "src/prometheus_protocol/verifier/trust.py",
    "src/prometheus_protocol/gate/promotion.py",
    "src/prometheus_protocol/gate/authorization.py",
    "src/prometheus_protocol/execution/executor.py",
    "src/prometheus_protocol/execution/controller.py",
    "src/prometheus_protocol/execution/pending.py",
    "src/prometheus_protocol/forge/miner.py",
    "src/prometheus_protocol/core/models.py",
    "src/prometheus_protocol/core/interfaces.py",
    # the orchestration skeleton (PR #46) is frozen too; this sprint only ADDS.
    "src/prometheus_protocol/orchestration/runtime.py",
    "src/prometheus_protocol/orchestration/gateway.py",
    "src/prometheus_protocol/orchestration/messages.py",
    "src/prometheus_protocol/orchestration/workflow.py",
)

def _git(*args: str) -> subprocess.CompletedProcess:
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return subprocess.run(["git", *args], capture_output=True, text=True, cwd=root)


@pytest.mark.skipif(
    _git("rev-parse", "--verify", "origin/main").returncode != 0,
    reason="origin/main not available in this checkout",
)
def test_hearth_and_orchestration_core_unchanged_versus_main():
    """No trusted-core file and no orchestration-skeleton file differs from
    origin/main — the last approved baseline (EX-1, PR #52, merged, is part of it).
    No exemptions: any frozen-file change vs that baseline fails. The ledger is
    not in this set (extended additively, deliberately outside the freeze)."""

    diff = _git("diff", "--name-only", "origin/main", "--", *_HEARTH_FILES)
    assert diff.returncode == 0, diff.stderr
    changed = [line for line in diff.stdout.splitlines() if line.strip()]
    assert changed == [], f"protected files changed vs origin/main: {changed}"
