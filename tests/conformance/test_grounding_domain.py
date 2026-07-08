"""Conformance: the grounding domain — soft evidence, mandatory human backstop.

The load-bearing claims of the first non-executable-truth domain:

* the grounding verifier emits SOFT-tier evidence only, abstains on anything
  unparseable, and cannot masquerade as a HARD verifier to the bank;
* a soft-only judgment NEVER authorizes, routes, or executes anything — the
  human backstop is structural (the bank marks it non-authoritative, the gate
  blocks it, the executor is never invoked);
* a human grounding review (HUMAN tier) is what unlocks the loop, decides the
  fused verdict, and calibrates the judge;
* the admissions harness arithmetic is exact against scripted judge output.

Only the demo test needs the isolation runtime (its publish beat executes in
the sandbox); everything else runs anywhere.
"""

from __future__ import annotations

import os

import pytest

from prometheus_protocol.benchmarks.grounding_eval import (
    SCRIPTED_REPLIES,
    ScriptedGroundingJudgeProvider,
    run_grounding_eval,
)
from prometheus_protocol.benchmarks.grounding_items import (
    GOLD_NOT_SUPPORTED,
    GOLD_SUPPORTED,
    build_grounding_items,
    task_for,
)
from prometheus_protocol.benchmarks.grounding_loop_demo import (
    HUMAN_REVIEWER_ID,
    human_review,
    run_loop,
)
from prometheus_protocol.benchmarks.judge_eval import compute_metrics
from prometheus_protocol.core.models import (
    ACTION_PYTHON_CODE,
    Evidence,
    ExecutableAction,
    Tier,
    Verdict,
)
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import OUTCOME_BLOCK
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.sandbox import NamespaceSandbox
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.grounding import GroundingTask, GroundingVerifier

_REQUIRE = (os.environ.get("PROM_REQUIRE_SANDBOX", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}


class _OneReplyProvider:
    """A provider whose assess() always returns one scripted reply."""

    def __init__(self, reply: str | Exception) -> None:
        self._reply = reply
        self.model = "scripted"

    def assess(self, *, prompt: str, system: str | None = None) -> str:
        if isinstance(self._reply, Exception):
            raise self._reply
        return self._reply


class _SentinelExecutor:
    """Fails the test if the controller ever asks it to execute."""

    def __init__(self) -> None:
        self.calls = 0

    def execute(self, decision):  # pragma: no cover - reaching this IS the failure
        self.calls += 1
        raise AssertionError("a grounding-unverified action reached the executor")


_TASK = GroundingTask(id="grounding/x", source="The sky was clear all day.")


def _soft(reply: str | Exception) -> Evidence:
    return GroundingVerifier(_OneReplyProvider(reply)).verify(
        code="It did not rain.", task=_TASK
    )


# --------------------------------------------------------------------------
# soft-tier honesty
# --------------------------------------------------------------------------


def test_grounding_evidence_is_soft_tier_and_strictly_parsed():
    supported = _soft("SUPPORTED 0.9")
    assert (supported.tier, supported.verdict) == (Tier.SOFT, Verdict.PASS)
    not_supported = _soft("not-supported 0.7")
    assert (not_supported.tier, not_supported.verdict) == (Tier.SOFT, Verdict.FAIL)
    for malformed in ("", "NOT", "unsupported", "It looks fine.", "TRUE 0.9"):
        evidence = _soft(malformed)
        assert (evidence.tier, evidence.verdict) == (Tier.SOFT, Verdict.ABSTAIN), malformed
    unavailable = _soft(RuntimeError("gateway down"))
    assert unavailable.verdict == Verdict.ABSTAIN
    assert "judge unavailable" in unavailable.detail


def test_grounding_judge_cannot_masquerade_as_hard():
    """The bank pins a verifier's tier; forged HARD evidence is rejected loudly."""

    bank = VerifierBank()
    bank.register("grounding-judge", Tier.SOFT)
    forged = Evidence(
        passed=True, total=1, passed_count=1,
        verifier_id="grounding-judge", verdict=Verdict.PASS, tier=Tier.HARD,
    )
    with pytest.raises(ValueError, match="tier is fixed"):
        bank.judge([forged])


# --------------------------------------------------------------------------
# the mandatory human backstop (structural, not configured)
# --------------------------------------------------------------------------


def test_soft_only_judgment_never_authorizes_routes_or_executes():
    """However confident the judge, soft-only evidence blocks at the gate.

    The gate's routing features are ON here; a soft-only PASS still may not
    even reach a human hold — non-authoritative judgments block outright, so
    nothing grounding-unverified can execute or wait for a rubber stamp.
    """

    bank = VerifierBank()
    bank.register("grounding-judge", Tier.SOFT)
    judgment = bank.judge([_soft("SUPPORTED 0.99")])
    assert judgment.verdict == Verdict.PASS
    assert judgment.authoritative is False

    gate = ActionGate(escalate_below=0.75, route_high_risk=True)
    for risk in ("low", "medium", "high"):
        decision = gate.decide(judgment, risk_class=risk, subject_id="publish:x")
        assert decision.outcome == OUTCOME_BLOCK, risk
        assert decision.approved is False

    executor = _SentinelExecutor()
    controller = ExecutionController(
        gate=gate, executor=executor, ledger=SqliteLedger(":memory:")
    )
    outcome = controller.submit(
        judgment=judgment,
        action=ExecutableAction(kind=ACTION_PYTHON_CODE, code="print('claim')"),
        risk_class="medium",
        subject_id="publish:x",
    )
    assert outcome.outcome == OUTCOME_BLOCK
    assert outcome.pending is None  # not even held for a human rubber stamp
    assert executor.calls == 0  # the executor was never invoked


def test_human_review_unlocks_and_calibrates():
    """HUMAN-tier evidence decides the verdict and calibrates the judge."""

    bank = VerifierBank()
    bank.register("grounding-judge", Tier.SOFT)
    bank.register(HUMAN_REVIEWER_ID, Tier.HUMAN)

    soft = _soft("SUPPORTED 0.9")
    human = human_review(Verdict.PASS, reviewer="op", note="entailed")
    fused = bank.judge([soft, human])
    assert fused.authoritative is True
    assert fused.verdict == Verdict.PASS
    assert fused.contributing == (HUMAN_REVIEWER_ID,)  # the human decides
    # The judge accrued a calibration sample against the human reference.
    samples = {e.verifier_id: e.samples for e in bank.rank()}
    assert samples["grounding-judge"] == 1

    # Human disagreement decides the other way: the judge cannot override.
    fused_fail = bank.judge(
        [_soft("SUPPORTED 0.99"), human_review(Verdict.FAIL, reviewer="op", note="not entailed")]
    )
    assert fused_fail.verdict == Verdict.FAIL
    assert fused_fail.authoritative is True
    gate = ActionGate(escalate_below=0.75, route_high_risk=True)
    assert gate.decide(fused_fail, risk_class="medium").outcome == OUTCOME_BLOCK


# --------------------------------------------------------------------------
# admissions harness arithmetic (scripted judge, exact counts)
# --------------------------------------------------------------------------


def test_admissions_arithmetic_is_exact_on_grounding_v2():
    """The harder set folds through the same fixture-tested arithmetic."""

    from prometheus_protocol.benchmarks.grounding_eval import SCRIPTED_REPLIES_V2
    from prometheus_protocol.benchmarks.grounding_items_v2 import (
        build_grounding_items_v2,
    )

    items = build_grounding_items_v2()
    judge = GroundingVerifier(
        ScriptedGroundingJudgeProvider(items, SCRIPTED_REPLIES_V2)
    )
    rows = run_grounding_eval(items, judge=judge)
    m = compute_metrics(rows)

    assert m.n_items == m.n_reference == 64
    assert (m.n_decided, m.n_abstained) == (62, 2)  # h36 abstain, h39 malformed
    assert (m.n_agree, m.agreement) == (57, 57 / 62)
    # The dangerous direction: three designed leaks on the subtlest shapes,
    # out of 44 decided gold-not-supported items (45 minus the h36 abstain).
    assert (m.reference_fails_decided, m.false_pass) == (44, 3)
    assert m.false_pass_rate == 3 / 44
    # The safe direction: two designed strict-judge refusals of 18 decided.
    assert (m.reference_passes_decided, m.false_fail) == (18, 2)
    assert m.false_fail_rate == 2 / 18
    assert (m.unstated_count, m.unstated_correct) == (1, 1)  # h08

    gold = {i.item_id: i.gold for i in items}
    false_passes = sorted(
        r.item_id for r in rows
        if gold[r.item_id] == GOLD_NOT_SUPPORTED and r.judged == Verdict.PASS
    )
    false_fails = sorted(
        r.item_id for r in rows
        if gold[r.item_id] == GOLD_SUPPORTED and r.judged == Verdict.FAIL
    )
    assert false_passes == ["h10", "h41", "h62"]
    assert false_fails == ["h15", "h64"]


def test_admissions_arithmetic_is_exact_against_gold():
    items = build_grounding_items()
    judge = GroundingVerifier(ScriptedGroundingJudgeProvider(items, SCRIPTED_REPLIES))
    rows = run_grounding_eval(items, judge=judge)
    m = compute_metrics(rows)

    assert m.n_items == m.n_reference == 44  # every item carries a gold label
    assert (m.n_decided, m.n_abstained) == (42, 2)  # g30 abstain, g33 malformed
    assert (m.n_agree, m.agreement) == (39, 39 / 42)
    # The dangerous direction: the two designed leaks, out of the 25 decided
    # gold-not-supported items (26 minus the g30 abstain).
    assert (m.reference_fails_decided, m.false_pass) == (25, 2)
    assert m.false_pass_rate == 2 / 25
    # The safe direction: one designed false-FAIL of 17 decided supported.
    assert (m.reference_passes_decided, m.false_fail) == (17, 1)
    assert m.false_fail_rate == 1 / 17
    assert (m.unstated_count, m.unstated_correct) == (1, 1)  # g01

    # The designed deviations are exactly where they were designed to be.
    by_id = {r.item_id: r for r in rows}
    gold = {i.item_id: i.gold for i in items}
    false_passes = sorted(
        r.item_id for r in rows
        if gold[r.item_id] == GOLD_NOT_SUPPORTED and r.judged == Verdict.PASS
    )
    false_fails = sorted(
        r.item_id for r in rows
        if gold[r.item_id] == GOLD_SUPPORTED and r.judged == Verdict.FAIL
    )
    assert false_passes == ["g06", "g43"]
    assert false_fails == ["g18"]
    assert by_id["g30"].judged == by_id["g33"].judged == Verdict.ABSTAIN


# --------------------------------------------------------------------------
# the demo end to end (needs the isolation runtime for the publish beat)
# --------------------------------------------------------------------------


def test_grounding_loop_demo_blocks_all_but_the_human_approved_publish():
    if not NamespaceSandbox.available():
        reason = "namespace isolation runtime (unprivileged user namespaces) unavailable"
        if _REQUIRE:
            pytest.fail(f"PROM_REQUIRE_SANDBOX=1 but {reason}")
        pytest.skip(reason)

    summary = run_loop(out=lambda line: None)
    assert summary["soft_only"] == {"outcome": "block", "executed": False}
    assert summary["human_unlocked"]["executed"] is True
    assert summary["ungrounded"] == {"outcome": "block", "executed": False}
    assert summary["abstain"] == {"outcome": "block", "executed": False}
    assert (summary["executions"], summary["executed_total"]) == (4, 1)
