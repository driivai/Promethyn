"""Unit tests for the soft model-judge verifier."""

from __future__ import annotations

from prometheus_protocol.core.interfaces import Provider
from prometheus_protocol.core.models import Case, Evidence, Task, Tier, Verdict
from prometheus_protocol.provider.mock import MockProvider
from prometheus_protocol.verifier import trust
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.model_judge import ModelJudgeVerifier

TASK = Task(
    id="t/f",
    entry_point="f",
    prompt="implement f",
    split="train",
    cases=(Case(args=(1,), expected=2),),
)


class ScriptedProvider(Provider):
    """A provider whose assessment replies are scripted, for determinism."""

    def __init__(self, replies):
        self._replies = list(replies)
        self._i = 0

    def propose_solution(self, *, prompt, entry_point, skills=()):
        return ""

    def assess(self, *, prompt, system=None):
        reply = self._replies[min(self._i, len(self._replies) - 1)]
        self._i += 1
        return reply


class ExplodingProvider(Provider):
    def propose_solution(self, *, prompt, entry_point, skills=()):
        return ""

    def assess(self, *, prompt, system=None):
        raise RuntimeError("endpoint down")


def _verify(reply: str) -> Evidence:
    return ModelJudgeVerifier(ScriptedProvider([reply])).verify(code="x", task=TASK)


def test_emits_soft_tier_evidence_with_id():
    evidence = _verify("PASS")
    assert evidence.tier == Tier.SOFT
    assert evidence.verifier_id == "model-judge"
    assert evidence.verdict == Verdict.PASS
    assert evidence.passed is True
    assert evidence.latency_ms is not None and evidence.latency_ms >= 0.0


def test_pass_fail_abstain_from_scripted_replies():
    assert _verify("PASS").verdict == Verdict.PASS
    assert _verify("FAIL").verdict == Verdict.FAIL
    assert _verify("ABSTAIN").verdict == Verdict.ABSTAIN


def test_strict_parsing_ignores_code_shaped_reply():
    # A reply that is code (contains the Python ``pass`` keyword) is not a verdict.
    assert _verify("def f():\n    pass").verdict == Verdict.ABSTAIN
    assert _verify("the solution passes the tests").verdict == Verdict.ABSTAIN


def test_provider_error_is_abstain():
    evidence = ModelJudgeVerifier(ExplodingProvider()).verify(code="x", task=TASK)
    assert evidence.verdict == Verdict.ABSTAIN


def test_unsupported_provider_is_abstain():
    # MockProvider does not implement assess(); the judge treats it as no opinion.
    evidence = ModelJudgeVerifier(MockProvider()).verify(code="x", task=TASK)
    assert evidence.verdict == Verdict.ABSTAIN


def test_abstain_creates_no_calibration_sample():
    bank = VerifierBank()
    bank.register("subprocess-tests", Tier.HARD)
    hard = Evidence(
        passed=True, total=1, passed_count=1,
        verifier_id="subprocess-tests", verdict=Verdict.PASS, tier=Tier.HARD,
    )
    soft = _verify("ABSTAIN")
    bank.register(soft.verifier_id, Tier.SOFT)
    bank.judge([hard, soft])
    assert trust.sample_count(bank._store.get(soft.verifier_id)) == 0


def test_judge_is_blind_to_hidden_cases():
    captured = {}

    class Capture(Provider):
        def propose_solution(self, *, prompt, entry_point, skills=()):
            return ""

        def assess(self, *, prompt, system=None):
            captured["prompt"] = prompt
            return "PASS"

    ModelJudgeVerifier(Capture()).verify(code="CANDIDATE_CODE", task=TASK)
    # The judge sees the task prompt and the candidate, never the hidden cases.
    assert "CANDIDATE_CODE" in captured["prompt"]
    assert "implement f" in captured["prompt"]
    assert "Case(" not in captured["prompt"]
