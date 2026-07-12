"""Conformance for the SOFT-judge calibration levers.

Before any live number is trusted, three things must hold:

1. each lever's AGGREGATION arithmetic is correct — scripted judge outputs with
   hand-computed expected verdicts/confidences (the levers are the new logic;
   the metric fold ``compute_metrics`` is already fixture-tested);
2. a SOFT verdict stays SOFT — no lever's Evidence is authoritative, and the
   bank+gate still treat it as advisory regardless of confidence;
3. default behaviour and the Hearth are unchanged — the levers are opt-in
   wrappers; the production judge path, the bank, the gate, and the executor are
   byte-identical to main, and the new temperature knob defaults to 0.

These need no provider and no sandbox: the levers are driven by scripted stub
verifiers/providers, so the arithmetic is proven fully offline.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from prometheus_protocol.benchmarks.judge_eval import compute_metrics, parse_confidence
from prometheus_protocol.core.interfaces import Provider, Verifier
from prometheus_protocol.core.models import Evidence, Skill, Tier, Verdict
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import OUTCOME_BLOCK
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.model_judge import ModelJudgeVerifier
from prometheus_protocol.verifier.soft_levers import (
    AdversarialSelfCheckProvider,
    ConfidenceThresholdJudge,
    EnsembleJudge,
    RepeatedSamplingJudge,
)


# --------------------------------------------------------------------------
# scripted stubs (no provider, no sandbox)
# --------------------------------------------------------------------------


class _StubJudge(Verifier):
    """Returns a fixed SOFT Evidence; ``detail`` carries a stated confidence."""

    def __init__(self, verdict: Verdict, detail: str, *, verifier_id: str = "stub"):
        self._verdict = verdict
        self._detail = detail
        self.verifier_id = verifier_id
        self.tier = Tier.SOFT

    def verify(self, *, code, task) -> Evidence:
        return Evidence(
            passed=(self._verdict == Verdict.PASS), total=1,
            passed_count=1 if self._verdict == Verdict.PASS else 0,
            verifier_id=self.verifier_id, verdict=self._verdict, tier=Tier.SOFT,
            detail=self._detail,
        )


class _CyclingJudge(Verifier):
    """Returns the next verdict in a fixed sequence on each verify() call."""

    def __init__(self, seq):
        self._seq = list(seq)
        self._i = 0
        self.verifier_id = "cycling"
        self.tier = Tier.SOFT

    def verify(self, *, code, task) -> Evidence:
        v = self._seq[self._i % len(self._seq)]
        self._i += 1
        return Evidence(passed=(v == Verdict.PASS), total=1,
                        passed_count=1 if v == Verdict.PASS else 0,
                        verifier_id="cycling", verdict=v, tier=Tier.SOFT, detail=v.value)


def _run(judge: Verifier) -> Evidence:
    return judge.verify(code="x", task=None)


# --------------------------------------------------------------------------
# 1. threshold arithmetic
# --------------------------------------------------------------------------


@pytest.mark.parametrize("verdict,detail,expected", [
    (Verdict.PASS, "PASS 0.90", Verdict.PASS),    # confident PASS survives
    (Verdict.PASS, "PASS 0.80", Verdict.PASS),    # exactly at θ survives (strict <)
    (Verdict.PASS, "PASS 0.79", Verdict.ABSTAIN), # just under -> withheld
    (Verdict.PASS, "PASS", Verdict.ABSTAIN),      # unstated -> withheld
    (Verdict.FAIL, "FAIL 0.90", Verdict.FAIL),    # FAIL untouched
    (Verdict.FAIL, "FAIL 0.10", Verdict.FAIL),    # low-confidence FAIL untouched
    (Verdict.ABSTAIN, "ABSTAIN", Verdict.ABSTAIN),
])
def test_threshold_downgrades_only_low_confidence_pass(verdict, detail, expected):
    j = ConfidenceThresholdJudge(
        _StubJudge(verdict, detail), min_confidence=0.8, confidence_parser=parse_confidence
    )
    ev = _run(j)
    assert ev.verdict == expected
    assert ev.tier == Tier.SOFT
    assert j.model_calls_per_item == 1


def test_threshold_never_turns_fail_into_pass():
    j = ConfidenceThresholdJudge(
        _StubJudge(Verdict.FAIL, "FAIL 0.05"), min_confidence=0.8,
        confidence_parser=parse_confidence,
    )
    assert _run(j).verdict == Verdict.FAIL


# --------------------------------------------------------------------------
# 2. ensemble arithmetic (unanimity to PASS)
# --------------------------------------------------------------------------


def _ensemble(verdicts, *, on_disagreement="abstain"):
    judges = [_StubJudge(v, f"{v.value} 0.9", verifier_id=f"j{i}") for i, v in enumerate(verdicts)]
    return EnsembleJudge(judges, on_disagreement=on_disagreement)


P, F, A = Verdict.PASS, Verdict.FAIL, Verdict.ABSTAIN


@pytest.mark.parametrize("verdicts,expected", [
    ([P, P], P),        # unanimous PASS
    ([P, P, P], P),
    ([F, F], F),        # unanimous FAIL
    ([P, F], A),        # disagreement -> abstain
    ([P, A], A),        # a withheld vote breaks unanimity
    ([F, A], A),        # not unanimous
    ([A, A], A),        # nobody decided
    ([P, P, F], A),     # one dissenter kills the PASS
])
def test_ensemble_requires_unanimity_to_pass(verdicts, expected):
    assert _run(_ensemble(verdicts)).verdict == expected


@pytest.mark.parametrize("verdicts,expected", [
    ([P, F], F),        # disagreement -> fail mode
    ([F, A], F),
    ([P, A], F),        # a lone withheld vote among passes -> forced FAIL
    ([A, A], A),        # all-abstain stays abstain even in fail mode
    ([P, P], P),
])
def test_ensemble_on_disagreement_fail_mode(verdicts, expected):
    assert _run(_ensemble(verdicts, on_disagreement="fail")).verdict == expected


def test_ensemble_forced_fail_confidence_is_broken_unanimity_never_zero():
    # [P, A] in fail mode: one non-PASS of two -> FAIL at (n-passes)/n = 0.5,
    # never a bare FAIL 0.00 (there ARE zero FAIL votes, but unanimity WAS broken).
    ev = _run(_ensemble([P, A], on_disagreement="fail"))
    assert ev.verdict == Verdict.FAIL
    assert parse_confidence(ev.detail) == pytest.approx(0.5, abs=1e-9)


def test_ensemble_pass_confidence_is_agreement_and_stays_soft():
    ev = _run(_ensemble([P, P, P]))
    assert ev.verdict == Verdict.PASS and ev.tier == Tier.SOFT
    assert parse_confidence(ev.detail) == 1.0
    assert _ensemble([P, P]).model_calls_per_item == 2
    assert _ensemble([P, P, P]).model_calls_per_item == 3


def test_ensemble_needs_two_judges():
    with pytest.raises(ValueError):
        EnsembleJudge([_StubJudge(P, "PASS 0.9")])


# --------------------------------------------------------------------------
# 3. k-sample arithmetic
# --------------------------------------------------------------------------


@pytest.mark.parametrize("seq,require,expected", [
    ([P, P, P], "unanimous", P),
    ([P, P, F], "unanimous", A),
    ([F, F, F], "unanimous", F),
    ([P, P, F], "majority", P),     # 2/3 pass
    ([P, F, F], "majority", F),     # 2/3 fail
    ([P, F, A], "majority", A),     # 1 pass, 1 fail -> no majority of 3
    ([P, P, A], "majority", P),     # 2/3 pass
    ([P, A, A], "majority", A),     # 1/3 pass -> abstain counts against
])
def test_k_sample_vote_rules(seq, require, expected):
    j = RepeatedSamplingJudge(_CyclingJudge(seq), k=3, require=require)
    ev = _run(j)
    assert ev.verdict == expected
    assert ev.tier == Tier.SOFT
    assert j.model_calls_per_item == 3


def test_k_sample_majority_confidence_is_vote_fraction():
    j = RepeatedSamplingJudge(_CyclingJudge([P, P, F]), k=3, require="majority")
    ev = _run(j)
    assert ev.verdict == Verdict.PASS
    # synthesised to 2 decimals (well within the 0.2-wide calibration buckets)
    assert parse_confidence(ev.detail) == pytest.approx(0.67, abs=1e-9)


# --------------------------------------------------------------------------
# 4. adversarial self-check (2 calls; can flip a naive PASS to FAIL)
# --------------------------------------------------------------------------


class _FlipProvider(Provider):
    """A naive single call PASSes; the reconsider (2nd) call FAILs. Records calls."""

    def __init__(self):
        self.calls = 0
        self.model = "flip-model"

    def propose_solution(self, *, prompt, entry_point, skills=()):  # pragma: no cover
        raise NotImplementedError

    def assess(self, *, prompt, system=None) -> str:
        self.calls += 1
        from prometheus_protocol.verifier.soft_levers import _CRITIQUE_SYSTEM

        if system == _CRITIQUE_SYSTEM:
            return "The candidate mishandles the boundary the task specifies."
        # the reconsider call sees the critique in the prompt -> now FAILs
        return "FAIL 0.8" if "skeptical reviewer" in prompt else "PASS 0.9"


def test_adversarial_makes_two_calls_and_can_flip_pass_to_fail():
    inner = _FlipProvider()
    wrapped = AdversarialSelfCheckProvider(inner)
    judge = ModelJudgeVerifier(wrapped, system_prompt="verdict system")
    ev = judge.verify(code="def f(): pass", task=_dummy_task())
    assert ev.verdict == Verdict.FAIL          # the self-check flipped it
    assert inner.calls == 2                     # critique + reconsider
    assert wrapped.model_calls_per_item == 2
    assert wrapped.model == "flip-model"        # identity preserved for actor split


def _dummy_task():
    from prometheus_protocol.core.models import Case, Task

    return Task(id="t", entry_point="f", prompt="do it", split="train", cases=(Case((), None),))


# --------------------------------------------------------------------------
# 5. end-to-end: threshold cuts false-PASS through the UNCHANGED metric fold
# --------------------------------------------------------------------------


def test_threshold_cuts_low_confidence_false_pass_end_to_end():
    """A mini gold set: three trap items (reference FAIL) that the base judge
    false-PASSes at 0.9, 0.7, 0.6. Threshold@0.8 should keep the confident
    false-PASS and withhold the two low-confidence ones — false-PASS 3/3 -> 1/1,
    with the denominator shrinking (the coverage cost is visible)."""

    from prometheus_protocol.benchmarks.judge_eval import JudgedRow

    replies = {"fp_hi": "PASS 0.9", "fp_mid": "PASS 0.7", "fp_lo": "PASS 0.6"}

    def judged(item_id, min_conf):
        base = _StubJudge(Verdict.PASS, replies[item_id])
        j = ConfidenceThresholdJudge(base, min_confidence=min_conf,
                                     confidence_parser=parse_confidence)
        ev = _run(j)
        return JudgedRow(item_id=item_id, actor_model="-", reference=Verdict.FAIL,
                         judged=ev.verdict, confidence=parse_confidence(ev.detail))

    baseline = compute_metrics([JudgedRow(k, "-", Verdict.FAIL, Verdict.PASS,
                                          parse_confidence(v)) for k, v in replies.items()])
    assert (baseline.false_pass, baseline.reference_fails_decided) == (3, 3)

    gated = compute_metrics([judged(k, 0.8) for k in replies])
    assert (gated.false_pass, gated.reference_fails_decided) == (1, 1)  # only fp_hi survives
    assert gated.n_abstained == 2  # the two low-confidence false-PASSes withheld


# --------------------------------------------------------------------------
# 6. SOFT stays SOFT — no lever grants authority
# --------------------------------------------------------------------------


@pytest.mark.parametrize("make", [
    lambda: ConfidenceThresholdJudge(_StubJudge(P, "PASS 0.99"), min_confidence=0.8,
                                     confidence_parser=parse_confidence),
    lambda: _ensemble([P, P, P]),
    lambda: RepeatedSamplingJudge(_CyclingJudge([P, P, P]), k=3, require="unanimous"),
])
def test_soft_stays_soft_no_lever_grants_authority(make):
    judge = make()
    ev = _run(judge)
    assert ev.verdict == Verdict.PASS and ev.tier == Tier.SOFT
    # However confident, a soft-only judgment is non-authoritative...
    judgment = VerifierBank().judge([ev])
    assert judgment.authoritative is False
    # ...and the gate blocks it (a soft PASS proposing anything cannot execute).
    from prometheus_protocol.core.models import ACTION_PYTHON_CODE, ExecutableAction

    gate = ActionGate(escalate_below=0.75, route_high_risk=True)
    decision = gate.decide(
        judgment,
        risk_class="low",
        action=ExecutableAction(kind=ACTION_PYTHON_CODE, code="print('x')"),
    )
    assert decision.outcome == OUTCOME_BLOCK


# --------------------------------------------------------------------------
# 7. default behaviour unchanged (the temperature knob defaults to 0)
# --------------------------------------------------------------------------


def test_judge_temperature_defaults_to_zero_everywhere():
    from prometheus_protocol.core.config import Config

    assert Config().judge_temperature == 0.0
    assert Config.from_env(env={}).judge_temperature == 0.0

    from prometheus_protocol.provider.remote import RemoteModelProvider

    p = RemoteModelProvider(api_base="http://x", model="m")
    assert p.assess_temperature == 0.0
    # 0.0 normalises to int 0 in the request payload -> byte-identical default.
    assert (p.assess_temperature or 0) == 0 and isinstance(p.assess_temperature or 0, int)


# --------------------------------------------------------------------------
# 8. the Hearth and the default judge path are unchanged vs main
# --------------------------------------------------------------------------

_UNCHANGED_FILES = (
    # Hearth
    "src/prometheus_protocol/verifier/bank.py",
    "src/prometheus_protocol/verifier/aggregate.py",
    "src/prometheus_protocol/verifier/trust.py",
    "src/prometheus_protocol/gate/promotion.py",
    "src/prometheus_protocol/gate/authorization.py",
    "src/prometheus_protocol/execution/executor.py",
    "src/prometheus_protocol/execution/controller.py",
    "src/prometheus_protocol/forge/miner.py",
    "src/prometheus_protocol/core/models.py",
    "src/prometheus_protocol/core/interfaces.py",
    # the DEFAULT soft-judge path — levers are opt-in wrappers, not edits
    "src/prometheus_protocol/verifier/model_judge.py",
    "src/prometheus_protocol/verifier/grounding.py",
    # the read-only harness the driver reuses
    "src/prometheus_protocol/benchmarks/judge_eval.py",
    "src/prometheus_protocol/benchmarks/grounding_eval.py",
)


def _git(*args: str) -> subprocess.CompletedProcess:
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return subprocess.run(["git", *args], capture_output=True, text=True, cwd=root)


@pytest.mark.skipif(
    _git("rev-parse", "--verify", "origin/main").returncode != 0,
    reason="origin/main not available in this checkout",
)
def test_hearth_and_default_judge_path_unchanged_versus_main():
    diff = _git("diff", "--name-only", "origin/main", "--", *_UNCHANGED_FILES)
    assert diff.returncode == 0, diff.stderr
    changed = [line for line in diff.stdout.splitlines() if line.strip()]
    assert changed == [], f"protected files changed vs origin/main: {changed}"
