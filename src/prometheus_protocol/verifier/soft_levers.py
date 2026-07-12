"""Configurable calibration levers for the SOFT judge — measured, not adopted.

The composition study (``docs/composition-study.md``) proved that combining
per-step confidences cannot manufacture signal the steps lack: lowering the
SOFT judge's own **false-PASS** (the dangerous direction) is the higher-leverage
path to chain trust. This module implements candidate levers for that, as
opt-in wrappers around the existing SOFT judge. They change **nothing** by
default: the production judge path is untouched, and each lever is measured by
``benchmarks/soft_calibration_eval.py`` against the recorded baselines before
any adoption.

Two hard invariants hold for every lever here:

* **A SOFT verdict stays SOFT.** Every wrapper emits ``Tier.SOFT`` Evidence.
  Better calibration can only tighten what the gate already treats as advisory
  (turn a shaky PASS into an ABSTAIN); it never makes a soft judgment
  authoritative. The bank still gives a soft-only judgment no authority and the
  gate still blocks it (tested in ``tests/conformance/test_soft_levers.py``).
* **The dangerous direction only.** The levers are built to move ABSTAIN/FAIL
  in exchange for cutting false-PASS. They never turn a FAIL into a PASS.

Each lever exposes ``model_calls_per_item`` so its cost is reported honestly: a
lever that halves false-PASS at 3× the model calls is a tradeoff, not a win.
"""

from __future__ import annotations

import time
from typing import Callable, Sequence

from prometheus_protocol.core.interfaces import Provider, Verifier
from prometheus_protocol.core.models import Evidence, Skill, Tier, Verdict

#: A parser that reads a stated confidence out of a judge reply / Evidence
#: detail (the domain supplies its own: code vs grounding vocabulary).
ConfidenceParser = Callable[[str], "float | None"]

_VERDICT_WORD = {Verdict.PASS: "PASS", Verdict.FAIL: "FAIL", Verdict.ABSTAIN: "ABSTAIN"}


def _synth_detail(verdict: Verdict, confidence: float | None, note: str) -> str:
    """Render a lever's decision so the EXISTING confidence parsers read it.

    Both domain parsers accept ``<token> <number>`` on the first line, so a
    synthesised ``PASS 0.67`` line round-trips the aggregated confidence through
    the unchanged harness. ABSTAIN carries no number (it is excluded from
    calibration anyway)."""

    word = _VERDICT_WORD[verdict]
    head = word if confidence is None else f"{word} {confidence:.2f}"
    return f"{head}\n{note}" if note else head


def _soft_evidence(
    verifier_id: str, verdict: Verdict, detail: str, *, cost: float
) -> Evidence:
    return Evidence(
        passed=(verdict == Verdict.PASS),
        total=1,
        passed_count=1 if verdict == Verdict.PASS else 0,
        failures=(),
        verifier_id=verifier_id,
        verdict=verdict,
        tier=Tier.SOFT,  # a lever NEVER changes the tier — SOFT stays SOFT
        cost=cost,
        latency_ms=cost * 1000.0,
        detail=detail[:1000],
    )


# --------------------------------------------------------------------------
# Lever 3: confidence-threshold gating (1x cost)
# --------------------------------------------------------------------------


class ConfidenceThresholdJudge(Verifier):
    """Refuse to accept a SOFT PASS below a confidence threshold → ABSTAIN.

    Only the dangerous direction is gated: a PASS whose stated confidence is
    below ``min_confidence`` (or unstated) becomes an ABSTAIN — it leaves the
    decided set rather than passing. FAIL and ABSTAIN are untouched. This trades
    coverage (the surviving PASS denominator shrinks; watch it, per the
    composition study's silence trap) for a lower false-PASS.

    Wraps the SOFT judge: it forwards the base Evidence on the surviving-PASS and
    non-PASS paths and emits SOFT on the downgrade path, so it never *upgrades*
    tier — a SOFT judgment stays SOFT. (It is not meant to wrap an authoritative
    verifier; the levers are SOFT-judge calibration, not a tier change.)
    """

    def __init__(
        self,
        base: Verifier,
        *,
        min_confidence: float,
        confidence_parser: ConfidenceParser,
        verifier_id: str | None = None,
    ) -> None:
        self._base = base
        self._min = min_confidence
        self._parse = confidence_parser
        self.verifier_id = verifier_id or f"{_base_id(base)}:threshold@{min_confidence:g}"
        self.tier = Tier.SOFT

    model_calls_per_item = 1

    def verify(self, *, code: str, task) -> Evidence:
        ev = self._base.verify(code=code, task=task)
        if ev.verdict != Verdict.PASS:
            return ev  # FAIL / ABSTAIN pass through unchanged (already SOFT)
        conf = self._parse(ev.detail)
        if conf is None or conf < self._min:
            note = (
                f"PASS withheld: stated confidence "
                f"{'unstated' if conf is None else f'{conf:.2f}'} < {self._min:g}\n"
                f"{ev.detail}"
            )
            return _soft_evidence(self.verifier_id, Verdict.ABSTAIN, note, cost=ev.cost or 0.0)
        return ev


# --------------------------------------------------------------------------
# Lever 1: ensemble of independent judges (Nx cost)
# --------------------------------------------------------------------------

_ON_DISAGREEMENT = ("abstain", "fail")


class EnsembleJudge(Verifier):
    """N independent judges; unanimity to PASS, else the non-unanimous outcome.

    A PASS requires **every** judge to decide PASS. Any FAIL, or any judge that
    withholds (ABSTAIN), breaks unanimity and the ensemble returns the
    ``on_disagreement`` outcome. Two cases are decided **independently** of
    ``on_disagreement``: a unanimous FAIL is always a FAIL, and an all-abstain
    vote is always an ABSTAIN (nobody had an opinion). Raising the bar for a PASS
    is the point: it should cut false-PASS at the cost of more abstains/
    false-FAILs — a tradeoff to be measured, not assumed.

    The synthesised confidence is the fraction of judges voting the returned
    verdict (agreement), so a unanimous decision reads as 1.0.
    """

    def __init__(
        self,
        judges: Sequence[Verifier],
        *,
        on_disagreement: str = "abstain",
        verifier_id: str = "ensemble-judge",
    ) -> None:
        if len(judges) < 2:
            raise ValueError("an ensemble needs at least two judges")
        if on_disagreement not in _ON_DISAGREEMENT:
            raise ValueError(f"on_disagreement must be one of {_ON_DISAGREEMENT}")
        self._judges = tuple(judges)
        self._on_disagreement = on_disagreement
        self.verifier_id = verifier_id
        self.tier = Tier.SOFT

    @property
    def model_calls_per_item(self) -> int:
        return len(self._judges)

    def verify(self, *, code: str, task) -> Evidence:
        started = time.monotonic()
        verdicts = [j.verify(code=code, task=task).verdict for j in self._judges]
        cost = time.monotonic() - started
        n = len(verdicts)
        passes = verdicts.count(Verdict.PASS)
        fails = verdicts.count(Verdict.FAIL)

        if passes == n:
            verdict, conf = Verdict.PASS, 1.0
        elif fails == n:
            verdict, conf = Verdict.FAIL, 1.0
        elif passes == 0 and fails == 0:
            verdict, conf = Verdict.ABSTAIN, None  # nobody had an opinion
        else:
            # a PASS is broken by any FAIL or any withheld vote; return the
            # configured non-unanimous outcome (never a PASS). A forced FAIL's
            # confidence is the fraction of judges that did NOT endorse a PASS
            # (how much unanimity was broken) — so a lone dissent among passes
            # reads as a low-but-nonzero FAIL, never a bare 0.00.
            verdict = Verdict.FAIL if self._on_disagreement == "fail" else Verdict.ABSTAIN
            conf = ((n - passes) / n) if verdict == Verdict.FAIL else None
        note = f"ensemble votes: PASS={passes} FAIL={fails} ABSTAIN={n - passes - fails} of {n}"
        return _soft_evidence(self.verifier_id, verdict, _synth_detail(verdict, conf, note), cost=cost)


# --------------------------------------------------------------------------
# Lever 2: self-consistency / repeated sampling (kx cost)
# --------------------------------------------------------------------------

_REQUIRE = ("majority", "unanimous")


class RepeatedSamplingJudge(Verifier):
    """Query the same base judge k times; require majority/unanimity to PASS.

    Hypothesis: cuts *variance*-driven false-PASSes. It cannot cut *systematic*
    ones — if the judge reliably misreads a subtle trap, k identical-in-spirit
    samples agree on the wrong answer. At temperature 0 the k samples are
    identical **where the endpoint is deterministic** (see ``remote.py``), so
    this lever is typically a no-op on the verdict unless the judge samples at
    temperature > 0 (see ``PROM_JUDGE_TEMPERATURE``). Note the reported
    confidence is the *agreement* fraction (winning votes / k), NOT the model's
    own stated confidence: at temperature 0 a unanimous decision therefore reads
    as 1.00 regardless of how sure the model actually was, so read the k-sample
    calibration column as agreement, not model certainty. Cost is k× model
    calls; report it.

    * ``unanimous``: PASS iff all k samples voted PASS (FAIL iff all k FAIL).
    * ``majority``: PASS iff PASS votes are a strict majority of all k samples
      (FAIL likewise); otherwise ABSTAIN. Abstained samples count against a
      majority, conservatively.
    """

    def __init__(
        self,
        base: Verifier,
        *,
        k: int = 3,
        require: str = "majority",
        verifier_id: str | None = None,
    ) -> None:
        if k < 1:
            raise ValueError("k must be >= 1")
        if require not in _REQUIRE:
            raise ValueError(f"require must be one of {_REQUIRE}")
        self._base = base
        self._k = k
        self._require = require
        self.verifier_id = verifier_id or f"{_base_id(base)}:k{k}-{require}"
        self.tier = Tier.SOFT

    @property
    def model_calls_per_item(self) -> int:
        return self._k

    def verify(self, *, code: str, task) -> Evidence:
        started = time.monotonic()
        verdicts = [self._base.verify(code=code, task=task).verdict for _ in range(self._k)]
        cost = time.monotonic() - started
        passes = verdicts.count(Verdict.PASS)
        fails = verdicts.count(Verdict.FAIL)

        if self._require == "unanimous":
            if passes == self._k:
                verdict, conf = Verdict.PASS, 1.0
            elif fails == self._k:
                verdict, conf = Verdict.FAIL, 1.0
            else:
                verdict, conf = Verdict.ABSTAIN, None
        else:  # majority of all k
            if passes * 2 > self._k:
                verdict, conf = Verdict.PASS, passes / self._k
            elif fails * 2 > self._k:
                verdict, conf = Verdict.FAIL, fails / self._k
            else:
                verdict, conf = Verdict.ABSTAIN, None
        note = f"k={self._k} {self._require} votes: PASS={passes} FAIL={fails}"
        return _soft_evidence(self.verifier_id, verdict, _synth_detail(verdict, conf, note), cost=cost)


# --------------------------------------------------------------------------
# Lever 4: adversarial self-check (2x cost) — a provider-level wrapper
# --------------------------------------------------------------------------

_CRITIQUE_SYSTEM = (
    "You are a skeptical red-team reviewer. Do not decide anything. In two or "
    "three sentences, state the STRONGEST specific case that the candidate is "
    "WRONG or that the claim is NOT supported — name the concrete flaw, the "
    "unstated assumption, or the missing entailment a careless reviewer would "
    "skip. If you genuinely cannot find one, say so briefly."
)

_CRITIQUE_INSTRUCTION = (
    "\n\nBefore any verdict: argue the strongest case that this should NOT be "
    "accepted. Name the specific flaw or the exact step that is not supported."
)


class AdversarialSelfCheckProvider(Provider):
    """Wrap a provider so each judge call first elicits the strongest case AGAINST.

    Two model calls per assessment: (1) ask a red-team reviewer for the
    strongest argument the candidate is wrong, then (2) re-ask the ORIGINAL
    verdict question with that critique in view. Domain-general: it operates on
    the raw prompt text and reuses the domain judge's own verdict ``system``
    prompt for the final decision, so the wrapped judge's parsing and tier are
    unchanged. Hypothesis: forces engagement with the failure mode subtle traps
    exploit. Cost: 2× model calls.
    """

    model_calls_per_item = 2

    def __init__(self, inner: Provider, *, model: str | None = None) -> None:
        self._inner = inner
        # Preserve the wrapped provider's identity for the actor-split report.
        self.model = model or getattr(inner, "model", "") or "unknown"

    def propose_solution(self, *, prompt: str, entry_point: str, skills: Sequence[Skill] = ()) -> str:
        return self._inner.propose_solution(prompt=prompt, entry_point=entry_point, skills=skills)

    def assess(self, *, prompt: str, system: str | None = None) -> str:
        critique = self._inner.assess(
            prompt=prompt + _CRITIQUE_INSTRUCTION, system=_CRITIQUE_SYSTEM
        )
        reconsider = (
            f"{prompt}\n\nA skeptical reviewer argued the strongest case AGAINST "
            f"accepting this:\n{critique.strip()}\n\nWeigh that objection honestly. "
            "If it identifies a real defect, do not accept. Now give your final "
            "verdict on the original single-line format."
        )
        return self._inner.assess(prompt=reconsider, system=system)

    def generate(self, *, prompt: str, system: str | None = None) -> str:
        return self._inner.generate(prompt=prompt, system=system)


def _base_id(base: Verifier) -> str:
    return getattr(base, "verifier_id", None) or getattr(base, "VERIFIER_ID", "judge")


__all__ = [
    "ConfidenceParser",
    "ConfidenceThresholdJudge",
    "EnsembleJudge",
    "RepeatedSamplingJudge",
    "AdversarialSelfCheckProvider",
]
