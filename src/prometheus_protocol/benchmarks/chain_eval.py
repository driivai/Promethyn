"""Measure candidate chain-composition rules against REAL chain outcomes.

For every chain in ``chain_items.CHAINS`` this harness:

1. grades each step through the REAL :class:`VerifierBank` to get its per-step
   confidence (documented profiles → documented advisor calibration; no hand-set
   numbers);
2. assembles the chain's SQL query from the step fragments and runs it through
   the REAL HARD :class:`SqlVerifier` against the reference — the chain is
   CORRECT / INCORRECT / (ABSTAIN, excluded) by EXECUTION, never a label;
3. applies each candidate composition rule and measures how well the composed
   number predicts the executed outcome: a calibration table, the
   false-confidence rate (scored-high-but-actually-wrong — the number that
   decides whether a rule can bear a halt decision), discrimination, and how
   each rule degrades with chain length.

The analysis functions are pure (scripted inputs → known tables), so the
measurement itself is proven correct before it is trusted
(``tests/conformance/test_composition.py``).

Run it: ``python -m prometheus_protocol.benchmarks.chain_eval`` (needs the
namespace isolation runtime for the HARD SQL ground truth).
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from typing import Callable, Sequence

from prometheus_protocol.benchmarks.chain_items import (
    CHAIN_SET_VERSION,
    CHAINS,
    FIXTURE_SQL,
    HARD_PASS,
    HARD_PROFILES,
    HARD_STRONG,
    HARD_WEAK,
    SCHEMA_SQL,
    SOFT_075,
    SOFT_0875,
    SOFT_095,
    SOFT_UNCAL,
    ChainCase,
)
from prometheus_protocol.core.models import Evidence, Tier, Verdict
from prometheus_protocol.orchestration.composition import RULES
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.sql import SqlTask, SqlVerifier

# --------------------------------------------------------------------------
# profile realisation — REAL bank confidences from documented calibration
# --------------------------------------------------------------------------

_ADVISOR = "chain-advisor"
_REF = "chain-hard-ref"


def _ev(verifier_id: str, tier: Tier, passed: bool) -> Evidence:
    return Evidence(
        passed=passed, total=1, passed_count=1 if passed else 0,
        verifier_id=verifier_id, tier=tier,
        verdict=Verdict.PASS if passed else Verdict.FAIL,
    )


def _warm(bank: VerifierBank, rounds: int) -> None:
    """Calibrate ``_ADVISOR`` by judging it beside a HARD reference it agrees
    with, alternating PASS/FAIL so it earns both sensitivity and specificity."""

    for i in range(rounds):
        p = (i % 2 == 0)
        bank.judge([_ev(_REF, Tier.HARD, p), _ev(_ADVISOR, Tier.SOFT, p)])


# rounds → advisor youden, from the probed relationship (4→0.5, 12→0.75, 40→0.909)
_SOFT_WARM = {SOFT_075: 4, SOFT_0875: 12, SOFT_095: 40}


def profile_confidence(profile: str) -> float:
    """The REAL bank confidence for an ACCEPTED (PASS) step at ``profile``.

    Each call uses a fresh bank with the profile's documented calibration, so the
    per-step confidence is a controlled, reproducible real value (not synthetic).
    """

    bank = VerifierBank()
    if profile == HARD_PASS:
        j = bank.judge([_ev(_REF, Tier.HARD, True)])
    elif profile == HARD_STRONG:
        _warm(bank, 20)
        j = bank.judge([_ev(_REF, Tier.HARD, True), _ev(_ADVISOR, Tier.SOFT, True)])
    elif profile == HARD_WEAK:
        _warm(bank, 20)
        j = bank.judge([_ev(_REF, Tier.HARD, True), _ev(_ADVISOR, Tier.SOFT, False)])
    elif profile == SOFT_UNCAL:
        j = bank.judge([_ev(_ADVISOR, Tier.SOFT, True)])
    elif profile in _SOFT_WARM:
        _warm(bank, _SOFT_WARM[profile])
        j = bank.judge([_ev(_ADVISOR, Tier.SOFT, True)])
    else:
        raise ValueError(f"unknown profile {profile!r}")
    return j.confidence


# --------------------------------------------------------------------------
# running one chain — real per-step confidence + real executed ground truth
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ChainOutcome:
    chain_id: str
    scenario: str
    n_steps: int
    confidences: tuple[float, ...]
    tiers: tuple[Tier, ...]
    #: True = executed correct, False = executed incorrect, None = abstained.
    correct: bool | None
    detail: str = ""


def run_chain(case: ChainCase, verifier: SqlVerifier) -> ChainOutcome:
    confidences = tuple(profile_confidence(s.profile) for s in case.steps)
    tiers = tuple(s.tier for s in case.steps)

    task = SqlTask(
        id=f"chain:{case.chain_id}",
        prompt=case.chain_id,
        schema_sql=SCHEMA_SQL,
        fixture_sql=FIXTURE_SQL,
        reference_query=case.reference_query(),
    )
    ev = verifier.verify(code=case.candidate_query(), task=task)
    if ev.verdict == Verdict.ABSTAIN:
        correct: bool | None = None
    else:
        correct = ev.verdict == Verdict.PASS
    return ChainOutcome(
        chain_id=case.chain_id, scenario=case.scenario, n_steps=case.n_steps,
        confidences=confidences, tiers=tiers, correct=correct, detail=ev.detail,
    )


# --------------------------------------------------------------------------
# pure analysis — proven correct in tests before it is trusted
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Bucket:
    lo: float
    hi: float
    n: int
    n_correct: int
    mean_composed: float

    @property
    def frac_correct(self) -> float | None:
        return None if self.n == 0 else self.n_correct / self.n


def calibration_table(
    composed: Sequence[float], correct: Sequence[bool], *, n_buckets: int = 5
) -> list[Bucket]:
    """Bucket chains by composed confidence and report the ACTUAL fraction
    correct per bucket. A well-calibrated rule's high bucket is ~high-% correct.

    Buckets are equal-width over [0, 1]; the top bucket is closed on the right so
    a composed value of exactly 1.0 lands in it.
    """

    if len(composed) != len(correct):
        raise ValueError("composed and correct must be the same length")
    width = 1.0 / n_buckets
    buckets: list[Bucket] = []
    for b in range(n_buckets):
        lo = b * width
        hi = (b + 1) * width
        top = b == n_buckets - 1
        members = [
            (c, ok) for c, ok in zip(composed, correct)
            if (lo <= c < hi) or (top and c == hi)
        ]
        n = len(members)
        n_correct = sum(1 for _, ok in members if ok)
        mean_c = sum(c for c, _ in members) / n if n else 0.0
        buckets.append(Bucket(lo=lo, hi=hi, n=n, n_correct=n_correct, mean_composed=mean_c))
    return buckets


def false_confidence(
    composed: Sequence[float], correct: Sequence[bool], *, threshold: float
) -> tuple[int, int, float | None]:
    """The dangerous direction: among chains the rule scored ``>= threshold``,
    how many were actually INCORRECT. Returns ``(n_high, n_high_wrong, rate)``;
    rate is None when no chain cleared the threshold."""

    high = [ok for c, ok in zip(composed, correct) if c >= threshold]
    n_high = len(high)
    n_high_wrong = sum(1 for ok in high if not ok)
    rate = None if n_high == 0 else n_high_wrong / n_high
    return n_high, n_high_wrong, rate


def discrimination(
    composed: Sequence[float], correct: Sequence[bool]
) -> tuple[float | None, float | None, float | None]:
    """Mean composed for correct vs incorrect chains, and their separation.
    A rule that cannot separate the two classes is useless regardless of
    calibration."""

    corr = [c for c, ok in zip(composed, correct) if ok]
    wrong = [c for c, ok in zip(composed, correct) if not ok]
    mc = sum(corr) / len(corr) if corr else None
    mw = sum(wrong) / len(wrong) if wrong else None
    sep = (mc - mw) if (mc is not None and mw is not None) else None
    return mc, mw, sep


def expected_calibration_error(buckets: Sequence[Bucket], total: int) -> float:
    """Sum over non-empty buckets of ``(n/total) * |mean_composed - frac_correct|``.
    0 is perfectly calibrated; higher is worse."""

    if total == 0:
        return 0.0
    ece = 0.0
    for bk in buckets:
        if bk.n and bk.frac_correct is not None:
            ece += (bk.n / total) * abs(bk.mean_composed - bk.frac_correct)
    return ece


# --------------------------------------------------------------------------
# evaluation over all rules
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleReport:
    name: str
    composed: tuple[float, ...]
    buckets: tuple[Bucket, ...]
    ece: float
    n_high: int
    n_high_wrong: int
    fc_rate: float | None
    mean_correct: float | None
    mean_incorrect: float | None
    separation: float | None


def evaluate_rule(
    name: str, rule: Callable, outcomes: Sequence[ChainOutcome], *, threshold: float
) -> RuleReport:
    decided = [o for o in outcomes if o.correct is not None]
    composed = [rule(o.confidences, o.tiers) for o in decided]
    correct = [bool(o.correct) for o in decided]
    buckets = calibration_table(composed, correct)
    ece = expected_calibration_error(buckets, len(decided))
    n_high, n_high_wrong, fc = false_confidence(composed, correct, threshold=threshold)
    mc, mw, sep = discrimination(composed, correct)
    return RuleReport(
        name=name, composed=tuple(composed), buckets=tuple(buckets), ece=ece,
        n_high=n_high, n_high_wrong=n_high_wrong, fc_rate=fc,
        mean_correct=mc, mean_incorrect=mw, separation=sep,
    )


def instrument_calibration(outcomes: Sequence[ChainOutcome]) -> dict:
    """Re-measure the per-step signal composition had to work with: per profile,
    how many steps carried a wrong-but-accepted fragment vs. the profile's
    confidence. This is the instrument's own honesty check."""

    # Recover per-step (profile, wrong) from the chain specs — the outcomes carry
    # confidences/tiers, the specs carry the wrong flags.
    from prometheus_protocol.benchmarks.chain_items import CHAINS as _C
    by_profile: dict[str, list[bool]] = {}
    for case in _C:
        for step in case.steps:
            by_profile.setdefault(step.profile, []).append(step.wrong)
    rows = {}
    for prof, wrongs in by_profile.items():
        n = len(wrongs)
        n_wrong = sum(1 for w in wrongs if w)
        rows[prof] = {
            "n_steps": n,
            "n_wrong": n_wrong,
            "empirical_reliability": (n - n_wrong) / n if n else None,
            "profile_confidence": profile_confidence(prof),
        }
    return rows


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------


def _fmt_pct(x: float | None) -> str:
    return "  n/a" if x is None else f"{100 * x:4.1f}%"


def run_study(*, threshold: float = 0.8, out=print) -> dict:
    verifier = SqlVerifier()
    outcomes = [run_chain(c, verifier) for c in CHAINS]

    decided = [o for o in outcomes if o.correct is not None]
    abstained = [o for o in outcomes if o.correct is None]
    n_correct = sum(1 for o in decided if o.correct)
    n_incorrect = sum(1 for o in decided if not o.correct)

    out(f"=== {CHAIN_SET_VERSION} ===")
    lengths = sorted({o.n_steps for o in outcomes})
    dist = {n: sum(1 for o in outcomes if o.n_steps == n) for n in lengths}
    out(f"chains: {len(outcomes)}  step-length distribution: "
        + ", ".join(f"N={n}:{dist[n]}" for n in lengths))
    out(f"ground truth (EXECUTED): correct {n_correct}, incorrect {n_incorrect}, "
        f"abstained/excluded {len(abstained)}")
    by_scn: dict[str, tuple[int, int]] = {}
    for o in decided:
        c, w = by_scn.get(o.scenario, (0, 0))
        by_scn[o.scenario] = (c + (1 if o.correct else 0), w + (0 if o.correct else 1))
    out("by scenario (correct/incorrect): "
        + ", ".join(f"{k} {v[0]}/{v[1]}" for k, v in sorted(by_scn.items())))
    if abstained:
        out("ABSTAINED chains (excluded from calibration): "
            + ", ".join(o.chain_id for o in abstained))

    out("")
    out("=== instrument self-calibration (what per-step signal composition saw) ===")
    out("profile          steps  wrong  empirical-reliability  profile-confidence")
    inst = instrument_calibration(outcomes)
    for prof in (HARD_PASS, HARD_STRONG, HARD_WEAK, SOFT_UNCAL, SOFT_075, SOFT_0875, SOFT_095):
        if prof not in inst:
            continue
        r = inst[prof]
        rel = _fmt_pct(r["empirical_reliability"])
        out(f"{prof:15s}  {r['n_steps']:4d}  {r['n_wrong']:5d}         {rel:>8s}"
            f"              {r['profile_confidence']:.3f}")

    reports = {
        name: evaluate_rule(name, rule, outcomes, threshold=threshold)
        for name, rule in RULES.items()
    }

    out("")
    out(f"=== calibration tables per rule (buckets of composed confidence) ===")
    for name, rep in reports.items():
        out(f"\n[{name}]  ECE={rep.ece:.3f}  "
            f"discrimination: correct̄={_fmtf(rep.mean_correct)} "
            f"incorrect̄={_fmtf(rep.mean_incorrect)} sep={_fmtf(rep.separation)}")
        out("  bucket         n   correct   frac-correct   mean-composed")
        for bk in rep.buckets:
            edge = "]" if bk.hi == 1.0 else ")"
            label = f"[{bk.lo:.1f},{bk.hi:.1f}{edge}"
            if bk.n:
                out(f"  {label:11s}  {bk.n:4d}   {bk.n_correct:5d}     "
                    f"{_fmt_pct(bk.frac_correct):>8s}      {bk.mean_composed:.3f}")
            else:
                out(f"  {label:11s}  {bk.n:4d}   {bk.n_correct:5d}          n/a         —")

    out("")
    out("=== the dangerous direction: false-confidence swept over thresholds ===")
    out("(of chains a rule scored >= θ, the fraction that were ACTUALLY INCORRECT;")
    out(" 'n' is how many chains cleared θ — a rule that clears few buys safety with silence)")
    sweep = (0.80, 0.90, 0.95)
    header = "rule                " + "   ".join(f"θ={t:.2f} (n)" for t in sweep)
    out(header)
    for name, rule in RULES.items():
        comp = [rule(o.confidences, o.tiers) for o in decided]
        corr = [bool(o.correct) for o in decided]
        cells = []
        for t in sweep:
            n_high, n_wrong, fc = false_confidence(comp, corr, threshold=t)
            cells.append(f"{_fmt_pct(fc):>5s} ({n_high:2d})")
        out(f"{name:18s}  " + "  ".join(cells))

    out("")
    out("=== degradation with chain length (false-confidence rate by N) ===")
    out("rule                " + "  ".join(f"N={n}" for n in lengths))
    for name, rule in RULES.items():
        cells = []
        for n in lengths:
            sub = [o for o in decided if o.n_steps == n]
            comp = [rule(o.confidences, o.tiers) for o in sub]
            corr = [bool(o.correct) for o in sub]
            _, _, fc = false_confidence(comp, corr, threshold=threshold)
            cells.append(_fmt_pct(fc))
        out(f"{name:18s}  " + "  ".join(f"{c:>5s}" for c in cells))

    return {
        "n_chains": len(outcomes),
        "decided": len(decided),
        "correct": n_correct,
        "incorrect": n_incorrect,
        "abstained": [o.chain_id for o in abstained],
        "reports": reports,
        "threshold": threshold,
    }


def _fmtf(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.3f}"


def instrument_self_check(out=print) -> bool:
    """Prove the instrument sound before trusting its measurement: every chain's
    reference must self-verify PASS, and every chain DESIGNED to end incorrect
    must actually execute to FAIL (no wrong fragment coincidentally equivalent).
    Returns True iff sound."""

    verifier = SqlVerifier()
    ok = True
    n_ref_checked = 0
    n_wrong_checked = 0
    for case in CHAINS:
        task = SqlTask(
            id=f"selfcheck:{case.chain_id}", prompt=case.chain_id,
            schema_sql=SCHEMA_SQL, fixture_sql=FIXTURE_SQL,
            reference_query=case.reference_query(),
        )
        # 1. reference self-verifies PASS
        ref = verifier.verify(code=case.reference_query(), task=task)
        n_ref_checked += 1
        if ref.verdict != Verdict.PASS:
            ok = False
            out(f"  UNSOUND: reference for {case.chain_id} did not self-verify "
                f"({ref.verdict.value}: {ref.detail})")
        # 2. a chain DESIGNED to end incorrect must execute FAIL
        if not case.ends_correct():
            n_wrong_checked += 1
            cand = verifier.verify(code=case.candidate_query(), task=task)
            if cand.verdict != Verdict.FAIL:
                ok = False
                out(f"  UNSOUND: {case.chain_id} is designed-wrong but executed "
                    f"{cand.verdict.value} (coincidental equivalence?): "
                    f"cand={case.candidate_query()!r}")
    out(f"  instrument self-check: {n_ref_checked} references self-verified, "
        f"{n_wrong_checked} designed-wrong candidates executed — "
        + ("SOUND" if ok else "UNSOUND"))
    return ok


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m prometheus_protocol.benchmarks.chain_eval",
        description="Measure chain-composition rules against executed ground truth.",
    )
    p.add_argument("--threshold", type=float, default=0.8,
                   help="halt/high threshold for the false-confidence measure")
    p.add_argument("--self-check-only", action="store_true")
    args = p.parse_args(argv)

    from prometheus_protocol.sandbox import NamespaceSandbox
    if not NamespaceSandbox.available():
        print("[chain_eval] the namespace isolation runtime is unavailable; the "
              "HARD SQL ground truth cannot be executed, so the study refuses to "
              "run on unverifiable ground truth.")
        return 1

    print("=== instrument self-check (executed) ===")
    sound = instrument_self_check()
    if not sound:
        print("[chain_eval] instrument is UNSOUND; refusing to report a measurement "
              "built on it.")
        return 1
    if args.self_check_only:
        return 0
    print("")
    run_study(threshold=args.threshold)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via main() in tests
    raise SystemExit(main())
