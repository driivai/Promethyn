"""The threshold lever is FREE: it is a post-hoc rule over stored baseline output.

A confidence threshold θ needs no model call. Given one baseline run's per-item
records `(item_id, verdict, confidence, gold, tier)`, every θ is a pure
recomputation: a PASS whose stated confidence is below θ (or unstated) becomes an
ABSTAIN; FAIL and ABSTAIN are untouched. So this module sweeps θ from 0.50 to
0.95 offline, with **zero model calls**, and emits the coverage-vs-false-PASS
frontier per set/arm.

The frontier is worth more than the levers combined: it makes the abstention
trade visible *by construction*. False-PASS can only fall as coverage falls, and
the curve shows how steeply — and, at each θ, exactly how many CORRECT PASSes
were withheld to catch how many FALSE ones. There is no recommended θ hardcoded
anywhere; any θ must be read off this frontier with its coverage cost stated next
to it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Sequence

from prometheus_protocol.benchmarks.judge_eval import JudgedRow
from prometheus_protocol.benchmarks.soft_calibration_report import Rate
from prometheus_protocol.core.models import Verdict

#: θ grid: 0.50 → 0.95 step 0.05 (integers ×100 to avoid float drift).
THETAS = tuple(t / 100 for t in range(50, 100, 5))


# --------------------------------------------------------------------------
# persistence: (item_id, verdict, confidence, gold, tier)
# --------------------------------------------------------------------------


def record_from_row(row: JudgedRow) -> dict:
    """One persisted baseline record. ``gold`` is the reference verdict; the
    judge is SOFT tier by construction (a lever never changes that)."""

    return {
        "item_id": row.item_id,
        "verdict": row.judged.value,
        "confidence": row.confidence,
        "gold": row.reference.value,
        "tier": "soft",
    }


def persist_records(rows: Sequence[JudgedRow], path: str, *, set_name: str, arm: str) -> None:
    payload = {
        "set": set_name,
        "arm": arm,
        "records": [record_from_row(r) for r in rows],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def load_records(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------
# the post-hoc recomputation (pure; zero model calls)
# --------------------------------------------------------------------------


def _verdict_at_theta(rec: dict, theta: float) -> Verdict:
    """A PASS below θ (or unstated) is withheld to ABSTAIN; else unchanged."""

    v = Verdict(rec["verdict"])
    if v != Verdict.PASS:
        return v
    conf = rec["confidence"]
    if conf is None or conf < theta:
        return Verdict.ABSTAIN
    return v


@dataclass(frozen=True)
class FrontierPoint:
    theta: float
    coverage: Rate            # decided / referenced
    false_pass: Rate          # judged PASS over gold-negative decided
    false_fail: Rate          # judged FAIL over gold-positive decided
    withheld_correct: int     # baseline PASSes on gold-POSITIVE now abstained
    withheld_false_pass: int  # baseline PASSes on gold-NEGATIVE now abstained

    def as_json(self) -> dict:
        return {
            "theta": self.theta,
            "coverage": self.coverage.as_json(),
            "false_PASS": self.false_pass.as_json(),
            "false_FAIL": self.false_fail.as_json(),
            "withheld_correct": self.withheld_correct,
            "withheld_false_pass": self.withheld_false_pass,
        }


def _point(records: Sequence[dict], theta: float) -> FrontierPoint:
    referenced = [r for r in records if r["gold"] in (Verdict.PASS.value, Verdict.FAIL.value)]
    gold_neg = [r for r in referenced if r["gold"] == Verdict.FAIL.value]
    gold_pos = [r for r in referenced if r["gold"] == Verdict.PASS.value]

    def decided(subset):
        return [r for r in subset if _verdict_at_theta(r, theta) in (Verdict.PASS, Verdict.FAIL)]

    dec_all = decided(referenced)
    dec_neg = decided(gold_neg)
    dec_pos = decided(gold_pos)
    fp = sum(1 for r in dec_neg if _verdict_at_theta(r, theta) == Verdict.PASS)
    ff = sum(1 for r in dec_pos if _verdict_at_theta(r, theta) == Verdict.FAIL)

    # what θ withheld relative to the ungated baseline (θ that accepts every PASS)
    withheld_correct = sum(
        1 for r in gold_pos
        if Verdict(r["verdict"]) == Verdict.PASS and _verdict_at_theta(r, theta) == Verdict.ABSTAIN
    )
    withheld_false_pass = sum(
        1 for r in gold_neg
        if Verdict(r["verdict"]) == Verdict.PASS and _verdict_at_theta(r, theta) == Verdict.ABSTAIN
    )
    return FrontierPoint(
        theta=theta,
        coverage=Rate(len(dec_all), len(referenced)),
        false_pass=Rate(fp, len(dec_neg)),
        false_fail=Rate(ff, len(dec_pos)),
        withheld_correct=withheld_correct,
        withheld_false_pass=withheld_false_pass,
    )


def sweep(records: Sequence[dict], thetas: Sequence[float] = THETAS) -> list[FrontierPoint]:
    return [_point(records, t) for t in thetas]


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------


def render_frontier(points: Sequence[FrontierPoint], *, set_name: str, arm: str) -> str:
    lines = [
        f"## Threshold frontier — set={set_name} arm={arm}  (θ-sweep, ZERO model calls)",
        "",
        "θ      coverage        false_PASS       false_FAIL       withheld(correct/false)",
        "----   --------------  ---------------  ---------------  -----------------------",
    ]
    for p in points:
        lines.append(
            f"{p.theta:.2f}   {p.coverage.render():<14s}  {p.false_pass.render():<15s}  "
            f"{p.false_fail.render():<15s}  {p.withheld_correct}/{p.withheld_false_pass}"
        )
    lines.append("")
    lines.append(
        "Read: false-PASS can only fall as coverage falls. At each θ the last "
        "column is the trade — CORRECT PASSes withheld to catch FALSE ones."
    )
    payload = {
        "set": set_name, "arm": arm,
        "frontier": [p.as_json() for p in points],
    }
    return "\n".join(lines) + "\n\n```json\n" + json.dumps(payload, indent=2) + "\n```\n"


def trade_at(points: Sequence[FrontierPoint], theta: float) -> str:
    """One-line statement of the coverage trade at a specific θ."""

    p = next((q for q in points if abs(q.theta - theta) < 1e-9), None)
    if p is None:
        return f"θ={theta:.2f} not in the swept grid"
    return (
        f"At θ={theta:.2f}: false_PASS {p.false_pass.render()}, "
        f"coverage {p.coverage.render()} — {p.withheld_correct} correct PASS(es) "
        f"withheld to catch {p.withheld_false_pass} false-PASS(es)."
    )


# --------------------------------------------------------------------------
# offline entry point (reproducible; zero model calls)
# --------------------------------------------------------------------------


def _scripted_grounding_v2_records() -> tuple[list[dict], str, str]:
    """The scripted grounding-v2 baseline as persisted records — the reproducible
    demo the report cites (θ=0.8 moves false-PASS 3/44 → 1/42)."""

    from prometheus_protocol.benchmarks.grounding_eval import (
        SCRIPTED_REPLIES_V2, ScriptedGroundingJudgeProvider, run_grounding_eval,
    )
    from prometheus_protocol.benchmarks.grounding_items_v2 import build_grounding_items_v2
    from prometheus_protocol.verifier.grounding import GroundingVerifier

    items = build_grounding_items_v2()
    provider = ScriptedGroundingJudgeProvider(items, SCRIPTED_REPLIES_V2)
    rows = run_grounding_eval(items, judge=GroundingVerifier(provider))
    return [record_from_row(r) for r in rows], "grounding-v2(scripted)", "scripted-smoke"


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="python -m prometheus_protocol.benchmarks.threshold_frontier",
        description="Post-hoc θ-sweep over a persisted baseline (zero model calls).",
    )
    p.add_argument("--from", dest="path", default=None,
                   help="a baseline JSON persisted by the driver's --persist")
    p.add_argument("--scripted-grounding-v2", action="store_true",
                   help="build the scripted grounding-v2 baseline offline and sweep it")
    args = p.parse_args(argv)

    if args.path:
        payload = load_records(args.path)
        records, set_name, arm = payload["records"], payload.get("set", "?"), payload.get("arm", "?")
    else:
        records, set_name, arm = _scripted_grounding_v2_records()

    points = sweep(records)
    print(render_frontier(points, set_name=set_name, arm=arm), end="")
    print("\n" + trade_at(points, 0.80))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via main() in tests
    raise SystemExit(main())
