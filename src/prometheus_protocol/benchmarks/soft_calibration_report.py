"""Standardized, denominator-carrying summary for the SOFT-lever driver.

The abstention trap (a lever that lowers false-PASS by refusing to decide) must
be impossible to miss, not something a reader has to remember to check. So this
block reports, together and always:

    items_total, items_scored, PASS, FAIL, ABSTAIN
    coverage    = items_scored / items_total
    false_PASS  = n/d   (d = gold-negative items that received a verdict)
    false_FAIL  = n/d   (d = gold-positive items that received a verdict)
    model_calls = N     (actual count)

**Every rate is emitted as num/den, never a bare percentage.** Any rate whose
denominator is < 20 carries its rule-of-three ceiling (3/d) alongside — a thin
denominator cannot resolve a rate below that, even at zero. A machine-readable
JSON object accompanies the human table, and each rate in it is a `{num, den,
rate}` object, so a rate structurally cannot be emitted without its denominator.
`tests/conformance/test_soft_calibration_report.py` fails the build otherwise.

The false-PASS / false-FAIL counts reuse the fixture-tested fold
`judge_eval.compute_metrics`; nothing here re-derives them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Sequence

from prometheus_protocol.benchmarks.judge_eval import JudgedRow, compute_metrics
from prometheus_protocol.core.models import Verdict

#: Below this denominator a rate is "thin": it carries its rule-of-three ceiling.
THIN_DENOMINATOR = 20


@dataclass(frozen=True)
class Rate:
    """A rate that cannot exist without its denominator."""

    num: int
    den: int

    @property
    def value(self) -> float | None:
        return None if self.den == 0 else self.num / self.den

    @property
    def rule_of_three_ceiling(self) -> float | None:
        """3/d — the 95% upper bound a 0/d observation would carry. Reported for
        thin denominators as a resolution floor: even a zero here proves no better."""

        return None if self.den == 0 else 3.0 / self.den

    def render(self) -> str:
        if self.den == 0:
            return f"{self.num}/{self.den} = -"
        s = f"{self.num}/{self.den} = {100 * self.value:.1f}%"
        if self.den < THIN_DENOMINATOR:
            s += (
                f"  [thin d<{THIN_DENOMINATOR}: rule-of-three ceiling "
                f"≤ {100 * self.rule_of_three_ceiling:.1f}%]"
            )
        return s

    def as_json(self) -> dict:
        return {
            "num": self.num,
            "den": self.den,
            "rate": self.value,
            "rule_of_three_ceiling": (
                self.rule_of_three_ceiling if self.den < THIN_DENOMINATOR else None
            ),
        }


@dataclass(frozen=True)
class StandardSummary:
    set_name: str
    arm: str
    lever: str
    items_total: int      # items carrying ground truth (the scoreable universe)
    items_scored: int     # judge returned PASS or FAIL
    judge_pass: int
    judge_fail: int
    abstain: int
    coverage: Rate        # items_scored / items_total
    false_pass: Rate      # judge PASS over gold-negative decided
    false_fail: Rate      # judge FAIL over gold-positive decided
    agreement: Rate
    model_calls: int

    def as_json(self) -> dict:
        return {
            "set": self.set_name,
            "arm": self.arm,
            "lever": self.lever,
            "items_total": self.items_total,
            "items_scored": self.items_scored,
            "judge_PASS": self.judge_pass,
            "judge_FAIL": self.judge_fail,
            "ABSTAIN": self.abstain,
            "coverage": self.coverage.as_json(),
            "false_PASS": self.false_pass.as_json(),
            "false_FAIL": self.false_fail.as_json(),
            "agreement": self.agreement.as_json(),
            "model_calls": self.model_calls,
        }

    def render(self) -> str:
        lines = [
            f"## Standardized summary — set={self.set_name} arm={self.arm} lever={self.lever}",
            "",
            f"items_total  : {self.items_total}",
            f"items_scored : {self.items_scored}   "
            f"(PASS {self.judge_pass}, FAIL {self.judge_fail}, ABSTAIN {self.abstain})",
            f"coverage     : {self.coverage.render()}",
            f"false_PASS   : {self.false_pass.render()}",
            f"false_FAIL   : {self.false_fail.render()}",
            f"agreement    : {self.agreement.render()}",
            f"model_calls  : {self.model_calls}   (actual; lever cost factor "
            f"{self.model_calls // self.items_total if self.items_total else '?'}×)",
        ]
        return "\n".join(lines)

    def render_json_block(self) -> str:
        return "```json\n" + json.dumps(self.as_json(), indent=2) + "\n```"


def summarize(
    rows: Sequence[JudgedRow],
    *,
    set_name: str,
    arm: str,
    lever: str,
    model_calls: int,
) -> StandardSummary:
    """Fold judged rows into the standardized summary. Pure; fixture-tested."""

    referenced = [r for r in rows if r.reference in (Verdict.PASS, Verdict.FAIL)]
    decided = [r for r in referenced if r.judged in (Verdict.PASS, Verdict.FAIL)]
    m = compute_metrics(rows)
    return StandardSummary(
        set_name=set_name,
        arm=arm,
        lever=lever,
        items_total=len(referenced),
        items_scored=len(decided),
        judge_pass=sum(1 for r in decided if r.judged == Verdict.PASS),
        judge_fail=sum(1 for r in decided if r.judged == Verdict.FAIL),
        abstain=len(referenced) - len(decided),
        coverage=Rate(len(decided), len(referenced)),
        false_pass=Rate(m.false_pass, m.reference_fails_decided),
        false_fail=Rate(m.false_fail, m.reference_passes_decided),
        agreement=Rate(m.n_agree, m.n_decided),
        model_calls=model_calls,
    )


def render_block(summary: StandardSummary) -> str:
    """The human table followed by the machine-readable JSON."""

    return summary.render() + "\n\n" + summary.render_json_block() + "\n"


__all__ = ["Rate", "StandardSummary", "summarize", "render_block", "THIN_DENOMINATOR"]
