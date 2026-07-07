"""Grounding admissions test: measure the soft grounding judge against gold.

MEASURE FIRST, GRANT AUTHORITY SECOND. In the grounding domain there is no
HARD verifier — ground truth is the curated gold label on each item of
``grounding_items`` — so before the grounding judge's opinion is given ANY
weight, its error profile must be measured here:

* **false-PASS** — judge says SUPPORTED where gold says NOT-SUPPORTED. The
  dangerous direction: with no hard backstop, a false PASS is what would let
  an ungrounded claim through, so this number is the judge's admissions test.
* **false-FAIL** — judge says NOT-SUPPORTED where gold says SUPPORTED (costs
  work; the safe direction).
* **abstain / agreement / calibration** — as in the code-domain judge eval.
* **per-category breakdown** — which trap families leak, which supported
  shapes get wrongly failed.

READ-ONLY BY CONSTRUCTION, like the code-domain judge eval: no bank, no trust
store, no ledger. Rows are folded into metrics in memory and dropped —
evaluation is not experience, and nothing here grants the judge weight.

The arithmetic core is REUSED from ``judge_eval`` (``JudgedRow`` +
``compute_metrics``, the fixture-tested fold): gold labels stand in the
reference position a HARD verdict occupies in the code domain. That is the
whole difference between the domains, made explicit in one import.

Determinism: the default (offline) mode uses a scripted judge with designed
deviations — two false-PASSes, one false-FAIL, one explicit abstain, one
malformed reply, one unstated confidence — so every counter below is
hand-checkable. The offline run validates the HARNESS, not any real judge.
Live numbers come from the operator dispatching the judge-eval-live workflow
with ``item_set=grounding-v1`` (both arms: the actor-family judge and the
independent-family judge), or locally:

    python -m prometheus_protocol.benchmarks.grounding_eval            # offline
    PROM_PROVIDER=remote PROM_API_BASE=... PROM_MODEL=... \\
        PROM_JUDGE_MODEL=... python -m prometheus_protocol.benchmarks.grounding_eval --live
"""

from __future__ import annotations

import argparse
from typing import Sequence

from prometheus_protocol.benchmarks.grounding_items import (
    GOLD_NOT_SUPPORTED,
    GOLD_SUPPORTED,
    GROUNDING_ITEM_SET_VERSION,
    GroundingEvalItem,
    build_grounding_items,
    task_for,
)
from prometheus_protocol.benchmarks.judge_eval import (
    BUCKET_EDGES,
    JudgedRow,
    compute_metrics,
)
from prometheus_protocol.core.interfaces import Provider, Verifier
from prometheus_protocol.core.models import Skill, Verdict
from prometheus_protocol.verifier.grounding import (
    GroundingVerifier,
    parse_grounding_confidence,
)

#: Identity the offline scripted judge reports.
SCRIPTED_JUDGE_MODEL = "scripted-grounding-judge"

#: Gold label -> the verdict it occupies in the reference position.
_GOLD_VERDICT = {
    GOLD_SUPPORTED: Verdict.PASS,
    GOLD_NOT_SUPPORTED: Verdict.FAIL,
}


class ScriptedGroundingJudgeProvider(Provider):
    """Deterministic offline judge stand-in for the harness reference run.

    Replies are scripted per item, keyed by the item's claim text (which the
    grounding prompt embeds verbatim). An honest SIMULATION: it validates the
    plumbing and arithmetic and says nothing about any real judge.
    """

    def __init__(
        self,
        items: Sequence[GroundingEvalItem],
        replies: dict[str, str],
        *,
        model: str = SCRIPTED_JUDGE_MODEL,
    ) -> None:
        self._claim_to_reply = {
            item.claim: replies[item.item_id]
            for item in items
            if item.item_id in replies
        }
        self.model = model

    def propose_solution(
        self, *, prompt: str, entry_point: str, skills: Sequence[Skill] = ()
    ) -> str:
        raise NotImplementedError("the scripted grounding judge only assesses")

    def assess(self, *, prompt: str, system: str | None = None) -> str:
        for claim, reply in self._claim_to_reply.items():
            if claim in prompt:
                return reply
        return "ABSTAIN"


#: Scripted reply per item. Correct verdicts everywhere EXCEPT the designed
#: deviations, so every metric is exercised with hand-checkable numbers:
#:   g06, g43 -> false-PASS (the dangerous direction; one confident, one mid)
#:   g18      -> false-FAIL at low confidence
#:   g30      -> explicit ABSTAIN (on a gold not-supported item)
#:   g33      -> malformed reply (parses to ABSTAIN; on a gold supported item)
#:   g01      -> correct verdict with NO stated confidence (the unstated row)
#: Expected fold over the 44 items: decided 42, abstained 2, agreement 39/42,
#: false-PASS 2/25 (26 gold-not-supported minus the g30 abstain), false-FAIL
#: 1/17 (18 gold-supported minus the g33 abstain), unstated 1 (correct).
SCRIPTED_REPLIES: dict[str, str] = {
    "g01": "SUPPORTED",
    "g02": "SUPPORTED 0.9",
    "g03": "SUPPORTED 0.85",
    "g04": "NOT-SUPPORTED 0.9",
    "g05": "NOT-SUPPORTED 0.85",
    "g06": "SUPPORTED 0.8",        # false-PASS: unstated causation slips by
    "g07": "NOT-SUPPORTED 0.15",   # correct at very low stated confidence
    "g08": "NOT-SUPPORTED 0.8",
    "g09": "SUPPORTED 0.95",
    "g10": "SUPPORTED 0.9",
    "g11": "SUPPORTED 0.85",
    "g12": "NOT-SUPPORTED 0.9",
    "g13": "NOT-SUPPORTED 0.85",
    "g14": "NOT-SUPPORTED 0.7",
    "g15": "NOT-SUPPORTED 0.9",
    "g16": "NOT-SUPPORTED 0.75",
    "g17": "SUPPORTED 0.95",
    "g18": "NOT-SUPPORTED 0.3",    # false-FAIL at low confidence
    "g19": "SUPPORTED 0.9",
    "g20": "NOT-SUPPORTED 0.9",
    "g21": "NOT-SUPPORTED 0.85",
    "g22": "NOT-SUPPORTED 0.5",    # correct at mid confidence
    "g23": "NOT-SUPPORTED 0.8",
    "g24": "SUPPORTED 0.9",
    "g25": "SUPPORTED 0.95",
    "g26": "SUPPORTED 0.8",
    "g27": "NOT-SUPPORTED 0.85",
    "g28": "NOT-SUPPORTED 0.8",
    "g29": "NOT-SUPPORTED 0.9",
    "g30": "ABSTAIN",              # explicit no-opinion
    "g31": "SUPPORTED 0.9",
    "g32": "SUPPORTED 0.95",
    "g33": "The claim seems fine to me.",  # malformed -> parser ABSTAIN
    "g34": "NOT-SUPPORTED 0.75",
    "g35": "NOT-SUPPORTED 0.9",
    "g36": "NOT-SUPPORTED 0.85",
    "g37": "NOT-SUPPORTED 0.7",
    "g38": "SUPPORTED 0.85",
    "g39": "SUPPORTED 0.9",
    "g40": "SUPPORTED 0.9",
    "g41": "NOT-SUPPORTED 0.85",
    "g42": "NOT-SUPPORTED 0.9",
    "g43": "SUPPORTED 0.55",       # false-PASS at mid confidence
    "g44": "NOT-SUPPORTED 0.8",
}


def run_grounding_eval(
    items: Sequence[GroundingEvalItem], *, judge: Verifier
) -> tuple[JudgedRow, ...]:
    """Judge every item; pair the judge's verdict with the gold reference.

    The gold label occupies the reference position (the role the HARD verdict
    plays in the code-domain eval). ``actor_model`` has no meaning here —
    grounding items carry no actor — so it is set to ``"-"`` and the
    actor-identity split is never computed.
    """

    rows = []
    for item in items:
        judged = judge.verify(code=item.claim, task=task_for(item))
        rows.append(
            JudgedRow(
                item_id=item.item_id,
                actor_model="-",
                reference=_GOLD_VERDICT[item.gold],
                judged=judged.verdict,
                confidence=parse_grounding_confidence(judged.detail),
            )
        )
    return tuple(rows)


def _pct(num: int, den: int) -> str:
    if den == 0:
        return f"{num}/{den} = -"
    return f"{num}/{den} = {100.0 * num / den:.1f}%"


def render_grounding_report(
    rows: Sequence[JudgedRow],
    items: Sequence[GroundingEvalItem],
    *,
    judge_model: str,
    mode: str,
) -> str:
    m = compute_metrics(rows)
    by_id = {item.item_id: item for item in items}
    lines = [
        f"# Grounding admissions test ({mode})",
        "",
        f"judge model : {judge_model}",
        f"item set    : {GROUNDING_ITEM_SET_VERSION}",
        f"items       : {m.n_items}",
        f"with gold reference : {m.n_reference}",
        f"judge decided : {m.n_decided}  |  judge abstained : {m.n_abstained}",
        "",
        "| metric | value |",
        "|---|---|",
        f"| agreement (of decided) | {_pct(m.n_agree, m.n_decided)} |",
        f"| false-PASS (judge SUPPORTED where gold NOT-SUPPORTED) | "
        f"{_pct(m.false_pass, m.reference_fails_decided)} |",
        f"| false-FAIL (judge NOT-SUPPORTED where gold SUPPORTED) | "
        f"{_pct(m.false_fail, m.reference_passes_decided)} |",
        "",
        "## Calibration (stated confidence vs correctness)",
        "",
        "| confidence | n | correct | accuracy |",
        "|---|---|---|---|",
    ]
    for b in m.buckets:
        edge = "]" if b.hi == BUCKET_EDGES[-1] else ")"
        acc = "-" if b.accuracy is None else f"{100.0 * b.accuracy:.1f}%"
        lines.append(f"| [{b.lo:.2f}, {b.hi:.2f}{edge} | {b.count} | {b.correct} | {acc} |")
    acc = "-" if m.unstated_count == 0 else f"{100.0 * m.unstated_correct / m.unstated_count:.1f}%"
    lines.append(f"| unstated | {m.unstated_count} | {m.unstated_correct} | {acc} |")

    # Per-category breakdown: where the dangerous direction leaks (trap
    # families passed) and where useful work is lost (support shapes failed).
    lines += [
        "",
        "## Trap categories (gold not-supported): judge decisions",
        "",
        "| category | decided | correctly failed | false-PASS |",
        "|---|---|---|---|",
    ]
    for category in sorted({i.category for i in items if i.gold == GOLD_NOT_SUPPORTED}):
        cat_rows = [
            r for r in rows
            if by_id[r.item_id].category == category
            and r.judged in (Verdict.PASS, Verdict.FAIL)
        ]
        fp = sum(1 for r in cat_rows if r.judged == Verdict.PASS)
        lines.append(
            f"| {category} | {len(cat_rows)} | {len(cat_rows) - fp} | {fp} |"
        )
    lines += [
        "",
        "## Support categories (gold supported): judge decisions",
        "",
        "| category | decided | correctly passed | false-FAIL |",
        "|---|---|---|---|",
    ]
    for category in sorted({i.category for i in items if i.gold == GOLD_SUPPORTED}):
        cat_rows = [
            r for r in rows
            if by_id[r.item_id].category == category
            and r.judged in (Verdict.PASS, Verdict.FAIL)
        ]
        ff = sum(1 for r in cat_rows if r.judged == Verdict.FAIL)
        lines.append(
            f"| {category} | {len(cat_rows)} | {len(cat_rows) - ff} | {ff} |"
        )
    lines += [
        "",
        "_Gold labels are a curated human reference — not executable truth. "
        "This measurement bounds the judge's advisory weight; it does not and "
        "cannot grant authority: soft-only judgments remain non-authoritative "
        "and the gate blocks them regardless of these numbers._",
    ]
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m prometheus_protocol.benchmarks.grounding_eval",
        description="Measure the soft grounding judge against gold labels (read-only).",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="judge via the configured provider (PROM_PROVIDER=remote, "
        "PROM_JUDGE_MODEL, ...) instead of the offline scripted reference",
    )
    args = parser.parse_args(argv)

    items = build_grounding_items()
    if args.live:
        from prometheus_protocol.core.config import Config
        from prometheus_protocol.runtime.factory import build_judge_provider

        config = Config.from_env()
        provider = build_judge_provider(config)
        judge_model = getattr(provider, "model", "") or "unknown"
        mode = "live provider"
    else:
        provider = ScriptedGroundingJudgeProvider(items, SCRIPTED_REPLIES)
        judge_model = provider.model
        mode = "offline scripted reference"

    judge = GroundingVerifier(provider)
    rows = run_grounding_eval(items, judge=judge)
    print(
        render_grounding_report(rows, items, judge_model=judge_model, mode=mode),
        end="",
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via main() in tests
    raise SystemExit(main())
