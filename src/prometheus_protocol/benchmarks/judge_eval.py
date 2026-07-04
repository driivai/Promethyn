"""Judge-quality evaluation: measure the soft judge against HARD ground truth.

The soft ``ModelJudgeVerifier`` is an advisor whose real quality — agreement
with ground truth, the dangerous false-PASS direction, calibration when it
states a confidence — had never been measured. This harness measures it, on the
code domain where the HARD subprocess verifier provides authoritative ground
truth:

* **agreement**: of the items where the judge gave a PASS/FAIL opinion, how
  often it matched the HARD verdict;
* **false-PASS rate**: of the items HARD failed (and the judge decided), how
  often the judge passed them — the dangerous direction, since in domains
  without a hard backstop a false PASS is what lets a bad candidate through;
* **false-FAIL rate**: of the items HARD passed (and the judge decided), how
  often the judge failed them (costs useful work, but is the safe direction);
* **calibration**: stated confidence, bucketed, against actual correctness;
* **actor-identity split**: judge error rates on candidates attributed to the
  judge's own model vs a different model (the correlated-grader signal).

READ-ONLY BY CONSTRUCTION: this module never imports the verifier bank, any
trust store, or the ledger. Verifiers are invoked directly and their Evidence
is folded into metrics in memory; nothing is calibrated, persisted, or
recorded. Evaluation is not experience.

Determinism: the default (offline) mode uses a scripted judge whose replies are
fixed per item, so every number below is reproducible bit-for-bit and the
harness arithmetic is fully testable without any model. The offline run
validates the HARNESS, not any real judge. Real judge quality comes from a live
provider config:

    python -m prometheus_protocol.benchmarks.judge_eval            # offline
    PROM_PROVIDER=remote PROM_API_BASE=... PROM_MODEL=... \\
        PROM_JUDGE_MODEL=... python -m prometheus_protocol.benchmarks.judge_eval --live

Confidence is elicited with an evaluation-only judge prompt (the production
judge prompt and verdict parsing are untouched): the judge is asked for the
same single verdict word, followed by an optional confidence number, which the
verdict parser ignores and this harness reads from the raw reply.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from typing import Sequence

from prometheus_protocol.core.interfaces import Provider, Verifier
from prometheus_protocol.core.models import Case, Skill, Task, Verdict
from prometheus_protocol.verifier.model_judge import ModelJudgeVerifier

#: Evaluation-only judge system prompt. Same one-word verdict contract as the
#: production prompt (the strict first-word parser is unchanged), plus a stated
#: confidence the harness reads from the raw reply.
EVAL_JUDGE_SYSTEM_PROMPT = (
    "You are a strict, independent reviewer. Decide whether the candidate "
    "solution satisfies the task. Reply with exactly one line: PASS, FAIL, or "
    "ABSTAIN, followed by a space and your confidence in that verdict as a "
    "number between 0 and 1 (for example: PASS 0.85). Answer ABSTAIN if you "
    "cannot decide."
)

#: Fixed calibration bucket edges; the last bucket is inclusive of 1.0.
BUCKET_EDGES = (0.0, 0.2, 0.4, 0.6, 0.8, 1.0)

# The stated confidence must immediately follow the verdict word as one
# well-formed number ("PASS 0.85"). Anchoring plus the trailing guard keep a
# malformed reply ("PASS 1.5", "PASS -0.5", "PASS 0,9", "PASS 0.5e-1") from
# being coerced into a wrong in-range value: it is unstated, never invented.
_CONFIDENCE = re.compile(r"^[^A-Za-z]*[A-Za-z]+[\s:=,]*([01](?:\.\d+)?)(?![\w.,])")

#: Marker comment that keys the scripted judge's reply to one eval item. It
#: rides inside the candidate code, which the judge prompt embeds verbatim.
_MARKER = "# eval-item: "

#: Model identities used by the offline reference run.
SCRIPTED_JUDGE_MODEL = "scripted-judge"
OTHER_ACTOR_MODEL = "other-actor"


# --------------------------------------------------------------------------
# data model
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class EvalItem:
    """One (task, candidate) pair with its actor attribution."""

    item_id: str
    task: Task
    code: str
    actor_model: str


@dataclass(frozen=True)
class JudgedRow:
    """One item after both verifiers ran: the reference verdict, the judge's
    verdict, and the confidence the judge stated (``None`` when unstated)."""

    item_id: str
    actor_model: str
    reference: Verdict
    judged: Verdict
    confidence: float | None


@dataclass(frozen=True)
class Bucket:
    """One calibration bucket: stated confidence in [lo, hi) vs correctness."""

    lo: float
    hi: float
    count: int
    correct: int

    @property
    def accuracy(self) -> float | None:
        return None if self.count == 0 else self.correct / self.count


@dataclass(frozen=True)
class JudgeMetrics:
    """Exact counts and rates for one set of judged rows.

    Rates are ``None`` (never a fake 0%) when their denominator is empty.
    ``n_reference`` counts rows with an authoritative PASS/FAIL reference; rows
    whose reference ABSTAINed carry no ground truth and are excluded from every
    rate. The judge's own ABSTAINs are counted, and excluded from agreement and
    error denominators (an abstain is "no opinion", not a wrong opinion).
    """

    n_items: int
    n_reference: int
    n_decided: int
    n_abstained: int
    n_agree: int
    agreement: float | None
    reference_fails_decided: int
    false_pass: int
    false_pass_rate: float | None
    reference_passes_decided: int
    false_fail: int
    false_fail_rate: float | None
    buckets: tuple[Bucket, ...]
    unstated_count: int
    unstated_correct: int


# --------------------------------------------------------------------------
# pure arithmetic
# --------------------------------------------------------------------------


def parse_confidence(detail: str) -> float | None:
    """Read the stated confidence from a judge reply, if any.

    Looks at the first non-empty line only (mirroring the verdict parser) and
    accepts exactly one well-formed number in [0, 1] immediately after the
    verdict word. A reply with no such number — including every reply of the
    production one-word prompt, and any malformed number — is "unstated": a
    confidence is never coerced or invented.
    """

    if not detail:
        return None
    for line in detail.strip().splitlines():
        if not line.strip():
            continue
        match = _CONFIDENCE.match(line)
        if not match:
            return None
        value = float(match.group(1))
        return value if 0.0 <= value <= 1.0 else None
    return None


def _bucket_index(confidence: float, edges: Sequence[float]) -> int:
    for i in range(len(edges) - 1):
        last = i == len(edges) - 2
        if edges[i] <= confidence < edges[i + 1] or (last and confidence == edges[-1]):
            return i
    raise ValueError(f"confidence {confidence!r} outside {edges!r}")


def compute_metrics(
    rows: Sequence[JudgedRow], *, edges: Sequence[float] = BUCKET_EDGES
) -> JudgeMetrics:
    """Fold judged rows into exact counts and rates. Pure; fixture-tested."""

    referenced = [r for r in rows if r.reference in (Verdict.PASS, Verdict.FAIL)]
    decided = [r for r in referenced if r.judged in (Verdict.PASS, Verdict.FAIL)]
    abstained = len(referenced) - len(decided)

    agree = [r for r in decided if r.judged == r.reference]
    ref_fail = [r for r in decided if r.reference == Verdict.FAIL]
    ref_pass = [r for r in decided if r.reference == Verdict.PASS]
    false_pass = [r for r in ref_fail if r.judged == Verdict.PASS]
    false_fail = [r for r in ref_pass if r.judged == Verdict.FAIL]

    counts = [[0, 0] for _ in range(len(edges) - 1)]  # [count, correct]
    unstated = [0, 0]
    for row in decided:
        correct = row.judged == row.reference
        if row.confidence is None:
            unstated[0] += 1
            unstated[1] += 1 if correct else 0
            continue
        slot = counts[_bucket_index(row.confidence, edges)]
        slot[0] += 1
        slot[1] += 1 if correct else 0
    buckets = tuple(
        Bucket(lo=edges[i], hi=edges[i + 1], count=c, correct=k)
        for i, (c, k) in enumerate(counts)
    )

    def rate(num: int, den: int) -> float | None:
        return None if den == 0 else num / den

    return JudgeMetrics(
        n_items=len(rows),
        n_reference=len(referenced),
        n_decided=len(decided),
        n_abstained=abstained,
        n_agree=len(agree),
        agreement=rate(len(agree), len(decided)),
        reference_fails_decided=len(ref_fail),
        false_pass=len(false_pass),
        false_pass_rate=rate(len(false_pass), len(ref_fail)),
        reference_passes_decided=len(ref_pass),
        false_fail=len(false_fail),
        false_fail_rate=rate(len(false_fail), len(ref_pass)),
        buckets=buckets,
        unstated_count=unstated[0],
        unstated_correct=unstated[1],
    )


def split_by_actor(
    rows: Sequence[JudgedRow], *, judge_model: str
) -> dict[str, JudgeMetrics]:
    """Metrics split by whether the candidate's actor is the judge's model."""

    same = [r for r in rows if r.actor_model == judge_model]
    different = [r for r in rows if r.actor_model != judge_model]
    return {
        "same_model": compute_metrics(same),
        "different_model": compute_metrics(different),
    }


# --------------------------------------------------------------------------
# the offline scripted reference
# --------------------------------------------------------------------------


class ScriptedJudgeProvider(Provider):
    """Deterministic offline judge stand-in for the reference run.

    Replies are scripted per eval item (keyed by the item marker embedded in
    the candidate code, which the judge prompt quotes verbatim). Like the mock
    proposer, this is an honest SIMULATION: it validates the harness plumbing
    and arithmetic, and says nothing about any real judge.
    """

    def __init__(self, replies: dict[str, str], *, model: str = SCRIPTED_JUDGE_MODEL) -> None:
        self._replies = dict(replies)
        self.model = model

    def propose_solution(
        self, *, prompt: str, entry_point: str, skills: Sequence[Skill] = ()
    ) -> str:
        raise NotImplementedError("the scripted judge only assesses")

    def assess(self, *, prompt: str, system: str | None = None) -> str:
        for item_id, reply in self._replies.items():
            if _MARKER + item_id in prompt:
                return reply
        return "ABSTAIN"


#: The scripted judge's reply per bundled item. Disagreements are deliberate:
#: two false-PASSes (one overconfident), one low-confidence false-FAIL, one
#: abstain, and one verdict with no stated confidence, so every metric and
#: every calibration bucket below is exercised with hand-checkable numbers.
SCRIPTED_REPLIES: dict[str, str] = {
    "c01": "PASS 0.95",
    "c02": "FAIL 0.9",
    "c03": "PASS 0.85",
    "c04": "PASS 0.9",   # false-PASS, overconfident (reference: FAIL)
    "c05": "FAIL 0.3",   # false-FAIL, low confidence (reference: PASS)
    "c06": "FAIL 0.75",
    "c07": "PASS 0.55",
    "c08": "PASS 0.55",  # false-PASS, mid confidence (reference: FAIL)
    "c09": "ABSTAIN",
    "c10": "PASS",       # correct, but no stated confidence
}


def _task(task_id: str, entry: str, prompt: str, cases: tuple[Case, ...]) -> Task:
    return Task(id=task_id, entry_point=entry, prompt=prompt, split="train", cases=cases)


def build_eval_items(
    *, same_actor: str = SCRIPTED_JUDGE_MODEL, other_actor: str = OTHER_ACTOR_MODEL
) -> tuple[EvalItem, ...]:
    """The bundled code-domain eval set: ten candidates over five tiny tasks.

    Half the candidates are attributed to the judge's own model and half to a
    different one, so the actor-identity split has both slices. Each candidate
    carries its item marker as a comment; the HARD verifier decides ground
    truth by executing it against the hidden cases.
    """

    add = _task("judge-eval/add", "add", "Return the sum of two integers.",
                (Case((2, 3), 5), Case((-1, 1), 0), Case((0, 0), 0)))
    clamp = _task("judge-eval/clamp", "clamp",
                  "Clamp x into the inclusive range [lo, hi].",
                  (Case((5, 0, 10), 5), Case((-3, 0, 10), 0), Case((12, 0, 10), 10)))
    absdiff = _task("judge-eval/absdiff", "absdiff",
                    "Return the absolute difference of a and b.",
                    (Case((5, 3), 2), Case((3, 5), 2)))
    max3 = _task("judge-eval/max3", "max_of_three",
                 "Return the largest of three numbers.",
                 (Case((1, 2, 3), 3), Case((3, 1, 2), 3), Case((2, 2, 2), 2)))
    evens = _task("judge-eval/evens", "evens",
                  "Return the even numbers of xs, in order.",
                  (Case(([1, 2, 3, 4],), [2, 4]), Case(([],), [])))

    def code(item_id: str, body: str) -> str:
        return f"{_MARKER}{item_id}\n{body}"

    return (
        EvalItem("c01", add, code("c01", "def add(a, b):\n    return a + b\n"), other_actor),
        EvalItem("c02", add, code("c02", "def add(a, b):\n    return a - b\n"), other_actor),
        EvalItem("c03", clamp, code(
            "c03", "def clamp(x, lo, hi):\n    return max(lo, min(x, hi))\n"), same_actor),
        EvalItem("c04", clamp, code(
            "c04", "def clamp(x, lo, hi):\n    return min(lo, max(x, hi))\n"), same_actor),
        EvalItem("c05", absdiff, code(
            "c05", "def absdiff(a, b):\n    return abs(a - b)\n"), other_actor),
        EvalItem("c06", absdiff, code(
            "c06", "def absdiff(a, b):\n    return a - b\n"), same_actor),
        EvalItem("c07", max3, code(
            "c07", "def max_of_three(a, b, c):\n    return max(a, b, c)\n"), other_actor),
        EvalItem("c08", max3, code(
            "c08", "def max_of_three(a, b, c):\n    return max(a, b)\n"), same_actor),
        EvalItem("c09", evens, code(
            "c09", "def evens(xs):\n    raise RuntimeError('unimplemented path')\n"),
            other_actor),
        EvalItem("c10", evens, code(
            "c10", "def evens(xs):\n    return [x for x in xs if x % 2 == 0]\n"), same_actor),
    )


# --------------------------------------------------------------------------
# the runner (verifiers injected; no bank, no store, no ledger)
# --------------------------------------------------------------------------


def run_judge_eval(
    items: Sequence[EvalItem], *, judge: Verifier, reference: Verifier
) -> tuple[JudgedRow, ...]:
    """Run both verifiers over the items and pair their verdicts.

    The reference verdict is ground truth (authoritative tier); the judge's
    Evidence contributes its verdict and, when stated, a confidence parsed from
    the raw reply carried in ``Evidence.detail``. Nothing is calibrated or
    persisted — the Evidence objects are folded into rows and dropped.
    """

    rows = []
    for item in items:
        ref = reference.verify(code=item.code, task=item.task)
        judged = judge.verify(code=item.code, task=item.task)
        rows.append(
            JudgedRow(
                item_id=item.item_id,
                actor_model=item.actor_model,
                reference=ref.verdict,
                judged=judged.verdict,
                confidence=parse_confidence(judged.detail),
            )
        )
    return tuple(rows)


# --------------------------------------------------------------------------
# rendering (deterministic markdown; no timestamps)
# --------------------------------------------------------------------------


def _pct(num: int, den: int) -> str:
    if den == 0:
        return f"{num}/{den} = -"
    return f"{num}/{den} = {100.0 * num / den:.1f}%"


def render_report(
    rows: Sequence[JudgedRow], *, judge_model: str, mode: str
) -> str:
    m = compute_metrics(rows)
    lines = [
        f"# Judge-quality evaluation ({mode})",
        "",
        f"judge model : {judge_model}",
        f"items       : {m.n_items}",
        f"with authoritative reference : {m.n_reference}",
        f"judge decided : {m.n_decided}  |  judge abstained : {m.n_abstained}",
        "",
        "| metric | value |",
        "|---|---|",
        f"| agreement (of decided) | {_pct(m.n_agree, m.n_decided)} |",
        f"| false-PASS (judge PASS where reference FAIL) | "
        f"{_pct(m.false_pass, m.reference_fails_decided)} |",
        f"| false-FAIL (judge FAIL where reference PASS) | "
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
    lines.append(
        f"| unstated | {m.unstated_count} | {m.unstated_correct} | "
        f"{'-' if m.unstated_count == 0 else _pct(m.unstated_correct, m.unstated_count).split('= ')[1]} |"
    )

    split = split_by_actor(rows, judge_model=judge_model)
    if any(s.n_items for s in split.values()) and split["same_model"].n_items:
        lines += [
            "",
            "## Actor-identity split (correlated-grader signal)",
            "",
            "| slice | decided | agreement | false-PASS | false-FAIL |",
            "|---|---|---|---|---|",
        ]
        for label, key in (("same model as judge", "same_model"),
                           ("different model", "different_model")):
            s = split[key]
            lines.append(
                f"| {label} | {s.n_decided} | {_pct(s.n_agree, s.n_decided)} | "
                f"{_pct(s.false_pass, s.reference_fails_decided)} | "
                f"{_pct(s.false_fail, s.reference_passes_decided)} |"
            )
    else:
        lines += [
            "",
            "_No items are attributed to the judge's model; for a live same-vs-"
            "different comparison, run the eval twice (judge model equal to the "
            "actor's, then distinct) and compare the two false-PASS rates._",
        ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m prometheus_protocol.benchmarks.judge_eval",
        description="Measure the soft judge against HARD ground truth (read-only).",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="judge via the configured provider (PROM_PROVIDER=remote, "
        "PROM_JUDGE_MODEL, ...) instead of the offline scripted reference",
    )
    parser.add_argument(
        "--item-set",
        choices=("live-v1", "live-v2"),
        default="live-v2",
        help="which committed item set a --live run evaluates (ignored in the "
        "offline scripted mode, which always uses its ten-item reference set)",
    )
    args = parser.parse_args(argv)

    # The HARD reference executes candidates under the mandatory isolating
    # sandbox. The memory cap is disabled for determinism across hosts; the
    # sandbox's other bounds (and its fail-closed refusal) stay in force.
    from prometheus_protocol.verifier.runner import SubprocessVerifier

    reference = SubprocessVerifier(memory_mb=0)

    if args.live:
        # Both committed sets share the same loader contract; the flag only
        # selects which module supplies it.
        if args.item_set == "live-v1":
            from prometheus_protocol.benchmarks.live_items import (
                LIVE_ITEM_SET_VERSION,
                build_live_eval_items,
            )
        else:
            from prometheus_protocol.benchmarks.live_items_v2 import (
                LIVE_ITEM_SET_VERSION,
                build_live_eval_items,
            )
        from prometheus_protocol.core.config import Config
        from prometheus_protocol.runtime.factory import build_judge_provider

        config = Config.from_env()
        provider = build_judge_provider(config)
        judge_model = getattr(provider, "model", "") or "unknown"
        mode = f"live provider, item set {LIVE_ITEM_SET_VERSION}"
        items = build_live_eval_items()
    else:
        provider = ScriptedJudgeProvider(SCRIPTED_REPLIES)
        judge_model = provider.model
        mode = "offline scripted reference"
        items = build_eval_items()

    judge = ModelJudgeVerifier(provider, system_prompt=EVAL_JUDGE_SYSTEM_PROMPT)
    rows = run_judge_eval(items, judge=judge, reference=reference)

    metrics = compute_metrics(rows)
    if metrics.n_reference == 0:
        print(
            "error: no authoritative reference verdicts were produced — is an "
            "isolating sandbox runtime available? (the reference refuses to run "
            "candidates unsandboxed)",
            file=sys.stderr,
        )
        return 1
    print(render_report(rows, judge_model=judge_model, mode=mode), end="")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via main() in tests
    raise SystemExit(main())
