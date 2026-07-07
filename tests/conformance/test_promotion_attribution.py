"""Conformance: multi-candidate promotion credits MARGINAL held-out lift.

The bug this pins against (flagged in the SQL learn-loop change, fixed here):
``run_cycle`` used to score every candidate against the cycle-start baseline,
so a candidate evaluated after an earlier promotion inherited that promotion's
lift — a free-riding skill could be promoted on improvement it did not cause.
Now the baseline advances by re-measurement after each promotion, so each
candidate's recorded lift is its marginal contribution over the state its
predecessors left.

These tests run the REAL shared pipeline (orchestrator, forge, unmodified
gate and firewall, markdown registry, ledger) over a synthetic two-cluster
benchmark with a deterministic book verifier, so they are fast, sandbox-free,
and domain-neutral: the accounting under test is the same one both the code
and SQL domains ride.

The synthetic corpus: cluster ``aa-real`` (sorts first) genuinely
generalises — its skill repairs the held-out `aa` tasks. Cluster ``zz-rider``
comes in two variants: a FREE-RIDER whose skill repairs nothing held-out, and
a genuinely MARGINAL one whose skill repairs exactly the held-out `zz` task.
Prompt tokens double as forge-fallback triggers, retrieval keys, and the
provider's relevance criterion — the same mechanics the real benchmarks use.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from prometheus_protocol.core.models import (
    SPLIT_HELDOUT,
    SPLIT_TRAIN,
    Case,
    Evidence,
    Task,
    Tier,
)
from prometheus_protocol.forge.miner import LessonForge
from prometheus_protocol.gate.promotion import PromotionGate
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.provider.mock import MockProvider, MockSolution
from prometheus_protocol.registry.markdown_registry import MarkdownSkillRegistry
from prometheus_protocol.runtime.orchestrator import Orchestrator

REAL_SKILL = "skill-aa-real"
RIDER_SKILL = "skill-zz-rider"


@dataclass(frozen=True)
class BookVerifier:
    """Deterministic stand-in for a HARD verifier: pass iff code is correct."""

    correct: Mapping[str, str]
    verifier_id: str = "stub-book"
    tier: Tier = Tier.HARD

    def verify(self, *, code: str, task: Task) -> Evidence:
        passed = code == self.correct[task.entry_point]
        return Evidence(
            passed=passed,
            total=1,
            passed_count=1 if passed else 0,
            failures=() if passed else ("does not match the correct solution",),
            verifier_id=self.verifier_id,
            tier=self.tier,
        )


def _task(task_id: str, entry: str, prompt: str, split: str, cluster: str | None) -> Task:
    return Task(
        id=task_id, entry_point=entry, prompt=prompt, split=split,
        cluster=cluster, cases=(Case(args=(), expected=None),),
    )


def _wrong(entry: str) -> str:
    return f"def {entry}():\n    return 'wrong'\n"


def _right(entry: str) -> str:
    return f"def {entry}():\n    return 'right'\n"


def _benchmark(*, rider_transfers: bool):
    """Two train failures (one per cluster) and four held-out tasks.

    Held-out baseline is always 1/4 (the clean task). The `aa` skill always
    repairs the two held-out `aa` tasks (3/4). Whether the `zz` skill repairs
    the held-out `zz` task is the scenario switch: a transferring rider earns
    a genuine marginal +1/4; a non-transferring one is a pure free-rider.
    """

    train = (
        _task("train/aa", "t_aa", "Handle the aa case.", SPLIT_TRAIN, "aa-real"),
        _task("train/zz", "t_zz", "Handle the zz case.", SPLIT_TRAIN, "zz-rider"),
    )
    heldout = (
        _task("heldout/aa-one", "h_aa_one", "Cover the aa family here.",
              SPLIT_HELDOUT, "aa-real"),
        _task("heldout/aa-two", "h_aa_two", "Another aa family item.",
              SPLIT_HELDOUT, "aa-real"),
        _task("heldout/zz-one", "h_zz_one", "Cover the zz family here.",
              SPLIT_HELDOUT, "zz-rider"),
        _task("heldout/clean", "h_clean", "A plain item with no trap.",
              SPLIT_HELDOUT, None),
    )
    book: dict[str, MockSolution] = {}
    correct: dict[str, str] = {}
    for task in (*train, *heldout):
        entry = task.entry_point
        correct[entry] = _right(entry)
        if task.cluster is None:
            book[entry] = MockSolution(baseline=_right(entry), improved=_right(entry))
        elif entry == "h_zz_one" and not rider_transfers:
            # The free-rider's held-out member: the skill changes nothing.
            book[entry] = MockSolution(baseline=_wrong(entry), improved=_wrong(entry))
        else:
            book[entry] = MockSolution(baseline=_wrong(entry), improved=_right(entry))
    return train, heldout, book, correct


def _orchestrator(tmp_path, book, correct) -> Orchestrator:
    return Orchestrator(
        provider=MockProvider(book),
        verifier=BookVerifier(correct),
        registry=MarkdownSkillRegistry(tmp_path / "skills"),
        gate=PromotionGate(),
        ledger=SqliteLedger(":memory:"),
        forge=LessonForge(),  # unknown clusters ride the fallback lesson
    )


def _rebase_rows(orchestrator: Orchestrator) -> list[dict]:
    return [r for r in orchestrator.ledger.attempts() if r["kind"] == "heldout-rebase"]


def test_free_riding_candidate_is_refused_on_zero_marginal_lift(tmp_path):
    """The fix, direction one: no credit for an earlier promotion's lift."""

    train, heldout, book, correct = _benchmark(rider_transfers=False)
    orchestrator = _orchestrator(tmp_path, book, correct)
    report = orchestrator.run_cycle(train, heldout, cycle=1)

    assert report.baseline_heldout_rate == 0.25
    decisions = {d.skill_id: d for d in report.decisions}
    real, rider = decisions[REAL_SKILL], decisions[RIDER_SKILL]
    # The genuine skill promotes on its own lift, measured from cycle start.
    assert real.approved and (real.rate_before, real.rate_after) == (0.25, 0.75)
    # The rider is scored against the RE-BASED baseline and shows zero
    # marginal lift. Against the stale cycle-start baseline its rate_after
    # would have cleared the promotion criterion — the old accounting
    # promoted exactly this skill, wrongly.
    assert rider.rate_before == 0.75  # re-based, not the 0.25 cycle start
    assert rider.rate_after == 0.75
    assert rider.rate_after > report.baseline_heldout_rate  # the old trap
    assert rider.approved is False
    assert report.promoted == (REAL_SKILL,)
    assert orchestrator.registry.get(RIDER_SKILL) is None
    assert report.post_heldout_rate == 0.75
    # Exactly one re-base measurement: after the one promotion, with one
    # candidate still to score.
    assert len(_rebase_rows(orchestrator)) == len(heldout)


def test_genuinely_marginal_candidate_still_promotes_on_its_own_lift(tmp_path):
    """The fix, direction two: marginal improvement is still rewarded."""

    train, heldout, book, correct = _benchmark(rider_transfers=True)
    orchestrator = _orchestrator(tmp_path, book, correct)
    report = orchestrator.run_cycle(train, heldout, cycle=1)

    decisions = {d.skill_id: d for d in report.decisions}
    marginal = decisions[RIDER_SKILL]
    assert marginal.approved is True
    assert (marginal.rate_before, marginal.rate_after) == (0.75, 1.0)
    assert report.promoted == (REAL_SKILL, RIDER_SKILL)
    assert report.post_heldout_rate == 1.0
    # Its ledger record claims exactly the marginal lift, nothing more.
    promote_rows = [
        r for r in orchestrator.ledger.promotions()
        if r["skill_id"] == RIDER_SKILL and r["action"] == "promote"
    ]
    assert [(r["rate_before"], r["rate_after"]) for r in promote_rows] == [(0.75, 1.0)]


def test_single_candidate_cycle_is_unchanged_by_the_fix(tmp_path):
    """One candidate: scored against the cycle-start baseline, no re-basing."""

    train, heldout, book, correct = _benchmark(rider_transfers=True)
    aa_only_train = tuple(t for t in train if t.cluster == "aa-real")
    orchestrator = _orchestrator(tmp_path, book, correct)
    report = orchestrator.run_cycle(aa_only_train, heldout, cycle=1)

    (decision,) = report.decisions
    assert decision.skill_id == REAL_SKILL
    assert decision.rate_before == report.baseline_heldout_rate == 0.25
    assert decision.approved is True
    assert _rebase_rows(orchestrator) == []  # the old accounting, exactly


def test_promote_promote_rollback_leaves_a_coherent_state(tmp_path):
    """Unwinding mid-cycle promotions restores measured state consistently."""

    train, heldout, book, correct = _benchmark(rider_transfers=True)
    orchestrator = _orchestrator(tmp_path, book, correct)
    report = orchestrator.run_cycle(train, heldout, cycle=1)
    assert report.promoted == (REAL_SKILL, RIDER_SKILL)
    assert report.post_heldout_rate == 1.0

    # Roll back the FIRST promotion while the second stays: the measured
    # state must equal what the remaining skill earns on its own (the aa
    # tasks regress, the zz task stays repaired, the clean task passes).
    orchestrator.registry.remove(REAL_SKILL)
    after_first = orchestrator.run_split(
        heldout, cycle=1, kind="post-rollback-a"
    ).pass_rate
    assert after_first == 0.5
    orchestrator.ledger.record_promotion(
        skill_id=REAL_SKILL, action="rollback", cycle=1,
        rate_before=report.post_heldout_rate, rate_after=after_first,
    )

    # Unwinding the second promotion too restores the cycle-start baseline
    # exactly — full reversibility survives the moving-baseline accounting.
    orchestrator.registry.remove(RIDER_SKILL)
    after_both = orchestrator.run_split(
        heldout, cycle=1, kind="post-rollback-b"
    ).pass_rate
    assert after_both == report.baseline_heldout_rate == 0.25
    orchestrator.ledger.record_promotion(
        skill_id=RIDER_SKILL, action="rollback", cycle=1,
        rate_before=after_first, rate_after=after_both,
    )

    history = [
        (r["skill_id"], r["action"], r["rate_before"], r["rate_after"])
        for r in orchestrator.ledger.promotions()
    ]
    assert history == [
        (REAL_SKILL, "promote", 0.25, 0.75),
        (RIDER_SKILL, "promote", 0.75, 1.0),
        (REAL_SKILL, "rollback", 1.0, 0.5),
        (RIDER_SKILL, "rollback", 0.5, 0.25),
    ]
