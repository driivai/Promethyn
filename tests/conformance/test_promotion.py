"""Conformance: the promotion and learning regression.

These are the numbers the protocol promises on the bundled benchmark:

  * held-out baseline pass rate is 40%,
  * one learning cycle reaches 100%,
  * the mined skill's ablation contribution is +60%,
  * a second cycle finds nothing left to learn,

plus the reversibility and auditability invariants.
"""

from __future__ import annotations

from harness.audit.report import audit_ledger

SKILL_ID = "skill-empty-input"


def test_baseline_heldout_rate_is_40_percent(orchestrator, benchmark):
    report = orchestrator.baseline(benchmark.heldout)
    assert report.pass_rate == 0.4


def test_one_cycle_reaches_100_percent(orchestrator, benchmark):
    cycle = orchestrator.run_cycle(benchmark.train, benchmark.heldout, cycle=1)
    assert cycle.baseline_heldout_rate == 0.4
    assert cycle.promoted == (SKILL_ID,)
    assert cycle.post_heldout_rate == 1.0
    assert cycle.learned is True


def test_ablation_contribution_is_60_percent(orchestrator, benchmark):
    orchestrator.run_cycle(benchmark.train, benchmark.heldout, cycle=1)
    assert orchestrator.ablation(benchmark.heldout, SKILL_ID) == 0.6


def test_second_cycle_learns_nothing(orchestrator, benchmark):
    orchestrator.run_cycle(benchmark.train, benchmark.heldout, cycle=1)
    cycle2 = orchestrator.run_cycle(benchmark.train, benchmark.heldout, cycle=2)
    assert cycle2.mined == ()
    assert cycle2.promoted == ()
    assert cycle2.learned is False
    assert cycle2.post_heldout_rate == 1.0


def test_promotion_is_reversible(orchestrator, benchmark):
    orchestrator.run_cycle(benchmark.train, benchmark.heldout, cycle=1)
    assert orchestrator.run_split(benchmark.heldout).pass_rate == 1.0
    # Removing the skill restores the baseline behaviour exactly.
    orchestrator.registry.remove(SKILL_ID)
    assert orchestrator.registry.get(SKILL_ID) is None
    assert orchestrator.run_split(benchmark.heldout).pass_rate == 0.4


def test_run_is_auditable(orchestrator, benchmark):
    orchestrator.run_cycle(benchmark.train, benchmark.heldout, cycle=1)
    summary = audit_ledger(orchestrator.ledger)
    assert summary["attempts"] > 0
    promoted_ids = [p["skill_id"] for p in summary["promotions"]]
    assert SKILL_ID in promoted_ids
