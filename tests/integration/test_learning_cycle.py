"""Integration: the whole loop, wired by the factory, end to end."""

from __future__ import annotations

from prometheus_protocol.core.models import SPLIT_HELDOUT, SPLIT_TRAIN


def test_baseline_split_rates(orchestrator, benchmark):
    report = orchestrator.baseline(benchmark.tasks)
    assert report.rate_for(SPLIT_TRAIN) == 0.4
    assert report.rate_for(SPLIT_HELDOUT) == 0.4


def test_cycle_persists_skill_and_records_history(orchestrator, benchmark, config):
    orchestrator.run_cycle(benchmark.train, benchmark.heldout, cycle=1)

    # The promoted skill is persisted to the registry directory on disk.
    skill_file = config.registry_dir / "skill-empty-input.md"
    assert skill_file.exists()
    assert "Guard against empty input" in skill_file.read_text(encoding="utf-8")

    # Retrieval now surfaces the skill for an empty-input prompt.
    retrieved = orchestrator.registry.retrieve("mean of an empty list")
    assert [s.id for s in retrieved] == ["skill-empty-input"]

    # The ledger captured attempts across several phases of the cycle.
    kinds = {row["kind"] for row in orchestrator.ledger.attempts()}
    assert {"heldout-before", "train", "heldout-after"} <= kinds


def test_metrics_helpers_agree_with_orchestrator(orchestrator, benchmark):
    from harness.eval.metrics import ablation_table, split_rates

    cycle = orchestrator.run_cycle(benchmark.train, benchmark.heldout, cycle=1)
    table = ablation_table(orchestrator, benchmark.heldout, cycle.promoted)
    assert table == {"skill-empty-input": 0.6}

    after = orchestrator.run_split(benchmark.tasks)
    rates = split_rates(after)
    assert rates[SPLIT_HELDOUT] == 1.0
    assert rates[SPLIT_TRAIN] == 1.0
