"""Conformance: the held-out firewall must hold, in code, not just in prose.

The firewall is the load-bearing safety invariant: the task ids the forge
learns from (train) and the task ids the gate scores against (held-out) must
never intersect.
"""

from __future__ import annotations

import pytest

from harness.benchmarks.python_functions import build_benchmark
from prometheus_protocol import FirewallError, assert_disjoint
from prometheus_protocol.core.models import SPLIT_HELDOUT, Case, Task
from prometheus_protocol.forge.miner import LessonForge
from prometheus_protocol.gate.promotion import PromotionGate


def test_benchmark_splits_are_disjoint():
    benchmark = build_benchmark()
    train_ids = {task.id for task in benchmark.train}
    heldout_ids = {task.id for task in benchmark.heldout}
    assert train_ids and heldout_ids
    assert train_ids.isdisjoint(heldout_ids)


def test_assert_disjoint_accepts_disjoint_sets():
    # Must not raise.
    assert_disjoint(["train/a", "train/b"], ["heldout/a", "heldout/b"])


def test_assert_disjoint_rejects_overlap():
    with pytest.raises(FirewallError):
        assert_disjoint(["shared/x", "train/b"], ["shared/x", "heldout/b"])


def test_gate_blocks_overlapping_ids():
    gate = PromotionGate()
    benchmark = build_benchmark()
    candidate = LessonForge().mine(
        failures=[],
        tasks_by_id={},
    )
    # Construct a held-out task whose id also appears in the train id set.
    leaky_task = Task(
        id="train/mean",  # deliberately a train id
        entry_point="mean",
        prompt="leak",
        split=SPLIT_HELDOUT,
        cases=(Case(args=([],), expected=0.0),),
    )

    def never_called(tasks, skill):  # pragma: no cover - must not run
        raise AssertionError("score_fn ran despite a firewall breach")

    from prometheus_protocol.core.models import Skill

    with pytest.raises(FirewallError):
        gate.evaluate(
            candidate=Skill(id="skill-x", title="x", body="x"),
            train_ids=[task.id for task in benchmark.train],
            heldout_tasks=[leaky_task],
            score_fn=never_called,
            rate_before=0.0,
        )
    assert candidate == []  # mining empty failures yields no skills


def test_forge_rejects_non_training_failures():
    """The forge side of the firewall: it must refuse held-out attempts."""
    from prometheus_protocol.core.models import Attempt, Evidence

    held_attempt = Attempt(
        task_id="heldout/median",
        split=SPLIT_HELDOUT,
        entry_point="median",
        code="",
        evidence=Evidence(passed=False, total=1, passed_count=0),
    )
    with pytest.raises(ValueError):
        LessonForge().mine([held_attempt], tasks_by_id={})
