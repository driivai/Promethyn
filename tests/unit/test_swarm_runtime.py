"""Unit tests for the swarm runtime pipeline."""

from __future__ import annotations

from prometheus_protocol.core.models import Verdict
from prometheus_protocol.swarm.models import KIND_PROPOSED_ACTION, TaskPacket


def test_pipeline_executes_a_clean_action(swarm_runtime):
    run = swarm_runtime.run(TaskPacket(goal="ship it", budget=5))
    actions = [r for r in run.records if r.proposal.kind == KIND_PROPOSED_ACTION]
    assert actions
    for record in actions:
        assert record.verified.judgment.verdict == Verdict.PASS
        assert record.decision is not None and record.decision.approved
        assert record.execution is not None
    assert len(swarm_runtime.executor.executed) == len(actions)


def test_nonaction_proposals_are_judged_but_not_executed(swarm_runtime):
    run = swarm_runtime.run(TaskPacket(goal="g", budget=5))
    nonactions = [r for r in run.records if r.proposal.kind != KIND_PROPOSED_ACTION]
    assert nonactions
    for record in nonactions:
        assert record.decision is None
        assert record.execution is None
        # Still judged: a verified proposal carries the bank's judgment.
        assert record.verified.judgment is not None


def test_chain_is_recorded_in_the_ledger(swarm_runtime):
    swarm_runtime.run(TaskPacket(goal="g", budget=5))
    rows = swarm_runtime.ledger.attempts()
    assert rows
    assert all(row["split"] == "swarm" for row in rows)
    assert any(row["kind"] == "swarm:executed" for row in rows)
    # The fused judgment (verdict + confidence) is captured per attempt.
    assert any("judgment" in row["evidence"] for row in rows)


def test_run_is_deterministic(swarm_runtime):
    packet = TaskPacket(goal="g", budget=5)
    first = swarm_runtime.run(packet)
    second = swarm_runtime.run(packet)
    assert [(r.proposal.id, r.verified.judgment.verdict) for r in first.records] == [
        (r.proposal.id, r.verified.judgment.verdict) for r in second.records
    ]
