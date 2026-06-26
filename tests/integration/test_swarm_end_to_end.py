"""Integration: a full TaskPacket runs end to end through the grounding stack."""

from __future__ import annotations

from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.swarm.debate import DebateLayer
from prometheus_protocol.swarm.executor import RecordingExecutor
from prometheus_protocol.swarm.models import (
    KIND_PROPOSED_ACTION,
    Proposal,
    Provenance,
    TaskPacket,
    content_hash,
)
from prometheus_protocol.swarm.roles import Role
from prometheus_protocol.swarm.runtime import SwarmRuntime
from prometheus_protocol.swarm.synthesis import RoleSynthesisEngine
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.store import InMemoryTrustStore


def _runtime(synthesis=None):
    return SwarmRuntime(
        synthesis=synthesis or RoleSynthesisEngine(),
        debate=DebateLayer(),
        bank=VerifierBank(InMemoryTrustStore()),
        gate=ActionGate(),
        executor=RecordingExecutor(),
        ledger=SqliteLedger(":memory:"),
    )


def test_full_packet_produces_a_recorded_chain(swarm_runtime):
    run = swarm_runtime.run(TaskPacket(goal="deliver the milestone", budget=5, risk_class="medium"))

    # The chain is produced end to end.
    assert run.records
    executed = [r for r in run.records if r.execution is not None]
    assert executed, "at least one approved action should reach the executor"

    # Every executed record has the full chain: proposal -> judgment -> decision.
    for record in executed:
        assert record.proposal.kind == KIND_PROPOSED_ACTION
        assert record.verified.judgment is not None
        assert record.decision is not None and record.decision.approved

    # The ledger holds the durable record of the run.
    rows = swarm_runtime.ledger.attempts()
    assert rows
    assert any(row["kind"] == "swarm:executed" for row in rows)


def test_proposal_with_failing_skeptic_check_never_reaches_executor():
    class WeakPlanner(Role):
        id = "weak-planner"
        kind = KIND_PROPOSED_ACTION

        def propose(self, packet, context):
            content = "act with no stated rationale"
            return [
                Proposal(
                    id="weak/act",
                    role_id=self.id,
                    kind=KIND_PROPOSED_ACTION,
                    content=content,
                    rationale="",  # fails the skeptic's states_rationale check
                    provenance=Provenance(content_hash=content_hash(content)),
                )
            ]

    runtime = _runtime(RoleSynthesisEngine([WeakPlanner()]))
    runtime.run(TaskPacket(goal="g", budget=5))
    assert runtime.executor.executed == []
    # And the ledger shows the action was rejected, not executed.
    kinds = {row["kind"] for row in runtime.ledger.attempts()}
    assert "swarm:rejected" in kinds
    assert "swarm:executed" not in kinds


def test_policy_violation_blocks_execution():
    class RecklessPlanner(Role):
        id = "reckless-planner"
        kind = KIND_PROPOSED_ACTION

        def propose(self, packet, context):
            content = "do something UNSAFE to hit the goal"
            return [
                Proposal(
                    id="reckless/act",
                    role_id=self.id,
                    kind=KIND_PROPOSED_ACTION,
                    content=content,
                    rationale="fastest path",
                    provenance=Provenance(content_hash=content_hash(content)),
                )
            ]

    runtime = _runtime(RoleSynthesisEngine([RecklessPlanner()]))
    runtime.run(TaskPacket(goal="g", budget=5))
    # The policy reviewer's check fails -> not authorized -> not executed.
    assert runtime.executor.executed == []
