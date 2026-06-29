"""Shakeout: happy-path / robustness smoke tests worth keeping (all passing).

These pin behaviour the end-to-end shakeout verified healthy; see
``docs/shakeout-report.md``.
"""

from __future__ import annotations

import pytest

from prometheus_protocol import Config, build_orchestrator
from prometheus_protocol._examples.python_functions import build_benchmark
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import GateDecision
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


@pytest.fixture
def orch(tmp_path):
    return build_orchestrator(
        Config(registry_dir=tmp_path / "skills", ledger_path=":memory:", verifier_memory_mb=0)
    )


def test_baseline_to_learn_lift_reproduces(orch):
    bench = build_benchmark()
    assert orch.baseline(bench.heldout).pass_rate == 0.4
    cycle = orch.run_cycle(bench.train, bench.heldout, cycle=1)
    assert cycle.promoted == ("skill-empty-input",)
    assert cycle.post_heldout_rate == 1.0
    assert orch.ablation(bench.heldout, "skill-empty-input") == 0.6


def test_full_chain_is_recorded_and_readable(orch):
    bench = build_benchmark()
    orch.run_cycle(bench.train, bench.heldout, cycle=1)
    rows = orch.ledger.attempts()
    assert rows
    # The fused judgment is recoverable per attempt (in the evidence JSON).
    assert any("judgment" in row["evidence"] for row in rows)


def test_empty_task_set_degrades_gracefully(orch):
    assert orch.baseline([]).pass_rate == 0.0
    cycle = orch.run_cycle([], [])
    assert cycle.mined == ()
    assert cycle.post_heldout_rate == 0.0


class _BadActor(Role):
    id = "bad-actor"
    kind = KIND_PROPOSED_ACTION

    def propose(self, packet, context):
        content = "do the thing"
        # Empty rationale -> the skeptic's check fails for this proposal.
        return [
            Proposal(
                id="bad/a",
                role_id=self.id,
                kind=KIND_PROPOSED_ACTION,
                content=content,
                rationale="",
                provenance=Provenance(content_hash=content_hash(content)),
            )
        ]


def _swarm_runtime(roles):
    return SwarmRuntime(
        synthesis=RoleSynthesisEngine(roles),
        debate=DebateLayer(),
        bank=VerifierBank(InMemoryTrustStore()),
        gate=ActionGate(),
        executor=RecordingExecutor(),
        ledger=SqliteLedger(":memory:"),
    )


def test_swarm_all_failing_proposals_execute_nothing():
    runtime = _swarm_runtime([_BadActor()])
    runtime.run(TaskPacket(goal="g", budget=5))
    assert runtime.executor.executed == []  # nothing reaches the executor, no crash


def test_wall_executor_rejects_non_decisions():
    executor = RecordingExecutor()
    proposal = Proposal(
        id="x", role_id="r", kind=KIND_PROPOSED_ACTION, content="c", rationale="r",
        provenance=Provenance(content_hash=content_hash("c")),
    )
    with pytest.raises(TypeError):
        executor.execute(proposal)  # INV-SWARM-1: a raw proposal cannot execute
    with pytest.raises(ValueError):
        executor.execute(GateDecision(approved=False, subject_id="x"))
    assert executor.execute(GateDecision(approved=True, subject_id="x")).executed is True
