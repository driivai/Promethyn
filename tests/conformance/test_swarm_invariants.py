"""Conformance: the swarm invariants INV-SWARM-1 .. INV-SWARM-6.

These pin the structural skeleton of the swarm: the typed wall, the mandatory
roles, the selection/certification split, the skeptic veto, the reuse contract,
and firewall preservation.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import pathlib

import pytest

import prometheus_protocol.swarm as swarm_pkg
from prometheus_protocol.core.models import Judgment, Verdict
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import GateDecision
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.swarm.debate import DebateLayer
from prometheus_protocol.swarm.executor import Executor, RecordingExecutor
from prometheus_protocol.swarm.models import (
    KIND_PROPOSED_ACTION,
    ExecutionResult,
    FalsificationCheck,
    Proposal,
    Provenance,
    TaskPacket,
    TestPlan,
    TestPlanEntry,
    VerificationRequest,
    content_hash,
)
from prometheus_protocol.swarm.roles import ProposerContext, Role
from prometheus_protocol.swarm.runtime import SwarmRuntime
from prometheus_protocol.swarm.synthesis import RoleSynthesisEngine, SwarmConfig
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.store import InMemoryTrustStore

_SWARM_DIR = pathlib.Path(swarm_pkg.__file__).parent
_SWARM_SOURCES = {p.name: p.read_text(encoding="utf-8") for p in _SWARM_DIR.glob("*.py")}
_COMBINED = "\n".join(_SWARM_SOURCES.values())


def _make_proposal(kind=KIND_PROPOSED_ACTION, content="c", rationale="r"):
    return Proposal(
        id="p/1",
        role_id="r",
        kind=kind,
        content=content,
        rationale=rationale,
        provenance=Provenance(content_hash=content_hash(content)),
    )


def _runtime(synthesis=None):
    return SwarmRuntime(
        synthesis=synthesis or RoleSynthesisEngine(),
        debate=DebateLayer(),
        bank=VerifierBank(InMemoryTrustStore()),
        gate=ActionGate(),
        executor=RecordingExecutor(),
        ledger=SqliteLedger(":memory:"),
    )


# -- INV-SWARM-1: the wall ---------------------------------------------------


def test_inv1_executor_accepts_only_approved_gate_decision():
    executor = RecordingExecutor()

    # A raw proposal or a test plan cannot be executed.
    with pytest.raises(TypeError):
        executor.execute(_make_proposal())
    with pytest.raises(TypeError):
        executor.execute(TestPlan(entries=()))

    # An unapproved decision is refused; an approved one is acted on.
    with pytest.raises(ValueError):
        executor.execute(GateDecision(approved=False, subject_id="p/1"))
    result = executor.execute(GateDecision(approved=True, subject_id="p/1"))
    assert result.executed and result.subject_id == "p/1"


def test_inv1_executor_exposes_no_proposal_entry_point():
    public = [name for name in dir(Executor) if not name.startswith("_")]
    assert "execute" in public
    assert all("propos" not in name.lower() and "plan" not in name.lower() for name in public)
    params = [p for p in inspect.signature(Executor.execute).parameters if p != "self"]
    assert params == ["decision"]


# -- INV-SWARM-2: debate selects, never certifies ---------------------------


def test_inv2_testplan_has_no_truth_or_approval_field():
    forbidden = {"verdict", "confidence", "approved", "approval", "judgment"}
    for dc in (TestPlan, TestPlanEntry, VerificationRequest, FalsificationCheck, Proposal):
        assert not ({f.name for f in dataclasses.fields(dc)} & forbidden)


def test_inv2_swarm_never_constructs_a_judgment_or_gate_decision():
    # The only producer of Judgment is the bank; of GateDecision, the gate.
    assert "Judgment(" not in _COMBINED
    assert "GateDecision(" not in _COMBINED
    assert "Judgment(" not in _SWARM_SOURCES["debate.py"]
    assert "GateDecision(" not in _SWARM_SOURCES["debate.py"]


# -- INV-SWARM-3: mandatory roles -------------------------------------------


def test_inv3_mandatory_roles_are_present_and_non_removable():
    mandatory = {"skeptic", "policy-reviewer"}
    # Even a config that tries to forbid them yields them.
    swarm = RoleSynthesisEngine().assemble(
        TaskPacket(goal="g"), SwarmConfig(disabled_roles=frozenset(mandatory))
    )
    assert mandatory <= set(swarm.role_ids())
    for role_id in mandatory:
        with pytest.raises(ValueError):
            swarm.remove(role_id)


# -- INV-SWARM-4: skeptic veto wired to verification ------------------------


def test_inv4_skeptic_check_is_in_the_test_plan_for_the_proposal():
    packet = TaskPacket(goal="g", budget=5)
    proposals = RoleSynthesisEngine().assemble(packet).propose(packet)
    plan = DebateLayer().select(proposals, packet.budget)
    action = next(e for e in plan.entries if e.proposal.kind == KIND_PROPOSED_ACTION)
    assert any(req.requested_by == "skeptic" for req in action.verification_requests)


def test_inv4_failing_check_cannot_reach_the_executor():
    class WeakPlanner(Role):
        id = "weak-planner"
        kind = KIND_PROPOSED_ACTION

        def propose(self, packet, context):
            # Empty rationale: the skeptic's "states_rationale" check will fail.
            content = "act without justification"
            return [
                Proposal(
                    id="weak/act",
                    role_id=self.id,
                    kind=KIND_PROPOSED_ACTION,
                    content=content,
                    rationale="",
                    provenance=Provenance(content_hash=content_hash(content)),
                )
            ]

    runtime = _runtime(RoleSynthesisEngine([WeakPlanner()]))
    run = runtime.run(TaskPacket(goal="g", budget=5))
    record = next(r for r in run.records if r.proposal.kind == KIND_PROPOSED_ACTION)
    assert record.verified.judgment.verdict == Verdict.FAIL
    assert record.decision is not None and not record.decision.approved
    assert record.execution is None
    assert runtime.executor.executed == []


# -- INV-SWARM-5: reuse, no fork --------------------------------------------


def test_inv5_swarm_reuses_grounding_components():
    # The runtime imports the existing bank, gate, ledger, memory, and provider.
    assert "from prometheus_protocol.verifier.bank import VerifierBank" in _COMBINED
    assert "from prometheus_protocol.gate.authorization import ActionGate" in _COMBINED
    assert "from prometheus_protocol.gate.promotion import GateDecision" in _COMBINED
    assert "Ledger" in _SWARM_SOURCES["runtime.py"]
    assert "from prometheus_protocol.memory" in _COMBINED
    assert "Provider" in _SWARM_SOURCES["runtime.py"]


def test_inv5_swarm_defines_no_duplicate_grounding_type():
    forbidden = {
        "Ledger",
        "SqliteLedger",
        "Gate",
        "PromotionGate",
        "Verifier",
        "VerifierBank",
        "TrustStore",
    }
    for name, source in _SWARM_SOURCES.items():
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.ClassDef):
                continue
            assert node.name not in forbidden, f"{name}: redefines {node.name}"
            base_names = {b.id for b in node.bases if isinstance(b, ast.Name)} | {
                b.attr for b in node.bases if isinstance(b, ast.Attribute)
            }
            assert not (base_names & forbidden), f"{name}: {node.name} forks a grounding type"


# -- INV-SWARM-6: firewall preserved ----------------------------------------


def test_inv6_role_inputs_exclude_judged_artifacts():
    # A role only ever sees the packet and proposer-side context.
    params = [p for p in inspect.signature(Role.propose).parameters if p != "self"]
    assert params == ["packet", "context"]

    # The proposer context exposes no Evidence/Judgment/verifier internals.
    context_fields = {f.name for f in dataclasses.fields(ProposerContext)}
    assert context_fields == {"packet", "proposals", "notes"}
    forbidden = {"evidence", "judgment", "verdict", "heldout", "held_out", "labels"}
    assert not (context_fields & forbidden)


def test_inv6_held_out_firewall_still_enforced():
    # The promotion firewall is untouched and still raises on intersection.
    from prometheus_protocol.gate.promotion import FirewallError, assert_disjoint

    assert_disjoint(["train/a"], ["heldout/b"])  # disjoint: no raise
    with pytest.raises(FirewallError):
        assert_disjoint(["shared/x"], ["shared/x"])
