"""Unit tests for debate selection (selection only, verdict-free test plans)."""

from __future__ import annotations

import dataclasses

from prometheus_protocol.swarm.debate import DebateLayer
from prometheus_protocol.swarm.models import (
    KIND_PROPOSED_ACTION,
    TestPlan,
    TestPlanEntry,
    VerificationRequest,
)
from prometheus_protocol.swarm.synthesis import RoleSynthesisEngine
from prometheus_protocol.swarm.models import TaskPacket
from prometheus_protocol._examples.swarm_tasks import build_swarm_provider

_TRUTH_FIELDS = {"verdict", "confidence", "approved", "approval", "judgment"}


def _proposals(packet: TaskPacket):
    # Roles reason via a deterministic mock provider (planner -> action,
    # analyst -> hypothesis), so selection is reproducible.
    engine = RoleSynthesisEngine(provider=build_swarm_provider())
    return engine.assemble(packet).propose(packet)


def test_testplan_carries_no_truth_or_approval_field():
    for dc in (TestPlan, TestPlanEntry, VerificationRequest):
        names = {f.name for f in dataclasses.fields(dc)}
        assert not (names & _TRUTH_FIELDS)


def test_budget_caps_the_number_verified():
    packet = TaskPacket(goal="g", budget=1)
    plan = DebateLayer().select(_proposals(packet), packet.budget)
    assert len(plan.entries) == 1
    # The most consequential proposal (an action) is verified first.
    assert plan.entries[0].proposal.kind == KIND_PROPOSED_ACTION


def test_zero_budget_selects_all_primaries():
    packet = TaskPacket(goal="g", budget=0)
    plan = DebateLayer().select(_proposals(packet), packet.budget)
    # planner (action) + analyst (hypothesis); critiques are not primaries.
    assert len(plan.entries) == 2
    assert all(e.proposal.kind != "critique" for e in plan.entries)


def test_skeptic_and_policy_checks_are_attached_to_the_action():
    packet = TaskPacket(goal="g", budget=5)
    plan = DebateLayer().select(_proposals(packet), packet.budget)
    action = next(e for e in plan.entries if e.proposal.kind == KIND_PROPOSED_ACTION)
    requesters = {req.requested_by for req in action.verification_requests}
    assert "skeptic" in requesters
    assert "policy-reviewer" in requesters


def test_selection_is_deterministic():
    packet = TaskPacket(goal="g", budget=5)
    first = DebateLayer().select(_proposals(packet), packet.budget)
    second = DebateLayer().select(_proposals(packet), packet.budget)
    assert [e.proposal.id for e in first.entries] == [
        e.proposal.id for e in second.entries
    ]
