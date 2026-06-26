"""Unit tests for role synthesis and the swarm assembly."""

from __future__ import annotations

import pytest

from prometheus_protocol.swarm.models import TaskPacket
from prometheus_protocol.swarm.synthesis import RoleSynthesisEngine, SwarmConfig

PACKET = TaskPacket(goal="goal")
MANDATORY = {"skeptic", "policy-reviewer"}


def test_assemble_injects_mandatory_roles():
    swarm = RoleSynthesisEngine().assemble(PACKET)
    assert MANDATORY <= set(swarm.role_ids())
    assert swarm.mandatory_ids == frozenset(MANDATORY)


def test_optional_roles_present_by_default():
    ids = set(RoleSynthesisEngine().assemble(PACKET).role_ids())
    assert {"planner", "analyst"} <= ids


def test_config_can_disable_an_optional_role():
    swarm = RoleSynthesisEngine().assemble(
        PACKET, SwarmConfig(disabled_roles=frozenset({"analyst"}))
    )
    assert "analyst" not in swarm.role_ids()
    assert "planner" in swarm.role_ids()


def test_config_cannot_disable_mandatory_roles():
    swarm = RoleSynthesisEngine().assemble(
        PACKET, SwarmConfig(disabled_roles=frozenset(MANDATORY))
    )
    assert MANDATORY <= set(swarm.role_ids())


def test_engine_without_optional_roles_still_yields_mandatory():
    swarm = RoleSynthesisEngine(optional_roles=[]).assemble(PACKET)
    assert set(swarm.role_ids()) == MANDATORY


def test_remove_mandatory_role_raises():
    swarm = RoleSynthesisEngine().assemble(PACKET)
    with pytest.raises(ValueError):
        swarm.remove("skeptic")
    with pytest.raises(ValueError):
        swarm.remove("policy-reviewer")


def test_remove_optional_role_is_allowed():
    swarm = RoleSynthesisEngine().assemble(PACKET).remove("analyst")
    assert "analyst" not in swarm.role_ids()
    assert MANDATORY <= set(swarm.role_ids())
