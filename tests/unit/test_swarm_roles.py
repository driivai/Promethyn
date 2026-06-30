"""Unit tests for provider-backed swarm roles, parsing, and the call budget."""

from __future__ import annotations

import pytest

from prometheus_protocol.core.interfaces import Provider
from prometheus_protocol.swarm.models import (
    KIND_CRITIQUE,
    KIND_HYPOTHESIS,
    KIND_PROPOSED_ACTION,
    TaskPacket,
)
from prometheus_protocol.swarm.prompts import parse_cases, parse_reasoning
from prometheus_protocol.swarm.roles import (
    AnalystRole,
    PlannerRole,
    ProposerContext,
    Skeptic,
    _make_proposal,
)
from prometheus_protocol.swarm.synthesis import RoleSynthesisEngine


class _Scripted(Provider):
    """A provider returning fixed text for generation and fixed code."""

    def __init__(self, *, text: str = "", code: str = "") -> None:
        self.text = text
        self.code = code

    def propose_solution(self, *, prompt, entry_point, skills=()):
        return self.code

    def generate(self, *, prompt, system=None):
        return self.text


class _Raising(Provider):
    def propose_solution(self, *, prompt, entry_point, skills=()):
        raise RuntimeError("boom")

    def generate(self, *, prompt, system=None):
        raise RuntimeError("boom")


class _Counting(Provider):
    def __init__(self) -> None:
        self.calls = 0

    def propose_solution(self, *, prompt, entry_point, skills=()):
        self.calls += 1
        return "def f():\n    return 1\n"

    def generate(self, *, prompt, system=None):
        self.calls += 1
        return "CONTENT: x\nRATIONALE: y"


_CTX = ProposerContext(packet=TaskPacket(goal="g"))


# -- parsing ---------------------------------------------------------------


def test_parse_reasoning_wellformed():
    assert parse_reasoning("CONTENT: do it\nRATIONALE: because") == ("do it", "because")


@pytest.mark.parametrize(
    "text",
    ["", "no markers here", "CONTENT: only content", "RATIONALE: only rationale"],
)
def test_parse_reasoning_malformed_is_none(text):
    assert parse_reasoning(text) is None


def test_parse_cases_wellformed_and_skips_garbage():
    text = 'CASE: [1, 2] -> 3\nnonsense\nCASE: ["a"] -> "A"\nCASE: bad -> bad'
    cases = parse_cases(text)
    assert [(c.args, c.expected) for c in cases] == [((1, 2), 3), (("a",), "A")]


def test_parse_cases_empty_when_nothing_parses():
    assert parse_cases("CASE: not json\nrandom text") == []


# -- reasoning roles -------------------------------------------------------


def test_planner_reasoning_produces_validated_action():
    role = PlannerRole(_Scripted(text="CONTENT: step\nRATIONALE: advances goal"))
    proposals = role.propose(TaskPacket(goal="g"), _CTX)
    assert len(proposals) == 1
    p = proposals[0]
    assert p.kind == KIND_PROPOSED_ACTION and p.role_id == "planner"
    assert p.content == "step" and p.rationale == "advances goal"
    # Provenance is set: content hash + recorded inputs.
    assert p.provenance.content_hash and p.provenance.inputs


def test_analyst_reasoning_produces_hypothesis():
    role = AnalystRole(_Scripted(text="CONTENT: h\nRATIONALE: r"))
    proposals = role.propose(TaskPacket(goal="g"), _CTX)
    assert len(proposals) == 1 and proposals[0].kind == KIND_HYPOTHESIS


def test_planner_code_domain_uses_propose_solution():
    code = "def add(a, b):\n    return a + b\n"
    role = PlannerRole(_Scripted(code=code))
    proposals = role.propose(TaskPacket(goal="add", entry_point="add"), _CTX)
    assert len(proposals) == 1
    assert proposals[0].kind == KIND_PROPOSED_ACTION and proposals[0].content == code


@pytest.mark.parametrize("role_cls", [PlannerRole, AnalystRole])
def test_malformed_reply_yields_no_proposal(role_cls):
    role = role_cls(_Scripted(text="garbage with no markers"))
    assert role.propose(TaskPacket(goal="g"), _CTX) == []


@pytest.mark.parametrize("role_cls", [PlannerRole, AnalystRole])
def test_provider_error_degrades_to_no_proposal(role_cls):
    assert role_cls(_Raising()).propose(TaskPacket(goal="g"), _CTX) == []


@pytest.mark.parametrize("role_cls", [PlannerRole, AnalystRole])
def test_no_provider_yields_no_proposal(role_cls):
    assert role_cls(None).propose(TaskPacket(goal="g"), _CTX) == []


# -- skeptic ---------------------------------------------------------------


def _action(content="def add(a, b):\n    return a + b\n"):
    return _make_proposal("planner", KIND_PROPOSED_ACTION, content, "candidate")


def test_skeptic_code_domain_attaches_executable_check():
    skeptic = Skeptic(_Scripted(text="CASE: [1, 2] -> 3\nCASE: [0, 0] -> 0"))
    ctx = ProposerContext(
        packet=TaskPacket(goal="add", entry_point="add"), proposals=(_action(),)
    )
    critiques = skeptic.propose(ctx.packet, ctx)
    assert len(critiques) == 1
    checks = critiques[0].falsification_checks
    executable = [c for c in checks if c.cases]
    assert len(executable) == 1
    assert executable[0].entry_point == "add"
    assert [(c.args, c.expected) for c in executable[0].cases] == [((1, 2), 3), ((0, 0), 0)]
    # Structural checks are still attached.
    assert any(not c.cases for c in checks)


def test_skeptic_reasoning_domain_has_structural_checks_only():
    skeptic = Skeptic(_Scripted(text="CASE: [1] -> 1"))
    # No entry_point -> not a code task -> no executable check, no provider call.
    ctx = ProposerContext(packet=TaskPacket(goal="g"), proposals=(_action(),))
    checks = skeptic.propose(ctx.packet, ctx)[0].falsification_checks
    assert checks and all(not c.cases for c in checks)


def test_skeptic_malformed_cases_attach_no_executable_check():
    skeptic = Skeptic(_Scripted(text="CASE: not-json"))
    ctx = ProposerContext(
        packet=TaskPacket(goal="add", entry_point="add"), proposals=(_action(),)
    )
    checks = skeptic.propose(ctx.packet, ctx)[0].falsification_checks
    assert checks and all(not c.cases for c in checks)  # only structural


# -- budget ----------------------------------------------------------------


def test_role_calls_are_capped_per_task():
    counter = _Counting()
    engine = RoleSynthesisEngine(provider=counter, max_role_calls=1)
    packet = TaskPacket(goal="g", entry_point="f", budget=5)
    engine.assemble(packet).propose(packet)
    assert counter.calls <= 1


def test_budget_resets_each_task():
    counter = _Counting()
    engine = RoleSynthesisEngine(provider=counter, max_role_calls=2)
    packet = TaskPacket(goal="g", budget=5)
    engine.assemble(packet).propose(packet)
    first = counter.calls
    engine.assemble(packet).propose(packet)
    # Each task draws at most the cap again (not cumulative across tasks).
    assert first <= 2 and counter.calls - first <= 2
