"""Integration: a provider-backed swarm run end to end against the mock provider.

Roles propose, the debate selects a verdict-free TestPlan, the bank judges, the
gate decides, and the no-op executor records. In the code domain the Skeptic's
model-generated cases are run by the HARD subprocess verifier: a correct
candidate is approved and executed (recorded), and a buggy one whose skeptic
case fails cannot be approved and never reaches the executor.
"""

from __future__ import annotations

import pytest

from prometheus_protocol import Config, build_swarm_runtime
from prometheus_protocol._examples.swarm_tasks import (
    build_swarm_provider,
    buggy_code_task,
    correct_code_task,
)
from prometheus_protocol.core.models import Verdict
from prometheus_protocol.swarm.models import KIND_PROPOSED_ACTION


def _runtime(task):
    provider = build_swarm_provider([task])
    return build_swarm_runtime(
        Config(ledger_path=":memory:", verifier_memory_mb=0), provider=provider
    )


def _action(run):
    return next(r for r in run.records if r.proposal.kind == KIND_PROPOSED_ACTION)


def test_correct_candidate_is_verified_approved_and_recorded():
    task = correct_code_task()
    runtime = _runtime(task)
    run = runtime.run(task.packet())

    action = _action(run)
    # The skeptic's executable cases are in the plan for the action.
    exec_reqs = [
        req
        for req in action.verification_requests
        if req.requested_by == "skeptic" and req.check.cases
    ]
    assert exec_reqs and exec_reqs[0].check.entry_point == "add"

    # Real HARD verification passed -> approved -> executed (recorded, no-op).
    assert action.verified.judgment.verdict == Verdict.PASS
    assert action.decision is not None and action.decision.approved
    assert action.execution is not None and action.execution.executed
    assert "no-op" in action.execution.detail
    assert runtime.executor.executed  # the wall: only the approved decision crossed


def test_buggy_candidate_fails_skeptic_check_and_is_not_executed():
    task = buggy_code_task()
    runtime = _runtime(task)
    run = runtime.run(task.packet())

    action = _action(run)
    # A skeptic case fails under real verification -> FAIL -> not approved.
    assert action.verified.judgment.verdict == Verdict.FAIL
    assert action.decision is not None and not action.decision.approved
    assert action.execution is None
    assert runtime.executor.executed == []  # nothing reached the executor


def test_full_chain_is_recorded_in_the_ledger():
    task = correct_code_task()
    runtime = _runtime(task)
    runtime.run(task.packet())
    rows = runtime.ledger.attempts()
    assert rows and all(row["split"] == "swarm" for row in rows)
    assert any(row["kind"] == "swarm:executed" for row in rows)
    assert any("judgment" in row["evidence"] for row in rows)


def test_run_is_deterministic():
    task = correct_code_task()
    runtime = _runtime(task)
    first = runtime.run(task.packet())
    second = runtime.run(task.packet())
    assert [(r.proposal.id, r.verified.judgment.verdict) for r in first.records] == [
        (r.proposal.id, r.verified.judgment.verdict) for r in second.records
    ]


def test_malformed_skeptic_cases_do_not_block_a_valid_candidate():
    # The skeptic gets a task whose entry point has no scripted cases, so it
    # produces no runnable executable check (it ABSTAINs). The action is still
    # verified by its structural checks and is not spuriously blocked.
    task = correct_code_task()
    # A code book that has the correct code but no scripted skeptic cases.
    from prometheus_protocol._examples.swarm_tasks import CodeTask

    nocase = CodeTask(entry_point="add", goal=task.goal, code=task.code, cases=())
    runtime = _runtime(nocase)
    run = runtime.run(nocase.packet())
    action = _action(run)
    # No executable case ran (ABSTAIN), but structural checks pass -> not blocked.
    assert action.verified.judgment.verdict == Verdict.PASS
    assert action.decision is not None and action.decision.approved
