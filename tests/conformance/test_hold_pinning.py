"""TASK 5: a hold is pinned at creation and approval compares against the pin.

``PendingActionService.hold`` rejects a caller-constructed ``GateDecision``
(``test_execution_descriptor.py::test_hold_admission_refuses_a_routed_decision_without_the_seam_proof``
and ``test_human_cannot_hold_a_failure_or_replace_the_validated_action``). The
hold carries the seam-minted record with the resolved requirements and the
policy version PINNED at creation. Approval compares against the pinned
resolution, not the current policy: a hold pinned to a superseded policy is
REFUSED as a rotation and voided, in either direction. Rotation can invalidate
the pending backlog explicitly. The TTL is unchanged
(``test_execution_expiry.py``).

Doctrine #4: the negative alone proves nothing, so the first test here is the
positive control — a legitimate approved hold still executes when the policy
has not moved — and the explicit-rotation test carries its own control beside
it (a hold created under the NEW policy is untouched and still executes).
"""

from __future__ import annotations

import pytest

from prometheus_protocol.core.models import (
    ACTION_PYTHON_CODE,
    Evidence,
    ExecutableAction,
    Tier,
    Verdict,
)
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.models import PendingStatus
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import GateDecision
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.policy.coverage import BoundResult
from prometheus_protocol.policy.execution import (
    ExecutionAuthorizer,
    ExecutionNotAuthorized,
    PinnedPolicySuperseded,
)
from prometheus_protocol.policy.profile import (
    PolicyRequirement,
    VerificationPolicy,
    policy_digest,
)
from prometheus_protocol.policy.resolver import resolve
from prometheus_protocol.policy.snapshot import ACTION_SANDBOX_EXECUTE, snapshot_digest
from prometheus_protocol.swarm.executor import Executor
from prometheus_protocol.swarm.models import ExecutionResult, content_hash
from prometheus_protocol.verifier.bank import VerifierBank
from tests.support.chain_rewrite import rewrite_entry_and_rehash

TARGET = "sandbox://pinning"
ATTEMPT = "attempt-1"
CLOCK = "2026-09-12T00:00:00+00:00"


def _policy(version: int, *check_ids: str) -> VerificationPolicy:
    return VerificationPolicy(
        policy_id="pinning-test",
        version=version,
        requirements=tuple(
            PolicyRequirement(
                check_id=check, permitted=(f"{check}-impl",), applies_to=(ACTION_SANDBOX_EXECUTE,)
            )
            for check in check_ids
        ),
        require_verification=(ACTION_SANDBOX_EXECUTE,),
    )


POLICY_A = _policy(1, "run", "audit")
POLICY_B_STRICTER = _policy(2, "run", "audit", "second-required-check")
POLICY_B_WEAKER = _policy(2, "run")


def action(code: str = "print('pin')") -> ExecutableAction:
    return ExecutableAction(kind=ACTION_PYTHON_CODE, code=code)


def assessment(a: ExecutableAction, policy: VerificationPolicy):
    """A REAL coverage-validated assessment under ``policy``: every requirement
    answered by its permitted implementation."""

    s = resolve(
        policy,
        artifact_sha256=content_hash(a.code),
        target_canonical=TARGET,
        action_class=ACTION_SANDBOX_EXECUTE,
        attempt_id=ATTEMPT,
    )
    results = [
        BoundResult(
            check_id=item.check_id,
            snapshot_digest=snapshot_digest(s),
            implementation=item.permitted[0],
            outcome=Evidence(
                passed=True,
                total=1,
                passed_count=1,
                failures=(),
                verifier_id=item.permitted[0],
                verdict=Verdict.PASS,
                tier=Tier.HARD,
            ),
        )
        for item in s.requirements
    ]
    return VerifierBank(policy_supplier=lambda: policy).assess(s, results)


class Spy(Executor):
    def __init__(self, *, refuse: bool = False) -> None:
        self.calls: list[GateDecision] = []
        self.refuse = refuse

    def execute(self, decision: GateDecision) -> ExecutionResult:
        self.calls.append(decision)
        if self.refuse:
            return ExecutionResult(
                executed=False, subject_id=decision.subject_id, refused=True, detail="no sandbox"
            )
        return ExecutionResult(executed=True, subject_id=decision.subject_id)


class Deployment:
    """A controller whose selected policy can be ROTATED under a live ledger."""

    def __init__(self, *, spy: Spy | None = None) -> None:
        self.current = [POLICY_A]
        self.spy = spy if spy is not None else Spy()
        self.ledger = SqliteLedger(":memory:")
        self.controller = ExecutionController(
            gate=ActionGate(
                authorizer=ExecutionAuthorizer(lambda: self.current[0]),
                target_canonical=TARGET,
                route_high_risk=True,
            ),
            executor=self.spy,
            ledger=self.ledger,
            clock=lambda: CLOCK,
        )

    def hold(self, a: ExecutableAction | None = None):
        a = a if a is not None else action()
        held = self.controller.submit(
            assessment=assessment(a, self.current[0]),
            action=a,
            attempt_id=ATTEMPT,
            risk_class="high",
        ).pending
        assert held is not None
        return held

    def rotate(self, policy: VerificationPolicy) -> None:
        self.current[0] = policy

    def row(self, pending_id: int) -> dict:
        row = self.ledger.pending_action(pending_id)
        assert row is not None
        return row


def test_a_hold_approved_under_an_unrotated_policy_still_executes():
    """THE POSITIVE CONTROL. Everything below refuses; this is what makes the
    refusals discriminating rather than universal."""

    d = Deployment()
    held = d.hold()
    assert held.record["policy_version"] == 1
    result = d.controller.approve(held.id, identity="human")
    assert result.executed and len(d.spy.calls) == 1
    assert d.controller.pending.get(held.id).status == PendingStatus.APPROVED
    row = d.ledger.executions()[-1]
    assert row["source"] == "human-approved" and row["authorization"] == held.record


@pytest.mark.parametrize(
    "rotated_to",
    [POLICY_B_STRICTER, POLICY_B_WEAKER],
    ids=["stricter-policy", "weaker-policy"],
)
def test_a_hold_pinned_to_a_superseded_policy_is_refused_and_invalidated(rotated_to):
    """Both directions. Stricter: the human approved something that no longer
    passes. Weaker: the rotation would silently weaken a pending authorization.
    Neither is what the human was shown, so neither inherits."""

    d = Deployment()
    held = d.hold()
    d.rotate(rotated_to)
    with pytest.raises(PinnedPolicySuperseded, match="policy rotated") as raised:
        d.controller.approve(held.id, identity="human")
    assert "v1" in str(raised.value) and "v2" in str(raised.value)
    assert d.spy.calls == []

    voided = d.controller.pending.get(held.id)
    assert voided.status == PendingStatus.INVALIDATED
    assert voided.human_decision is None, "a rotation is not a human decision"
    row = d.row(held.id)
    assert row["invalidated_at"] == CLOCK
    assert "policy rotated" in row["invalidated_reason"]
    assert row["decided_by"] == "system:policy-rotation"
    # Voided is terminal: a second approval attempt is refused as decided, and
    # the hold no longer lists as pending.
    with pytest.raises(ValueError, match="already invalidated"):
        d.controller.approve(held.id, identity="human")
    assert [p.id for p in d.controller.list_pending()] == []


def test_the_record_pins_the_policy_version_the_hold_was_created_under():
    d = Deployment()
    held = d.hold()
    d.rotate(POLICY_B_STRICTER)
    # The row is NOT rewritten by the rotation: it still says v1.
    assert d.row(held.id)["authorization"]["policy_version"] == 1
    assert d.row(held.id)["authorization"]["policy_digest"] == policy_digest(POLICY_A)


def test_explicit_rotation_invalidates_every_pending_hold_pinned_to_the_old_policy_and_only_those():
    d = Deployment()
    first = d.hold(action("print(1)"))
    second = d.hold(action("print(2)"))
    d.rotate(POLICY_B_STRICTER)
    third = d.hold(action("print(3)"))  # created under the NEW policy

    voided = d.controller.invalidate_superseded_holds()
    assert sorted(p.id for p in voided) == sorted([first.id, second.id])
    assert all(p.status == PendingStatus.INVALIDATED for p in voided)
    assert [p.id for p in d.controller.list_pending()] == [third.id]
    # Idempotent.
    assert d.controller.invalidate_superseded_holds() == []
    # And the control: the hold pinned to the selected policy still executes.
    assert d.controller.approve(third.id, identity="human").executed
    assert len(d.spy.calls) == 1


def test_a_retry_after_rotation_is_refused_and_the_human_decision_is_untouched():
    """An approved-but-never-executed hold (the executor refused, fail-closed)
    is retry-eligible. After a rotation the retry is refused as superseded, the
    approval record stays exactly as the human left it (decided stays decided),
    and the refused attempt is recorded with the pinned record."""

    d = Deployment(spy=Spy(refuse=True))
    held = d.hold()
    first = d.controller.approve(held.id, identity="human")
    assert first.refused and not first.executed
    d.rotate(POLICY_B_STRICTER)
    with pytest.raises(PinnedPolicySuperseded):
        d.controller.retry_execution(held.id, identity="human")
    after = d.controller.pending.get(held.id)
    assert after.status == PendingStatus.APPROVED
    assert after.human_decision is not None and after.human_decision.identity == "human"
    assert d.row(held.id)["invalidated_at"] is None
    refused_row = d.ledger.executions()[-1]
    assert refused_row["source"] == "retry-refused"
    assert refused_row["authorization"] == held.record
    assert len(d.spy.calls) == 1, "the executor was not called again"


def test_relabelling_a_hold_to_the_new_policy_does_not_get_it_approved():
    """The layered case. An adversary who can rewrite the row, its chain entry
    and every later hash relabels the hold as pinned to the NEW policy. The
    pinned-policy check is satisfied; the seam then re-resolves the new policy
    for the action, and the assessment's snapshot digest — which commits to
    the OLD requirements — does not match. Refused, nothing executes."""

    d = Deployment()
    held = d.hold()
    d.rotate(POLICY_B_STRICTER)
    relabelled = dict(held.record)
    relabelled["policy_version"] = POLICY_B_STRICTER.version
    relabelled["policy_digest"] = policy_digest(POLICY_B_STRICTER)
    import json

    d.ledger._conn.execute(
        "UPDATE pending_actions SET authorization = ? WHERE id = ?",
        (json.dumps(relabelled), held.id),
    )
    d.ledger._conn.commit()
    entry = next(
        e for e in d.ledger.chained_events() if e["subject"] == f"pending:{held.id}"
    )
    rewrite_entry_and_rehash(d.ledger, seq=entry["seq"], payload=relabelled)
    assert d.ledger.verify_chain().ok
    with pytest.raises(ExecutionNotAuthorized, match="re-resolved") as raised:
        d.controller.approve(held.id, identity="human")
    assert not isinstance(raised.value, PinnedPolicySuperseded)
    assert d.spy.calls == []
