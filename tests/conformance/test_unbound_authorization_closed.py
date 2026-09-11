"""PHASE-1.2b — a raw authoritative Judgment cannot authorize anything.

Checkpoint 2 enforced requirement coverage and then named its own exposure in
the docs rather than only in a report: ``VerifierBank.judge`` and the
``ExecutionController.submit`` path predated the policy layer, so an old call
path bypassed it entirely. This is that route closed, proven at every surface
that could carry a verdict into a consequence.

WHAT IS ASSERTED, and in which form. The sprint asked whether the insufficiency
is a CONSTRUCTION or a CHECK. It is both, at different layers, and the tests are
split accordingly so the report cannot overclaim:

* :class:`TestTheInterfaceHasNoParameterForIt` — the construction. No
  authorization surface has a parameter that accepts a ``Judgment``. This is what
  makes forgetting a check impossible rather than unlikely.
* :class:`TestTheConstructorRefusesAForge` — the guard. A ``PolicyAssessment``
  cannot be built except by minting, and a copy of one is refused. In-process
  Python still reaches past this and the residual is named, not hidden.
* :class:`TestNothingExecutes` — the consequence, behaviourally: no approval, no
  executor call, through the real runtime.
* :class:`TestThePositiveControl` — the other half of every refusal here.
  Without it this file would pass by breaking everything.
"""

from __future__ import annotations

import dataclasses

import pytest

from prometheus_protocol.core.models import (
    ACTION_PYTHON_CODE,
    ExecutableAction,
    Judgment,
    Tier,
    Unavailability,
    Unavailable,
    Verdict,
)
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import OUTCOME_APPROVE
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.orchestration.gateway import ActionGateway
from prometheus_protocol.policy.assessment import (
    PolicyAssessment,
    UnboundAuthorization,
    mint,
)
from prometheus_protocol.policy.execution import ExecutionAuthorizer
from prometheus_protocol.swarm.models import content_hash
from prometheus_protocol.swarm.executor import RecordingExecutor

from tests.support.assessments import a_policy, a_snapshot, carrying, covered

_ACTION = ExecutableAction(kind=ACTION_PYTHON_CODE, code="print('x')")


def _authoritative_pass() -> Judgment:
    """Exactly what used to be sufficient: an authoritative PASS at full
    confidence. Nothing about it is malformed — that is the point."""

    return Judgment(verdict=Verdict.PASS, confidence=1.0, authoritative=True)


def _controller(executor=None, ledger=None):
    return ExecutionController(
        gate=ActionGate(
            target_canonical="sandbox://test",
            escalate_below=0.75,
            route_high_risk=True,
            authorizer=ExecutionAuthorizer(lambda: a_policy()),
        ),
        executor=executor if executor is not None else RecordingExecutor(),
        ledger=ledger if ledger is not None else SqliteLedger(":memory:"),
    )


# ===========================================================================
# 1. The construction: there is no parameter for an unbound verdict
# ===========================================================================


class TestTheInterfaceHasNoParameterForIt:
    """The completion condition, stated as the sprint stated it: an unbound
    judgment should be UNABLE TO BE PRESENTED, not presented and rejected."""

    def test_the_gate_has_no_judgment_parameter(self):
        import inspect

        params = inspect.signature(ActionGate.decide).parameters
        assert "judgment" not in params
        assert "assessment" in params

    def test_the_execution_controller_has_no_judgment_keyword(self):
        import inspect

        params = inspect.signature(ExecutionController.submit).parameters
        assert "judgment" not in params, (
            "the old keyword is back. Leaving it would leave the bypass "
            "reachable by a caller that never migrated."
        )
        assert "assessment" in params

    def test_the_action_gateway_has_no_judgment_keyword(self):
        import inspect

        params = inspect.signature(ActionGateway.route_action).parameters
        assert "judgment" not in params
        assert "assessment" in params

    def test_the_migration_authority_has_no_judgment_parameter(self):
        import inspect

        from prometheus_protocol.chokepoint.approval import ApprovalAuthority
        from prometheus_protocol.chokepoint.recorded_authority import (
            RecordedApprovalAuthority,
        )

        # BOTH implementations. The recorded one is what build_migration_runtime
        # actually constructs, and migrating only the base class would have left
        # production on the old surface while every test went green.
        for surface in (
            ApprovalAuthority.authorize,
            RecordedApprovalAuthority.authorize,
        ):
            params = inspect.signature(surface).parameters
            assert "judgment" not in params, surface
            assert "assessment" in params, surface

    @pytest.mark.parametrize(
        "outcome",
        [
            Judgment(verdict=Verdict.PASS, confidence=1.0, authoritative=True),
            Judgment(verdict=Verdict.PASS, confidence=0.5, authoritative=True),
            Unavailable(
                verifier_id="v",
                tier=Tier.HARD,
                reason=Unavailability.INFRA_FAULT,
                detail="down",
            ),
        ],
    )
    def test_presenting_one_anyway_raises_rather_than_returning_unapproved(
        self, outcome
    ):
        """A falsy return would be worse than useless: a caller could read it as
        a policy denial and keep handing over unbound verdicts forever."""

        with pytest.raises(UnboundAuthorization):
            ActionGate(
                target_canonical="sandbox://test",
            ).decide(outcome, attempt_id="attempt-1", risk_class="low", subject_id="s")
        with pytest.raises(UnboundAuthorization):
            _controller().submit(
                attempt_id="attempt-1",
                assessment=outcome,
                action=_ACTION,
                subject_id="s",
            )


# ===========================================================================
# 2. The guard: an assessment cannot be forged by construction or by copy
# ===========================================================================


class TestTheConstructorRefusesAForge:
    def test_direct_construction_is_refused(self):
        with pytest.raises(UnboundAuthorization):
            PolicyAssessment(
                snapshot_digest="a" * 64,
                policy_id="p",
                policy_digest="d" * 64,
                action_class="sandbox.execute",
                attempt_id="t",
                artifact_sha256="a" * 64,
                target_canonical="t",
                outcome=_authoritative_pass(),
            )

    def test_copying_a_real_one_is_refused(self):
        """``dataclasses.replace`` copies every init field — the minting token
        included — and MINTED A VALID-LOOKING ASSESSMENT before the token was
        consumed in ``__post_init__``. Measured, then closed. This is the stdlib
        version of the "bespoke copy helper" the 2d guard names."""

        real = covered()
        with pytest.raises(UnboundAuthorization):
            dataclasses.replace(real, outcome=_authoritative_pass())

    def test_a_real_assessment_still_works_after_the_token_is_consumed(self):
        """The negative control for the line above: consuming the token must not
        break the object it was consumed on."""

        real = covered()
        assert isinstance(real.outcome, Judgment)
        assert real.outcome.verdict == Verdict.PASS
        assert real == covered()  # equality survives; the token is not data

    def test_minting_reads_every_field_off_the_snapshot(self):
        """An assessment cannot describe one action while being bound to
        another, because there is no parameter through which they could
        disagree."""

        snapshot = a_snapshot(attempt_id="attempt-xyz")
        assessment = mint(snapshot, _authoritative_pass())
        assert assessment.attempt_id == "attempt-xyz"
        assert assessment.action_class == snapshot.action_class
        assert assessment.artifact_sha256 == snapshot.artifact_sha256


# ===========================================================================
# 3. The consequence: no approval, no executor call
# ===========================================================================


class TestNothingExecutes:
    def test_no_approval_and_zero_executor_calls_at_the_controller(self):
        executor = RecordingExecutor()
        controller = _controller(executor)
        with pytest.raises(UnboundAuthorization):
            controller.submit(
                attempt_id="attempt-1",
                assessment=_authoritative_pass(),
                action=_ACTION,
                subject_id="s",
            )
        assert executor.executed == []

    def test_the_migration_authority_mints_no_capability(self):
        """The most consequential class in the system: a signed, single-use
        capability against a privileged database principal."""

        from prometheus_protocol.chokepoint.approval import ApprovalAuthority
        from prometheus_protocol.chokepoint.signer import LocalHmacSigner

        authority = ApprovalAuthority(signer=LocalHmacSigner(b"k" * 32))
        with pytest.raises(UnboundAuthorization):
            authority.authorize(
                _authoritative_pass(),
                attempt_id="attempt-1",
                artifact=_migration_artifact(),
                target=_migration_target(),
                now=1000.0,
            )

    def test_an_assessment_for_a_DIFFERENT_action_mints_no_capability(self):
        """A capability is minted for one artifact against one principal. An
        assessment resolved for a different one is evidence about a different
        action, and accepting it would let a policy evaluation of a harmless
        migration authorize a destructive one."""

        from prometheus_protocol.chokepoint.approval import ApprovalAuthority
        from prometheus_protocol.chokepoint.signer import LocalHmacSigner
        from prometheus_protocol.policy.snapshot import ACTION_DATABASE_MIGRATE

        authority = ApprovalAuthority(signer=LocalHmacSigner(b"k" * 32))
        artifact, target = _migration_artifact(), _migration_target()
        elsewhere = carrying(
            _authoritative_pass(),
            action_class=ACTION_DATABASE_MIGRATE,
            artifact_sha256="b" * 64,  # a different artifact
            target_canonical=target.canonical,
        )
        assert (
            authority.authorize(
                elsewhere,
                attempt_id="attempt-1",
                artifact=artifact,
                target=target,
                now=1000.0,
            )
            is None
        )

    def test_an_assessment_for_a_DIFFERENT_ACTION_CLASS_mints_no_capability(self):
        """A sandbox execution and a database migration are different
        consequences. An assessment that a sandbox run was verified says nothing
        about whether a migration was, and the artifact digest alone would not
        catch it — the same SQL text could be the artifact of either."""

        from prometheus_protocol.chokepoint.approval import ApprovalAuthority
        from prometheus_protocol.chokepoint.signer import LocalHmacSigner
        from prometheus_protocol.policy.snapshot import ACTION_SANDBOX_EXECUTE

        authority = ApprovalAuthority(signer=LocalHmacSigner(b"k" * 32))
        artifact, target = _migration_artifact(), _migration_target()
        wrong_class = carrying(
            _authoritative_pass(),
            action_class=ACTION_SANDBOX_EXECUTE,  # not database.migrate
            artifact_sha256=artifact.sha256,  # everything else matches
            target_canonical=target.canonical,
        )
        assert (
            authority.authorize(
                wrong_class,
                attempt_id="attempt-1",
                artifact=artifact,
                target=target,
                now=1000.0,
            )
            is None
        )


# ===========================================================================
# 4. The positive control
# ===========================================================================


class TestThePositiveControl:
    """Without this the sprint could pass by breaking everything."""

    def test_a_covered_assessment_still_authorizes_and_still_executes(self):
        executor = RecordingExecutor()
        controller = _controller(executor)
        outcome = controller.submit(
            attempt_id="attempt-1",
            assessment=covered(artifact_sha256=content_hash(_ACTION.code)),
            action=_ACTION,
            risk_class="low",
            subject_id="ok",
        )
        assert outcome.outcome == OUTCOME_APPROVE
        assert outcome.execution is not None and executor.executed

    def test_a_covered_assessment_mints_a_migration_capability(self):
        from prometheus_protocol.chokepoint.approval import Approval, ApprovalAuthority
        from prometheus_protocol.chokepoint.signer import LocalHmacSigner

        from tests.support.assessments import for_migration

        authority = ApprovalAuthority(signer=LocalHmacSigner(b"k" * 32))
        artifact, target = _migration_artifact(), _migration_target()
        approval = authority.authorize(
            for_migration(_authoritative_pass(), artifact=artifact, target=target),
            attempt_id="attempt-1",
            artifact=artifact,
            target=target,
            now=1000.0,
        )
        assert isinstance(approval, Approval)

    def test_a_refused_coverage_still_refuses_after_all_this(self):
        """The Checkpoint-2 essential regression, still holding: a required
        check with no satisfactory result authorizes nothing, and it now cannot
        even reach the gate as a bare verdict."""

        executor = RecordingExecutor()
        controller = _controller(executor)
        unavailable = covered(
            Unavailable(
                verifier_id="test-verifier",
                tier=Tier.HARD,
                reason=Unavailability.INFRA_FAULT,
                detail="down",
            ),
            artifact_sha256=content_hash(_ACTION.code),
        )
        assert isinstance(unavailable.outcome, Unavailable)
        outcome = controller.submit(
            attempt_id="attempt-1",
            assessment=unavailable,
            action=_ACTION,
            risk_class="low",
            subject_id="no",
        )
        assert outcome.outcome != OUTCOME_APPROVE
        assert executor.executed == []


def _migration_artifact():
    from prometheus_protocol.chokepoint.approval import MigrationArtifact

    return MigrationArtifact(sql="SELECT 1;")


def _migration_target():
    from prometheus_protocol.chokepoint.approval import MigrationTarget

    return MigrationTarget(
        host="127.0.0.1", port=5432, dbname="appdb", user="migrator", schema="public"
    )
