"""Building a :class:`PolicyAssessment` in a test, honestly.

WHY THIS EXISTS AND WHAT IT IS NOT. PHASE-1.2b made a policy-evaluated,
action-bound assessment the only thing an authorization surface reads. Roughly a
hundred existing tests constructed a ``Judgment`` and handed it to the gate, the
execution controller, the action gateway or the migration approval authority.
Those tests are not testing the policy layer — they test gate thresholds, TTL
expiry, retry behaviour, ledger rows — and rewriting each to stand up a policy,
resolve a snapshot and bind results would bury what they actually assert.

So this module gives them an assessment. Two ways, and the difference matters:

* :func:`covered` runs the REAL path — a policy value, a resolved snapshot, a
  bound result, ``VerifierBank.assess``. Use it whenever the test cares that
  coverage held. The verdict is the bank's, so its confidence is the bank's too.
* :func:`carrying` mints an assessment around an outcome the test names, via the
  same ``policy.assessment.mint`` the bank uses. Use it when the test needs an
  EXACT ``Judgment`` — a specific confidence against a gate floor, say — which
  the bank's fusion will not reproduce on demand.

:func:`carrying` is a forge, deliberately, and confining it to one file under
``tests/`` is the point. Test code is trusted and always could do this; what
must never happen is a PRODUCTION module doing it, and that is asserted
separately by ``test_no_second_aggregator.py::test_only_the_bank_mints_a_policy_assessment``,
which sweeps ``src/`` and permits exactly ``VerifierBank.assess``. A helper here
cannot weaken that sweep, because the sweep does not look here.
"""

from __future__ import annotations

from prometheus_protocol.core.models import (
    Evidence,
    Judgment,
    Tier,
    Unavailable,
    Verdict,
)
from prometheus_protocol.policy.assessment import PolicyAssessment, mint
from prometheus_protocol.policy.coverage import BoundResult
from prometheus_protocol.policy.profile import (
    PolicyRequirement,
    VerificationPolicy,
)
from prometheus_protocol.policy.resolver import resolve
from prometheus_protocol.policy.snapshot import (
    ACTION_SANDBOX_EXECUTE,
    snapshot_digest,
)
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.store import InMemoryTrustStore

CHECK = "executable.cases"
IMPL = "test-verifier"
ARTIFACT = "a" * 64
TARGET = "sandbox://test"


def a_policy(
    *,
    check_id: str = CHECK,
    implementation: str = IMPL,
    action_class: str = ACTION_SANDBOX_EXECUTE,
) -> VerificationPolicy:
    """A one-requirement policy value. R1: the resolver takes a VALUE, so a test
    supplying its own policy is the intended shape, not a workaround."""

    return VerificationPolicy(
        policy_id="test-profile",
        version=1,
        requirements=(
            PolicyRequirement(
                check_id=check_id,
                permitted=(implementation,),
                applies_to=(action_class,),
            ),
        ),
        require_verification=(action_class,),
    )


def a_snapshot(
    *,
    action_class: str = ACTION_SANDBOX_EXECUTE,
    artifact_sha256: str = ARTIFACT,
    target_canonical: str = TARGET,
    attempt_id: str = "attempt-1",
    policy: VerificationPolicy | None = None,
):
    return resolve(
        policy if policy is not None else a_policy(action_class=action_class),
        artifact_sha256=artifact_sha256,
        target_canonical=target_canonical,
        action_class=action_class,
        attempt_id=attempt_id,
    )


def covered(
    outcome: Evidence | Unavailable | None = None,
    *,
    action_class: str = ACTION_SANDBOX_EXECUTE,
    check_id: str = CHECK,
    implementation: str = IMPL,
    bank: VerifierBank | None = None,
    **snapshot_kwargs,
) -> PolicyAssessment:
    """The real path: policy -> snapshot -> bound result -> ``bank.assess``.

    ``outcome`` defaults to a passing HARD result, so ``covered()`` is the
    positive control every refusal test needs beside it.
    """

    if outcome is None:
        outcome = Evidence(
            passed=True, total=1, passed_count=1, failures=(),
            verifier_id=implementation, verdict=Verdict.PASS, tier=Tier.HARD,
        )
    policy = a_policy(
        check_id=check_id, implementation=implementation, action_class=action_class
    )
    snapshot = a_snapshot(action_class=action_class, policy=policy, **snapshot_kwargs)
    the_bank = bank if bank is not None else VerifierBank(InMemoryTrustStore())
    return the_bank.assess(snapshot, [BoundResult(
        check_id=check_id,
        snapshot_digest=snapshot_digest(snapshot),
        implementation=implementation,
        outcome=outcome,
    )])


def carrying(
    outcome: Judgment | Unavailable,
    *,
    action_class: str = ACTION_SANDBOX_EXECUTE,
    **snapshot_kwargs,
) -> PolicyAssessment:
    """An assessment carrying EXACTLY this outcome. A forge — see the module
    docstring for why it is confined here and what asserts that it stays."""

    return mint(a_snapshot(action_class=action_class, **snapshot_kwargs), outcome)


def for_migration(outcome, *, artifact, target) -> PolicyAssessment:
    """An assessment bound to THIS artifact and THIS database principal.

    ``ApprovalAuthority.authorize`` checks all three — action class, artifact
    digest, canonical target — because a capability is minted for one artifact
    against one principal, and an assessment resolved for a different one is
    evidence about a different action. A helper that let those drift would make
    every migration test pass while proving nothing about the binding.
    """

    from prometheus_protocol.policy.snapshot import ACTION_DATABASE_MIGRATE

    return carrying(
        outcome,
        action_class=ACTION_DATABASE_MIGRATE,
        artifact_sha256=artifact.sha256,
        target_canonical=target.canonical,
    )


def workflow_policy(*implementations: str) -> VerificationPolicy:
    """A policy permitting these graders to satisfy ``workflow.grade``.

    PHASE-1.2b. ``WorkflowRuntime`` takes a policy VALUE, and under the shipped
    baseline a caller-chosen grader satisfies nothing — which is the point: a
    workflow author must not be able to authorize a sandbox execution just by
    supplying a grader. A deployment that trusts its graders names them, and
    this is a test doing exactly that.
    """

    from prometheus_protocol.policy.profile import CHECK_WORKFLOW_GRADE

    return VerificationPolicy(
        policy_id="test-workflow",
        version=1,
        requirements=(
            PolicyRequirement(
                check_id=CHECK_WORKFLOW_GRADE,
                permitted=tuple(implementations),
                applies_to=(ACTION_SANDBOX_EXECUTE,),
            ),
        ),
        require_verification=(ACTION_SANDBOX_EXECUTE,),
    )


def authorize_migration(authority, outcome, *, artifact, target, **kwargs):
    """Call a migration approval authority with a correctly bound assessment.

    The binding is built FROM the artifact and target being passed to
    ``authorize``, so a test cannot accidentally assert that a mismatched
    assessment was accepted — the mismatch cases construct their assessment
    deliberately instead.
    """

    return authority.authorize(
        for_migration(outcome, artifact=artifact, target=target),
        artifact=artifact,
        target=target,
        **kwargs,
    )


def a_judgment(
    verdict: Verdict = Verdict.PASS,
    *,
    confidence: float = 1.0,
    authoritative: bool = True,
    **kwargs,
) -> Judgment:
    """The Judgment shape most migrated tests were already building inline."""

    return Judgment(
        verdict=verdict,
        confidence=confidence,
        authoritative=authoritative,
        **kwargs,
    )
