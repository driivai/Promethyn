"""Checkpoint B: the trusted execution descriptor is one enforcement seam."""

from dataclasses import replace

import pytest

from prometheus_protocol.core.models import (
    ACTION_PYTHON_CODE,
    Evidence,
    ExecutableAction,
    Judgment,
    Tier,
    Verdict,
)
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.policy.coverage import BoundResult
from prometheus_protocol.policy.execution import (
    ExecutionAuthorizer,
    ExecutionNotAuthorized,
)
from prometheus_protocol.policy.profile import PolicyRequirement, VerificationPolicy
from prometheus_protocol.policy.resolver import resolve
from prometheus_protocol.policy.snapshot import ACTION_SANDBOX_EXECUTE, snapshot_digest
from prometheus_protocol.swarm.models import ExecutionResult, content_hash
from prometheus_protocol.verifier.bank import VerifierBank

POLICY = VerificationPolicy(
    policy_id="descriptor-test",
    version=1,
    requirements=(
        PolicyRequirement(
            check_id="run", permitted=("runner",), applies_to=(ACTION_SANDBOX_EXECUTE,)
        ),
    ),
    require_verification=(ACTION_SANDBOX_EXECUTE,),
)
TARGET = "sandbox://descriptor"
ATTEMPT = "attempt-1"


def action(code="print('ok')"):
    return ExecutableAction(kind=ACTION_PYTHON_CODE, code=code)


def snapshot(a=None, policy=POLICY):
    a = a or action()
    return resolve(
        policy,
        artifact_sha256=content_hash(a.code),
        target_canonical=TARGET,
        action_class=ACTION_SANDBOX_EXECUTE,
        attempt_id=ATTEMPT,
    )


def assessment(a=None, verdict=Verdict.PASS, confidence=1.0):
    s = snapshot(a)
    bank = VerifierBank(policy_supplier=lambda: POLICY)
    evidence = Evidence(
        passed=verdict == Verdict.PASS,
        total=1,
        passed_count=1 if verdict == Verdict.PASS else 0,
        failures=(),
        verifier_id="runner",
        verdict=verdict,
        tier=Tier.HARD,
    )
    return bank.assess(
        s,
        [
            BoundResult(
                check_id="run",
                snapshot_digest=snapshot_digest(s),
                implementation="runner",
                outcome=evidence,
            )
        ],
    )


def gate():
    return ActionGate(
        authorizer=ExecutionAuthorizer(lambda: POLICY),
        target_canonical=TARGET,
        escalate_below=0.75,
    )


class Spy:
    def __init__(self):
        self.calls = []

    def execute(self, decision):
        self.calls.append(decision)
        return ExecutionResult(executed=True, subject_id=decision.subject_id)


def test_bank_re_resolves_and_rejects_honestly_redigested_weakened_snapshot():
    original = snapshot()
    weakened = replace(original, requirements=())
    assert (
        weakened.policy_id == original.policy_id
        and weakened.policy_digest == original.policy_digest
    )
    # A re-digest-only implementation would accept this bound structural pass.
    bound = BoundResult(
        check_id="structural",
        snapshot_digest=snapshot_digest(weakened),
        implementation="structural",
        outcome=_hard_pass("structural"),
    )
    with pytest.raises(ExecutionNotAuthorized, match="re-resolved"):
        VerifierBank(policy_supplier=lambda: POLICY).assess(weakened, [bound])


def _hard_pass(verifier_id: str) -> Evidence:
    """A passing HARD result whose verifier_id is set BY KEYWORD.

    ``Evidence`` is ``(passed, total, passed_count, failures, stdout, stderr,
    duration_s, timed_out, verifier_id, verdict, ...)``, so the positional form
    used elsewhere in this file puts the implementation name into ``stdout`` and
    leaves ``verifier_id`` at its default. That is invisible wherever the seam
    refuses BEFORE coverage runs, and becomes ``coverage.invalid_evidence`` — the
    result names one implementation and the evidence another — as soon as a test
    expects coverage to hold. A positive control is exactly such a test.
    """

    return Evidence(
        passed=True,
        total=1,
        passed_count=1,
        failures=(),
        verifier_id=verifier_id,
        verdict=Verdict.PASS,
        tier=Tier.HARD,
    )


#: Two requirements, so ONE can be dropped and the snapshot still be non-empty.
#: ``POLICY`` above has a single requirement, which makes ``requirements=()`` the
#: only weakening expressible against it — and an implementation that merely
#: REJECTED EMPTY SNAPSHOTS would pass the test above while closing nothing. The
#: design names "rejecting only an empty snapshot" as an insufficient fix, so the
#: proof of the sufficient one has to weaken partially.
_TWO_REQUIREMENT_POLICY = VerificationPolicy(
    policy_id="descriptor-test-two",
    version=1,
    requirements=(
        PolicyRequirement(
            check_id="run", permitted=("runner",), applies_to=(ACTION_SANDBOX_EXECUTE,)
        ),
        PolicyRequirement(
            check_id="audit",
            permitted=("auditor",),
            applies_to=(ACTION_SANDBOX_EXECUTE,),
        ),
    ),
    require_verification=(ACTION_SANDBOX_EXECUTE,),
)


def test_bank_re_resolves_and_rejects_a_PARTIALLY_weakened_snapshot():
    """The reproduced R1 attack, at its actual strength: drop ONE of two.

    This is the negative half of the pair; the positive control is
    :func:`test_bank_mints_for_the_unweakened_two_requirement_snapshot` below.
    Without the positive control a seam that refused everything would pass this.
    """

    original = resolve(
        _TWO_REQUIREMENT_POLICY,
        artifact_sha256=content_hash(action().code),
        target_canonical=TARGET,
        action_class=ACTION_SANDBOX_EXECUTE,
        attempt_id=ATTEMPT,
    )
    weakened = replace(
        original,
        requirements=tuple(r for r in original.requirements if r.check_id != "audit"),
    )
    # Still non-empty, and still citing the policy it no longer satisfies — the
    # signature of the reproduced attack, not a degenerate case.
    assert [r.check_id for r in weakened.requirements] == ["run"]
    assert (
        weakened.policy_id == original.policy_id
        and weakened.policy_digest == original.policy_digest
    )
    bound = BoundResult(
        check_id="run",
        snapshot_digest=snapshot_digest(weakened),
        implementation="runner",
        outcome=_hard_pass("runner"),
    )
    with pytest.raises(ExecutionNotAuthorized, match="re-resolved"):
        VerifierBank(policy_supplier=lambda: _TWO_REQUIREMENT_POLICY).assess(
            weakened, [bound]
        )


def test_bank_mints_for_the_unweakened_two_requirement_snapshot():
    """POSITIVE CONTROL for the partial-weakening refusal above.

    The same policy, the same artifact, nothing dropped, and a result for BOTH
    requirements: the bank mints. A refusal here would mean the test above
    proves only that the seam refuses, never that it discriminates.
    """

    intact = resolve(
        _TWO_REQUIREMENT_POLICY,
        artifact_sha256=content_hash(action().code),
        target_canonical=TARGET,
        action_class=ACTION_SANDBOX_EXECUTE,
        attempt_id=ATTEMPT,
    )
    digest = snapshot_digest(intact)
    results = [
        BoundResult(
            check_id=check,
            snapshot_digest=digest,
            implementation=impl,
            outcome=_hard_pass(impl),
        )
        for check, impl in (("run", "runner"), ("audit", "auditor"))
    ]
    assessed = VerifierBank(policy_supplier=lambda: _TWO_REQUIREMENT_POLICY).assess(
        intact, results
    )
    assert assessed.snapshot_digest == digest
    assert assessed.policy_id == "descriptor-test-two"
    assert isinstance(assessed.outcome, Judgment)
    assert assessed.outcome.verdict == Verdict.PASS


def test_descriptor_refuses_each_cross_action_mismatch_before_execution():
    a = action()
    assessed = assessment(a)
    spy = Spy()
    controller = ExecutionController(
        gate=gate(), executor=spy, ledger=SqliteLedger(":memory:")
    )
    for replacement in (
        action("print('different artifact')"),
        ExecutableAction(kind="git_delete_branch", code=a.code),
    ):
        with pytest.raises(ExecutionNotAuthorized):
            controller.submit(
                attempt_id="attempt-1", assessment=assessed, action=replacement
            )
    for field, value in (
        ("target_canonical", "sandbox://other"),
        ("action_class", "branch.delete"),
        ("policy_digest", "0" * 64),
        ("attempt_id", "attempt-2"),
    ):
        from prometheus_protocol.policy.assessment import _restore_persisted

        values = {
            name: getattr(assessed, name)
            for name in (
                "snapshot_digest",
                "policy_id",
                "policy_digest",
                "artifact_sha256",
                "target_canonical",
                "action_class",
                "attempt_id",
            )
        }
        values[field] = value
        forged = _restore_persisted(
            outcome=assessed.outcome, coverage=assessed.coverage, **values
        )
        with pytest.raises(ExecutionNotAuthorized):
            gate().decide(forged, action=a, attempt_id=ATTEMPT)
    assert spy.calls == []


@pytest.mark.parametrize(
    "label,minted_target,minted_attempt,gate_target,presented_attempt",
    [
        ("target", "sandbox://other", ATTEMPT, TARGET, ATTEMPT),
        ("attempt", TARGET, "attempt-OLD", TARGET, "attempt-NEW"),
    ],
)
def test_a_LEGITIMATELY_minted_assessment_does_not_cross_target_or_attempt(
    label, minted_target, minted_attempt, gate_target, presented_attempt
):
    """The two R2 dimensions the suite did not cover, found by mutation.

    ``test_descriptor_refuses_each_cross_action_mismatch_before_execution``
    forges an assessment by replacing ONE field while keeping the original
    snapshot digest, so the digest comparison catches it whatever the descriptor
    is built from. That makes it blind to how the descriptor sourced the field:
    measured, taking ``target_canonical`` and ``attempt_id`` from the assessment
    instead of from the gate's configured target and the caller's attempt left
    the whole suite GREEN.

    This presents a LEGITIMATELY MINTED assessment — correct digest, correct
    policy, minted by the real bank — for a different target or attempt, which
    is the shape the digest is actually protecting against. Under the same
    mutation this authorizes: measured, ``approved=True`` for both rows.
    """

    snapshot = resolve(
        POLICY,
        artifact_sha256=content_hash(action().code),
        target_canonical=minted_target,
        action_class=ACTION_SANDBOX_EXECUTE,
        attempt_id=minted_attempt,
    )
    assessed = VerifierBank(policy_supplier=lambda: POLICY).assess(
        snapshot,
        [
            BoundResult(
                check_id="run",
                snapshot_digest=snapshot_digest(snapshot),
                implementation="runner",
                outcome=_hard_pass("runner"),
            )
        ],
    )
    guarded = ActionGate(
        authorizer=ExecutionAuthorizer(lambda: POLICY),
        target_canonical=gate_target,
        escalate_below=0.75,
    )
    with pytest.raises(ExecutionNotAuthorized):
        guarded.decide(assessed, action=action(), attempt_id=presented_attempt)


def test_a_legitimately_minted_assessment_on_its_OWN_target_and_attempt_passes():
    """POSITIVE CONTROL for the pair above.

    Same policy, same artifact, minted for the gate's own target and presented
    under its own attempt: it authorizes. Without this the two refusals above
    would be satisfied by a seam that refused everything.
    """

    snapshot = resolve(
        POLICY,
        artifact_sha256=content_hash(action().code),
        target_canonical=TARGET,
        action_class=ACTION_SANDBOX_EXECUTE,
        attempt_id=ATTEMPT,
    )
    assessed = VerifierBank(policy_supplier=lambda: POLICY).assess(
        snapshot,
        [
            BoundResult(
                check_id="run",
                snapshot_digest=snapshot_digest(snapshot),
                implementation="runner",
                outcome=_hard_pass("runner"),
            )
        ],
    )
    decision = gate().decide(assessed, action=action(), attempt_id=ATTEMPT)
    assert decision.approved


def test_the_snapshot_digest_covers_every_descriptor_field():
    """Doctrine #8 applied to the digest: what varies here is the FIELD LIST.

    TWO LAYERS, MEASURED — and the first measurement of this was wrong, so the
    correction is recorded rather than quietly applied. Deleting any one of the
    six names from the per-field loop leaves the whole suite green, which looks
    like the loop being decorative. It is not: it is REDUNDANT WHILE THE DIGEST
    IS PRESENT. Removing the digest comparison instead leaves the R2 behavioural
    proofs still passing, and a direct probe then refuses with "assessment
    target_canonical does not match execution descriptor" — the loop carrying
    the load. Both layers independently cover the same six fields.

    That redundancy is exactly why the field LIST is what has to be pinned. A
    seventh descriptor field added tomorrow would be covered by NEITHER layer:
    not by the digest, which commits to ``SNAPSHOT_FIELDS``, and not by the
    loop, whose tuple is written out by hand. Two layers that both enumerate the
    same six fields give no protection at all against the set changing, which is
    the one thing that varies here.
    """

    from dataclasses import fields

    from prometheus_protocol.policy.execution import ExecutionDescriptor
    from prometheus_protocol.policy.snapshot import SNAPSHOT_FIELDS

    descriptor_fields = {f.name for f in fields(ExecutionDescriptor)}
    digested = set(SNAPSHOT_FIELDS)
    uncovered = descriptor_fields - digested
    assert uncovered == set(), (
        f"descriptor field(s) {sorted(uncovered)} are not committed to by the "
        "snapshot digest. Enforcement is single-layer through that digest, so a "
        "field outside it is enforced by nothing — the per-field loop in "
        "authorize_context is unreachable. Either add the field to the snapshot "
        "encoding (a deliberate digest change) or record here why it carries no "
        "authority."
    )


def test_correct_binding_authorizes_and_executes():
    a = action()
    spy = Spy()
    result = ExecutionController(
        gate=gate(), executor=spy, ledger=SqliteLedger(":memory:")
    ).submit(
        attempt_id="attempt-1", assessment=assessment(a), action=a, subject_id="subject"
    )
    assert result.execution is not None and result.execution.executed
    assert len(spy.calls) == 1
    assert spy.calls[0].authorization.descriptor.attempt_id == ATTEMPT


def test_human_hold_requires_same_proof_and_revalidates_on_approval_and_retry():
    a = action()
    spy = Spy()
    ledger = SqliteLedger(":memory:")
    controller = ExecutionController(gate=gate(), executor=spy, ledger=ledger)
    # Genuine low-confidence PASS routes; the human resolves risk, not coverage.
    from prometheus_protocol.policy.assessment import mint

    low = mint(snapshot(a), Judgment(verdict=Verdict.PASS, confidence=0.6, authoritative=True))
    held = controller.submit(attempt_id="attempt-1", assessment=low, action=a).pending
    assert held is not None and spy.calls == []
    controller.approve(held.id, identity="human")
    assert len(spy.calls) == 1
    # Persisted proof is mandatory; legacy/hollowed rows refuse on reload/retry.
    ledger._conn.execute(
        "UPDATE pending_actions SET authorization=NULL WHERE id=?", (held.id,)
    )
    with pytest.raises(ExecutionNotAuthorized, match="re-verification"):
        controller.retry_execution(held.id, identity="human")


def test_human_cannot_hold_a_failure_or_replace_the_validated_action():
    a = action()
    g = gate()
    from prometheus_protocol.policy.assessment import mint

    failed = mint(snapshot(a), Judgment(verdict=Verdict.FAIL, confidence=1.0, authoritative=True))
    decision = g.decide(failed, action=a, attempt_id=ATTEMPT)
    assert decision.effective_outcome == "block"
    with pytest.raises(ValueError, match="only a routed"):
        ExecutionController(
            gate=g, executor=Spy(), ledger=SqliteLedger(":memory:")
        ).pending.hold(decision)
    routed = g.decide(
        mint(snapshot(a), Judgment(verdict=Verdict.PASS, confidence=0.6, authoritative=True)),
        action=a,
        attempt_id=ATTEMPT,
    )
    with pytest.raises(ExecutionNotAuthorized, match="differs"):
        ExecutionController(
            gate=g, executor=Spy(), ledger=SqliteLedger(":memory:")
        ).pending.hold(routed, action=action("print('replacement')"))


def test_non_baseline_profile_changes_coverage_behavior():
    from prometheus_protocol.policy.profile import load_profile

    strict = load_profile("defense-in-depth")
    a = action()
    s = snapshot(a, policy=strict)
    only_executable = BoundResult(
        check_id="executable.cases",
        snapshot_digest=snapshot_digest(s),
        implementation="subprocess-tests",
        outcome=Evidence(
            passed=True,
            total=1,
            passed_count=1,
            failures=(),
            verifier_id="subprocess-tests",
            verdict=Verdict.PASS,
            tier=Tier.HARD,
        ),
    )
    result = VerifierBank(policy_supplier=lambda: strict).assess(s, [only_executable])
    from prometheus_protocol.core.models import Unavailable

    assert isinstance(result.outcome, Unavailable)
    assert "structural.predicates" in result.outcome.detail


def test_user_factories_refuse_an_unknown_selected_profile(tmp_path):
    from prometheus_protocol.core.config import Config
    from prometheus_protocol.runtime.factory import (
        build_execution_controller,
        build_orchestrator,
        build_swarm_runtime,
        build_workflow_runtime,
    )

    bad = Config(ledger_path=":memory:", verification_profile="not-a-profile")
    for factory in (build_orchestrator, build_execution_controller):
        with pytest.raises(ValueError, match="no committed verification profile"):
            factory(bad)
    with pytest.raises(ValueError, match="no committed verification profile"):
        build_swarm_runtime(bad, provider=object())
    with pytest.raises(ValueError, match="no committed verification profile"):
        build_workflow_runtime(bad)

    from prometheus_protocol.chokepoint.runner import (
        DbTarget,
        MigrationRunnerConfig,
        build_migration_runtime,
    )

    migration = MigrationRunnerConfig(
        target=DbTarget("db.internal", 5432, "app", "migrator", "password"),
        approval_store_path=tmp_path / "approvals.db",
        signing_key=b"k" * 32,
    )
    with pytest.raises(ValueError, match="no committed verification profile"):
        build_migration_runtime(
            migration,
            audit=object(),
            authorization=object(),
            settings=bad,
        )


def test_assessment_from_a_different_policy_is_not_relabelled_as_selected():
    other = VerificationPolicy(
        policy_id="other-policy",
        version=1,
        requirements=(
            PolicyRequirement(
                check_id="other",
                permitted=("other-runner",),
                applies_to=(ACTION_SANDBOX_EXECUTE,),
            ),
        ),
        require_verification=(ACTION_SANDBOX_EXECUTE,),
    )
    a = action()
    s = snapshot(a, policy=other)
    result = BoundResult(
        check_id="other",
        snapshot_digest=snapshot_digest(s),
        implementation="other-runner",
        outcome=Evidence(
            passed=True,
            total=1,
            passed_count=1,
            failures=(),
            verifier_id="other-runner",
            verdict=Verdict.PASS,
            tier=Tier.HARD,
        ),
    )
    assessed = VerifierBank(policy_supplier=lambda: other).assess(s, [result])
    assert assessed.policy_digest != snapshot(a).policy_digest
    with pytest.raises(ExecutionNotAuthorized):
        gate().decide(assessed, action=a, attempt_id=ATTEMPT)
    # Refusal did not rewrite history to the context's selected digest.
    assert assessed.policy_digest != snapshot(a).policy_digest


def test_hold_admission_refuses_a_routed_decision_without_the_seam_proof():
    from prometheus_protocol.gate.promotion import GateDecision

    a = action()
    hollow = GateDecision(
        approved=False,
        subject_id="s",
        outcome="route",
        action=a,
        judgment=Judgment(verdict=Verdict.FAIL, confidence=1.0, authoritative=True),
    )
    controller = ExecutionController(
        gate=gate(), executor=Spy(), ledger=SqliteLedger(":memory:")
    )
    with pytest.raises(ExecutionNotAuthorized, match="validated execution descriptor"):
        controller.pending.hold(hollow)


def test_nonbaseline_profile_is_injected_into_the_execution_factory():
    from prometheus_protocol.core.config import Config
    from prometheus_protocol.core.models import Unavailable
    from prometheus_protocol.policy.profile import load_profile
    from prometheus_protocol.runtime.factory import build_execution_controller

    selected = load_profile("defense-in-depth")
    a = action()
    s = resolve(
        selected,
        artifact_sha256=content_hash(a.code),
        target_canonical="sandbox://execution",
        action_class=ACTION_SANDBOX_EXECUTE,
        attempt_id=ATTEMPT,
    )
    only = BoundResult(
        check_id="executable.cases",
        snapshot_digest=snapshot_digest(s),
        implementation="subprocess-tests",
        outcome=Evidence(
            passed=True,
            total=1,
            passed_count=1,
            failures=(),
            verifier_id="subprocess-tests",
            verdict=Verdict.PASS,
            tier=Tier.HARD,
        ),
    )
    assessed = VerifierBank(policy_supplier=lambda: selected).assess(s, [only])
    assert isinstance(assessed.outcome, Unavailable)
    controller = build_execution_controller(
        Config(ledger_path=":memory:", verification_profile="defense-in-depth")
    )
    result = controller.submit(attempt_id="attempt-1", assessment=assessed, action=a)
    assert result.outcome == "unavailable" and result.execution is None


def test_hold_approval_re_resolves_the_policy_instead_of_redigesting_the_hold():
    """A hold created under policy A must not be approved by re-digesting what
    the hold says; the SELECTED policy decides. TASK 5 sharpened what happens
    when the selected policy has moved: the hold is pinned to A, so after a
    rotation to B approval is refused AS A ROTATION (``PinnedPolicySuperseded``,
    a distinct refusal) and the hold is voided, rather than being silently
    re-evaluated against B in either direction. ``tests/conformance/
    test_hold_pinning.py`` carries the full rotation contract and its positive
    control; this keeps the original property under its original name."""

    from prometheus_protocol.execution.models import PendingStatus
    from prometheus_protocol.policy.execution import PinnedPolicySuperseded

    current = [POLICY]
    authorizer = ExecutionAuthorizer(lambda: current[0])
    a = action()
    from prometheus_protocol.policy.assessment import mint

    low = mint(snapshot(a), Judgment(verdict=Verdict.PASS, confidence=0.6, authoritative=True))
    ledger = SqliteLedger(":memory:")
    controller = ExecutionController(
        gate=ActionGate(
            authorizer=authorizer,
            target_canonical=TARGET,
            escalate_below=0.75,
        ),
        executor=Spy(),
        ledger=ledger,
    )
    held = controller.submit(
        assessment=low,
        action=a,
        attempt_id=ATTEMPT,
    ).pending
    assert held is not None
    current[0] = VerificationPolicy(
        policy_id=POLICY.policy_id,
        version=2,
        requirements=POLICY.requirements
        + (
            PolicyRequirement(
                check_id="second-required-check",
                permitted=("runner-2",),
                applies_to=(ACTION_SANDBOX_EXECUTE,),
            ),
        ),
        require_verification=(ACTION_SANDBOX_EXECUTE,),
    )
    with pytest.raises(PinnedPolicySuperseded, match="policy rotated"):
        controller.pending._revalidate(held)
    voided = controller.pending.get(held.id)
    assert voided is not None and voided.status == PendingStatus.INVALIDATED
    with pytest.raises(ValueError, match="already invalidated"):
        controller.approve(held.id, identity="human")


def test_correctly_bound_migration_assessment_still_mints_a_capability():
    from prometheus_protocol.chokepoint.approval import (
        ApprovalAuthority,
        MigrationArtifact,
        MigrationTarget,
    )
    from prometheus_protocol.policy.profile import DEFAULT_PROFILE_ID, load_profile
    from prometheus_protocol.policy.snapshot import ACTION_DATABASE_MIGRATE

    artifact = MigrationArtifact("CREATE TABLE checkpoint_b (id integer);")
    target = MigrationTarget("db.internal", 5432, "app", "migrator", "public")
    policy = load_profile(DEFAULT_PROFILE_ID)
    attempt_id = "migration-attempt-1"
    resolved = resolve(
        policy,
        artifact_sha256=artifact.sha256,
        target_canonical=target.canonical,
        action_class=ACTION_DATABASE_MIGRATE,
        attempt_id=attempt_id,
    )
    evidence = Evidence(
        passed=True,
        total=1,
        passed_count=1,
        failures=(),
        verifier_id="subprocess-tests",
        verdict=Verdict.PASS,
        tier=Tier.HARD,
    )
    assessed = VerifierBank(policy_supplier=lambda: policy).assess(
        resolved,
        [
            BoundResult(
                check_id="executable.cases",
                snapshot_digest=snapshot_digest(resolved),
                implementation="subprocess-tests",
                outcome=evidence,
            )
        ],
    )
    authority = ApprovalAuthority(key=b"k" * 32)
    approval = authority.authorize(
        assessed,
        artifact=artifact,
        target=target,
        attempt_id=attempt_id,
        now=1000.0,
    )
    assert approval is not None
    assert authority.verify(
        approval,
        artifact=artifact,
        target=target,
        now=1001.0,
    ).ok
    assert (
        authority.authorize(
            assessed,
            artifact=artifact,
            target=target,
            attempt_id="different-attempt",
            now=1000.0,
        )
        is None
    )
