"""The bank's coverage enforcement table, one refusal test per row.

Every row of the table in ``policy/coverage.py`` gets a test that REFUSES, and
the four R3 boundary cases get their own — especially both-permitted-unavailable,
which is the line between this design and quorum.
"""

from __future__ import annotations

import pytest

from prometheus_protocol.core.models import (
    Evidence,
    Judgment,
    Tier,
    Unavailability,
    Unavailable,
    Verdict,
)
from prometheus_protocol.policy.coverage import (
    REFUSED_ABSTAINED,
    REFUSED_AMBIGUOUS,
    REFUSED_INCOMPLETE,
    REFUSED_INVALID_EVIDENCE,
    REFUSED_UNSATISFACTORY,
    BoundResult,
    CoverageRefused,
    CoverageSatisfied,
    validate_coverage,
)
from prometheus_protocol.policy.profile import (
    CHECK_EXECUTABLE_CASES,
    IMPL_SUBPROCESS,
    PolicyRequirement,
    VerificationPolicy,
    load_profile,
)
from prometheus_protocol.policy.resolver import resolve
from prometheus_protocol.policy.snapshot import snapshot_digest
from prometheus_protocol.verifier.bank import VerifierBank

ARTIFACT = "a" * 64
TARGET = '{"host":"db.internal","dbname":"appdb"}'
ATTEMPT = "attempt-0001"

#: A second permitted implementation, for the R3 boundary cases. Named here
#: rather than in the shipped profile: the shipped baseline permits exactly one,
#: and inventing a sibling in production data to make a test convenient would be
#: writing the policy to fit the test.
IMPL_SIBLING = "container-tests"


def a_snapshot(*, policy: VerificationPolicy | None = None):
    return resolve(
        policy or load_profile("baseline"),
        artifact_sha256=ARTIFACT,
        target_canonical=TARGET,
        action_class="sandbox.execute",
        attempt_id=ATTEMPT,
    )


def two_permitted_policy() -> VerificationPolicy:
    return VerificationPolicy(
        policy_id="two-permitted",
        version=1,
        requirements=(
            PolicyRequirement(
                check_id=CHECK_EXECUTABLE_CASES,
                permitted=(IMPL_SUBPROCESS, IMPL_SIBLING),
                applies_to=("sandbox.execute", "database.migrate"),
            ),
        ),
        # PHASE-1.2b — stated EXPLICITLY rather than left to the default, which
        # is every action class. ``branch.delete`` arrived this sprint, and a
        # policy that covers a class while requiring nothing for it is the
        # emptiest fail-open; the floor refused this fixture until the coverage
        # it actually makes claims about was named. That the default breaks every
        # policy when a consequence class is added is the fail-closed direction
        # and is intended: a new way to cause harm should force each policy to
        # decide about it, not be silently covered by nothing.
        require_verification=("sandbox.execute", "database.migrate"),
    )


def evidence(verdict: Verdict, *, verifier_id: str = IMPL_SUBPROCESS) -> Evidence:
    return Evidence(
        passed=verdict == Verdict.PASS,
        total=1,
        passed_count=1 if verdict == Verdict.PASS else 0,
        failures=() if verdict == Verdict.PASS else ("case failed",),
        verifier_id=verifier_id,
        verdict=verdict,
        tier=Tier.HARD,
    )


def unavailable(*, verifier_id: str = IMPL_SUBPROCESS) -> Unavailable:
    return Unavailable(
        verifier_id=verifier_id,
        tier=Tier.HARD,
        reason=Unavailability.INFRA_FAULT,
        detail="sandbox unavailable",
    )


def result(outcome, *, snapshot, implementation=IMPL_SUBPROCESS, check=CHECK_EXECUTABLE_CASES):
    return BoundResult(
        check_id=check,
        snapshot_digest=snapshot_digest(snapshot),
        implementation=implementation,
        outcome=outcome,
    )


# ===========================================================================
# The enforcement table, row by row
# ===========================================================================


def test_row_valid_bound_satisfactory_result_satisfies_the_requirement():
    snapshot = a_snapshot()
    outcome = validate_coverage(snapshot, [result(evidence(Verdict.PASS), snapshot=snapshot)])
    assert isinstance(outcome, CoverageSatisfied)
    assert outcome.answered_by == {CHECK_EXECUTABLE_CASES: IMPL_SUBPROCESS}
    assert outcome.recorded_unavailable == ()


def test_row_fail_refuses_authorization():
    snapshot = a_snapshot()
    outcome = validate_coverage(snapshot, [result(evidence(Verdict.FAIL), snapshot=snapshot)])
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_UNSATISFACTORY
    assert outcome.check_id == CHECK_EXECUTABLE_CASES


def test_row_abstain_refuses_and_is_preserved_as_an_abstention():
    """An abstention means the check RAN and reached no conclusion. Flattening
    it into 'incomplete' would lose an operationally different situation."""

    snapshot = a_snapshot()
    outcome = validate_coverage(snapshot, [result(evidence(Verdict.ABSTAIN), snapshot=snapshot)])
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_ABSTAINED
    assert outcome.reason != REFUSED_INCOMPLETE
    assert "abstent" in outcome.detail


def test_row_unavailable_refuses_as_incomplete():
    snapshot = a_snapshot()
    outcome = validate_coverage(snapshot, [result(unavailable(), snapshot=snapshot)])
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_INCOMPLETE


def test_row_missing_refuses_as_incomplete():
    """THE ESSENTIAL SHAPE. No result at all for a required check — which is what
    a swallowed exception, a timeout, or an omitted plan entry all look like from
    here — refuses on the same row as an explicit outage."""

    snapshot = a_snapshot()
    outcome = validate_coverage(snapshot, [])
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_INCOMPLETE


def test_row_wrong_attempt_binding_refuses_as_invalid_evidence():
    """One digest commits to policy, artifact, target, action and attempt, so a
    result for a different attempt is caught by one comparison."""

    snapshot = a_snapshot()
    other = resolve(
        load_profile("baseline"),
        artifact_sha256=ARTIFACT,
        target_canonical=TARGET,
        action_class="sandbox.execute",
        attempt_id="attempt-9999",
    )
    stale = result(evidence(Verdict.PASS), snapshot=other)
    outcome = validate_coverage(snapshot, [stale])
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_INVALID_EVIDENCE


@pytest.mark.parametrize(
    "field,value",
    [
        ("artifact_sha256", "d" * 64),
        ("target_canonical", '{"host":"other.internal","dbname":"appdb"}'),
        ("action_class", "database.migrate"),
    ],
)
def test_row_wrong_artifact_target_or_action_binding_refuses(field, value):
    snapshot = a_snapshot()
    kwargs = dict(
        artifact_sha256=ARTIFACT,
        target_canonical=TARGET,
        action_class="sandbox.execute",
        attempt_id=ATTEMPT,
    )
    kwargs[field] = value
    other = resolve(load_profile("baseline"), **kwargs)
    outcome = validate_coverage(snapshot, [result(evidence(Verdict.PASS), snapshot=other)])
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_INVALID_EVIDENCE


def test_row_wrong_policy_binding_refuses_as_invalid_evidence():
    snapshot = a_snapshot()
    other = a_snapshot(policy=two_permitted_policy())
    outcome = validate_coverage(snapshot, [result(evidence(Verdict.PASS), snapshot=other)])
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_INVALID_EVIDENCE


def test_row_a_result_claiming_one_implementation_with_anothers_evidence_refuses():
    """A caller must not be able to name a permitted implementation while
    presenting work done by something else."""

    snapshot = a_snapshot()
    mislabelled = BoundResult(
        check_id=CHECK_EXECUTABLE_CASES,
        snapshot_digest=snapshot_digest(snapshot),
        implementation=IMPL_SUBPROCESS,
        outcome=evidence(Verdict.PASS, verifier_id="something-else"),
    )
    outcome = validate_coverage(snapshot, [mislabelled])
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_INVALID_EVIDENCE
    assert "names one implementation" in outcome.detail


def test_row_duplicates_refuse_and_never_count_toward_coverage():
    """Two reports from the SAME implementation for one requirement cannot both
    be the answer, and picking either is a choice nothing authorised."""

    snapshot = a_snapshot()
    once = result(evidence(Verdict.PASS), snapshot=snapshot)
    outcome = validate_coverage(snapshot, [once, once])
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_AMBIGUOUS


def test_row_conflicting_results_refuse_ambiguity():
    """Two DIFFERENT permitted implementations reaching different verdicts means
    the operator's R4 equivalence assertion is wrong. Refusing is the only
    honest reading; preferring one would be a policy nobody wrote."""

    snapshot = a_snapshot(policy=two_permitted_policy())
    outcome = validate_coverage(
        snapshot,
        [
            result(evidence(Verdict.PASS), snapshot=snapshot),
            result(
                evidence(Verdict.FAIL, verifier_id=IMPL_SIBLING),
                snapshot=snapshot,
                implementation=IMPL_SIBLING,
            ),
        ],
    )
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_AMBIGUOUS
    assert "different verdicts" in outcome.detail


# ===========================================================================
# The R3 boundary — the line between this design and quorum
# ===========================================================================


def test_r3_two_permitted_one_unavailable_the_other_satisfactory_is_SATISFIED():
    """Nothing is absent: the requirement was never keyed to one implementation.
    And the record shows WHICH one answered, which is R4's control."""

    snapshot = a_snapshot(policy=two_permitted_policy())
    outcome = validate_coverage(
        snapshot,
        [
            result(unavailable(), snapshot=snapshot),
            result(
                evidence(Verdict.PASS, verifier_id=IMPL_SIBLING),
                snapshot=snapshot,
                implementation=IMPL_SIBLING,
            ),
        ],
    )
    assert isinstance(outcome, CoverageSatisfied)
    assert outcome.answered_by == {CHECK_EXECUTABLE_CASES: IMPL_SIBLING}
    # The outage is RECORDED and irrelevant — it neither satisfied nor blocked.
    assert outcome.recorded_unavailable == ((CHECK_EXECUTABLE_CASES, IMPL_SUBPROCESS),)


def test_r3_both_permitted_unavailable_REFUSES():
    """THE LINE. If two-permitted-one-unavailable ever read as 'covered', that
    would be quorum wearing this design's clothes. Absence never satisfies,
    however many implementations were permitted."""

    snapshot = a_snapshot(policy=two_permitted_policy())
    outcome = validate_coverage(
        snapshot,
        [
            result(unavailable(), snapshot=snapshot),
            result(
                unavailable(verifier_id=IMPL_SIBLING),
                snapshot=snapshot,
                implementation=IMPL_SIBLING,
            ),
        ],
    )
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_INCOMPLETE


def test_r3_one_permitted_unavailable_with_no_other_result_REFUSES():
    snapshot = a_snapshot()
    outcome = validate_coverage(snapshot, [result(unavailable(), snapshot=snapshot)])
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_INCOMPLETE


def test_r3_a_satisfactory_result_from_an_unpermitted_implementation_is_invalid():
    snapshot = a_snapshot()
    outcome = validate_coverage(
        snapshot,
        [
            BoundResult(
                check_id=CHECK_EXECUTABLE_CASES,
                snapshot_digest=snapshot_digest(snapshot),
                implementation=IMPL_SIBLING,
                outcome=evidence(Verdict.PASS, verifier_id=IMPL_SIBLING),
            )
        ],
    )
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_INVALID_EVIDENCE
    assert "not a permitted implementation" in outcome.detail


def test_r3_the_permitted_set_size_never_appears_in_the_decision():
    """A behavioural statement of the ruling: growing the permitted set without
    adding a RESULT changes nothing. If size were doing any work, it would."""

    one = a_snapshot()
    two = a_snapshot(policy=two_permitted_policy())
    assert isinstance(validate_coverage(one, []), CoverageRefused)
    assert isinstance(validate_coverage(two, []), CoverageRefused)
    assert (
        validate_coverage(one, []).reason == validate_coverage(two, []).reason
    ), "the size of the permitted set changed the outcome"


# ===========================================================================
# The R4 residuals, as passing tests
# ===========================================================================


def test_r4_residual_equivalence_of_permitted_implementations_is_asserted_not_verified():
    """NAMED, not hidden. Nothing checks that two permitted implementations are
    equally strong; the operator asserts it by naming them in the policy.

    What IS true, and is the managed part: the record shows which one answered,
    so a reviewer can see that A was down and B answered.
    """

    snapshot = a_snapshot(policy=two_permitted_policy())
    weak = validate_coverage(
        snapshot,
        [
            result(unavailable(), snapshot=snapshot),
            result(
                evidence(Verdict.PASS, verifier_id=IMPL_SIBLING),
                snapshot=snapshot,
                implementation=IMPL_SIBLING,
            ),
        ],
    )
    assert isinstance(weak, CoverageSatisfied)
    # Nothing anywhere compared the two implementations' strength.
    assert weak.answered_by[CHECK_EXECUTABLE_CASES] == IMPL_SIBLING
    assert (CHECK_EXECUTABLE_CASES, IMPL_SUBPROCESS) in weak.recorded_unavailable


def test_r4_residual_an_attacker_downing_the_stronger_gets_the_weaker_to_answer():
    """Inherent to permitting more than one. The policy NAMING them is the
    auditable control, and this test records that the exposure is real rather
    than implying it is closed.

    The control that does hold: the same attacker cannot get coverage with NO
    answer, which is the test directly above this one.
    """

    snapshot = a_snapshot(policy=two_permitted_policy())
    attacked = validate_coverage(
        snapshot,
        [
            result(unavailable(), snapshot=snapshot),
            result(
                evidence(Verdict.PASS, verifier_id=IMPL_SIBLING),
                snapshot=snapshot,
                implementation=IMPL_SIBLING,
            ),
        ],
    )
    assert isinstance(attacked, CoverageSatisfied), (
        "this is the residual, and it is expected to hold: downing the stronger "
        "implementation lets the weaker one answer"
    )
    both_down = validate_coverage(
        snapshot,
        [
            result(unavailable(), snapshot=snapshot),
            result(
                unavailable(verifier_id=IMPL_SIBLING),
                snapshot=snapshot,
                implementation=IMPL_SIBLING,
            ),
        ],
    )
    assert isinstance(both_down, CoverageRefused), (
        "the residual does NOT extend to satisfying a requirement with no answer"
    )


# ===========================================================================
# The bank's authorization-capable entry point
# ===========================================================================


def _bank() -> VerifierBank:
    bank = VerifierBank()
    bank.register(IMPL_SUBPROCESS, Tier.HARD)
    bank.register(IMPL_SIBLING, Tier.HARD)
    return bank


def test_bank_refuses_before_fusing_when_a_required_check_is_missing():
    snapshot = a_snapshot()
    outcome = _bank().judge_covered(snapshot, [])
    assert isinstance(outcome, Unavailable)
    assert outcome.reason == Unavailability.INFRA_FAULT
    assert not hasattr(outcome, "verdict"), "an Unavailable must carry no verdict"


def test_bank_reports_a_failed_required_check_as_a_failure_not_an_outage():
    """A FAIL is a real answer. Reporting it as unavailable would lose that the
    check ran and said no."""

    snapshot = a_snapshot()
    outcome = _bank().judge_covered(
        snapshot, [result(evidence(Verdict.FAIL), snapshot=snapshot)]
    )
    assert isinstance(outcome, Judgment)
    assert outcome.verdict == Verdict.FAIL
    assert outcome.authoritative is True


@pytest.mark.parametrize(
    "results_factory,expected_reason",
    [
        (lambda s: [result(evidence(Verdict.ABSTAIN), snapshot=s)], Unavailability.POLICY_REFUSAL),
        (lambda s: [result(unavailable(), snapshot=s)], Unavailability.INFRA_FAULT),
        (lambda s: [], Unavailability.INFRA_FAULT),
    ],
)
def test_bank_returns_unavailable_for_every_non_failure_refusal(results_factory, expected_reason):
    snapshot = a_snapshot()
    outcome = _bank().judge_covered(snapshot, results_factory(snapshot))
    assert isinstance(outcome, Unavailable)
    assert outcome.reason == expected_reason


def test_bank_fuses_normally_once_coverage_holds():
    """Fusion behaviour for what survives is UNCHANGED — this adds a gate in
    front of it, it does not re-tune it."""

    snapshot = a_snapshot()
    passing = evidence(Verdict.PASS)

    covered = _bank().judge_covered(snapshot, [result(passing, snapshot=snapshot)])
    direct = _bank().judge([passing])

    assert isinstance(covered, Judgment) and isinstance(direct, Judgment)
    assert covered.verdict == direct.verdict == Verdict.PASS
    assert covered.authoritative is direct.authoritative is True
    assert covered.confidence == pytest.approx(direct.confidence)


def test_bank_refuses_a_hard_pass_beside_an_unavailable_that_covered_a_requirement():
    """The second reproduced fail-open, at the bank.

    A HARD PASS alongside a HARD Unavailable returned an authoritative PASS with
    the outage kept only as metadata. That is CORRECT when the two are redundant
    and either suffices. It is a fail-open when the unavailable one was the only
    permitted implementation for a requirement — and now those are different
    outcomes, because the policy says which case it is.
    """

    # The unavailable one covers the requirement; the passing one is a different
    # check nobody required. Coverage refuses.
    snapshot = a_snapshot()
    unrelated = BoundResult(
        check_id="structural.predicates",
        snapshot_digest=snapshot_digest(snapshot),
        implementation="swarm-checks",
        outcome=evidence(Verdict.PASS, verifier_id="swarm-checks"),
    )
    refused = _bank().judge_covered(
        snapshot, [result(unavailable(), snapshot=snapshot), unrelated]
    )
    assert isinstance(refused, Unavailable), (
        "a passing unrequired check must not stand in for a required one"
    )

    # Redundant case: two permitted, one down, the other passed. Still a PASS,
    # because nothing is absent.
    redundant = a_snapshot(policy=two_permitted_policy())
    allowed = _bank().judge_covered(
        redundant,
        [
            result(unavailable(), snapshot=redundant),
            result(
                evidence(Verdict.PASS, verifier_id=IMPL_SIBLING),
                snapshot=redundant,
                implementation=IMPL_SIBLING,
            ),
        ],
    )
    assert isinstance(allowed, Judgment)
    assert allowed.verdict == Verdict.PASS


# ===========================================================================
# The fail-open found while building this, pinned so it cannot come back
# ===========================================================================


def test_an_unrequired_failing_check_is_fused_not_dropped():
    """A REGRESSION for a fail-open introduced and caught during this sprint.

    An earlier draft skipped results for unrequired checks while validating, and
    then built the fusible set from required results only. A failing structural
    check — which policy does not require — was therefore DISCARDED whenever the
    required check happened to pass, turning a FAIL into an authoritative PASS.

    Coverage decides WHETHER to fuse. It does not get to decide what the fusion
    is allowed to see.
    """

    snapshot = a_snapshot()
    required_pass = result(evidence(Verdict.PASS), snapshot=snapshot)
    unrequired_fail = BoundResult(
        check_id="structural.predicates",
        snapshot_digest=snapshot_digest(snapshot),
        implementation="swarm-checks",
        outcome=evidence(Verdict.FAIL, verifier_id="swarm-checks"),
    )

    covered = validate_coverage(snapshot, [required_pass, unrequired_fail])
    assert isinstance(covered, CoverageSatisfied)
    assert unrequired_fail.outcome in covered.graded, "the failing check was dropped"

    # And its effect is VISIBLE in the judgment. What the bank then does with a
    # HARD disagreement — PASS at confidence 0.5 with ``conflict`` set, which the
    # gate routes to a human — is pre-existing fusion behaviour this sprint does
    # not re-tune. The property under test is that the failing result reaches
    # fusion at all: dropped, it would produce a clean confident PASS with no
    # conflict flagged and nothing to route.
    fused = _bank().judge_covered(snapshot, [required_pass, unrequired_fail])
    assert isinstance(fused, Judgment)
    assert fused.conflict is True, "the disagreement was not seen"
    assert fused.confidence == pytest.approx(0.5)

    dropped = _bank().judge_covered(snapshot, [required_pass])
    assert dropped.conflict is False and dropped.confidence > 0.5, (
        "control: with the failing check absent the judgment is clean and "
        "confident, which is exactly what the fail-open produced"
    )


def test_an_unrequired_result_with_a_bad_binding_is_still_invalid_evidence():
    """Binding is checked for EVERY result, not only required ones: a result
    claiming to answer this attempt while bound to another is invalid however
    little the policy asked of it."""

    snapshot = a_snapshot()
    other = resolve(
        load_profile("baseline"),
        artifact_sha256=ARTIFACT,
        target_canonical=TARGET,
        action_class="sandbox.execute",
        attempt_id="attempt-9999",
    )
    stale_unrequired = BoundResult(
        check_id="structural.predicates",
        snapshot_digest=snapshot_digest(other),
        implementation="swarm-checks",
        outcome=evidence(Verdict.PASS, verifier_id="swarm-checks"),
    )
    outcome = validate_coverage(
        snapshot, [result(evidence(Verdict.PASS), snapshot=snapshot), stale_unrequired]
    )
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_INVALID_EVIDENCE


# ===========================================================================
# The resolver: requirements come from the policy, never from the plan
# ===========================================================================


def test_the_resolver_refuses_an_action_class_the_policy_does_not_cover():
    """Silence is not permission."""

    from prometheus_protocol.policy.resolver import ResolutionRefused

    narrow = VerificationPolicy(
        policy_id="sandbox-only",
        version=1,
        requirements=(
            PolicyRequirement(
                check_id=CHECK_EXECUTABLE_CASES,
                permitted=(IMPL_SUBPROCESS,),
                applies_to=("sandbox.execute",),
            ),
        ),
        require_verification=("sandbox.execute",),
    )
    with pytest.raises(ResolutionRefused, match="does not cover"):
        resolve(
            narrow,
            artifact_sha256=ARTIFACT,
            target_canonical=TARGET,
            action_class="database.migrate",
            attempt_id=ATTEMPT,
        )


def test_an_untrusted_request_can_only_ADD():
    """A requested check that collides with a policy requirement is refused
    rather than merged: merging is where a downgrade would hide, because any
    widening of the policy's permitted set would be a weakening performed by
    untrusted input."""

    from prometheus_protocol.policy.resolver import ResolutionRefused
    from prometheus_protocol.policy.snapshot import BoundRequirement

    # Adding is fine, and the addition is recorded.
    added = resolve(
        load_profile("baseline"),
        artifact_sha256=ARTIFACT,
        target_canonical=TARGET,
        action_class="sandbox.execute",
        attempt_id=ATTEMPT,
        requested_checks=(
            BoundRequirement(check_id="extra.lint", permitted=("linter",)),
        ),
    )
    assert "extra.lint" in added.check_ids
    assert CHECK_EXECUTABLE_CASES in added.check_ids

    # Colliding is refused — including an attempt to widen the permitted set.
    with pytest.raises(ResolutionRefused, match="collides with a policy requirement"):
        resolve(
            load_profile("baseline"),
            artifact_sha256=ARTIFACT,
            target_canonical=TARGET,
            action_class="sandbox.execute",
            attempt_id=ATTEMPT,
            requested_checks=(
                BoundRequirement(
                    check_id=CHECK_EXECUTABLE_CASES,
                    permitted=(IMPL_SUBPROCESS, "anything-i-control"),
                ),
            ),
        )


def test_a_policy_covering_a_class_with_no_requirement_is_refused_at_construction():
    """An empty requirement set is satisfied by anything — the emptiest possible
    fail-open, arrived at by omission rather than by decision."""

    from prometheus_protocol.policy.profile import PolicyError

    with pytest.raises(PolicyError, match="states no requirement"):
        VerificationPolicy(
            policy_id="empty",
            version=1,
            requirements=(
                PolicyRequirement(
                    check_id=CHECK_EXECUTABLE_CASES,
                    permitted=(IMPL_SUBPROCESS,),
                    applies_to=("sandbox.execute",),
                ),
            ),
            require_verification=("sandbox.execute", "database.migrate"),
        )


def test_the_shipped_profile_names_implementations_that_really_exist():
    """A profile naming an id nothing reports would be a permanently
    unsatisfiable requirement, indistinguishable at the bank from a check that
    was omitted."""

    from prometheus_protocol.swarm.runtime import CHECK_VERIFIER_ID
    from prometheus_protocol.tools.git import MERGE_CHECK_VERIFIER_ID
    from prometheus_protocol.verifier.runner import SubprocessVerifier

    assert IMPL_SUBPROCESS == SubprocessVerifier.VERIFIER_ID
    from prometheus_protocol.policy.profile import (
        IMPL_GIT_MERGE_CHECK,
        IMPL_SWARM_STRUCTURAL,
    )

    assert IMPL_SWARM_STRUCTURAL == CHECK_VERIFIER_ID
    # PHASE-1.2b — the merge check became a permitted implementation when
    # ``branch.delete`` became an action class. Read off the implementation, not
    # retyped here, so a rename there fails this rather than silently leaving the
    # profile naming an id nothing reports.
    assert IMPL_GIT_MERGE_CHECK == MERGE_CHECK_VERIFIER_ID

    reporters = {
        SubprocessVerifier.VERIFIER_ID,
        CHECK_VERIFIER_ID,
        MERGE_CHECK_VERIFIER_ID,
    }
    for requirement in load_profile("baseline").requirements:
        for implementation in requirement.permitted:
            assert implementation in reporters, (
                f"{implementation} is permitted but nothing reports under it"
            )
