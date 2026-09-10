"""PHASE-1.2 CHECKPOINT 3 — advisory evidence cannot satisfy a requirement.

WHAT THIS SPRINT TURNED OUT TO BE. The brief asked for the three soft-lever
wrappers to be migrated into the policy path as callers of the one enforced
aggregation rule. The pre-build report answered no to all three gating
questions: no wrapper satisfies a requirement under any shipped policy, no
production path reaches authorization with a wrapper's verdict, and no wrapper is
a permitted implementation anywhere. The only non-test importer of
``verifier/soft_levers.py`` is ``benchmarks/soft_calibration_eval.py``, an
offline ``argparse`` benchmark that never touches a gate, controller, bank
assessment or approval authority.

So the wrappers were not migrated. What was built instead is the structural
non-participation the brief named as the correct smaller sprint — and it is not
vacuous, because the measurement that justified it found something:

    coverage outcome: CoverageSatisfied
    -> SOFT evidence SATISFIES the requirement: True

``validate_coverage`` was tier-blind. That is correct for R2 — what is REQUIRED
is keyed by check identity, never by tier — but it was also applied to the
separate question of what COUNTS as satisfying one, and there it was wrong. A
policy naming any advisory implementation as permitted made advisory evidence
sufficient for coverage. The system stayed fail-closed only because the gate
refuses a non-authoritative judgment: one control, one layer later, and not the
one the policy layer was supposed to be providing.

THE RULE IS OVER WHAT THE EVIDENCE IS, NOT WHAT IT IS CALLED. Two of the three
wrappers derive their identity at construction — ``f"{base}:threshold@{x}"``,
``f"{base}:k{k}-{require}"`` — so any rule over identity strings would be a rule
over spellings, which is the failure already recorded in ``docs/threat-model.md``
(identifier spellings vs symbols). Reading ``Evidence.tier`` covers every
wrapper, every derived identity, and every implementation this package has never
heard of — including a deployment's own, which R1 requires to keep working.
"""

from __future__ import annotations

import pytest

from prometheus_protocol.core.models import (
    AUTHORITATIVE_TIERS,
    Evidence,
    Judgment,
    Tier,
    Unavailability,
    Unavailable,
    Verdict,
)
from prometheus_protocol.policy.coverage import (
    REFUSED_ADVISORY_ONLY,
    REFUSED_INCOMPLETE,
    BoundResult,
    CoverageRefused,
    CoverageSatisfied,
    validate_coverage,
)
from prometheus_protocol.policy.profile import PolicyRequirement, VerificationPolicy
from prometheus_protocol.policy.resolver import resolve
from prometheus_protocol.policy.snapshot import ACTION_SANDBOX_EXECUTE, snapshot_digest
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.store import InMemoryTrustStore

CHECK = "the.requirement"


def a_policy(*permitted: str) -> VerificationPolicy:
    return VerificationPolicy(
        policy_id="p",
        version=1,
        requirements=(
            PolicyRequirement(
                check_id=CHECK, permitted=permitted, applies_to=(ACTION_SANDBOX_EXECUTE,)
            ),
        ),
        require_verification=(ACTION_SANDBOX_EXECUTE,),
    )


def a_snapshot(policy):
    return resolve(
        policy,
        artifact_sha256="a" * 64,
        target_canonical="sandbox://t",
        action_class=ACTION_SANDBOX_EXECUTE,
        attempt_id="attempt-1",
    )


def evidence(implementation: str, tier, verdict: Verdict = Verdict.PASS) -> Evidence:
    return Evidence(
        passed=verdict == Verdict.PASS,
        total=1,
        passed_count=1 if verdict == Verdict.PASS else 0,
        failures=() if verdict == Verdict.PASS else ("no",),
        verifier_id=implementation,
        verdict=verdict,
        tier=tier,
    )


def bind(snapshot, implementation: str, outcome, *, check_id: str = CHECK) -> BoundResult:
    return BoundResult(
        check_id=check_id,
        snapshot_digest=snapshot_digest(snapshot),
        implementation=implementation,
        outcome=outcome,
    )


def cover(*results, policy=None):
    policy = policy if policy is not None else a_policy("impl")
    snapshot = a_snapshot(policy)
    return validate_coverage(snapshot, [r(snapshot) for r in results])


# ===========================================================================
# 1. The rule, over every tier
# ===========================================================================


@pytest.mark.parametrize("tier", [Tier.HARD, Tier.HUMAN])
def test_authoritative_evidence_satisfies(tier):
    """The positive control for the whole file. Without it, "advisory cannot
    satisfy" would pass by nothing ever satisfying."""

    # Named explicitly above rather than iterating AUTHORITATIVE_TIERS, so the
    # parametrisation cannot silently shrink if that set ever does — and the
    # next line is what ties the two together.
    assert {Tier.HARD, Tier.HUMAN} == set(AUTHORITATIVE_TIERS)

    outcome = cover(lambda s: bind(s, "impl", evidence("impl", tier)))
    assert isinstance(outcome, CoverageSatisfied)
    assert outcome.answered_by == {CHECK: "impl"}


def test_advisory_evidence_does_not_satisfy():
    outcome = cover(lambda s: bind(s, "impl", evidence("impl", Tier.SOFT)))
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_ADVISORY_ONLY
    assert outcome.check_id == CHECK


def test_a_missing_tier_fails_closed():
    """``Evidence.tier`` is optional and the bank resolves it from the trust
    store at fusion time. Coverage holds no store, so a missing tier is a tier it
    could not establish — and could-not-establish is never established."""

    outcome = cover(lambda s: bind(s, "impl", evidence("impl", None)))
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_ADVISORY_ONLY


def test_the_refusal_names_the_implementation_not_the_evidence_text():
    """The bounded-diagnostic discipline: it says which implementation, never
    what the verifier reported."""

    outcome = cover(lambda s: bind(s, "impl", evidence("impl", Tier.SOFT)))
    assert "impl" in outcome.detail
    assert "advisory" in outcome.detail


# ===========================================================================
# 2. The three wrappers, by what their evidence IS
# ===========================================================================


def _wrapper_evidence(wrapper):
    """Run a wrapper over a stub judge and take the Evidence it really emits."""

    from prometheus_protocol.core.models import Task

    task = Task(id="t", entry_point="f", prompt="p", split="train", cases=())
    return wrapper.verify(code="x", task=task)


class _StubJudge:
    verifier_id = "stub-judge"
    tier = Tier.SOFT

    def __init__(self, verdict=Verdict.PASS):
        self._verdict = verdict

    def verify(self, *, code, task):
        return evidence(self.verifier_id, Tier.SOFT, self._verdict)


def _wrappers():
    from prometheus_protocol.verifier.soft_levers import (
        ConfidenceThresholdJudge,
        EnsembleJudge,
        RepeatedSamplingJudge,
    )

    return [
        (
            "ConfidenceThresholdJudge",
            ConfidenceThresholdJudge(
                _StubJudge(),
                min_confidence=0.0,
                # Reads nothing out of the detail: the threshold is 0.0, so the
                # judge's PASS survives. This fixture is about the TIER of what
                # the wrapper emits, not about its parsing.
                confidence_parser=lambda _detail: 1.0,
            ),
        ),
        ("EnsembleJudge", EnsembleJudge([_StubJudge(), _StubJudge(), _StubJudge()])),
        ("RepeatedSamplingJudge", RepeatedSamplingJudge(_StubJudge(), k=3, require="unanimous")),
    ]


@pytest.mark.parametrize("name,wrapper", _wrappers(), ids=[n for n, _ in _wrappers()])
def test_no_wrapper_can_satisfy_a_requirement_even_when_permitted(name, wrapper):
    """THE STRUCTURAL NON-PARTICIPATION, proven per wrapper.

    The policy here PERMITS the wrapper by its own reported identity — the most
    favourable case an operator could construct for it — and it still cannot
    satisfy, because what it emits is advisory. No identity string appears in the
    rule, so a wrapper's derived id cannot route around it.
    """

    emitted = _wrapper_evidence(wrapper)
    assert isinstance(emitted, Evidence)
    assert emitted.tier == Tier.SOFT
    assert emitted.decided == Verdict.PASS, "the fixture must produce a PASS to be a real test"

    policy = a_policy(emitted.verifier_id)
    outcome = cover(
        lambda s: bind(s, emitted.verifier_id, emitted), policy=policy
    )
    assert isinstance(outcome, CoverageRefused), name
    assert outcome.reason == REFUSED_ADVISORY_ONLY, name


@pytest.mark.parametrize("name,wrapper", _wrappers(), ids=[n for n, _ in _wrappers()])
def test_each_wrapper_still_works_as_advisory_calibration(name, wrapper):
    """THE POSITIVE CONTROL, per wrapper. With every judge reachable and
    agreeing, the wrapper still produces its verdict and that verdict still
    reaches fusion as an UNREQUIRED result. Breaking all three would otherwise
    satisfy every refusal above."""

    emitted = _wrapper_evidence(wrapper)
    assert emitted.decided == Verdict.PASS, name
    assert emitted.tier == Tier.SOFT, name

    # Bound to a check nothing requires: validated, fused, irrelevant to coverage.
    policy = a_policy("hard-impl")
    snapshot = a_snapshot(policy)
    outcome = validate_coverage(snapshot, [
        bind(snapshot, "hard-impl", evidence("hard-impl", Tier.HARD)),
        bind(snapshot, emitted.verifier_id, emitted, check_id="advisory.check"),
    ])
    assert isinstance(outcome, CoverageSatisfied), name
    assert outcome.answered_by == {CHECK: "hard-impl"}
    assert emitted in outcome.graded, (
        f"{name}: the advisory result was DROPPED rather than fused. Advisory "
        "evidence does not satisfy, but it must still inform confidence."
    )


# ===========================================================================
# 3. The existing unavailability property, re-proven post-change
# ===========================================================================


class _UnavailableJudge:
    verifier_id = "down-judge"
    tier = Tier.SOFT

    def verify(self, *, code, task):
        return Unavailable(
            verifier_id=self.verifier_id, tier=Tier.SOFT,
            reason=Unavailability.INFRA_FAULT, detail="down",
        )


@pytest.mark.parametrize("name", ["EnsembleJudge", "RepeatedSamplingJudge"])
def test_partial_unavailability_is_still_not_unanimous(name):
    """TYPE-GATE's property, unchanged by this sprint and re-proven here: a
    partially-unavailable ensemble is still not unanimous, so the reachable
    judges cannot decide on the quorum's behalf. Nothing in CHECKPOINT 3 touched
    the wrappers' internals; this asserts that is still true."""

    from prometheus_protocol.verifier.soft_levers import EnsembleJudge, RepeatedSamplingJudge

    if name == "EnsembleJudge":
        wrapper = EnsembleJudge([_StubJudge(), _UnavailableJudge(), _StubJudge()])
    else:
        wrapper = RepeatedSamplingJudge(_UnavailableJudge(), k=3, require="unanimous")

    emitted = _wrapper_evidence(wrapper)
    assert isinstance(emitted, Unavailable), (
        f"{name}: a verdict was computed from the reachable judges"
    )
    assert not hasattr(emitted, "verdict")


def test_an_unavailable_wrapper_cannot_satisfy_either():
    """R3's line at the wrapper layer: an ensemble whose members are unavailable
    has produced NO result, and the reachable members do not decide on the
    quorum's behalf. It refuses as incomplete — never as satisfied."""

    from prometheus_protocol.verifier.soft_levers import EnsembleJudge

    wrapper = EnsembleJudge([_StubJudge(), _UnavailableJudge(), _StubJudge()])
    emitted = _wrapper_evidence(wrapper)
    policy = a_policy(emitted.verifier_id)
    outcome = cover(lambda s: bind(s, emitted.verifier_id, emitted), policy=policy)
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_INCOMPLETE


# ===========================================================================
# 4. R3's line: an acceptance condition can never satisfy without a result
# ===========================================================================


def test_no_acceptance_condition_can_satisfy_without_a_result():
    """The closed acceptance set is what makes this checkable rather than
    argued: there is no ``ANY_RESULT`` and no ``BEST_EFFORT`` to reach for."""

    from prometheus_protocol.policy.profile import ACCEPTANCE_CONDITIONS, ACCEPT_PASS

    assert ACCEPTANCE_CONDITIONS == {ACCEPT_PASS}, (
        "an acceptance condition was added. Any condition satisfiable without a "
        "satisfactory result is quorum or substitution, both deferred by ruling."
    )
    # And with no result at all, every requirement refuses regardless.
    outcome = cover(policy=a_policy("impl"))
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_INCOMPLETE


def test_advisory_plus_unavailable_authoritative_still_refuses():
    """The R4 residual's worst case, at this layer: the strong implementation is
    down and a permitted advisory one answered. It must not stand in."""

    policy = a_policy("hard-impl", "soft-impl")
    outcome = cover(
        lambda s: bind(s, "hard-impl", Unavailable(
            verifier_id="hard-impl", tier=Tier.HARD,
            reason=Unavailability.INFRA_FAULT, detail="down")),
        lambda s: bind(s, "soft-impl", evidence("soft-impl", Tier.SOFT)),
        policy=policy,
    )
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_ADVISORY_ONLY


# ===========================================================================
# 5. End to end, through the bank
# ===========================================================================


def test_the_bank_reports_an_advisory_only_requirement_as_unavailable():
    """Not as a FAIL: nothing failed. The required check has no authoritative
    answer, which is a could-not-verify, and EX-1 says that is never a verdict."""

    policy = a_policy("soft-impl")
    snapshot = a_snapshot(policy)
    bank = VerifierBank(InMemoryTrustStore())
    outcome = bank.assess(snapshot, [
        bind(snapshot, "soft-impl", evidence("soft-impl", Tier.SOFT))
    ]).outcome
    assert isinstance(outcome, Unavailable)
    assert not hasattr(outcome, "verdict")
    assert outcome.reason == Unavailability.POLICY_REFUSAL


def test_the_bank_still_authorizes_a_properly_covered_action():
    """The end-to-end positive control."""

    policy = a_policy("hard-impl")
    snapshot = a_snapshot(policy)
    bank = VerifierBank(InMemoryTrustStore())
    outcome = bank.assess(snapshot, [
        bind(snapshot, "hard-impl", evidence("hard-impl", Tier.HARD))
    ]).outcome
    assert isinstance(outcome, Judgment)
    assert outcome.verdict == Verdict.PASS and outcome.authoritative


# ===========================================================================
# 6. The residual, recorded rather than implied
# ===========================================================================


class TestTheTierClaimResidual:
    """The rule reads the tier the evidence REPORTS. That is what makes it work
    for derived identities and unknown implementations, and it is therefore only
    as good as the report. Both halves measured, neither hidden.

    NOT NEW TO THIS SPRINT: the bank has always seeded an unknown verifier's tier
    from its first evidence. What changed is that the tier is now load-bearing in
    one more place, so the residual is worth a test that states it.
    """

    def _lying(self):
        return evidence("liar", Tier.HARD)  # a SOFT implementation claiming HARD

    def test_a_REGISTERED_verifier_cannot_lie_about_its_tier(self):
        """The control. The bank refuses evidence contradicting the stored tier,
        loudly, rather than silently re-weighting it."""

        policy = a_policy("liar")
        snapshot = a_snapshot(policy)
        bank = VerifierBank(InMemoryTrustStore())
        bank.register("liar", Tier.SOFT)
        with pytest.raises(ValueError, match="a verifier's tier is fixed"):
            bank.assess(snapshot, [bind(snapshot, "liar", self._lying())])

    def test_an_UNREGISTERED_verifier_is_believed_and_this_is_the_residual(self):
        """The gap, recorded. Registration is the control, and it is the
        deployment's responsibility — exactly like constructing a result for
        every check it ran."""

        policy = a_policy("liar")
        snapshot = a_snapshot(policy)
        bank = VerifierBank(InMemoryTrustStore())  # deliberately not registered
        outcome = bank.assess(snapshot, [bind(snapshot, "liar", self._lying())]).outcome
        assert isinstance(outcome, Judgment) and outcome.authoritative, (
            "if this now refuses, the residual is closed — say so and delete this "
            "test in the same change"
        )

    def test_coverage_holds_no_trust_store(self):
        """Why the residual is not closed HERE. Reaching for a store would make
        the coverage decision depend on mutable calibration state; coverage
        validates the evidence it is given."""

        import ast
        import inspect

        from prometheus_protocol.policy import coverage

        # Over IMPORTS, not over the word "trust" appearing in prose — the
        # docstrings discuss trusted callers at length, and a substring rule
        # would be a rule over spellings.
        tree = ast.parse(inspect.getsource(coverage))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.update(f"{node.module}.{a.name}" for a in node.names)
            elif isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
        assert not any("verifier.store" in name or "TrustStore" in name for name in imported), (
            f"coverage reached for a trust store: {sorted(imported)}"
        )

    def test_the_docs_state_the_residual(self):
        import inspect

        from prometheus_protocol.policy import coverage

        doc = coverage.__doc__ or ""
        assert "CLAIMS a tier it does not have" in doc
        assert "Registration is the control" in doc
