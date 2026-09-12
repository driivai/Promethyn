"""The only thing that authorizes: a policy-evaluated, action-bound assessment.

WHAT THIS CLOSES. Checkpoint 2 built requirement coverage and then named its own
exposure rather than implying it away: a raw authoritative ``Judgment`` still
authorized. ``ActionGate.decide``, ``ExecutionController.submit``,
``ActionGateway.route_action`` and ``ApprovalAuthority.authorize`` all took a
``Judgment`` and asked it one question — is this an authoritative PASS — which a
``Judgment`` can answer without any policy ever having been resolved. So the
system was policy-enforced on the paths that had migrated and unenforced
everywhere else, which is the shape of claim this repository keeps having to
correct.

THE CHANGE IS A TYPE, NOT A CHECK. The authorization surfaces no longer accept a
``Judgment`` at all. They accept a :class:`PolicyAssessment`, which carries the
resolved :class:`~prometheus_protocol.policy.snapshot.BoundRequirements` digest
the decision is bound to *and* the outcome coverage validation produced. A raw
``Judgment`` is not one and cannot be made into one by any public call: it is
not "presented and rejected", it is unable to be presented.

HOW STRUCTURAL THAT ACTUALLY IS — stated plainly, because overclaiming here is
exactly the failure this repository keeps correcting.

* At the INTERFACE it is a construction OF THE TYPE. No authorization surface
  has a parameter that takes a ``Judgment``. Checkpoint B adds the content
  enforcement: ``VerifierBank.assess`` re-resolves the configured policy before
  minting, and ``ExecutionAuthorizer`` compares this assessment with the concrete
  action, trusted target and mandatory attempt before producing the object an
  executor accepts.
* The human path consumes that same object. ``PendingActionService.hold`` refuses
  a bare ``GateDecision`` and persists the validated binding; reload, approval
  and retry re-resolve the selected policy before execution. A human resolves a
  risk decision and has no API that manufactures completion of a required check.
* At the CONSTRUCTOR it is a guard, not a construction. :class:`PolicyAssessment`
  refuses to be built except through :func:`mint`, which the bank calls after
  coverage has been validated. In-process Python can still reach past that —
  ``object.__setattr__``, importing :data:`_MINT` directly, or rebuilding the
  dataclass field by field. That is the same residual class as ``frozen=True``
  and it is named here rather than left to be discovered: **the control against
  arbitrary in-process code is the process boundary, not this module.**

WHAT AN ASSESSMENT DOES NOT PROMISE. It says a policy was resolved for THIS
action and coverage was validated against it. It does not say the policy was a
good one, that the permitted implementations are equivalent (R4), or that the
caller constructed a result for every check it actually ran — coverage validates
the evidence it is GIVEN, and caller completeness stays the caller's contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from prometheus_protocol.core.models import Judgment, Unavailable
from prometheus_protocol.policy.coverage import CoverageRefused, CoverageSatisfied
from prometheus_protocol.policy.snapshot import (
    BoundRequirements,
    _identity,
    snapshot_digest,
)


@dataclass(frozen=True)
class CoverageReport:
    """What coverage validation produced, carried on the assessment for the
    authorization record (R6).

    ``CoverageSatisfied`` carries ``answered_by`` and ``recorded_unavailable``
    and ``judge_covered`` used to drop both, passing only the graded results on
    to fusion — measured: ``answered_by == {"check.a": "impl-weak"}`` at the
    coverage layer and nothing downstream, so a reviewer could see that B
    answered and never that A was down. This is the report, kept.

    ``answered_by`` names WHICH permitted implementation satisfied each
    requirement; ``unavailable`` names the permitted implementations that could
    not answer (the R4 residual made visible); ``refusal`` is the enforcement
    row that refused, when one did. ``recorded`` is False only for an assessment
    minted around a caller-named outcome with no coverage validation behind it
    — the in-process test forge — so a record can say "no coverage report was
    recorded" rather than carry an empty one that reads as "nothing was
    unavailable".
    """

    answered_by: tuple[tuple[str, str], ...] = ()
    unavailable: tuple[tuple[str, str], ...] = ()
    refusal: tuple[str, str, str] | None = None
    recorded: bool = True


#: The report of an assessment minted with no coverage validation behind it.
UNRECORDED_COVERAGE = CoverageReport(recorded=False)


def coverage_report(outcome: CoverageSatisfied | CoverageRefused) -> CoverageReport:
    """The report for what ``validate_coverage`` returned."""

    if isinstance(outcome, CoverageRefused):
        return CoverageReport(
            refusal=(outcome.reason, outcome.check_id, outcome.detail),
        )
    return CoverageReport(
        answered_by=tuple(sorted(outcome.answered_by.items())),
        unavailable=tuple(outcome.recorded_unavailable),
    )


class UnboundAuthorization(Exception):
    """Something that is not a policy-evaluated assessment reached authorization.

    Raised rather than returned. A refusal that a caller could mistake for "not
    approved" would put an unbound judgment back on the authorization path with
    a falsy value standing in for a policy decision, and the whole point is that
    there is no policy decision to stand in for.
    """


#: The minting token. Module-private and passed positionally, so a
#: ``PolicyAssessment(...)`` written anywhere else raises. It is not a security
#: boundary — see the module docstring — it is what makes an accidental
#: construction impossible and a deliberate one a visible, greppable act that
#: the 2d sweep can police.
_MINT = object()


@dataclass(frozen=True)
class PolicyAssessment:
    """A coverage-validated outcome, DESCRIBING the action it was resolved for.

    The description is the snapshot digest, exactly as in
    :class:`~prometheus_protocol.policy.coverage.BoundResult`: one value already
    committing to the policy, the policy's content, the artifact, the canonical
    target, the action class and the verification attempt.

    ENFORCEMENT. The assessment alone describes what the bank assessed. It
    becomes authority only through ``ExecutionAuthorizer``, which re-resolves the
    configured policy for the concrete action, trusted target and attempt, then
    compares the snapshot digest and every identifying field. The resulting
    ``AuthorizedExecution`` — not this value alone — is what action decisions,
    holds and executors require.
    """

    #: The snapshot this assessment answers, in one value. Note that the
    #: snapshot itself is NOT carried: a holder of this assessment cannot
    #: re-derive which requirements were resolved, only that some set digesting
    #: to this value was. ExecutionAuthorizer compares it with a fresh resolve.
    snapshot_digest: str
    #: Carried for the audit record, all of it already committed to by the
    #: digest above. Kept as fields so a reader of a recorded decision does not
    #: have to hold the snapshot to know what was assessed. The execution descriptor
    #: and pending hold persist these identities.
    policy_id: str
    policy_digest: str
    action_class: str
    attempt_id: str
    artifact_sha256: str
    target_canonical: str
    #: What coverage validation produced. A ``Judgment`` when coverage held (or
    #: when a required check FAILED — a failure is a real answer); an
    #: ``Unavailable`` when there was no satisfactory result for a required
    #: check. Never a fabricated verdict.
    outcome: Judgment | Unavailable
    #: What coverage validation produced (R6): which implementation answered
    #: each requirement, which could not, and the refusing row if any. Carried
    #: so the authorization record can say it; it decides nothing here. The
    #: default is the explicit "unrecorded" report, so a direct construction
    #: still reaches the minting check below rather than a missing-argument
    #: TypeError that says nothing about why it was refused.
    coverage: CoverageReport = UNRECORDED_COVERAGE
    #: The minting proof. Not data — the sole reason it is a field is that a
    #: dataclass validates its fields in ``__post_init__``, so a direct
    #: construction has to supply it and cannot. Excluded from ``repr`` and from
    #: equality so it never appears in a diagnostic or changes what two equal
    #: assessments mean.
    _minted: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._minted is not _MINT:
            raise UnboundAuthorization(
                "a PolicyAssessment is minted by VerifierBank.assess after coverage "
                "has been validated, never constructed directly. Constructing one "
                "here would assert that a policy was resolved and coverage checked "
                "when neither happened — which is the unbound-judgment route this "
                "type exists to close."
            )
        # CONSUME the token. Without this, ``dataclasses.replace`` copies every
        # init field — the token included — and mints a valid-looking assessment
        # carrying an outcome coverage never validated. Measured: it did exactly
        # that before this line existed. Clearing the token means a copy inherits
        # a spent one and is refused, which closes the stdlib version of the
        # "bespoke copy helper" the 2d guard names as unconstrained.
        object.__setattr__(self, "_minted", None)
        object.__setattr__(
            self,
            "snapshot_digest",
            _identity(self.snapshot_digest, what="snapshot_digest"),
        )
        if not isinstance(self.outcome, (Judgment, Unavailable)):
            raise UnboundAuthorization(
                "an assessment carries a Judgment or an Unavailable; anything else "
                "would be an outcome kind no authorization surface knows how to read"
            )
        if not isinstance(self.coverage, CoverageReport):
            raise UnboundAuthorization(
                "an assessment carries a CoverageReport; the record has to be able to "
                "say what answered and what could not"
            )


def mint(
    snapshot: BoundRequirements,
    outcome: Judgment | Unavailable,
    coverage: CoverageReport | None = None,
) -> PolicyAssessment:
    """Build an assessment. Called by the bank, after coverage was validated.

    Deliberately not a classmethod: a classmethod is discoverable from the type
    a caller already holds, and this should be reachable only from the module
    that ran the validation the assessment attests to.

    Every identifying field is read OFF the snapshot rather than accepted as an
    argument, so an assessment cannot describe one action while being bound to
    another — there is no parameter through which they could disagree.

    ``coverage`` is the report the bank produced. Left ``None`` — the test
    forge's shape — the assessment carries :data:`UNRECORDED_COVERAGE`, which
    says so explicitly rather than presenting an empty report as a clean one.
    """

    return PolicyAssessment(
        snapshot_digest=snapshot_digest(snapshot),
        policy_id=snapshot.policy_id,
        policy_digest=snapshot.policy_digest,
        action_class=snapshot.action_class,
        attempt_id=snapshot.attempt_id,
        artifact_sha256=snapshot.artifact_sha256,
        target_canonical=snapshot.target_canonical,
        outcome=outcome,
        coverage=coverage if coverage is not None else UNRECORDED_COVERAGE,
        _minted=_MINT,
    )


def _restore_persisted(
    *,
    snapshot_digest: str,
    policy_id: str,
    policy_digest: str,
    action_class: str,
    attempt_id: str,
    artifact_sha256: str,
    target_canonical: str,
    outcome: Judgment | Unavailable,
    coverage: CoverageReport,
) -> PolicyAssessment:
    """Reconstitute persisted data for ``ExecutionAuthorizer`` re-validation.

    Private deliberately: no application API may turn a judgment into an
    assessment. The execution authorizer is the sole consumer and never returns
    this intermediate value without re-resolving the selected policy.
    """

    return PolicyAssessment(
        snapshot_digest=snapshot_digest,
        policy_id=policy_id,
        policy_digest=policy_digest,
        action_class=action_class,
        attempt_id=attempt_id,
        artifact_sha256=artifact_sha256,
        target_canonical=target_canonical,
        outcome=outcome,
        coverage=coverage,
        _minted=_MINT,
    )


def require_assessment(candidate: object, *, surface: str) -> PolicyAssessment:
    """The one translation every authorization surface uses.

    Kept in one place so the refusal wording, and the decision to RAISE rather
    than return a falsy value, cannot drift between the four surfaces. A surface
    that quietly returned "not approved" for an unbound judgment would let a
    caller keep passing one and read the refusal as a policy denial.
    """

    if isinstance(candidate, PolicyAssessment):
        return candidate
    if isinstance(candidate, (Judgment, Unavailable)):
        raise UnboundAuthorization(
            f"{surface} received a raw {type(candidate).__name__}. An authoritative "
            "verdict is no longer sufficient to authorize an action: it says what the "
            "evidence showed, never whether a policy required that evidence. Resolve "
            "requirements with policy.resolver.resolve, bind results to the snapshot, "
            "and use VerifierBank.assess."
        )
    raise UnboundAuthorization(
        f"{surface} received {type(candidate).__name__}, which is not a "
        "PolicyAssessment. Authorization reads a policy-evaluated, action-bound "
        "assessment and nothing else."
    )
