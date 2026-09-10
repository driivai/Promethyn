"""Requirement coverage, validated BEFORE fusion.

THE GAP THIS CLOSES. Every producer in this codebase implements "couldn't-verify
is never verified-clean". The AGGREGATE did not. Two reproduced fail-opens came
from the same shape: an aggregate that substitutes *everything that ran passed*
for *everything REQUIRED passed*. Once a required check can be absent without
anything noticing, a passing structural predicate becomes a synthetic
authoritative PASS and the gate approves.

So coverage is decided here, against the resolved snapshot, and it is decided
BEFORE any fusion happens. Fusion answers "how confident are we in the verdict
we have"; it was never able to answer "is there a verdict we are missing",
because nothing told it what was owed.

THE BINDING, AND WHY IT IS ONE FIELD. A :class:`BoundResult` names the
``snapshot_digest`` it answers. That single value already commits to the policy,
the policy's content, the artifact, the canonical target, the action class and
the verification attempt — so "wrong artifact", "wrong target", "wrong attempt"
and "wrong policy" are one comparison rather than four that could disagree. A
result carrying a different digest is invalid evidence, not weaker evidence.

R3, AND THE LINE. A requirement with two permitted implementations is satisfied
when AT LEAST ONE of them produced a valid, satisfactory, correctly bound
result. Unavailable results from the others are RECORDED and IRRELEVANT: they
neither satisfy nor block. Nothing in this module counts permitted
implementations, compares their number to the results, or treats one
implementation's silence as evidence about another's. There is no code path in
which absence satisfies anything — :func:`validate_coverage` reaches
``satisfied`` for a requirement only by holding a satisfactory result in hand.

WHAT THIS DOES NOT COVER, named rather than implied:

* **It validates the evidence it is GIVEN.** A trusted caller that never
  constructs a :class:`BoundResult` for a check it ran presents the same picture
  as a check that never ran, and coverage refuses — which is the safe direction,
  but it means the caller's completeness is the caller's contract.
* **The permitted implementations are asserted equivalent by the operator**
  (R4). Nothing here verifies that ``subprocess-verifier`` and some future
  sibling are equally strong. What this module guarantees is that the record
  says WHICH one answered.
* **An attacker who can make the stronger permitted implementation unavailable
  may get the weaker one to answer** (R4). That is inherent to permitting more
  than one; the policy naming them is the auditable control, not this code.
* **A verifier that CLAIMS a tier it does not have is believed here**
  (CHECKPOINT 3). The satisfaction rule reads ``Evidence.tier`` — the tier the
  evidence reports — because that is what covers derived identities and
  implementations this package has never seen. It is therefore only as good as
  the report. This is not new: the bank has always seeded an unknown verifier's
  tier from its first evidence. What changed is that the tier is now load-bearing
  in one more place, so the residual is worth stating precisely:

  - a REGISTERED verifier cannot lie. ``VerifierBank._ensure_stats`` refuses
    evidence whose tier contradicts the stored one, loudly — measured;
  - an UNREGISTERED verifier's claim is believed, and its evidence can satisfy a
    requirement — also measured.

  **Registration is the control**, and it is a deployment's responsibility, in
  the same way that constructing a result for every check it ran is (above).
  Coverage deliberately holds no trust store: it validates the evidence it is
  GIVEN, and reaching for a store here would make the coverage decision depend on
  mutable calibration state.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from prometheus_protocol.core.models import (
    AUTHORITATIVE_TIERS,
    Evidence,
    Unavailable,
    Verdict,
    partition_outcomes,
)
from prometheus_protocol.policy.snapshot import (
    BoundRequirements,
    SnapshotError,
    _identity,
    snapshot_digest,
)

#: Why coverage was refused. Closed, and each maps to one row of the enforcement
#: table so a refusal names its row rather than describing it in prose.
REFUSED_UNSATISFACTORY = "coverage.unsatisfactory"
REFUSED_ABSTAINED = "coverage.abstained"
REFUSED_INCOMPLETE = "coverage.incomplete"
REFUSED_INVALID_EVIDENCE = "coverage.invalid_evidence"
REFUSED_AMBIGUOUS = "coverage.ambiguous"
#: PHASE-1.2 CHECKPOINT 3. The only PASS for a required check came from ADVISORY
#: evidence. Distinct from every reason above because the check RAN, REPORTED,
#: and PASSED — it simply cannot be what satisfies a requirement.
REFUSED_ADVISORY_ONLY = "coverage.advisory_only"

REFUSAL_REASONS: frozenset[str] = frozenset({
    REFUSED_UNSATISFACTORY,
    REFUSED_ABSTAINED,
    REFUSED_INCOMPLETE,
    REFUSED_INVALID_EVIDENCE,
    REFUSED_AMBIGUOUS,
    REFUSED_ADVISORY_ONLY,
})


@dataclass(frozen=True)
class BoundResult:
    """One check's result, bound to the snapshot it answers.

    Constructed by TRUSTED code that ran the check and holds the snapshot. It is
    deliberately a separate type from :class:`~prometheus_protocol.core.models.Evidence`
    rather than fields added to it: an ``Evidence`` is what a verifier produces
    and knows nothing about policy, while a binding is a claim about which
    question was being answered. Keeping them apart means a verifier cannot
    accidentally assert a binding, and an unbound ``Evidence`` cannot be mistaken
    for a covered one.
    """

    #: The requirement identity this answers.
    check_id: str
    #: The snapshot this result is bound to — one value committing to policy,
    #: artifact, target, action class and attempt.
    snapshot_digest: str
    #: Which permitted implementation answered. Checked against the evidence's
    #: own ``verifier_id``, so a caller cannot claim one implementation while
    #: presenting another's work.
    implementation: str
    outcome: Evidence | Unavailable

    def __post_init__(self) -> None:
        object.__setattr__(self, "check_id", _identity(self.check_id, what="check_id"))
        object.__setattr__(
            self, "snapshot_digest", _identity(self.snapshot_digest, what="snapshot_digest")
        )
        object.__setattr__(
            self, "implementation", _identity(self.implementation, what="implementation")
        )
        if not isinstance(self.outcome, (Evidence, Unavailable)):
            raise SnapshotError(
                "a bound result carries an Evidence or an Unavailable; anything else "
                "would be an outcome kind nothing here knows how to judge"
            )


@dataclass(frozen=True)
class CoverageRefused:
    """Coverage failed. Carries the row of the table that refused, and which
    requirement — so an operator sees WHICH check was not covered and WHY,
    without the refusal quoting anything a verifier produced."""

    reason: str
    check_id: str
    detail: str = ""

    def __post_init__(self) -> None:
        if self.reason not in REFUSAL_REASONS:
            raise SnapshotError(
                f"{self.reason!r} is not a coverage refusal reason. The set is closed: "
                f"{sorted(REFUSAL_REASONS)}."
            )


@dataclass(frozen=True)
class CoverageSatisfied:
    """Every requirement in the snapshot has a valid, satisfactory, correctly
    bound result.

    ``answered_by`` records WHICH permitted implementation satisfied each
    requirement, and ``recorded_unavailable`` records the permitted
    implementations that could not answer. The second is the R4 residual made
    visible: a reviewer can see that A was down and B answered.
    """

    answered_by: dict[str, str]
    recorded_unavailable: tuple[tuple[str, str], ...] = ()
    #: The results that passed validation, in snapshot order. These are what may
    #: then be fused — and only these.
    graded: tuple[Evidence, ...] = field(default=())


def _satisfactory(outcome: Evidence) -> bool:
    """The only acceptance condition the policy admits today: a PASS verdict.

    Read off ``decided`` rather than ``passed``: ``passed`` is a count-derived
    convenience, while ``decided`` is the verdict the verifier reached and the
    one every other authorization path in this codebase reads.
    """

    return outcome.decided == Verdict.PASS


def _authoritative(outcome: Evidence) -> bool:
    """Whether this evidence can be what SATISFIES a requirement.

    PHASE-1.2 CHECKPOINT 3. Read off the tier the evidence REPORTS, never off
    the implementation's name. That is the whole design: the soft-lever wrappers
    derive their identities at construction
    (``f"{base}:threshold@{x}"``, ``f"{base}:k{k}-{require}"``), so any rule over
    identity strings would be a rule over spellings — the failure already
    recorded in the threat model. A rule over what the evidence IS covers every
    wrapper, every derived identity, and every implementation this package has
    never heard of, including a deployment's own.

    ``tier is None`` FAILS CLOSED. ``Evidence.tier`` is optional and the bank
    resolves it from the trust store at fusion time; coverage holds no store, so
    a missing tier is a tier it could not establish, and could-not-establish is
    never established. Exactly one ``Evidence`` in ``src/`` omits it and it is a
    conformance fixture, not a coverage producer.

    THIS DOES NOT MAKE REQUIREMENTS TIER-KEYED (R2). What is REQUIRED still comes
    from the policy and the action class alone, keyed by check identity. This is
    the separate question of what COUNTS as satisfying one — the same kind of
    condition as "a PASS verdict", applied to the same evidence.
    """

    return outcome.tier in AUTHORITATIVE_TIERS


def validate_coverage(
    snapshot: BoundRequirements, results: tuple[BoundResult, ...] | list[BoundResult]
) -> CoverageSatisfied | CoverageRefused:
    """The enforcement table, implemented row for row.

    ==========================================  =================================
    required-check result                       behaviour
    ==========================================  =================================
    valid, correctly bound satisfactory result  requirement satisfied
    FAIL                                        refuse (``unsatisfactory``)
    ABSTAIN                                     refuse (``abstained``), and the
                                                abstention is preserved as such
    Unavailable / exception / timeout / missing refuse (``incomplete``)
    wrong artifact, target, attempt, verifier   refuse (``invalid_evidence``)
      or policy binding
    duplicate or conflicting results            refuse (``ambiguous``); a
                                                duplicate NEVER counts toward
                                                coverage
    a PASS from ADVISORY evidence only          refuse (``advisory_only``); the
                                                check ran and passed, and still
                                                does not satisfy
    ==========================================  =================================

    Exceptions and timeouts are the caller's to turn into an ``Unavailable``
    before calling — which every producer in this codebase already does — and a
    check that raised and was swallowed arrives here as MISSING, which refuses
    on the same row. That is deliberate: the two are indistinguishable from
    here, and both mean the required check has no result.
    """

    digest = snapshot_digest(snapshot)
    required = {item.check_id: item.permitted for item in snapshot.requirements}

    # -- validate each result before any of it is counted --------------------
    #
    # Binding first, so an unbound or misattributed result never reaches the
    # satisfaction logic at all. A result for a check nobody requires is not an
    # error: policy requirements are a floor, and the untrusted side may request
    # more. It simply cannot contribute to coverage.
    seen: dict[str, set[str]] = {}
    for result in results:
        # BINDING IS CHECKED FOR EVERY RESULT, required or not. An earlier draft
        # skipped unrequired results entirely here and then built ``graded`` from
        # required ones only — which silently DROPPED a failing unrequired check
        # instead of fusing it, turning a FAIL into a PASS whenever coverage
        # happened to hold. That is a fail-open of exactly the shape this module
        # exists to remove, so unrequired results are validated and fused; they
        # simply do not COUNT toward coverage.
        if result.snapshot_digest != digest:
            return CoverageRefused(
                REFUSED_INVALID_EVIDENCE,
                result.check_id,
                "result is bound to a different verification attempt",
            )
        permitted = required.get(result.check_id)
        if permitted is not None and result.implementation not in permitted:
            return CoverageRefused(
                REFUSED_INVALID_EVIDENCE,
                result.check_id,
                f"{result.implementation} is not a permitted implementation",
            )
        claimed = result.outcome.verifier_id
        if claimed != result.implementation:
            return CoverageRefused(
                REFUSED_INVALID_EVIDENCE,
                result.check_id,
                "the result names one implementation and the evidence another",
            )
        # DUPLICATES NEVER COUNT. Two results from the SAME implementation for
        # one requirement are an ambiguity, not corroboration: they cannot both
        # be the answer, and picking either is a choice nothing authorised.
        if permitted is None:
            # Not required: validated, fusible, and irrelevant to coverage.
            continue
        answered = seen.setdefault(result.check_id, set())
        if result.implementation in answered:
            return CoverageRefused(
                REFUSED_AMBIGUOUS,
                result.check_id,
                "the same implementation reported twice for one requirement",
            )
        answered.add(result.implementation)

    # -- then decide each requirement, independently -------------------------
    answered_by: dict[str, str] = {}
    unavailable: list[tuple[str, str]] = []
    graded: list[Evidence] = []

    for item in snapshot.requirements:
        for_check = [r for r in results if r.check_id == item.check_id]

        # CONFLICT. Two DIFFERENT permitted implementations that reached
        # different verdicts is an ambiguity the bank must not resolve by
        # preference: R3 says they are interchangeable, and interchangeable
        # answers that disagree mean the operator's equivalence assertion (R4)
        # is wrong. Refusing is the only honest reading.
        # ``partition_outcomes`` rather than a narrowed comprehension: a
        # comprehension filtering TO one member silently drops anything that is
        # neither, with no diagnostic. Here that would mean a third outcome kind
        # vanishing out of a conflict check.
        judged, _absent = partition_outcomes([r.outcome for r in for_check])
        verdicts = {item.decided for item in judged}
        if len(verdicts) > 1:
            return CoverageRefused(
                REFUSED_AMBIGUOUS,
                item.check_id,
                "permitted implementations reached different verdicts",
            )

        satisfied_by: str | None = None
        saw_fail = False
        saw_abstain = False
        advisory_pass: str | None = None
        for result in for_check:
            if isinstance(result.outcome, Unavailable):
                # RECORDED AND IRRELEVANT (R3). It does not satisfy, and it does
                # not block a sibling that answered.
                unavailable.append((item.check_id, result.implementation))
                continue
            if _satisfactory(result.outcome):
                # A PASS, but only AUTHORITATIVE evidence satisfies. Advisory
                # evidence is remembered separately so the refusal below can say
                # what actually happened rather than "nothing answered".
                if _authoritative(result.outcome):
                    if satisfied_by is None:
                        satisfied_by = result.implementation
                elif advisory_pass is None:
                    advisory_pass = result.implementation
            elif result.outcome.decided == Verdict.ABSTAIN:
                saw_abstain = True
            else:
                saw_fail = True

        if saw_fail:
            # A FAIL is a real answer, and it refuses regardless of whether a
            # sibling passed — that disagreement was already caught above as a
            # conflict, so reaching here means the only answers were failures.
            return CoverageRefused(
                REFUSED_UNSATISFACTORY, item.check_id, "the required check failed"
            )
        if satisfied_by is not None:
            answered_by[item.check_id] = satisfied_by
            continue
        if advisory_pass is not None:
            # ADVISORY EVIDENCE CANNOT SATISFY A REQUIREMENT, however confident
            # it is. Ordered before the abstention row deliberately: when a
            # permitted implementation passed advisory and another abstained,
            # the operationally important fact is that the policy permits an
            # implementation which can never satisfy what it was permitted for.
            # That is a policy error to fix, not a run to retry.
            return CoverageRefused(
                REFUSED_ADVISORY_ONLY,
                item.check_id,
                f"the only satisfactory result came from {advisory_pass}, which "
                "reports advisory evidence; a requirement is satisfied by "
                "authoritative evidence or not at all",
            )
        if saw_abstain:
            # PRESERVED AS AN ABSTENTION, not flattened into "incomplete": an
            # abstention means the check RAN and reached no conclusion, which is
            # a different operational situation from a check that could not run.
            return CoverageRefused(
                REFUSED_ABSTAINED,
                item.check_id,
                "the required check abstained; an abstention is not a satisfactory result",
            )
        # Nothing satisfactory, nothing failed, nothing abstained: either every
        # permitted implementation was unavailable, or none reported at all.
        # THIS IS THE LINE (R3): absence never satisfies, however many
        # implementations were permitted.
        return CoverageRefused(
            REFUSED_INCOMPLETE,
            item.check_id,
            "no permitted implementation produced a result for the required check",
        )

    # Everything valid gets fused — required results AND the extra checks the
    # untrusted side requested. Coverage decided WHETHER to fuse; it does not get
    # to decide what the fusion is allowed to see, because dropping a result here
    # is how a failing unrequired check would vanish.
    fusible, _unavailable = partition_outcomes([r.outcome for r in results])
    graded = list(fusible)
    return CoverageSatisfied(
        answered_by=answered_by,
        recorded_unavailable=tuple(sorted(unavailable)),
        graded=tuple(graded),
    )
