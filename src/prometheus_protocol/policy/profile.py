"""The immutable verification policy, and the committed profiles that supply it.

WHAT A POLICY IS. A frozen, versioned statement of what must be verified before
an action of a given class may be authorized. It carries, per requirement:

* the CHECK IDENTITY that must have produced a valid, satisfactory, correctly
  bound result (R2 — never a verifier, never a tier);
* the verifier IMPLEMENTATIONS permitted to satisfy it (R3 — interchangeable
  redundancy, never quorum);
* APPLICABILITY: which action classes the requirement applies to;
* ACCEPTANCE: what counts as satisfactory, from a closed set.

WHAT "FROZEN" DOES AND DOES NOT BUY, stated honestly. ``frozen=True`` prevents
accidental mutation — a caller that assigns to a policy field gets an error
instead of quietly reshaping the requirements every later decision is measured
against. It is NOT protection against hostile Python inside the privileged
process: ``object.__setattr__`` reaches straight through it, and anything able
to run arbitrary code in this process can also replace this module. The control
against that is the process boundary and the code-integrity story, not this
keyword. What frozen genuinely gives is that a policy value cannot drift between
the moment it is digested and the moment it is enforced.

R1 — WHERE POLICY LIVES, AND THE STAGING DECISION.

Profiles are COMMITTED DATA in this package, so a profile edit is a visible
reviewable line in a diff rather than a silent runtime reconfiguration. The
active profile is selected by a ``Config`` field on ``SECURITY_FIELDS``, and its
content digest is bound into every snapshot the resolver produces, so a decision
is bound to the policy that produced it and a later edit cannot be presented as
the policy a past decision ran under.

CORRECTED CLAIM. An earlier version of the paragraph above said the profiles
were "under the content-based Hearth sanction". They are not: the Hearth ledger
(``tests/conformance/hearth_ledger.py``) digests 21 files and this module is not
one of them. What guards a profile's content is the digest binding — the pinned
record carries the policy digest and approval re-checks the hold's pinned policy
against the selected one (``execution/pending.py:670-677``) — not a
sanctioned-bytes check. The sentence was a claim about existing machinery made
without reading it, and it is withdrawn here rather than left to be believed.

WHAT A REQUIREMENT'S PERMITTED SET IS CHECKED AGAINST (G26). Every name in
``permitted`` must be an identity declared in ``policy/implementations.py``; an
undeclared one is refused at construction with a typed reason, and an empty
registry is refused outright. The ``IMPL_*`` constants below are the declared
objects themselves, not copies of them.

**This is right for this version and wrong for the product, and that is a
deliberate staging decision rather than an oversight.** A licensed component
whose customers cannot supply their own digest-pinned policy without a code
change is a bad product shape: their policy is their risk decision, not ours.
So the resolver takes a policy VALUE, never reaching for a module-level
constant — :func:`load_profile` is one supplier of that value and the
customer-supplied, digest-pinned supplier is a later addition beside it, not a
rewrite of everything downstream. Nothing below hard-codes ``PROFILES``.

WHAT THIS MODULE DOES NOT DECIDE. It does not decide whether a policy is a GOOD
policy. A profile that requires nothing validates, digests and enforces exactly
as well as one that requires everything; ``require_verification`` refusing an
empty requirement set for an action class is a floor against the emptiest
mistake, not a judgement about adequacy.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from prometheus_protocol.policy.implementations import (
    GIT_MERGE_CHECK,
    SUBPROCESS_TESTS,
    SWARM_CHECKS,
    ImplementationSiteUnresolved,
    registered_implementations,
    verify_implementation,
)
from prometheus_protocol.policy.snapshot import (
    ACTION_CLASSES,
    BoundRequirement,
    SnapshotError,
    _identity,
    _lp,
)

_DOMAIN = b"prom-verification-policy-v1\x00"

#: What a requirement will accept as satisfying it. Closed, because "what counts
#: as satisfactory" is exactly the kind of thing a free-form field would let a
#: profile weaken by inventing a permissive word.
#:
#: There is deliberately no ``ANY_RESULT`` and no ``BEST_EFFORT``: both would be
#: ways of satisfying a requirement without a satisfactory result, which is the
#: line R3 draws.
ACCEPT_PASS = "pass"
ACCEPTANCE_CONDITIONS: frozenset[str] = frozenset({ACCEPT_PASS})


#: Same shape as ``CONFIG_REFUSAL_REASONS`` and ``EXECUTION_REFUSAL_REASONS``,
#: and for the same reason: a test asserting WHICH refusal fired does so
#: structurally, and an unknown reason is refused at construction so a typo
#: cannot become a reason nothing asserts on. Not every ``PolicyError`` carries
#: one; the two here are the ones that must be told apart from each other and
#: from a runtime ``Unavailable`` (G26).
POLICY_REFUSAL_REASONS: frozenset[str] = frozenset({
    "implementation_not_registered",  # a permitted name no declared implementation reports under
    "implementation_registry_empty",  # nothing is declared; validating against nothing is refused
    "implementation_site_unresolved", # declared, but the declared site is missing or reports another identity
})


class PolicyError(ValueError):
    """A policy could not be constructed, or does not admit what was asked.

    ``reason``, when set, comes from :data:`POLICY_REFUSAL_REASONS`.
    ``implementation`` and ``check_id`` carry the offending name and the
    requirement it sat in, so a refusal names what to fix without a caller
    parsing prose.
    """

    def __init__(
        self,
        *args: object,
        reason: str | None = None,
        implementation: str | None = None,
        check_id: str | None = None,
    ) -> None:
        super().__init__(*args)
        if reason is not None and reason not in POLICY_REFUSAL_REASONS:
            raise ValueError(
                f"{reason!r} is not a known policy refusal reason; add it to "
                f"POLICY_REFUSAL_REASONS deliberately. Known: "
                f"{sorted(POLICY_REFUSAL_REASONS)}"
            )
        self.reason = reason
        self.implementation = implementation
        self.check_id = check_id


@dataclass(frozen=True)
class PolicyRequirement:
    """One requirement in a policy, before it is bound to an artifact.

    ``applies_to`` is what makes this a POLICY requirement rather than a plan
    entry: it says which action classes the requirement covers, so the
    requirement exists for every action of that class whether or not any plan
    produced a matching check. That is R2's consequence — a missing executable
    check cannot erase a requirement, because the requirement was never derived
    from the checks.
    """

    check_id: str
    permitted: tuple[str, ...]
    applies_to: tuple[str, ...]
    acceptance: str = ACCEPT_PASS

    def __post_init__(self) -> None:
        # Reuse the snapshot's identity and permitted-set normalisation rather
        # than re-implementing it: two normalisers for one concept is two
        # canonical forms waiting to disagree.
        probe = BoundRequirement(check_id=self.check_id, permitted=self.permitted)
        object.__setattr__(self, "check_id", probe.check_id)
        object.__setattr__(self, "permitted", probe.permitted)

        # G26. Every permitted name must be the identity of a DECLARED
        # implementation. Checked here, with the requirement in hand, because
        # the alternative is what this used to do: construct cleanly and refuse
        # on every assessment as ``coverage.incomplete`` — a configuration
        # error presenting as a runtime outage, permanent for the action class.
        # The empty registry is refused FIRST and DISTINCTLY: with nothing
        # declared, "not registered" would be true of every name and would read
        # as N misspellings when the fault is that nothing was declared at all.
        registry = registered_implementations()
        if not registry:
            raise PolicyError(
                f"requirement {self.check_id!r} cannot be validated: no "
                "implementation has been declared, so there is nothing to check "
                "its permitted set against. An empty registry is refused rather "
                "than read as permissive.",
                reason="implementation_registry_empty",
                check_id=self.check_id,
            )
        for name in self.permitted:
            if name not in registry:
                raise PolicyError(
                    f"requirement {self.check_id!r} permits {name!r}, which is not "
                    "the identity of any declared implementation. Declared: "
                    f"{sorted(registry)}. A name nothing reports under would "
                    "construct cleanly and then fail on every assessment as "
                    "coverage.incomplete — a configuration error wearing a runtime "
                    "outage. Declare it in policy/implementations.py at the site "
                    "that reports it, or fix the spelling.",
                    reason="implementation_not_registered",
                    implementation=name,
                    check_id=self.check_id,
                )

        if isinstance(self.applies_to, (str, bytes)):
            raise PolicyError("applies_to must be a sequence of action classes, not a string")
        classes = tuple(self.applies_to)
        if not classes:
            raise PolicyError(
                f"requirement {self.check_id!r} applies to no action class, so it "
                "would never be resolved. A requirement that covers nothing is a "
                "profile error, not a no-op."
            )
        unknown = sorted(set(classes) - ACTION_CLASSES)
        if unknown:
            raise PolicyError(
                f"requirement {self.check_id!r} names unknown action class(es) "
                f"{unknown}. The set is closed: {sorted(ACTION_CLASSES)}. A typo here "
                "would silently make the requirement apply to nothing."
            )
        duplicates = sorted({c for c in classes if classes.count(c) > 1})
        if duplicates:
            raise PolicyError(
                f"requirement {self.check_id!r} names {duplicates} more than once"
            )
        object.__setattr__(self, "applies_to", tuple(sorted(classes)))

        if self.acceptance not in ACCEPTANCE_CONDITIONS:
            raise PolicyError(
                f"{self.acceptance!r} is not an acceptance condition. The set is "
                f"closed: {sorted(ACCEPTANCE_CONDITIONS)}."
            )

    def bound(self) -> BoundRequirement:
        """The requirement as it appears in a snapshot: identity and permitted
        implementations. Applicability and acceptance are how the resolver
        SELECTED and will JUDGE it; they are not part of what is bound, because
        the snapshot answers "which checks were required here", and the policy
        digest already binds the rules that produced that answer."""

        return BoundRequirement(check_id=self.check_id, permitted=self.permitted)


#: The encoded field set of a policy requirement, in order.
POLICY_REQUIREMENT_FIELDS: tuple[str, ...] = (
    "check_id",
    "permitted",
    "applies_to",
    "acceptance",
)


@dataclass(frozen=True)
class VerificationPolicy:
    """A versioned, immutable policy. Its digest is what decisions bind to."""

    policy_id: str
    version: int
    requirements: tuple[PolicyRequirement, ...]
    #: Action classes this policy refuses to authorize at all — an explicit
    #: "this profile does not cover that" rather than the silence that would
    #: otherwise read as "no requirements apply".
    require_verification: tuple[str, ...] = field(default=tuple(ACTION_CLASSES))

    def __post_init__(self) -> None:
        object.__setattr__(self, "policy_id", _identity(self.policy_id, what="policy_id"))
        if not isinstance(self.version, int) or isinstance(self.version, bool):
            raise PolicyError("policy version must be an integer")
        if self.version < 1:
            raise PolicyError("policy version starts at 1")

        items = tuple(self.requirements)
        for item in items:
            if not isinstance(item, PolicyRequirement):
                raise PolicyError("every policy requirement must be a PolicyRequirement")
        ids = [item.check_id for item in items]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise PolicyError(
                f"check identities {duplicates} appear more than once in {self.policy_id!r}"
            )
        object.__setattr__(
            self, "requirements", tuple(sorted(items, key=lambda r: r.check_id))
        )

        covered = tuple(sorted(set(self.require_verification)))
        unknown = sorted(set(covered) - ACTION_CLASSES)
        if unknown:
            raise PolicyError(f"require_verification names unknown action class(es) {unknown}")
        object.__setattr__(self, "require_verification", covered)

        # THE FLOOR. A profile that covers an action class but requires nothing
        # for it would resolve to an empty requirement set, and an empty set is
        # satisfied by anything — the emptiest possible fail-open, arrived at by
        # omission rather than by decision. Refuse it at construction.
        for action_class in covered:
            if not any(action_class in item.applies_to for item in items):
                raise PolicyError(
                    f"policy {self.policy_id!r} covers {action_class!r} but states no "
                    "requirement for it. An empty requirement set is satisfied by "
                    "anything; if that is genuinely intended, remove the class from "
                    "require_verification so the refusal is explicit rather than empty."
                )

    def covers(self, action_class: str) -> bool:
        return action_class in self.require_verification

    def applicable(self, action_class: str) -> tuple[PolicyRequirement, ...]:
        """Requirements this policy states for ``action_class``, in canonical order."""

        return tuple(r for r in self.requirements if action_class in r.applies_to)


#: The encoded field set of a policy, in order.
POLICY_FIELDS: tuple[str, ...] = (
    "policy_id",
    "version",
    "requirements",
    "require_verification",
)


def _encode(value: object) -> bytes:
    """The policy encoder.

    Same discipline as the snapshot's — length prefixes, committed counts,
    committed names, one-byte type tags — under its OWN domain separator,
    because a policy and a coverage claim are different statements and one
    domain for both would let a preimage produced for one be presented as the
    other.
    """

    if isinstance(value, bool):  # before int: bool is a subclass of int
        return b"b" + (b"\x01" if value else b"\x00")
    if isinstance(value, int):
        return b"i" + int(value).to_bytes(8, "big", signed=True)
    if isinstance(value, str):
        return b"s" + value.encode("utf-8")
    if isinstance(value, PolicyRequirement):
        return b"R" + _record(POLICY_REQUIREMENT_FIELDS, value)
    if isinstance(value, tuple):
        parts = [b"L", len(value).to_bytes(8, "big")]
        parts.extend(_lp(_encode(element)) for element in value)
        return b"".join(parts)
    raise TypeError(
        f"no canonical encoding for {type(value).__name__} in a verification policy"
    )


def _record(field_names: tuple[str, ...], obj: object) -> bytes:
    parts = [len(field_names).to_bytes(8, "big")]
    for name in field_names:
        parts.append(_lp(name.encode("ascii")))
        parts.append(_lp(_encode(getattr(obj, name))))
    return b"".join(parts)


def policy_preimage(policy: VerificationPolicy) -> bytes:
    """The exact bytes the policy digest is taken over. Public so an auditor can
    recompute it from the documented rule."""

    return _DOMAIN + _record(POLICY_FIELDS, policy)


def policy_digest(policy: VerificationPolicy) -> str:
    """The SHA-256 of :func:`policy_preimage`, hex.

    This is what a snapshot binds, so a profile edited after a decision cannot
    be presented as the profile that decision ran under.
    """

    return hashlib.sha256(policy_preimage(policy)).hexdigest()


# ---------------------------------------------------------------------------
# The committed profiles (R1). Data, not behaviour.
# ---------------------------------------------------------------------------

#: The check identities this codebase's own verifiers answer to. Named here so a
#: profile cannot invent a check nothing produces — which would be a permanently
#: unsatisfiable requirement, indistinguishable at the bank from a check that
#: was omitted.
CHECK_EXECUTABLE_CASES = "executable.cases"
CHECK_STRUCTURAL = "structural.predicates"

#: PHASE-1.2b. What a workflow step's grader answers. The shipped baseline does
#: NOT require it anywhere, deliberately: a workflow's grader is chosen by
#: whoever wrote the workflow, so requiring it under the baseline would let any
#: caller-supplied grader satisfy a requirement by existing. A deployment whose
#: graders are trusted to authorize supplies a policy that names them.
CHECK_WORKFLOW_GRADE = "workflow.grade"

#: PHASE-1.2b. The proof a branch delete is lossless: zero commits reachable
#: from the branch and absent from the base. Named as its own check because it
#: is not "did some code run" — it is a content claim about the repository, and
#: the only thing that makes an irreversible delete safe.
CHECK_MERGE_PROOF = "branch.merge_proof"

#: The verifier implementation identities permitted to answer them. NOT SPELLED
#: HERE ANY MORE. Until G26 these were literals a person had copied off
#: ``SubprocessVerifier.VERIFIER_ID`` and two module constants, and one test
#: compared the copies by hand; nothing at construction did, so a misspelling
#: constructed cleanly and failed as incomplete coverage on every assessment.
#: Each is now the SAME OBJECT as its declaration in
#: ``policy/implementations.py``, which the implementation sites consume by
#: reference too — one spelling, two references — and ``PolicyRequirement``
#: refuses any permitted name the registry has not declared.
IMPL_SUBPROCESS = SUBPROCESS_TESTS
IMPL_SWARM_STRUCTURAL = SWARM_CHECKS
IMPL_GIT_MERGE_CHECK = GIT_MERGE_CHECK


_BASELINE = VerificationPolicy(
    policy_id="baseline",
    version=1,
    requirements=(
        # Untrusted code must actually have been RUN, by an implementation
        # permitted to run it. A structural predicate is not a substitute: that
        # substitution is precisely the reproduced fail-open this sprint exists
        # to close.
        PolicyRequirement(
            check_id=CHECK_EXECUTABLE_CASES,
            permitted=(IMPL_SUBPROCESS,),
            applies_to=("sandbox.execute", "database.migrate"),
        ),
        # PHASE-1.2b. A branch delete is irreversible, so the policy requires
        # the proof that makes it lossless rather than a risk heuristic about
        # it. Deliberately NOT applied to the other two classes: neither runs a
        # merge check, and a requirement nothing can satisfy is indistinguishable
        # at the bank from a check that was omitted.
        PolicyRequirement(
            check_id=CHECK_MERGE_PROOF,
            permitted=(IMPL_GIT_MERGE_CHECK,),
            applies_to=("branch.delete",),
        ),
    ),
)

_DEFENSE_IN_DEPTH = VerificationPolicy(
    policy_id="defense-in-depth",
    version=1,
    requirements=_BASELINE.requirements + (
        PolicyRequirement(
            check_id=CHECK_STRUCTURAL,
            permitted=(IMPL_SWARM_STRUCTURAL,),
            applies_to=("sandbox.execute",),
        ),
    ),
)

#: Committed profiles by id. NOT read by the resolver — the resolver takes a
#: policy VALUE (R1). This mapping is one supplier of such a value; a
#: customer-supplied digest-pinned supplier is a later addition beside it.
PROFILES: dict[str, VerificationPolicy] = {
    _BASELINE.policy_id: _BASELINE,
    _DEFENSE_IN_DEPTH.policy_id: _DEFENSE_IN_DEPTH,
}

#: The profile selected when configuration does not name one.
DEFAULT_PROFILE_ID = _BASELINE.policy_id


def verify_policy_implementations(
    policy: VerificationPolicy, *, action_class: str | None = None
) -> None:
    """The second registry check (G26, PR #111 P2): every permitted name's
    DECLARED SITE must resolve and report that identity.

    Construction checked that each name is declared. A declaration is a claim,
    and this is the claim being tested — when the policy is put to use, which is
    the earliest moment every site is importable (see the registry's module
    docstring for why not at declaration). ``action_class`` narrows the check to
    the requirements that apply; the resolver passes it, ``load_profile`` checks
    the whole profile. Refuses with ``implementation_site_unresolved``, naming
    the implementation and the requirement, so a declaration pointing nowhere is
    a configuration error here and not incomplete coverage on every assessment.
    """

    items = policy.requirements if action_class is None else policy.applicable(action_class)
    for item in items:
        for name in item.permitted:
            try:
                verify_implementation(name)
            except ImplementationSiteUnresolved as exc:
                raise PolicyError(
                    f"policy {policy.policy_id!r}, requirement {item.check_id!r}: {exc}",
                    reason="implementation_site_unresolved",
                    implementation=name,
                    check_id=item.check_id,
                ) from exc


def load_profile(profile_id: str) -> VerificationPolicy:
    """One supplier of a policy value: the committed profile with this id.

    Refuses an unknown id rather than falling back to a default. A typo in the
    selected profile must not silently authorize under a policy nobody chose —
    that is the omission attack wearing a configuration error.

    Also verifies every permitted implementation's declared site
    (:func:`verify_policy_implementations`): a committed profile whose declared
    implementation has gone missing is refused at load, with the site named.
    """

    try:
        _identity(profile_id, what="profile_id")
    except SnapshotError as exc:
        raise PolicyError(str(exc)) from None
    policy = PROFILES.get(profile_id)
    if policy is None:
        raise PolicyError(
            f"no committed verification profile {profile_id!r}. Available: "
            f"{sorted(PROFILES)}. An unknown profile is refused rather than "
            "defaulted: authorizing under a policy nobody selected is the "
            "failure this refusal exists to prevent."
        )
    verify_policy_implementations(policy)
    return policy
