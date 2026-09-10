"""The trusted resolver: a policy value plus this action, into a bound snapshot.

WHAT MAKES IT TRUSTED. Its inputs are the policy VALUE the deployment selected
and facts about the action being authorized — the artifact digest, the canonical
target, the action class, the verification attempt. It is trusted APPLICATION
code, called from the wiring that already holds those facts. It is never handed
an untrusted proposal or test plan and asked what should be required.

WHAT UNTRUSTED INPUT MAY AND MAY NOT DO. A proposal or test plan may REQUEST
additional checks — :func:`resolve` accepts them and records them. It can never
remove, replace, downgrade, or omit-into-nonexistence a policy requirement,
because the requirement set is derived from the policy and the action class
ALONE. Requested checks are unioned in; nothing about them is consulted when
deciding what the policy requires.

THE OMISSION RULE — the one that kills the obvious wrong design.

The reproduced fail-open was not a mislabeled check. It was an ABSENT one: a
plan with no executable entry point produced no executable check, the aggregate
saw only a passing structural predicate, and "everything that ran passed" became
a HARD PASS. Adding a ``required=True`` field to the plan does not fix that,
because the attack is omission — the attacker simply does not emit the entry the
flag would have been on.

So the requirement comes from the policy, and an empty entry point is not a
smaller plan; it is a plan that CANNOT SATISFY a requirement the policy states
regardless. :func:`resolve` does not consult the plan to decide what is
required, so there is no code path in which an omission shrinks the requirement
set. The bank then refuses, because the required check has no result. Stated as
the rule the sprint names: *if policy requires executable verification for a
code action, an empty entry point means VERIFICATION CANNOT PROCEED — not "this
action needs only structural checks."*

R3, RESTATED WHERE IT IS EASIEST TO GET WRONG. This module records permitted
implementations per requirement. It never reasons about how MANY are permitted,
and never treats an unavailable implementation as evidence about another. The
permitted set is not a quorum, not a fallback chain, and not an ordering; it is
the answer to "was this requirement ever keyed to one implementation?" — no.
"""

from __future__ import annotations

from collections.abc import Iterable

from prometheus_protocol.policy.profile import (
    PolicyError,
    VerificationPolicy,
    policy_digest,
)
from prometheus_protocol.policy.snapshot import (
    ACTION_CLASSES,
    BoundRequirement,
    BoundRequirements,
)


class ResolutionRefused(PolicyError):
    """The action cannot be verified under the selected policy.

    A refusal, never a degraded resolution: there is no snapshot that means
    "less was required than the policy states".
    """


def resolve(
    policy: VerificationPolicy,
    *,
    artifact_sha256: str,
    target_canonical: str,
    action_class: str,
    attempt_id: str,
    requested_checks: Iterable[BoundRequirement] = (),
) -> BoundRequirements:
    """Resolve ``policy`` into the concrete requirements for THIS action.

    ``policy`` is a VALUE, deliberately (R1): nothing here reaches for a
    module-level profile table, so a customer-supplied digest-pinned policy is a
    different supplier of this argument rather than a rewrite of this function.

    ``requested_checks`` is the untrusted side's ask. It can only ADD. A
    requested check whose identity collides with a policy requirement is
    refused rather than merged, because a merge is where a downgrade would hide:
    the policy's permitted set and the request's would have to be reconciled,
    and any reconciliation that widened the policy's set is a weakening
    performed by untrusted input.
    """

    if action_class not in ACTION_CLASSES:
        raise ResolutionRefused(
            f"{action_class!r} is not a known action class. The set is closed: "
            f"{sorted(ACTION_CLASSES)}. An unrecognised class is refused rather "
            "than resolved to an empty requirement set."
        )
    if not policy.covers(action_class):
        raise ResolutionRefused(
            f"policy {policy.policy_id!r} does not cover {action_class!r}. A policy "
            "that says nothing about an action class cannot authorize it — silence "
            "is not permission."
        )

    required = tuple(item.bound() for item in policy.applicable(action_class))
    if not required:
        # Unreachable while VerificationPolicy refuses a covered class with no
        # requirement, and asserted rather than assumed: the empty requirement
        # set is satisfied by anything, so it must never be constructible here
        # even if the policy floor is later loosened.
        raise ResolutionRefused(
            f"policy {policy.policy_id!r} covers {action_class!r} but resolved no "
            "requirement. An empty requirement set is satisfied by anything."
        )

    policy_required = {item.check_id for item in required}
    extra: list[BoundRequirement] = []
    for item in requested_checks:
        if not isinstance(item, BoundRequirement):
            raise ResolutionRefused(
                "a requested check must be a BoundRequirement; a raw tuple would "
                "bypass its normalisation"
            )
        if item.check_id in policy_required:
            raise ResolutionRefused(
                f"requested check {item.check_id!r} collides with a policy "
                "requirement of the same identity. Requests may only ADD: merging "
                "the two permitted sets is where a downgrade would hide, because "
                "any widening of the policy's set would be a weakening performed "
                "by untrusted input."
            )
        extra.append(item)

    return BoundRequirements(
        policy_id=policy.policy_id,
        policy_digest=policy_digest(policy),
        artifact_sha256=artifact_sha256,
        target_canonical=target_canonical,
        action_class=action_class,
        attempt_id=attempt_id,
        requirements=required + tuple(extra),
    )
