"""The live state of an execution target, and the digest a hold is pinned to.

WHAT THIS IS FOR. A hold records evidence at assessment time and executes later
against the SAME evidence, replayed from the persisted record
(``execution/pending.py`` restores coverage from the record rather than
re-running any check). For ``branch.delete`` that gap is a data-loss path: a
branch reviewed as having zero commits absent from the base can gain commits
before the human approves, and the delete executes on the replayed "provably
lossless". This module is the first half of closing it — what "the state" IS,
and how two readings of it are compared.

THE COVERED SET IS DERIVED, NOT HAND-LISTED. One frozen dataclass per action
class, one field per ASPECT, and :func:`aspects_of` reads the field names off
the dataclass. The cautionary case is ``_DESCRIPTOR_FIELDS`` in
``policy/execution.py``: three hand-written copies of six names that agreed
only because a person kept them agreeing. The encoder here iterates the derived
names, so an aspect added to the dataclass is covered by construction and an
aspect collected but not encoded cannot exist.

WHAT THE SET EXCLUDES, AND THE RULE BEHIND IT. Not only what cannot be
meaningfully compared, but **what the act of executing changes**. A digest that
can never match refuses every execution, which reads as broken rather than
secure and trains an operator to remove the requirement — the G21 road. The
rule was earned twice on the migration side (per-session settings the executor
sets; the receipt schema the executor creates) and is applied here before
anything is built. For ``branch.delete`` the executor's only write is the
delete itself, which happens after the comparison, so nothing it does is in the
set — recorded as a measurement in ``docs/live-state-pinning-design.md`` §1.5,
not as an assumption.

THE ENCODER IS REUSED, THE DOMAIN IS NOT. ``policy/snapshot.py``'s encoder is
type-tagged, length-prefixed and committed-count, with three named tests for
the forgeries that matter, and this module calls it rather than writing a
second one: a second encoder is the hand-enumeration failure again. The DOMAIN
separator is this module's own, so a state preimage can never be reinterpreted
as a requirements preimage, and the **state type's name is committed** inside
it, so two state types that happen to share field values cannot share a digest.

WHAT A DIGEST PROVES, AND DOES NOT. That the aspects THIS CODE READ are
unchanged between two readings. It does not prove the aspect list is complete
over what the target can vary — that list is written by a person, and
:func:`aspects_of` travelling in the record is what makes the gap legible
rather than invisible.
"""

from __future__ import annotations

import dataclasses
import hashlib

from prometheus_protocol.policy.snapshot import SnapshotError, _identity, _lp, _record

#: This module's own domain. NOT ``prom-bound-requirements-v1``: a coverage
#: claim and an observation of a target are different statements, and one
#: domain for both would let a preimage produced for one be presented as the
#: other. Same reasoning, and same shape, as the snapshot encoder's own.
_DOMAIN = b"prom-target-state-v1\x00"


class TargetStateError(ValueError):
    """A target state could not be constructed from the values given."""


@dataclasses.dataclass(frozen=True)
class BranchDeleteState:
    """The live state of a ``branch.delete`` target.

    THE THREE ASPECTS, and why each is in. ``unmerged_commits`` is the merge
    proof's own subject — the count of commits reachable from the branch and
    not from the base (``tools/git.py`` reads exactly this) — and it is the
    value a stale approval gets wrong. The two TIPS are in because the count
    alone is not the state: a branch can gain a commit and the base gain the
    same commit, leaving the count at zero while both moved, and a reviewer who
    approved against one pair of tips did not approve against another. Pinning
    the count alone would be pinning the CONCLUSION rather than the subject it
    was drawn from.

    What could vary outside these three, stated rather than left to be found:
    the reflog (a branch can be reset and restored with the tips ending where
    they began), anything about OTHER branches, the working tree, and the
    remote. None is part of "is deleting this branch lossless", which is the
    question the merge proof answers, but a deployment whose loss model is
    wider than that is not covered by this set.
    """

    branch_tip: str
    base_tip: str
    unmerged_commits: int

    def __post_init__(self) -> None:
        for name in ("branch_tip", "base_tip"):
            try:
                _identity(getattr(self, name), what=name)
            except SnapshotError as exc:
                raise TargetStateError(str(exc)) from None
        count = self.unmerged_commits
        if isinstance(count, bool) or not isinstance(count, int):
            raise TargetStateError("unmerged_commits must be an integer")
        if count < 0:
            raise TargetStateError("unmerged_commits cannot be negative")


def aspects_of(state: object) -> tuple[str, ...]:
    """The covered set for ``state``, READ OFF the dataclass.

    Refuses a non-dataclass rather than returning an empty tuple: an empty
    aspect list would digest a constant and compare equal to everything, which
    is the empty-set-reads-as-a-pass failure with the worst possible blast
    radius (doctrine #8).
    """

    if not dataclasses.is_dataclass(state) or isinstance(state, type):
        raise TargetStateError(
            f"a target state must be a frozen dataclass INSTANCE, not "
            f"{type(state).__name__}; the covered set is derived from its fields "
            "and anything else derives an empty set, which compares equal to "
            "everything"
        )
    names = tuple(f.name for f in dataclasses.fields(state))
    if not names:
        raise TargetStateError(
            f"{type(state).__name__} declares no aspects; a digest over nothing "
            "matches every target"
        )
    return names


def state_preimage(state: object) -> bytes:
    """The exact bytes the digest is taken over.

    Public so an auditor can recompute it from the documented rule rather than
    trusting the function that produced it — the discipline
    ``policy/snapshot.py`` states for its own preimage.
    """

    names = aspects_of(state)
    return _DOMAIN + _lp(type(state).__name__.encode("utf-8")) + _record(names, state)


def state_digest(state: object) -> str:
    """The SHA-256 of :func:`state_preimage`, hex."""

    return hashlib.sha256(state_preimage(state)).hexdigest()
