"""The bound-requirements snapshot, and the one encoding its digest is taken over.

WHAT THIS IS. When the trusted resolver turns a selected policy into concrete
requirements for one artifact, one target, one action and one verification
attempt, the result is a :class:`BoundRequirements` snapshot. That snapshot is
persisted and bound into the authorization record, so a decision can be shown
to have been made under a particular coverage claim.

WHY THE ENCODING IS PINNED BEFORE ANYTHING IS BUILT ON IT. Because the digest is
what the authorization record carries, encoding ambiguity is a FORGEABILITY
issue, not a hygiene one. Two distinct requirement sets that produced the same
digest would let one coverage claim stand in for another: a record could say
"these checks were required and covered" while the bytes it committed to
actually describe a weaker set. So the rule is written down here, pinned by a
known-answer vector that a test rebuilds BY HAND from this docstring, and
committed to the tree.

THE RULE, in full::

    lp(x)     = u64_be(len(x)) || x
    u64_be(n) = n.to_bytes(8, "big")

    record(FIELDS, obj) = u64_be(len(FIELDS))
                       || for name in FIELDS:  lp(name) || lp(encode_value(obj.name))

    encode_value(v):
        None              -> b"n"
        bool              -> b"b" || (b"\\x01" if v else b"\\x00")
        int               -> b"i" || int64_be(v, signed)
        str               -> b"s" || utf-8(v)
        tuple             -> b"L" || u64_be(len(v)) || for e in v: lp(encode_value(e))
        BoundRequirement  -> b"R" || record(REQUIREMENT_FIELDS, v)
        anything else     -> TypeError

    snapshot_preimage(s) = DOMAIN || record(SNAPSHOT_FIELDS, s)
    snapshot_digest(s)   = hex(sha256(snapshot_preimage(s)))

Every part of that is load-bearing and each answers a specific forgery:

* **The domain separator** (:data:`_DOMAIN`) keeps a snapshot preimage from being
  reinterpretable as some other structure this codebase hashes. It deliberately
  does NOT share ``prom-config-posture-v1``: a posture and a coverage claim are
  different statements, and one domain for both would let a preimage produced
  for one be presented as the other.
* **Length prefixes on every name and value** stop a field boundary from being
  forged by embedding a delimiter — a ``check_id`` containing the bytes of the
  next field name cannot shift the parse.
* **The committed field count**, at BOTH levels, means adding or removing a field
  moves the digest instead of silently producing the old one.
* **The committed field NAMES** mean renaming a field moves the digest too, so a
  rename cannot quietly repurpose a slot.
* **One-byte type tags** keep ``True``, ``1`` and ``"1"`` — and ``None`` and
  ``""``, and an empty tuple — from sharing a preimage.
* **The element count on a sequence** keeps ``("a", "b")`` and ``("ab",)`` apart
  independently of the length prefixes.
* **A distinct tag for a requirement record** keeps a requirement from colliding
  with a string that happens to encode the same bytes.

CANONICAL BY CONSTRUCTION, NOT BY THE ENCODER. The encoder does not sort
anything. Instead :class:`BoundRequirement` and :class:`BoundRequirements`
normalise on construction — sorted, and duplicates REFUSED rather than silently
collapsed. The consequence is the property that matters: there is exactly one
constructible representation of any requirement set, so two callers who mean the
same thing cannot produce two digests, and a caller cannot produce two distinct
objects that mean the same thing and hash alike. Refusing duplicates rather than
deduplicating them is deliberate: a policy listing a check twice is a policy
someone should look at, not a shape to paper over.

NO FLOAT ENCODING, deliberately. Nothing in a coverage claim is a measurement.
``encode_value`` raises ``TypeError`` on a float rather than carrying one, so a
threshold that wandered into a snapshot fails loudly at the boundary. Adding
float support later is a deliberate bump of the domain separator, not an
in-place widening.

WHAT THIS DOES NOT COVER — stated because a named gap is worth more than a
hidden one:

* **The canonical target is bound as the string it is GIVEN.** This module
  commits to ``target_canonical`` exactly; it cannot check that the caller's
  string names a complete principal. A caller that produces an under-specified
  canonical form binds an under-specified target, and the digest attests to that
  faithfully. Completeness of the principal is the caller's contract
  (``MigrationTarget.canonical`` is the worked example).
* **A digest binds a claim, not its truth.** That the resolver produced this
  requirement set is what the snapshot attests. Whether the policy behind it is
  a *good* policy is not a property any encoding can carry.
* **Nothing here measures the running code.** The same caveat PIH-4a states for
  the posture applies unchanged: a modified interpreter or a modified copy of
  this module encodes the same snapshot the same way.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

_DOMAIN = b"prom-bound-requirements-v1\x00"

_TAG_NONE = b"n"
_TAG_BOOL = b"b"
_TAG_INT = b"i"
_TAG_STR = b"s"
_TAG_SEQ = b"L"
_TAG_REQUIREMENT = b"R"

#: What kind of thing is being authorized. Closed on purpose, and checked at
#: construction: the action class selects which policy requirements apply, so an
#: unrecognised class must never silently mean "no requirements apply". A new
#: class is added here deliberately, in the same change that teaches a policy
#: what to require for it.
ACTION_CLASSES: frozenset[str] = frozenset({
    #: Executing proposed or generated code.
    "code.execute",
    #: Applying a schema/data migration to a database principal.
    "migration.execute",
    #: Promoting a skill into the registry.
    "skill.promote",
    #: A swarm proposal advancing to the gate.
    "proposal.advance",
})


class SnapshotError(ValueError):
    """A snapshot could not be constructed from the values given."""


def _lp(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def _identity(value: object, *, what: str) -> str:
    """A check, implementation, policy or attempt identity.

    Non-empty, no outer whitespace, no NUL. The same shape ``MigrationTarget``
    demands of its fields, and for the same reason: an identity with an
    invisible edge is an identity two readers disagree about.
    """

    if not isinstance(value, str) or not value.strip():
        raise SnapshotError(f"{what} must be a non-empty string")
    if value != value.strip():
        raise SnapshotError(f"{what} cannot have outer whitespace")
    if "\x00" in value:
        raise SnapshotError(f"{what} cannot contain NUL")
    return value


@dataclass(frozen=True)
class BoundRequirement:
    """One requirement, keyed by CHECK IDENTITY.

    ``check_id`` names the check that must have produced a valid, satisfactory,
    correctly bound result. ``permitted`` names the verifier IMPLEMENTATIONS
    that are allowed to satisfy it.

    THERE IS NO TIER FIELD, AND THAT IS THE DESIGN (R2). Requiredness and tier
    are different concepts: HARD means "authoritative evidence", never "this
    check covers every requirement". A ``tier`` here would invite exactly the
    conflation that produces a plausible-looking system which still fails open.

    ``permitted`` HAVING MORE THAN ONE ENTRY IS NOT QUORUM (R3). It says the
    requirement was never keyed to one implementation. It is satisfied when at
    least one permitted implementation produced a valid, satisfactory, correctly
    bound result — never by the size of this tuple, and never by unavailable
    results from the others.
    """

    check_id: str
    permitted: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "check_id", _identity(self.check_id, what="check_id")
        )
        if isinstance(self.permitted, (str, bytes)):
            raise SnapshotError("permitted implementations must be a sequence, not a string")
        names = [
            _identity(name, what="permitted implementation")
            for name in tuple(self.permitted)
        ]
        if not names:
            raise SnapshotError(
                f"requirement {self.check_id!r} permits no implementation, so nothing "
                "could ever satisfy it. A requirement no implementation can meet is a "
                "policy error, not a permanently-failing check."
            )
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise SnapshotError(
                f"requirement {self.check_id!r} lists {duplicates} more than once. "
                "Duplicates are refused rather than collapsed: one canonical form per "
                "requirement is what keeps two meanings from sharing a digest."
            )
        object.__setattr__(self, "permitted", tuple(sorted(names)))


#: The encoded field set of a requirement, in order. Asserted against the
#: dataclass by a conformance test, so a field added later cannot be left
#: unhashed.
REQUIREMENT_FIELDS: tuple[str, ...] = ("check_id", "permitted")


@dataclass(frozen=True)
class BoundRequirements:
    """The coverage claim for ONE artifact, target, action and attempt.

    This is what gets persisted and bound into the authorization record. Every
    field is part of the binding: a snapshot resolved for a different artifact,
    a different target, a different action class or a different attempt is a
    different snapshot and hashes differently, so evidence bound to one cannot
    be replayed under another.
    """

    #: Which policy was selected, and the digest of its content. Both, because
    #: the id alone would let a policy be edited under a decision that cited it,
    #: and the digest alone would not say which profile a reader should go read.
    policy_id: str
    policy_digest: str
    #: The artifact under verification.
    artifact_sha256: str
    #: The complete principal, canonicalised by the caller. See the module
    #: docstring for what this module can and cannot check about it.
    target_canonical: str
    #: One of :data:`ACTION_CLASSES`.
    action_class: str
    #: The verification attempt this coverage claim belongs to.
    attempt_id: str
    #: The resolved requirements, sorted by ``check_id``, duplicates refused.
    requirements: tuple[BoundRequirement, ...]

    def __post_init__(self) -> None:
        for name in (
            "policy_id",
            "policy_digest",
            "artifact_sha256",
            "target_canonical",
            "attempt_id",
        ):
            object.__setattr__(
                self, name, _identity(getattr(self, name), what=name)
            )
        if self.action_class not in ACTION_CLASSES:
            raise SnapshotError(
                f"{self.action_class!r} is not a known action class. The set is "
                f"closed: {sorted(ACTION_CLASSES)}. An unrecognised class must never "
                "silently resolve to 'no requirements apply'."
            )
        items = tuple(self.requirements)
        for item in items:
            if not isinstance(item, BoundRequirement):
                raise SnapshotError(
                    "every requirement must be a BoundRequirement; a plain tuple or "
                    "dict here would bypass its normalisation"
                )
        ids = [item.check_id for item in items]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise SnapshotError(
                f"check identities {duplicates} appear more than once. A requirement "
                "set is keyed by check identity; two entries for one identity have no "
                "single meaning."
            )
        object.__setattr__(
            self, "requirements", tuple(sorted(items, key=lambda r: r.check_id))
        )

    @property
    def check_ids(self) -> tuple[str, ...]:
        return tuple(item.check_id for item in self.requirements)

    def permitted_for(self, check_id: str) -> tuple[str, ...] | None:
        """The implementations permitted for ``check_id``, or ``None`` when this
        snapshot requires no such check. ``None`` is not "anything goes" — a
        caller reading it must treat an unrequired check as unrequired."""

        for item in self.requirements:
            if item.check_id == check_id:
                return item.permitted
        return None


#: The encoded field set of a snapshot, in order. Asserted against the dataclass
#: by a conformance test.
SNAPSHOT_FIELDS: tuple[str, ...] = (
    "policy_id",
    "policy_digest",
    "artifact_sha256",
    "target_canonical",
    "action_class",
    "attempt_id",
    "requirements",
)


def encode_value(value: object) -> bytes:
    """One unambiguous encoding per value, type tag first.

    An unsupported type raises rather than being stringified: a silently
    stringified value is an encoding nobody pinned, and it is exactly how two
    different claims come to share a preimage.
    """

    if value is None:
        return _TAG_NONE
    if isinstance(value, bool):  # before int: bool is a subclass of int
        return _TAG_BOOL + (b"\x01" if value else b"\x00")
    if isinstance(value, int):
        return _TAG_INT + int(value).to_bytes(8, "big", signed=True)
    if isinstance(value, str):
        return _TAG_STR + value.encode("utf-8")
    if isinstance(value, BoundRequirement):
        return _TAG_REQUIREMENT + _record(REQUIREMENT_FIELDS, value)
    if isinstance(value, tuple):
        parts = [_TAG_SEQ, len(value).to_bytes(8, "big")]
        parts.extend(_lp(encode_value(element)) for element in value)
        return b"".join(parts)
    raise TypeError(
        f"no canonical encoding for {type(value).__name__} in a bound-requirements "
        "snapshot. Widening this is a deliberate bump of the domain separator, "
        "never an in-place addition."
    )


def _record(field_names: tuple[str, ...], obj: object) -> bytes:
    parts = [len(field_names).to_bytes(8, "big")]
    for name in field_names:
        parts.append(_lp(name.encode("ascii")))
        parts.append(_lp(encode_value(getattr(obj, name))))
    return b"".join(parts)


def snapshot_preimage(snapshot: BoundRequirements) -> bytes:
    """The exact bytes the digest is taken over.

    Public so an auditor can recompute the digest from the documented rule
    rather than trusting the function that produced it — the PIH-4a discipline:
    the spec and the implementation are checked against each other, not each
    against itself.
    """

    return _DOMAIN + _record(SNAPSHOT_FIELDS, snapshot)


def snapshot_digest(snapshot: BoundRequirements) -> str:
    """The SHA-256 of :func:`snapshot_preimage`, hex. Deterministic across
    processes and hosts for one resolved coverage claim."""

    return hashlib.sha256(snapshot_preimage(snapshot)).hexdigest()

