"""The bound-requirements snapshot encoding, pinned by a hand-built known answer.

THE PIH-4a DISCIPLINE, applied to a second digest. A test that computes the
expected preimage by calling the function under test proves only that the
function agrees with itself. So the vector below is rebuilt HERE, from the rule
written in ``policy/snapshot.py``'s docstring, using nothing from the module but
the field tuples and the values — and then compared. The spec and the
implementation are checked against each other.

WHY THIS IS NOT HYGIENE. The digest is bound into the authorization record. Two
distinct requirement sets sharing a digest would let one coverage claim stand in
for another: a record could commit to "these checks were required" while the
bytes describe a weaker set. Every ambiguity test below names the specific
forgery it refuses.
"""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Any

import pytest

from prometheus_protocol.policy import snapshot as snap
from prometheus_protocol.policy.snapshot import (
    ACTION_CLASSES,
    REQUIREMENT_FIELDS,
    SNAPSHOT_FIELDS,
    BoundRequirement,
    BoundRequirements,
    SnapshotError,
    snapshot_digest,
    snapshot_preimage,
)

TARGET = (
    '{"dbname":"appdb","host":"db.internal","port":5432,'
    '"schema":"public","user":"migrator"}'
)


def a_snapshot(**overrides: object) -> BoundRequirements:
    # ``dict[str, Any]`` states what this holds rather than letting the join
    # collapse to a type no field accepts — every value is still checked against
    # its own annotation at the call.
    values: dict[str, Any] = dict(
        policy_id="baseline-v1",
        policy_digest="b" * 64,
        artifact_sha256="a" * 64,
        target_canonical=TARGET,
        action_class="migration.execute",
        attempt_id="attempt-0001",
        requirements=(
            BoundRequirement(
                check_id="structural.syntax", permitted=("swarm.structural",)
            ),
            BoundRequirement(
                check_id="executable.cases",
                permitted=("verifier.subprocess", "verifier.container"),
            ),
        ),
    )
    values.update(overrides)
    return BoundRequirements(**values)


# ---------------------------------------------------------------------------
# 1. the known answer
# ---------------------------------------------------------------------------

#: Observed once, then pinned — never predicted. Any change to the domain
#: separator, the field order, the committed field count, the per-field name
#: commitment, the length prefixes, the type tags or the sequence counts moves
#: this. That is the point: an encoding that can drift silently is two digests
#: for one coverage claim. Change it only with a deliberate version bump of the
#: domain separator, in the same commit, with the reason.
GOLDEN_DIGEST = "631a78cb62ef2beba6ce85cc3c43ce020b925c91375acf22224a8fab9213678c"
GOLDEN_PREIMAGE_BYTES = 769


def _u64(n: int) -> bytes:
    return n.to_bytes(8, "big")


def _lp(raw: bytes) -> bytes:
    return _u64(len(raw)) + raw


def _hand_encode_value(value) -> bytes:
    """encode_value, rebuilt from the docstring. Deliberately NOT imported."""

    if value is None:
        return b"n"
    if isinstance(value, bool):
        return b"b" + (b"\x01" if value else b"\x00")
    if isinstance(value, int):
        return b"i" + int(value).to_bytes(8, "big", signed=True)
    if isinstance(value, str):
        return b"s" + value.encode("utf-8")
    if isinstance(value, BoundRequirement):
        return b"R" + _hand_record(REQUIREMENT_FIELDS, value)
    if isinstance(value, tuple):
        out = b"L" + _u64(len(value))
        for element in value:
            out += _lp(_hand_encode_value(element))
        return out
    raise AssertionError(f"the hand encoder has no rule for {type(value).__name__}")


def _hand_record(field_names, obj) -> bytes:
    out = _u64(len(field_names))
    for name in field_names:
        out += _lp(name.encode("ascii"))
        out += _lp(_hand_encode_value(getattr(obj, name)))
    return out


def _hand_preimage(snapshot: BoundRequirements) -> bytes:
    return b"prom-bound-requirements-v1\x00" + _hand_record(SNAPSHOT_FIELDS, snapshot)


def test_the_encoding_matches_its_pinned_known_answer():
    assert snapshot_digest(a_snapshot()) == GOLDEN_DIGEST
    assert len(snapshot_preimage(a_snapshot())) == GOLDEN_PREIMAGE_BYTES


def test_the_preimage_is_reconstructible_by_hand_from_the_documented_rule():
    """The whole point of the vector: an auditor does not have to trust the
    function that produced the digest."""

    rebuilt = _hand_preimage(a_snapshot())
    assert rebuilt == snapshot_preimage(a_snapshot())
    assert hashlib.sha256(rebuilt).hexdigest() == GOLDEN_DIGEST


def test_the_preimage_starts_with_its_own_domain_and_field_count():
    domain = b"prom-bound-requirements-v1\x00"
    preimage = snapshot_preimage(a_snapshot())
    assert preimage.startswith(domain)
    # The field count is committed immediately after the domain, so adding or
    # removing a field moves the digest instead of silently producing the old one.
    assert preimage[len(domain):len(domain) + 8] == _u64(len(SNAPSHOT_FIELDS))


def test_the_domain_is_not_shared_with_the_posture_digest():
    """A posture and a coverage claim are different statements. One domain for
    both would let a preimage produced for one be presented as the other."""

    from prometheus_protocol.attestation import posture

    assert snap._DOMAIN != posture._DOMAIN  # noqa: SLF001 - that is the assertion


# ---------------------------------------------------------------------------
# 2. the field set cannot drift out from under the digest
# ---------------------------------------------------------------------------


def test_the_encoded_field_set_equals_the_dataclass_fields():
    """The void-guard check: a field added to the snapshot but left out of
    SNAPSHOT_FIELDS would be bound by nothing, silently."""

    declared = tuple(f.name for f in dataclasses.fields(BoundRequirements))
    assert SNAPSHOT_FIELDS == declared, "SNAPSHOT_FIELDS drifted from the snapshot"

    declared_req = tuple(f.name for f in dataclasses.fields(BoundRequirement))
    assert REQUIREMENT_FIELDS == declared_req, (
        "REQUIREMENT_FIELDS drifted from the requirement"
    )


def test_every_field_actually_moves_the_digest():
    """A field in the tuple that no longer reaches the preimage would pass the
    set-equality check above and still be unbound."""

    baseline = snapshot_digest(a_snapshot())
    flips = {
        "policy_id": "baseline-v2",
        "policy_digest": "c" * 64,
        "artifact_sha256": "d" * 64,
        "target_canonical": TARGET.replace("appdb", "otherdb"),
        "action_class": "code.execute",
        "attempt_id": "attempt-0002",
        "requirements": (
            BoundRequirement(check_id="structural.syntax", permitted=("swarm.structural",)),
        ),
    }
    assert set(flips) == set(SNAPSHOT_FIELDS), "a bound field has no flip test"
    for name, value in flips.items():
        assert snapshot_digest(a_snapshot(**{name: value})) != baseline, name


def test_every_requirement_field_actually_moves_the_digest():
    baseline = snapshot_digest(a_snapshot())
    flips = {
        "check_id": "executable.cases.v2",
        "permitted": ("verifier.subprocess",),
    }
    assert set(flips) == set(REQUIREMENT_FIELDS), "a bound requirement field has no flip test"
    for name, value in flips.items():
        changed = BoundRequirement(
            **{
                "check_id": "executable.cases",
                "permitted": ("verifier.subprocess", "verifier.container"),
                name: value,
            }
        )
        moved = a_snapshot(
            requirements=(
                BoundRequirement(check_id="structural.syntax", permitted=("swarm.structural",)),
                changed,
            )
        )
        assert snapshot_digest(moved) != baseline, name


# ---------------------------------------------------------------------------
# 3. the specific forgeries the encoding refuses
# ---------------------------------------------------------------------------


def test_type_tags_keep_lookalike_values_apart():
    """``True``, ``1`` and ``"1"`` are three different claims."""

    assert snap.encode_value(True) != snap.encode_value(1)
    assert snap.encode_value(1) != snap.encode_value("1")
    assert snap.encode_value(None) != snap.encode_value("")
    assert snap.encode_value(None) != snap.encode_value(())
    assert snap.encode_value(()) != snap.encode_value("")


def test_a_sequence_cannot_be_confused_with_its_concatenation():
    """``("a", "b")`` and ``("ab",)`` are different permitted sets."""

    assert snap.encode_value(("a", "b")) != snap.encode_value(("ab",))
    assert snap.encode_value(("a", "b")) != snap.encode_value(("a", "b", ""))


def test_a_value_cannot_forge_a_field_boundary():
    """A value carrying the next field's name must not shift the parse.

    Note where the defence actually sits, because it is two layers and only one
    of them is the encoding: the NUL-carrying version of this attack never
    reaches the encoder at all, because ``_identity`` refuses NUL at
    construction. What the LENGTH PREFIXES defend is the rest of it — a value
    that legitimately contains the next field's name.
    """

    with pytest.raises(SnapshotError, match="cannot contain NUL"):
        a_snapshot(policy_id="baseline-v1\x00policy_digest")

    smuggled = a_snapshot(policy_id="baseline-v1policy_digest")
    assert snapshot_digest(smuggled) != snapshot_digest(a_snapshot())

    # And the property under the prefixes, stated directly: where one value ends
    # and the next begins cannot be moved by the bytes inside either.
    assert _lp(b"ab") + _lp(b"c") != _lp(b"a") + _lp(b"bc")


def test_a_requirement_cannot_collide_with_a_plain_string():
    """The record tag is what keeps a requirement and a string apart."""

    requirement = BoundRequirement(check_id="c", permitted=("i",))
    assert snap.encode_value(requirement) != snap.encode_value("c")
    assert snap.encode_value((requirement,)) != snap.encode_value(("c",))


def test_an_unsupported_type_raises_rather_than_being_stringified():
    with pytest.raises(TypeError):
        snap.encode_value(["a", "list"])
    with pytest.raises(TypeError):
        snap.encode_value({"a": "dict"})
    with pytest.raises(TypeError):
        snap.encode_value(1.5)
    with pytest.raises(TypeError):
        snap.encode_value(b"bytes")


# ---------------------------------------------------------------------------
# 4. canonical by construction — one representation per meaning
# ---------------------------------------------------------------------------


def test_requirement_order_does_not_change_the_digest():
    """Two resolvers that produced the same set in different order mean the same
    thing, so they must produce the same claim."""

    forward = a_snapshot()
    backward = a_snapshot(requirements=tuple(reversed(forward.requirements)))
    assert snapshot_digest(backward) == snapshot_digest(forward)


def test_permitted_order_does_not_change_the_digest():
    a = BoundRequirement(check_id="c", permitted=("x", "y"))
    b = BoundRequirement(check_id="c", permitted=("y", "x"))
    assert snap.encode_value(a) == snap.encode_value(b)


def test_duplicates_are_refused_rather_than_collapsed():
    """Refusing is what keeps one canonical form per requirement. Collapsing
    would silently accept two spellings of one policy."""

    with pytest.raises(SnapshotError, match="more than once"):
        BoundRequirement(check_id="c", permitted=("x", "x"))
    with pytest.raises(SnapshotError, match="more than once"):
        a_snapshot(
            requirements=(
                BoundRequirement(check_id="same", permitted=("x",)),
                BoundRequirement(check_id="same", permitted=("y",)),
            )
        )


def test_a_requirement_permitting_nothing_is_refused():
    """A requirement no implementation can satisfy is a policy error, not a
    permanently-failing check that quietly blocks everything."""

    with pytest.raises(SnapshotError, match="permits no implementation"):
        BoundRequirement(check_id="c", permitted=())


def test_a_string_is_not_accepted_as_a_permitted_set():
    """``permitted="verifier.subprocess"`` would otherwise become a tuple of
    single characters."""

    with pytest.raises(SnapshotError, match="not a string"):
        BoundRequirement(check_id="c", permitted="verifier.subprocess")


def test_identities_with_invisible_edges_are_refused():
    for bad in ("", "   ", " leading", "trailing ", "has\x00nul"):
        with pytest.raises(SnapshotError):
            BoundRequirement(check_id=bad, permitted=("x",))
        with pytest.raises(SnapshotError):
            BoundRequirement(check_id="c", permitted=(bad,))
        with pytest.raises(SnapshotError):
            a_snapshot(policy_id=bad)


def test_a_raw_tuple_cannot_stand_in_for_a_requirement():
    """A plain tuple would bypass BoundRequirement's normalisation, which is
    where the canonical form comes from."""

    with pytest.raises(SnapshotError, match="must be a BoundRequirement"):
        a_snapshot(requirements=(("check", ("impl",)),))


def test_an_unknown_action_class_is_refused():
    """An unrecognised class must never silently resolve to 'no requirements
    apply' — which is the omission attack wearing a typo."""

    with pytest.raises(SnapshotError, match="not a known action class"):
        a_snapshot(action_class="code.exec")
    assert "migration.execute" in ACTION_CLASSES


# ---------------------------------------------------------------------------
# 5. the accessors say what they mean
# ---------------------------------------------------------------------------


def test_permitted_for_reports_absence_as_absence():
    """``None`` means this snapshot requires no such check. It is not a wildcard,
    and a caller that read it as one would have invented a requirement."""

    snapshot = a_snapshot()
    assert snapshot.permitted_for("executable.cases") == (
        "verifier.container",
        "verifier.subprocess",
    )
    assert snapshot.permitted_for("nobody.requires.this") is None
    assert snapshot.check_ids == ("executable.cases", "structural.syntax")
