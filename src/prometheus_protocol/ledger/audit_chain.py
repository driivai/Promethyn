"""A minimal tamper-EVIDENT hash chain for the audit ledger.

PROM-AUDIT found the ledger "append-only by convention only" — a record that
claimed an integrity it did not have (a void guard in Promethyn's own product).
This closes it: each entry commits to the hash of the prior entry, so any
retroactive edit, deletion, or reorder of an interior entry breaks every link
after it and is caught by :func:`verify_rows`.

This is tamper-EVIDENCE, not tamper-proofing. See the DOES / DOES NOT statement
in ``docs/ledger-integrity.md``; the load-bearing honesty is that a bare hash
chain stored in one file cannot, on its own, detect a full rewrite from genesis
or a pure tail-truncation — only an externally anchored tip can. Overclaiming
here would itself be the void guard we are closing, so the limit is named, and
:func:`verify_rows` accepts an ``expected_tip`` anchor that turns truncation into
a detected condition.

Canonical encoding (pinned; ambiguity would mean two valid chains for one
history). The entry hash is::

    sha256( DOMAIN
            || u64_be(seq)
            || lp(created_at) || lp(event) || lp(subject)
            || lp(canonical_json(payload))
            || lp(prev_hash_bytes) )

where ``lp(x) = u64_be(len(x)) || x`` length-prefixes every variable field (so no
field boundary can be forged by embedding a delimiter), ``u64_be`` is an 8-byte
big-endian integer, ``canonical_json`` is ``json.dumps(sort_keys=True,
separators=(",", ":"), ensure_ascii=True)``, and the genesis entry's ``prev_hash``
is the fixed :data:`GENESIS_ROOT`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

_DOMAIN = b"prom-audit-chain-v1\x00"

#: The fixed, known root the first real entry chains onto. A constant, so an
#: auditor with no prior state can still verify the chain begins correctly.
GENESIS_ROOT = hashlib.sha256(b"prom-audit-chain-v1/genesis").hexdigest()

# Verification statuses. VALID/BROKEN/TRUNCATED are conclusions; NOT_VERIFIABLE
# is the EX-1 distinction — the check could not run (malformed/missing data), so
# it must NOT be read as VALID.
VALID = "valid"
BROKEN = "broken"
TRUNCATED = "truncated"
NOT_VERIFIABLE = "not_verifiable"


def canonical_json(payload: object) -> str:
    """The one canonical serialization of a payload. Deterministic across runs."""

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(8, "big") + b


def entry_hash(
    *,
    seq: int,
    created_at: str,
    event: str,
    subject: str,
    payload_canonical: str,
    prev_hash: str,
) -> str:
    """The hash an entry commits to — over its own content AND the prior hash."""

    preimage = b"".join((
        _DOMAIN,
        int(seq).to_bytes(8, "big"),
        _lp(created_at.encode("utf-8")),
        _lp(event.encode("utf-8")),
        _lp(subject.encode("utf-8")),
        _lp(payload_canonical.encode("utf-8")),
        _lp(bytes.fromhex(prev_hash)),
    ))
    return hashlib.sha256(preimage).hexdigest()


@dataclass(frozen=True)
class ChainTip:
    """An anchor: the seq and hash of a chain's last entry, held out-of-band so
    truncation/rewrite past this point becomes detectable."""

    seq: int
    entry_hash: str


@dataclass(frozen=True)
class ChainVerification:
    """The auditor's verdict. ``ok`` is True only for a fully-verified VALID
    chain; any other status (including NOT_VERIFIABLE) is not-ok, so a chain that
    could not be checked is never mistaken for a clean one."""

    status: str
    length: int
    broken_index: int | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == VALID

    def render(self) -> str:
        if self.status == VALID:
            return f"chain valid ({self.length} entries)"
        where = f" at entry {self.broken_index}" if self.broken_index is not None else ""
        return f"chain {self.status.upper()}{where}: {self.detail}"


def verify_rows(rows: list[dict], *, expected_tip: ChainTip | None = None) -> ChainVerification:
    """Walk the chain in storage order from genesis; report the FIRST failure.

    ``rows`` must be in insertion (id) order — NOT sorted by ``seq`` — so a
    reorder that rewrites the ``seq`` column is still caught as a discontinuity.
    Returns the first broken/not-verifiable link with its index and a specific
    reason, never a bare boolean.
    """

    expected_prev = GENESIS_ROOT
    expected_seq = 1
    anchored_hash: str | None = None
    for row in rows:
        seq = row.get("seq")
        stored_hash = row.get("entry_hash")
        prev_hash = row.get("prev_hash")
        payload_raw = row.get("payload")

        # NOT_VERIFIABLE: a missing/malformed field means the check itself cannot
        # run here — distinct from a mismatch, and never reported as valid.
        if stored_hash is None or prev_hash is None or seq is None or payload_raw is None:
            return ChainVerification(NOT_VERIFIABLE, expected_seq - 1, seq,
                                     "entry has a missing seq/hash/payload field")
        try:
            # Decodability gate only. The hash below commits to the EXACT stored
            # payload bytes, NOT a re-serialization — so any byte-level edit
            # (whitespace, key reorder, or duplicate-key injection that a JSON
            # parser would normalize away) still changes the hash and is caught.
            json.loads(payload_raw)
        except (ValueError, TypeError):
            return ChainVerification(NOT_VERIFIABLE, expected_seq - 1, seq,
                                     "entry payload is not decodable JSON")

        if seq != expected_seq:
            return ChainVerification(
                BROKEN, expected_seq - 1, seq,
                f"seq discontinuity: expected {expected_seq}, found {seq} "
                "(an interior entry was deleted or reordered)")
        if prev_hash != expected_prev:
            return ChainVerification(
                BROKEN, expected_seq - 1, seq,
                f"prev-hash mismatch: entry stores {prev_hash[:16]}…, "
                f"prior entry hashed to {expected_prev[:16]}…")
        try:
            # The hash commits to the EXACT stored payload bytes (payload_raw),
            # not a re-serialization, so a byte-level edit is caught. A None/absent
            # created_at/event/subject or a bad-hex prev_hash raises here
            # (AttributeError included) and is reported NOT_VERIFIABLE — never a
            # crash, never read as valid.
            recomputed = entry_hash(
                seq=seq, created_at=row["created_at"], event=row["event"],
                subject=row["subject"], payload_canonical=payload_raw,
                prev_hash=prev_hash,
            )
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            return ChainVerification(NOT_VERIFIABLE, expected_seq - 1, seq,
                                     f"entry could not be re-hashed: {exc}")
        if recomputed != stored_hash:
            return ChainVerification(
                BROKEN, expected_seq - 1, seq,
                f"content edited: stored hash {stored_hash[:16]}…, "
                f"recomputed {recomputed[:16]}…")

        # Pin the entry AT the anchored seq: its hash must still equal the
        # out-of-band anchor no matter how far the chain has since grown, so a
        # rewrite-then-extend cannot slip past by merely making the chain longer.
        if expected_tip is not None and seq == expected_tip.seq:
            anchored_hash = stored_hash
        expected_prev = stored_hash
        expected_seq += 1

    length = expected_seq - 1

    # Truncation / rewrite is only detectable against an out-of-band anchor.
    if expected_tip is not None:
        if length < expected_tip.seq:
            return ChainVerification(
                TRUNCATED, length, length,
                f"chain ends at seq {length} but the anchored tip is seq "
                f"{expected_tip.seq}: {expected_tip.seq - length} entrie(s) truncated")
        # length >= tip.seq: seqs are contiguous, so an entry with seq == tip.seq
        # was walked and anchored_hash is set. It must still equal the anchored
        # value, else the prefix up to the anchor was rewritten — including a
        # rewrite that then extended the chain past the anchor point.
        if anchored_hash != expected_tip.entry_hash:
            return ChainVerification(
                BROKEN, expected_tip.seq, expected_tip.seq,
                "entry at the anchored seq does not match the anchored tip "
                "(chain rewritten)")

    return ChainVerification(VALID, length, None, "")
