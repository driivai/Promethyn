"""The genesis rewrite: the one attack a bare hash chain cannot see.

Attacker 3 has read/write access to the ledger *file* — a backup process, a
misconfigured mount, a lower-privileged account — but not to the whole host. The
chain already catches edits, deletions and reorders of interior entries, because
each entry commits to its predecessor. It cannot catch an attacker who rewrites
**every** entry: they recompute the chain from genesis and every link checks out.
``docs/ledger-integrity.md`` has always said so.

The only thing that catches that is a copy of the tip kept where the attacker
cannot write it. The primitive existed; nothing stored one. These tests hold the
wiring to account, and — just as importantly — hold the *honest limit* to
account: the last test here proves the attack SUCCEEDS when the attacker also
controls the anchor, because pretending otherwise would be the void guard this
project is named for.

Every test performs the rewrite for real: the chain is rebuilt with correct
hashes, and its internal consistency is asserted before the anchor is consulted.
A test where the forged chain was merely broken would prove nothing.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from prometheus_protocol.ledger.audit_chain import (
    BROKEN,
    GENESIS_ROOT,
    NOT_VERIFIABLE,
    TRUNCATED,
    VALID,
    ChainTip,
    canonical_json,
    entry_hash,
    verify_rows,
)
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger, verify_ledger_file
from prometheus_protocol.ledger.tip_anchor import (
    AnchorRewind,
    AnchorUnavailable,
    FileTipAnchor,
)

CREATED_AT = "2026-01-01T00:00:00Z"


def _ledger(tmp_path: Path, *, anchored: bool = True):
    anchor = FileTipAnchor(tmp_path / "anchor" / "tip.json") if anchored else None
    return SqliteLedger(tmp_path / "ledger.db", tip_anchor=anchor), anchor


def _append(ledger, n: int = 3) -> None:
    for index in range(n):
        ledger.record_chained(
            event="authorize", subject="db://appdb",
            payload={"step": index}, created_at=CREATED_AT,
        )


def _rewrite_chain_from_genesis(path: Path, payloads: list[dict]) -> None:
    """The attack: replace every row with a fresh, internally-consistent chain.

    This is what an adversary with write access to the file does — not a
    corruption, a *substitution*. The rebuilt chain verifies perfectly on its own
    terms, which is exactly why an out-of-band anchor is the only thing that can
    tell the difference.
    """

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("DELETE FROM audit_chain")
        prev = GENESIS_ROOT
        for seq, payload in enumerate(payloads, start=1):
            canonical = canonical_json(payload)
            digest = entry_hash(
                seq=seq, created_at=CREATED_AT, event="authorize",
                subject="db://appdb", payload_canonical=canonical, prev_hash=prev,
            )
            conn.execute(
                "INSERT INTO audit_chain (seq, created_at, event, subject, payload, "
                "prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (seq, CREATED_AT, "authorize", "db://appdb", canonical, prev, digest),
            )
            prev = digest
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# The anchor is actually written — the audit's "available, not operational"
# ---------------------------------------------------------------------------


def test_appending_writes_the_anchor(tmp_path):
    ledger, anchor = _ledger(tmp_path)
    assert anchor.read() is None, "an anchor exists before anything was appended"
    _append(ledger, 3)
    tip = anchor.read()
    assert tip is not None, "appending did not anchor the tip"
    assert tip.seq == 3
    assert tip.entry_hash == ledger.chain_tip().entry_hash
    ledger.close()


def test_verify_uses_the_configured_anchor_without_being_asked(tmp_path):
    """Operational, not merely available: an auditor cannot forget to pass it."""

    ledger, _ = _ledger(tmp_path)
    _append(ledger, 3)
    assert ledger.verify_chain().status == VALID
    ledger.close()


# ---------------------------------------------------------------------------
# The genesis rewrite
# ---------------------------------------------------------------------------


def test_a_full_genesis_rewrite_is_detected_by_the_anchor(tmp_path):
    ledger, anchor = _ledger(tmp_path)
    _append(ledger, 3)
    honest_tip = anchor.read()
    ledger.close()

    _rewrite_chain_from_genesis(
        tmp_path / "ledger.db",
        [{"step": 0}, {"step": 1}, {"forged": "the migration never happened"}],
    )

    # The forged chain is internally perfect — this is the premise of the attack.
    reopened = SqliteLedger(tmp_path / "ledger.db")
    unanchored = verify_rows(reopened.chained_events())
    assert unanchored.status == VALID, (
        f"the forged chain was not internally consistent, so this test would "
        f"prove nothing: {unanchored.render()}"
    )
    reopened.close()

    # With the anchor, the substitution is caught.
    anchored = verify_ledger_file(tmp_path / "ledger.db", tip_anchor=anchor)
    assert anchored.status == BROKEN, anchored.render()
    assert "anchored" in anchored.detail
    # And the substitution really did change the tip — otherwise the anchor
    # would have matched and the detection above would be vacuous.
    forged = SqliteLedger(tmp_path / "ledger.db")
    try:
        assert forged.chain_tip().entry_hash != honest_tip.entry_hash
    finally:
        forged.close()


def test_deleting_the_ledger_is_detected_by_the_anchor(tmp_path):
    """The cheapest attack of all: remove the file. SQLite recreates it empty,
    and an empty chain is internally consistent, so without an anchor this reads
    as ``valid (0 entries)``."""

    ledger, anchor = _ledger(tmp_path)
    _append(ledger, 3)
    ledger.close()
    (tmp_path / "ledger.db").unlink()

    unanchored = SqliteLedger(tmp_path / "ledger.db")
    assert unanchored.verify_chain().status == VALID, "premise check"
    assert unanchored.verify_chain().length == 0
    unanchored.close()

    anchored = verify_ledger_file(tmp_path / "ledger.db", tip_anchor=anchor)
    assert anchored.status == TRUNCATED, anchored.render()


def test_truncating_the_tail_is_detected_by_the_anchor(tmp_path):
    ledger, anchor = _ledger(tmp_path)
    _append(ledger, 5)
    ledger.close()

    conn = sqlite3.connect(tmp_path / "ledger.db")
    conn.execute("DELETE FROM audit_chain WHERE seq > 3")
    conn.commit()
    conn.close()

    assert verify_ledger_file(tmp_path / "ledger.db").status == VALID, "premise check"
    anchored = verify_ledger_file(tmp_path / "ledger.db", tip_anchor=anchor)
    assert anchored.status == TRUNCATED, anchored.render()


def test_honest_appends_past_the_anchor_stay_valid(tmp_path):
    """The anchor must not cry wolf: normal growth is not tampering."""

    ledger, anchor = _ledger(tmp_path)
    _append(ledger, 3)
    _append(ledger, 4)
    assert ledger.verify_chain().status == VALID
    assert anchor.read().seq == 7
    ledger.close()


# ---------------------------------------------------------------------------
# The honest limit: an attacker who also owns the anchor
# ---------------------------------------------------------------------------


def test_an_attacker_who_also_controls_the_anchor_is_NOT_detected(tmp_path):
    """Stated as a passing test because it is the residual, not a defect.

    If the anchor shares the ledger's medium and permissions, the attacker
    rewrites both and the substitution is invisible. This is the whole reason
    the anchor's value is a *deployment* property — it must live in a trust
    domain the ledger-file adversary cannot write. An anchor sitting next to the
    ledger is theatre, and this test records that plainly rather than letting the
    feature imply a protection it does not have.
    """

    ledger, anchor = _ledger(tmp_path)
    _append(ledger, 3)
    ledger.close()

    forged = [{"step": 0}, {"step": 1}, {"forged": "the migration never happened"}]
    _rewrite_chain_from_genesis(tmp_path / "ledger.db", forged)

    # The attacker rewrites the anchor too — trivially, since it is a file they
    # can reach. (Written directly, bypassing the monotonic guard, exactly as an
    # attacker with filesystem access would.)
    forged_tip = SqliteLedger(tmp_path / "ledger.db").chain_tip()
    anchor.path.write_text(
        json.dumps({"version": 1, "seq": forged_tip.seq, "entry_hash": forged_tip.entry_hash}),
        encoding="utf-8",
    )

    result = verify_ledger_file(tmp_path / "ledger.db", tip_anchor=anchor)
    assert result.status == VALID, (
        "this documents the residual: with the anchor on the same medium the "
        "rewrite is undetectable, and the honest claim is that the anchor helps "
        "only when it is genuinely out of reach"
    )


# ---------------------------------------------------------------------------
# The anchor refuses to erase its own evidence
# ---------------------------------------------------------------------------


def test_the_anchor_refuses_to_move_backwards(tmp_path):
    anchor = FileTipAnchor(tmp_path / "tip.json")
    anchor.write(ChainTip(seq=5, entry_hash="a" * 64))
    with pytest.raises(AnchorRewind):
        anchor.write(ChainTip(seq=3, entry_hash="b" * 64))
    assert anchor.read().seq == 5, "the rejected write still altered the anchor"


def test_the_anchor_refuses_a_different_hash_at_the_same_seq(tmp_path):
    anchor = FileTipAnchor(tmp_path / "tip.json")
    anchor.write(ChainTip(seq=5, entry_hash="a" * 64))
    with pytest.raises(AnchorRewind):
        anchor.write(ChainTip(seq=5, entry_hash="b" * 64))


def test_a_rewound_ledger_cannot_silently_re_anchor(tmp_path):
    """End to end: after a truncation, the next honest append must not quietly
    write a lower tip and destroy the evidence."""

    ledger, anchor = _ledger(tmp_path)
    _append(ledger, 5)
    ledger.close()

    conn = sqlite3.connect(tmp_path / "ledger.db")
    conn.execute("DELETE FROM audit_chain WHERE seq > 2")
    conn.commit()
    conn.close()

    reopened, _ = _ledger(tmp_path)
    with pytest.raises(AnchorRewind):
        _append(reopened, 1)
    assert anchor.read().seq == 5, "the anchor was rewound by an append"
    reopened.close()


# ---------------------------------------------------------------------------
# Couldn't-verify is not verified-clean
# ---------------------------------------------------------------------------


def test_an_unreadable_anchor_is_not_verifiable_not_valid(tmp_path):
    ledger, anchor = _ledger(tmp_path)
    _append(ledger, 3)
    anchor.path.write_text("{ this is not json", encoding="utf-8")

    result = ledger.verify_chain()
    assert result.status == NOT_VERIFIABLE, result.render()
    assert not result.ok
    ledger.close()


@pytest.mark.parametrize(
    "body",
    ['{"version": 99, "seq": 1, "entry_hash": "' + "a" * 64 + '"}',
     '{"version": 1, "seq": 0, "entry_hash": "' + "a" * 64 + '"}',
     '{"version": 1, "seq": 1, "entry_hash": "short"}',
     '{"version": 1, "seq": 1, "entry_hash": "' + "z" * 64 + '"}',
     '[]'],
    ids=["bad-version", "seq-zero", "short-hash", "non-hex-hash", "not-an-object"],
)
def test_a_malformed_anchor_is_reported_not_ignored(tmp_path, body):
    """A malformed anchor must never degrade to "verify without one" — that
    would turn a tampered anchor into a clean bill of health."""

    ledger, anchor = _ledger(tmp_path)
    _append(ledger, 2)
    anchor.path.write_text(body, encoding="utf-8")
    with pytest.raises(AnchorUnavailable):
        anchor.read()
    assert ledger.verify_chain().status == NOT_VERIFIABLE
    ledger.close()


def test_a_missing_anchor_is_absence_not_corruption(tmp_path):
    """No anchor yet is a legitimate state (nothing has been appended)."""

    anchor = FileTipAnchor(tmp_path / "never-written.json")
    assert anchor.read() is None


def test_the_anchor_file_is_owner_only(tmp_path):
    anchor = FileTipAnchor(tmp_path / "tip.json")
    anchor.write(ChainTip(seq=1, entry_hash="a" * 64))
    import stat as stat_module

    mode = stat_module.S_IMODE(anchor.path.stat().st_mode)
    assert mode & 0o077 == 0, f"anchor is group/other accessible: {mode:04o}"
