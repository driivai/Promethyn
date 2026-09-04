"""The verifier's own void-guard check: couldn't-verify is never verified-clean.

The ledger's integrity check is itself a guard, and a guard that answers "valid"
when it could not actually run is the exact failure this project exists to name —
applied, here, to the thing doing the naming. EX-1 draws the distinction for
verdicts (``Unavailable`` carries no verdict); this file holds the chain verifier
to the same standard.

Every way the check can fail to run is exercised: the file is missing, is not a
database, is truncated mid-page, has been corrupted, holds an entry whose payload
is not decodable, or is missing a field the hash is computed over. Each must come
back ``NOT_VERIFIABLE`` — distinct from ``VALID`` and distinct from ``BROKEN`` —
and ``ok`` must be False for all of them.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from prometheus_protocol.core.errors import StateError
from prometheus_protocol.ledger.audit_chain import (
    BROKEN,
    NOT_VERIFIABLE,
    VALID,
    verify_rows,
)
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger, verify_ledger_file

CREATED_AT = "2026-01-01T00:00:00Z"


def _healthy(path: Path, entries: int = 3) -> None:
    ledger = SqliteLedger(path)
    for index in range(entries):
        ledger.record_chained(
            event="authorize", subject="db://appdb",
            payload={"step": index}, created_at=CREATED_AT,
        )
    ledger.close()


# ---------------------------------------------------------------------------
# A healthy ledger really does verify — else everything below is vacuous
# ---------------------------------------------------------------------------


def test_a_healthy_ledger_verifies(tmp_path):
    path = tmp_path / "ledger.db"
    _healthy(path)
    result = verify_ledger_file(path)
    assert result.status == VALID and result.ok
    assert result.length == 3


# ---------------------------------------------------------------------------
# Unrunnable conditions -> NOT_VERIFIABLE, never VALID
# ---------------------------------------------------------------------------


def test_a_missing_file_is_not_verifiable(tmp_path):
    result = verify_ledger_file(tmp_path / "absent.db")
    assert result.status == NOT_VERIFIABLE
    assert not result.ok
    assert "no ledger file" in result.detail


def test_a_file_that_is_not_a_database_is_not_verifiable(tmp_path):
    path = tmp_path / "garbage.db"
    path.write_text("this is not a sqlite database", encoding="utf-8")
    result = verify_ledger_file(path)
    assert result.status == NOT_VERIFIABLE and not result.ok


def test_a_truncated_database_is_not_verifiable(tmp_path):
    path = tmp_path / "ledger.db"
    _healthy(path)
    raw = path.read_bytes()
    path.write_bytes(raw[: len(raw) // 3])
    result = verify_ledger_file(path)
    assert result.status == NOT_VERIFIABLE and not result.ok


def test_a_corrupted_database_is_not_verifiable(tmp_path):
    path = tmp_path / "ledger.db"
    _healthy(path)
    raw = bytearray(path.read_bytes())
    for offset in range(2000, min(len(raw), 6000)):
        raw[offset] = 0
    path.write_bytes(bytes(raw))
    result = verify_ledger_file(path)
    assert result.status == NOT_VERIFIABLE and not result.ok


def test_a_directory_in_place_of_a_ledger_is_not_verifiable(tmp_path):
    directory = tmp_path / "ledger.db"
    directory.mkdir()
    result = verify_ledger_file(directory)
    assert result.status == NOT_VERIFIABLE and not result.ok


def test_a_ledger_path_that_is_not_a_regular_file_is_not_verifiable(tmp_path):
    """A named pipe stands in for "the path exists but cannot be read as a
    database". Chosen over a ``chmod 000`` file deliberately: root bypasses
    permission bits, so that version would SKIP for a privileged runner — and a
    security test that skips is the void guard this sprint is closing.
    """

    path = tmp_path / "ledger.db"
    import os as os_module

    try:
        os_module.mkfifo(path)
    except (OSError, AttributeError):  # pragma: no cover - platform without FIFOs
        pytest.skip("cannot create a FIFO here")
    result = verify_ledger_file(path)
    assert result.status == NOT_VERIFIABLE and not result.ok


def test_opening_an_unopenable_ledger_still_fails_closed(tmp_path):
    """The lower-level constructor raises rather than returning a ledger that
    would verify as empty. Both shapes are acceptable; silently VALID is not."""

    path = tmp_path / "garbage.db"
    path.write_text("not a database", encoding="utf-8")
    with pytest.raises(StateError):
        SqliteLedger(path)


# ---------------------------------------------------------------------------
# Row-level unverifiable conditions, distinct from a genuine break
# ---------------------------------------------------------------------------


def _rows(path: Path) -> list[dict]:
    ledger = SqliteLedger(path)
    try:
        return ledger.chained_events()
    finally:
        ledger.close()


def test_an_undecodable_payload_is_not_verifiable_not_broken(tmp_path):
    path = tmp_path / "ledger.db"
    _healthy(path)
    rows = _rows(path)
    rows[1]["payload"] = "{not json"
    result = verify_rows(rows)
    assert result.status == NOT_VERIFIABLE, result.render()
    assert not result.ok


@pytest.mark.parametrize("field", ["seq", "entry_hash", "prev_hash", "payload"])
def test_a_missing_field_is_not_verifiable(tmp_path, field):
    path = tmp_path / "ledger.db"
    _healthy(path)
    rows = _rows(path)
    rows[1][field] = None
    result = verify_rows(rows)
    assert result.status == NOT_VERIFIABLE, result.render()
    assert not result.ok


@pytest.mark.parametrize("field", ["created_at", "event", "subject"])
def test_a_none_hashed_field_is_not_verifiable_rather_than_a_crash(tmp_path, field):
    """These are hashed but not separately null-checked, so a ``None`` reaches
    the hash function. It must be reported, not raised."""

    path = tmp_path / "ledger.db"
    _healthy(path)
    rows = _rows(path)
    rows[1][field] = None
    result = verify_rows(rows)
    assert result.status == NOT_VERIFIABLE, result.render()
    assert not result.ok


def test_a_real_edit_is_BROKEN_not_merely_unverifiable(tmp_path):
    """The distinction has to cut both ways: a chain that CAN be checked and
    fails is ``BROKEN``, not softened into "could not verify"."""

    path = tmp_path / "ledger.db"
    _healthy(path)
    rows = _rows(path)
    rows[1]["payload"] = '{"step":99}'  # decodable, but not what was hashed
    result = verify_rows(rows)
    assert result.status == BROKEN, result.render()
    assert not result.ok


def test_not_verifiable_is_never_ok(tmp_path):
    """One assertion for the property the whole file exists to protect."""

    path = tmp_path / "ledger.db"
    _healthy(path)
    rows = _rows(path)
    rows[0]["entry_hash"] = None
    for result in (
        verify_rows(rows),
        verify_ledger_file(tmp_path / "absent.db"),
    ):
        assert result.status == NOT_VERIFIABLE
        assert result.ok is False
        assert result.status != VALID
