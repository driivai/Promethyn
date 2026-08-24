"""Regression: receipt comparison must not depend on the driver's return type.

A PostgreSQL ``text`` column can come back as ``str`` **or** as ``bytes``
depending on the driver build and connection settings. ``bytes != str`` is
silently True in Python — never an error — so a receipt check written against
whichever type the local driver happened to return is a check that passes for the
wrong reason (a void guard), and on the other driver it misclassifies a COMMITTED
migration as a conflict during crash reconciliation.

These tests drive the REAL ``postgres_receipt_lookup`` / ``postgres_executor``
with an injected fake driver that returns each representation, so they fail if
anyone reintroduces a raw comparison — regardless of which driver is installed
locally. No live database required.
"""

from __future__ import annotations

import sys
import types

import pytest

from prometheus_protocol.chokepoint import (
    RECEIPT_COMMITTED,
    RECEIPT_CONFLICT,
    DbTarget,
)
from prometheus_protocol.chokepoint.runner import (
    _receipt_text,
    postgres_receipt_lookup,
)

EXECUTION_ID = "a" * 64
ARTIFACT_SHA = "b" * 64


def _target() -> DbTarget:
    return DbTarget(host="127.0.0.1", port=5432, dbname="appdb",
                    user="migrator", password="secret", schema="public")


class _FakeCursor:
    """Replays a scripted sequence of fetchone() results for the lookup query."""

    def __init__(self, rows: list[object]) -> None:
        self._rows = list(rows)
        self.executed: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None, **kwargs):
        self.executed.append(sql)

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None


class _FakeConnection:
    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self):
        return self._cursor

    def commit(self):
        pass


def _install_fake_driver(monkeypatch, receipt_row: object) -> None:
    """Inject a psycopg stand-in whose receipt row uses a chosen representation.

    The scripted rows mirror the real lookup: advisory lock acquired, the receipt
    relation exists, then the receipt row itself.
    """

    cursor = _FakeCursor([(True,), ("promethyn_internal.migration_receipts",), receipt_row])
    module = types.ModuleType("psycopg")
    module.Error = type("Error", (Exception,), {})
    module.connect = lambda **kwargs: _FakeConnection(cursor)
    monkeypatch.setitem(sys.modules, "psycopg", module)


# -- the normalization helper itself -----------------------------------------

def test_receipt_text_normalizes_both_representations():
    assert _receipt_text("abc") == "abc"
    assert _receipt_text(b"abc") == "abc"
    assert _receipt_text(bytearray(b"abc")) == "abc"
    assert _receipt_text(memoryview(b"abc")) == "abc"


def test_receipt_text_rejects_undecodable_and_unexpected_types():
    # Never equal to an expected str → the caller fails closed.
    assert _receipt_text(b"\xff\xfe") is None
    assert _receipt_text(None) is None
    assert _receipt_text(12345) is None


# -- the real lookup, under each driver representation ------------------------

@pytest.mark.parametrize("representation", ["str", "bytes"])
def test_committed_receipt_recognized_regardless_of_driver_type(monkeypatch, representation):
    """A matching receipt is COMMITTED whether the driver returns str or bytes.

    Without normalization the ``bytes`` case returns RECEIPT_CONFLICT — a
    committed migration misreported during crash reconciliation.
    """

    target = _target()
    canonical = target.identity.canonical
    if representation == "bytes":
        row = (ARTIFACT_SHA.encode(), canonical.encode(), "2026-01-01 00:00:00+00")
    else:
        row = (ARTIFACT_SHA, canonical, "2026-01-01 00:00:00+00")
    _install_fake_driver(monkeypatch, row)

    status = postgres_receipt_lookup(EXECUTION_ID, ARTIFACT_SHA, target)

    assert status.state == RECEIPT_COMMITTED, (
        f"{representation} receipt must be recognized as committed; "
        "a bytes-vs-str comparison was reintroduced"
    )


@pytest.mark.parametrize("representation", ["str", "bytes"])
def test_genuine_mismatch_still_conflicts(monkeypatch, representation):
    """Normalization must not paper over a REAL mismatch (the fix isn't 'always equal')."""

    target = _target()
    other_sha = "c" * 64
    canonical = target.identity.canonical
    if representation == "bytes":
        row = (other_sha.encode(), canonical.encode(), "2026-01-01 00:00:00+00")
    else:
        row = (other_sha, canonical, "2026-01-01 00:00:00+00")
    _install_fake_driver(monkeypatch, row)

    status = postgres_receipt_lookup(EXECUTION_ID, ARTIFACT_SHA, target)

    assert status.state == RECEIPT_CONFLICT


def test_target_mismatch_still_conflicts_as_bytes(monkeypatch):
    """A receipt for a DIFFERENT target must conflict even when returned as bytes."""

    target = _target()
    row = (
        ARTIFACT_SHA.encode(),
        b'{"database":"otherdb","host":"10.0.0.9","port":5432,"schema":"public","user":"migrator"}',
        "2026-01-01 00:00:00+00",
    )
    _install_fake_driver(monkeypatch, row)

    status = postgres_receipt_lookup(EXECUTION_ID, ARTIFACT_SHA, target)

    assert status.state == RECEIPT_CONFLICT


def test_undecodable_receipt_conflicts_fail_closed(monkeypatch):
    """A corrupt (non-UTF-8) receipt is a mismatch, never silently committed."""

    target = _target()
    row = (b"\xff\xfe" + b"a" * 62, target.identity.canonical.encode(),
           "2026-01-01 00:00:00+00")
    _install_fake_driver(monkeypatch, row)

    status = postgres_receipt_lookup(EXECUTION_ID, ARTIFACT_SHA, target)

    assert status.state == RECEIPT_CONFLICT
