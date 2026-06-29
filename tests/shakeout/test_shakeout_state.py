"""Shakeout repros for F2 (corrupt state) — RED BY DESIGN — plus a healthy
persistence smoke test. See ``docs/shakeout-report.md`` (F2)."""

from __future__ import annotations

import pytest

from prometheus_protocol.core.models import Tier
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.verifier.store import SqliteTrustStore
from prometheus_protocol.verifier.trust import TrustStats


@pytest.mark.xfail(
    strict=True,
    reason="F2: a corrupt trust.db raises a raw sqlite3.DatabaseError; it should "
    "raise a clear domain error naming the file",
)
def test_corrupt_trust_store_errors_clearly(tmp_path):
    path = tmp_path / "trust.db"
    path.write_bytes(b"this is not a database " * 64)
    with pytest.raises(ValueError):  # desired: a clear, typed domain error
        SqliteTrustStore(path)


@pytest.mark.xfail(
    strict=True,
    reason="F2: a corrupt ledger.db raises a raw sqlite3.DatabaseError; it should "
    "raise a clear domain error naming the file",
)
def test_corrupt_ledger_errors_clearly(tmp_path):
    path = tmp_path / "ledger.db"
    path.write_bytes(b"garbage" * 128)
    with pytest.raises(ValueError):
        SqliteLedger(path)


def test_trust_calibration_persists_across_restart(tmp_path):
    path = tmp_path / "trust.db"
    stats = TrustStats("model-judge", Tier.SOFT, tp=5, tn=5)

    store = SqliteTrustStore(path)
    store.put("model-judge", stats)
    store.close()

    reopened = SqliteTrustStore(path)
    try:
        assert reopened.get("model-judge") == stats
    finally:
        reopened.close()
