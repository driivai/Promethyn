"""Operability coverage for corrupt persistent state (F2), plus a healthy
persistence smoke test. See ``docs/shakeout-report.md`` (F2).

Originally RED-by-design repros; now green. A corrupt trust store or ledger
raises a typed :class:`StateError` that names the offending file instead of a
raw ``sqlite3.DatabaseError``.
"""

from __future__ import annotations

import pytest

from prometheus_protocol.core.errors import StateError
from prometheus_protocol.core.models import Tier
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.verifier.store import SqliteTrustStore
from prometheus_protocol.verifier.trust import TrustStats


def test_corrupt_trust_store_errors_clearly(tmp_path):
    path = tmp_path / "trust.db"
    path.write_bytes(b"this is not a database " * 64)
    with pytest.raises(StateError) as excinfo:
        SqliteTrustStore(path)
    # The message names the file so an operator knows what to remove/repair.
    assert "trust.db" in str(excinfo.value)
    # It is also a domain error (and a ValueError is not raised raw from sqlite3).
    assert excinfo.value.__cause__ is not None


def test_corrupt_ledger_errors_clearly(tmp_path):
    path = tmp_path / "ledger.db"
    path.write_bytes(b"garbage" * 128)
    with pytest.raises(StateError) as excinfo:
        SqliteLedger(path)
    assert "ledger.db" in str(excinfo.value)
    assert excinfo.value.__cause__ is not None


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
