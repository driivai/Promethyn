"""Unit tests for the TrustStore adapters."""

from __future__ import annotations

from prometheus_protocol.core.models import Tier
from prometheus_protocol.verifier.store import InMemoryTrustStore, SqliteTrustStore
from prometheus_protocol.verifier.trust import TrustStats


def _stats(vid: str = "v") -> TrustStats:
    return TrustStats(verifier_id=vid, tier=Tier.SOFT, tp=3, fn=1, tn=2, fp=4)


def test_in_memory_get_put_all():
    store = InMemoryTrustStore()
    assert store.get("v") is None
    store.put("v", _stats())
    assert store.get("v") == _stats()
    assert store.all() == {"v": _stats()}


def test_sqlite_round_trip_and_persistence(tmp_path):
    path = tmp_path / "trust.db"
    store = SqliteTrustStore(path)
    store.put("v", _stats())
    store.close()

    # Reopen: trust survives the restart, tier prior included.
    reopened = SqliteTrustStore(path)
    restored = reopened.get("v")
    assert restored == _stats()
    assert restored.tier == Tier.SOFT
    assert reopened.all() == {"v": _stats()}
    reopened.close()


def test_sqlite_put_is_an_upsert(tmp_path):
    store = SqliteTrustStore(tmp_path / "trust.db")
    store.put("v", TrustStats(verifier_id="v", tier=Tier.SOFT, tp=1))
    store.put("v", TrustStats(verifier_id="v", tier=Tier.SOFT, tp=9))
    assert store.get("v").tp == 9
    assert len(store.all()) == 1
    store.close()
