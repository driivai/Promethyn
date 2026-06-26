"""Persistence port for verifier trust state, plus two adapters.

The port keeps the trust math (in :mod:`prometheus_protocol.verifier.trust`)
free of I/O. Adapters persist the confusion counts and the tier prior so a
verifier's earned trust survives restarts.
"""

from __future__ import annotations

import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path

from prometheus_protocol.core.models import Tier
from prometheus_protocol.verifier.trust import TrustStats


class TrustStore(ABC):
    """A keyed store of :class:`TrustStats`, one entry per verifier id."""

    @abstractmethod
    def get(self, verifier_id: str) -> TrustStats | None:
        raise NotImplementedError

    @abstractmethod
    def put(self, verifier_id: str, stats: TrustStats) -> None:
        raise NotImplementedError

    @abstractmethod
    def all(self) -> dict[str, TrustStats]:
        raise NotImplementedError


class InMemoryTrustStore(TrustStore):
    """Non-persistent adapter backed by a dictionary."""

    def __init__(self) -> None:
        self._stats: dict[str, TrustStats] = {}

    def get(self, verifier_id: str) -> TrustStats | None:
        return self._stats.get(verifier_id)

    def put(self, verifier_id: str, stats: TrustStats) -> None:
        self._stats[verifier_id] = stats

    def all(self) -> dict[str, TrustStats]:
        return dict(self._stats)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS verifier_trust (
    verifier_id TEXT PRIMARY KEY,
    tier        TEXT    NOT NULL,
    tp          INTEGER NOT NULL,
    fn          INTEGER NOT NULL,
    tn          INTEGER NOT NULL,
    fp          INTEGER NOT NULL
);
"""


class SqliteTrustStore(TrustStore):
    """SQLite-backed adapter. Pass ``":memory:"`` for an ephemeral instance."""

    def __init__(self, path: Path | str = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def get(self, verifier_id: str) -> TrustStats | None:
        row = self._conn.execute(
            "SELECT * FROM verifier_trust WHERE verifier_id = ?", (verifier_id,)
        ).fetchone()
        return None if row is None else _row_to_stats(row)

    def put(self, verifier_id: str, stats: TrustStats) -> None:
        self._conn.execute(
            """
            INSERT INTO verifier_trust (verifier_id, tier, tp, fn, tn, fp)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(verifier_id) DO UPDATE SET
                tier = excluded.tier,
                tp = excluded.tp,
                fn = excluded.fn,
                tn = excluded.tn,
                fp = excluded.fp
            """,
            (
                verifier_id,
                stats.tier.value,
                stats.tp,
                stats.fn,
                stats.tn,
                stats.fp,
            ),
        )
        self._conn.commit()

    def all(self) -> dict[str, TrustStats]:
        rows = self._conn.execute(
            "SELECT * FROM verifier_trust ORDER BY verifier_id"
        ).fetchall()
        return {row["verifier_id"]: _row_to_stats(row) for row in rows}

    def close(self) -> None:
        self._conn.close()


def _row_to_stats(row: sqlite3.Row) -> TrustStats:
    return TrustStats(
        verifier_id=row["verifier_id"],
        tier=Tier(row["tier"]),
        tp=row["tp"],
        fn=row["fn"],
        tn=row["tn"],
        fp=row["fp"],
    )
