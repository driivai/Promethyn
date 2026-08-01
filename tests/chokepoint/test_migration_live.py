"""Live end-to-end: the brokered runner applies a real migration to a real
PostgreSQL, exactly once, and refuses a replay against the live DB.

Gated on a configured database (``PROM_CHOKEPOINT_PG_DSN`` component env vars).
Without one it SKIPS locally, but under ``PROM_REQUIRE_PG=1`` (set in a CI that
provisions a DB) an absent DB FAILS — so this is never a silently-skipped guard.
"""

from __future__ import annotations

import os
import time

import pytest

from prometheus_protocol.chokepoint import (
    ApprovalAuthority,
    BrokeredMigrationRunner,
    ConsumedApprovals,
    DbTarget,
    MigrationArtifact,
    REPLAY,
    psql_executor,
)
from prometheus_protocol.core.models import Judgment, Verdict

_REQUIRE = (os.environ.get("PROM_REQUIRE_PG", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}


def _target_from_env() -> DbTarget | None:
    host = os.environ.get("PROM_CHOKEPOINT_PG_HOST")
    if not host:
        return None
    return DbTarget(
        host=host,
        port=int(os.environ.get("PROM_CHOKEPOINT_PG_PORT", "5432")),
        dbname=os.environ.get("PROM_CHOKEPOINT_PG_DB", "appdb"),
        user=os.environ.get("PROM_CHOKEPOINT_PG_USER", "migrator"),
        password=os.environ.get("PROM_CHOKEPOINT_PG_PASSWORD", ""),
    )


def _require_db() -> DbTarget:
    target = _target_from_env()
    if target is None:
        if _REQUIRE:
            pytest.fail("PROM_REQUIRE_PG=1 but PROM_CHOKEPOINT_PG_HOST is unset")
        pytest.skip("no configured PostgreSQL (set PROM_CHOKEPOINT_PG_HOST)")
    return target


def _scalar(target: DbTarget, query: str) -> str:
    import shutil, subprocess
    env = dict(os.environ); env["PGPASSWORD"] = target.password
    proc = subprocess.run(
        [shutil.which("psql") or "/usr/bin/psql", "-h", target.host, "-p", str(target.port),
         "-U", target.user, "-d", target.dbname, "-tAc", query],
        capture_output=True, text=True, env=env, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def test_live_end_to_end_and_replay_refused():
    target = _require_db()
    auth = ApprovalAuthority()
    runner = BrokeredMigrationRunner(
        authority=auth, target=target, consumed=ConsumedApprovals(),
        executor=psql_executor, clock=time.time,
    )
    # A uniquely-named table so the run is observable and the suite is re-runnable.
    tbl = f"chokepoint_probe_{int(time.time()*1000)}"
    art = MigrationArtifact(f"CREATE TABLE {tbl} (id int);")
    judgment = Judgment(verdict=Verdict.PASS, confidence=1.0, authoritative=True,
                        contributing=("hard-check",))

    approval = auth.authorize(judgment, artifact=art, target=target.identity, now=time.time())
    assert approval is not None

    try:
        # Legitimate path: the table does not exist yet, then does.
        assert _scalar(target, f"SELECT to_regclass('{tbl}') IS NULL") == "t"
        first = runner.execute(approval=approval, artifact=art)
        assert first.executed and not first.refused, first.detail
        assert _scalar(target, f"SELECT to_regclass('{tbl}') IS NOT NULL") == "t"

        # Replay the SAME approval: refused, and the DB is not touched again
        # (a second CREATE of the same table would ERROR — proof it never ran).
        second = runner.execute(approval=approval, artifact=art)
        assert second.refused and second.reason == REPLAY, second.detail
        assert _scalar(target, f"SELECT count(*) FROM pg_tables WHERE tablename='{tbl}'") == "1"
    finally:
        _scalar(target, f"DROP TABLE IF EXISTS {tbl}")
