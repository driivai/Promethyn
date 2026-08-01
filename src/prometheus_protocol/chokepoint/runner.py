"""The brokered migration runner — the exclusive credential holder.

This is the trusted-zone component that alone can touch the target database. It
executes a migration **only** when presented an approval that verifies against
the exact artifact and its own bound target, has not expired, and has never been
spent before. Everything else is refused, and a refusal never touches the DB.

Order of enforcement in :meth:`execute` (each step fail-closed):

1. re-hash the artifact and verify the approval (signature, artifact, target,
   expiry) — a bound-field failure refuses *before* any DB contact;
2. atomically **spend** the approval's nonce — a second use of the same approval
   loses the race and is refused as a replay;
3. only then run the migration through the credentialed executor.

The runner is bound to ONE target and ONE credential at construction (like the
git tool is bound to one repo): an approval naming a different target fails step
1, and no method exists that runs SQL without an approval — the agent cannot
hand the runner a bare migration.

The credential lives in the runner's config (a DSN with a password), sourced
from the runner zone — never from the agent, never from the artifact. The
default executor shells out to ``psql`` with the password passed via the
``PGPASSWORD`` environment variable (not argv), so it never appears in a process
listing.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from prometheus_protocol.chokepoint.approval import (
    Approval,
    ApprovalAuthority,
    MigrationArtifact,
    VerifyResult,
)

REPLAY = "replay"


@dataclass(frozen=True)
class MigrationResult:
    """What the runner did. ``executed`` is True only when the DB was touched and
    the migration succeeded; ``refused`` is True when authorization failed and the
    DB was NOT touched. Exactly one of the two is True, except an authorized
    migration that ran but errored (``executed=False, refused=False``)."""

    executed: bool
    refused: bool
    reason: str
    detail: str = ""


@dataclass(frozen=True)
class DbTarget:
    """Connection coordinates for the target DB. The password is the credential
    the runner exclusively holds; ``identity`` is what an approval binds to."""

    host: str
    port: int
    dbname: str
    user: str
    password: str

    @property
    def identity(self) -> str:
        # What target binding checks against. Deliberately excludes the password.
        return f"{self.dbname}@{self.host}:{self.port}"


class MigrationExecutor(Protocol):
    """Runs approved SQL against the target. Injected so tests can supply a spy
    that proves a refusal never reaches the DB."""

    def __call__(self, sql: str, target: DbTarget) -> tuple[bool, str]: ...


def psql_executor(sql: str, target: DbTarget) -> tuple[bool, str]:
    """Default executor: apply the migration through ``psql``, credential in env.

    ``ON_ERROR_STOP=1`` and a single-transaction ``--single-transaction`` so a
    failing migration leaves nothing half-applied. Returns (ok, detail)."""

    psql = shutil.which("psql") or "/usr/bin/psql"
    env = dict(os.environ)
    env["PGPASSWORD"] = target.password  # never in argv → not in `ps`
    env["PGCONNECT_TIMEOUT"] = "10"
    with tempfile.TemporaryDirectory(prefix="prom-mig-") as tmp:
        path = Path(tmp, "migration.sql")
        path.write_text(sql, encoding="utf-8")
        proc = subprocess.run(
            [psql, "-h", target.host, "-p", str(target.port), "-U", target.user,
             "-d", target.dbname, "-v", "ON_ERROR_STOP=1", "--single-transaction",
             "-f", str(path)],
            capture_output=True, text=True, env=env, timeout=60,
        )
    ok = proc.returncode == 0
    detail = (proc.stderr or proc.stdout or "").strip()[:500]
    return ok, detail


class ConsumedApprovals:
    """Atomic single-use store: a nonce can be claimed at most once, ever.

    Backed by SQLite with the nonce as PRIMARY KEY, so a concurrent second claim
    raises IntegrityError and loses — replay protection that holds even under
    two drivers racing. ``:memory:`` for an ephemeral instance."""

    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS consumed ("
            "nonce TEXT PRIMARY KEY, spent_at TEXT NOT NULL)"
        )
        self._conn.commit()

    def claim(self, nonce: str, spent_at: str) -> bool:
        """True iff this call is the first to spend ``nonce``."""

        try:
            self._conn.execute(
                "INSERT INTO consumed (nonce, spent_at) VALUES (?, ?)",
                (nonce, spent_at),
            )
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def close(self) -> None:
        self._conn.close()


class BrokeredMigrationRunner:
    """Executes migrations only on a valid, current, bound, unspent approval."""

    def __init__(
        self,
        *,
        authority: ApprovalAuthority,
        target: DbTarget,
        consumed: ConsumedApprovals | None = None,
        executor: MigrationExecutor = psql_executor,
        clock: Callable[[], float],
    ) -> None:
        self._authority = authority
        self._target = target
        self._consumed = consumed if consumed is not None else ConsumedApprovals()
        self._executor = executor
        self._clock = clock

    @property
    def target(self) -> DbTarget:
        return self._target

    def execute(self, *, approval: Approval, artifact: MigrationArtifact) -> MigrationResult:
        # STEP 1 — verify every bound field before touching anything. A failure
        # here refuses with NO DB contact and NO nonce spent.
        verdict: VerifyResult = self._authority.verify(
            approval, artifact=artifact, target=self._target.identity, now=self._clock(),
        )
        if not verdict.ok:
            return MigrationResult(
                executed=False, refused=True, reason=verdict.reason,
                detail=f"approval rejected: {verdict.reason}; DB not touched",
            )

        # STEP 2 — spend the nonce atomically. A replay (already spent) loses the
        # race and is refused here, still before the DB.
        if not self._consumed.claim(approval.nonce, self._now_iso()):
            return MigrationResult(
                executed=False, refused=True, reason=REPLAY,
                detail="approval already spent (single-use); DB not touched",
            )

        # STEP 3 — authorized, current, bound, first use: run it.
        ok, detail = self._executor(artifact.sql, self._target)
        return MigrationResult(
            executed=ok, refused=False, reason="ok" if ok else "migration_error",
            detail=(f"migration applied to {self._target.identity}" if ok
                    else f"authorized but migration failed: {detail}"),
        )

    def _now_iso(self) -> str:
        # A string stamp for the consumed row; derived from the injected clock so
        # tests stay deterministic.
        return repr(self._clock())
