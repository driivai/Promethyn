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
3. durably record an execution intent — an unavailable audit sink refuses before
   database contact;
4. only then run the migration and append an outcome linked to that intent.

The runner is bound to ONE target and ONE credential at construction (like the
git tool is bound to one repo): an approval naming a different target fails step
1, and no method exists that runs SQL without an approval — the agent cannot
hand the runner a bare migration.

The credential lives in the runner's config, sourced from the runner zone —
never from the agent, never from the artifact. The default executor uses the
PostgreSQL wire protocol directly; it never interprets psql meta-commands.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Protocol

from prometheus_protocol.chokepoint.approval import (
    Approval,
    ApprovalAuthority,
    MigrationArtifact,
    MigrationTarget,
    VerifyResult,
)

REPLAY = "replay"
STORE_UNAVAILABLE = "approval_store_unavailable"
AUDIT_UNAVAILABLE = "audit_unavailable"
AUDIT_OUTCOME_UNAVAILABLE = "audit_outcome_unavailable"


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
    audit_recorded: bool = False


@dataclass(frozen=True)
class _AuditAppend:
    """Internal result of one synchronous audit append."""

    recorded: bool
    seq: int | None = None
    error_type: str = ""


@dataclass(frozen=True)
class DbTarget:
    """Connection coordinates for the target DB. The password is the credential
    the runner exclusively holds; ``identity`` is what an approval binds to."""

    host: str
    port: int
    dbname: str
    user: str
    password: str
    schema: str = "public"

    @property
    def identity(self) -> MigrationTarget:
        # The signed identity excludes only the rotatable credential.  Principal
        # and schema are authority boundaries and therefore must be included.
        return MigrationTarget(
            host=self.host,
            port=self.port,
            dbname=self.dbname,
            user=self.user,
            schema=self.schema,
        )


@dataclass(frozen=True)
class MigrationRunnerConfig:
    """Required production wiring for the privileged migration runner."""

    target: DbTarget
    signing_key: bytes
    approval_store_path: str | Path

    def __post_init__(self) -> None:
        if not isinstance(self.target, DbTarget):
            raise TypeError("migration runner target must be a DbTarget")
        if not isinstance(self.signing_key, bytes) or len(self.signing_key) < 32:
            raise ValueError("migration runner signing key must be at least 32 bytes")
        if not isinstance(self.approval_store_path, (str, os.PathLike)) or not os.fspath(
            self.approval_store_path
        ):
            raise ValueError("migration runner approval_store_path is required")
        # Force validation of every canonical target field at configuration time.
        _ = self.target.identity


class MigrationExecutor(Protocol):
    """Runs approved SQL against the target. Injected so tests can supply a spy
    that proves a refusal never reaches the DB."""

    def __call__(self, sql: str, target: DbTarget) -> tuple[bool, str]: ...


class AuditSink(Protocol):
    """A tamper-evident append target for the runner's decisions. Satisfied by
    ``SqliteLedger`` (``record_chained``). A successful return is a durability
    boundary: implementations must return only after the entry is committed.
    Every runner construction requires a sink; tests may supply a recording
    double that honors the same successful-return contract."""

    def record_chained(
        self, *, event: str, subject: str, payload: dict[str, object], created_at: str
    ) -> int: ...


def postgres_executor(sql: str, target: DbTarget) -> tuple[bool, str]:
    """Apply approved SQL through PostgreSQL's wire protocol, in one transaction.

    This deliberately does *not* shell out to ``psql``. A psql input file has a
    second command language (``\\!``, ``\\connect``, ``\\copy`` and friends) that
    could execute on the privileged runner or switch away from the signed target.
    The driver sends the artifact only as SQL, so those strings are server syntax
    errors rather than client-side escape hatches.

    The bound schema is quoted as exactly one PostgreSQL identifier and installed
    as the transaction-local search path. A server-side statement timeout bounds
    execution after the connection's own timeout has elapsed.
    """

    try:
        psycopg = import_module("psycopg")
    except ImportError:
        return False, "psycopg is unavailable; refusing to execute migration"

    try:
        with psycopg.connect(
            host=target.host,
            port=target.port,
            dbname=target.dbname,
            user=target.user,
            password=target.password,
            connect_timeout=10,
            autocommit=False,
        ) as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_catalog.set_config("
                "'search_path', pg_catalog.quote_ident(%s), true)",
                (target.schema,),
            )
            cursor.execute(
                "SELECT pg_catalog.set_config("
                "'statement_timeout', '60000', true)"
            )
            cursor.execute(sql, prepare=False)
    except psycopg.Error as exc:
        return False, str(exc).strip()[:500]
    return True, ""


# Compatibility name for callers of the alpha API. The implementation is now
# driver-backed; retaining the name does not retain psql's meta-command surface.
psql_executor = postgres_executor


class ConsumedApprovals:
    """Durable atomic single-use store: a nonce can be claimed once, ever.

    Backed by SQLite with the nonce as PRIMARY KEY, so a concurrent second claim
    raises IntegrityError and loses.  A filesystem path is mandatory: an
    in-memory store would forget spent approvals on restart and turn a captured,
    still-current approval back into an executable capability.

    One instance is safe to share between threads.  Independent instances and
    processes coordinate through SQLite.  If an instance crosses ``fork()``, it
    detects the PID change and reconnects instead of reusing an inherited SQLite
    connection."""

    def __init__(self, path: str | Path) -> None:
        raw_path = os.fspath(path)
        if not raw_path or raw_path == ":memory:":
            raise ValueError(
                "consumed-approval store requires a durable filesystem path"
            )
        configured_path = Path(raw_path).expanduser()
        if configured_path.is_symlink():
            raise ValueError("consumed-approval store cannot be a symlink")
        durable_path = configured_path.absolute()
        parent_existed = durable_path.parent.exists()
        durable_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if not parent_existed:
            os.chmod(durable_path.parent, 0o700)
        self._validate_directory(durable_path.parent)
        if not durable_path.exists():
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(durable_path, flags, 0o600)
            except FileExistsError:
                # Another runner may have created it between the existence check
                # and the atomic create. Validate that file exactly as usual.
                pass
            else:
                os.close(descriptor)
        self._validate_file(durable_path)
        self.path = durable_path
        self._lock = threading.RLock()
        self._pid = os.getpid()
        self._conn: sqlite3.Connection | None = None
        try:
            self._conn = self._connect()
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS consumed ("
                "nonce TEXT PRIMARY KEY, spent_at TEXT NOT NULL)"
            )
            self._conn.commit()
            if durable_path.is_symlink():
                raise ValueError("consumed-approval store became a symlink")
            self._validate_file(durable_path)
        except Exception:
            self.close()
            raise

    @staticmethod
    def _validate_directory(path: Path) -> None:
        info = path.stat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"consumed-approval parent is not a directory: {path}")
        if info.st_mode & 0o022:
            raise PermissionError(
                f"consumed-approval parent must not be group/world writable: {path}"
            )
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise PermissionError(
                f"consumed-approval parent must be owned by the runner user: {path}"
            )

    @staticmethod
    def _validate_file(path: Path) -> None:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"consumed-approval store is not a regular file: {path}")
        if info.st_mode & 0o077:
            raise PermissionError(
                f"consumed-approval store permissions must be 0600: {path}"
            )
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise PermissionError(
                f"consumed-approval store must be owned by the runner user: {path}"
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=30.0, check_same_thread=False)
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _connection(self) -> sqlite3.Connection:
        current_pid = os.getpid()
        if current_pid != self._pid:
            # SQLite connections must not be reused across fork boundaries.
            if self._conn is not None:
                try:
                    self._conn.close()
                except sqlite3.Error:
                    pass
            self._conn = self._connect()
            self._pid = current_pid
        if self._conn is None:
            raise RuntimeError("consumed-approval store is closed")
        return self._conn

    def claim(self, nonce: str, spent_at: str) -> bool:
        """True iff this call is the first to spend ``nonce``."""

        with self._lock:
            conn = self._connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT INTO consumed (nonce, spent_at) VALUES (?, ?)",
                    (nonce, spent_at),
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                conn.rollback()
                return False
            except Exception:
                conn.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


class BrokeredMigrationRunner:
    """Executes migrations only on a valid, current, bound, unspent approval."""

    def __init__(
        self,
        *,
        authority: ApprovalAuthority,
        target: DbTarget,
        consumed: ConsumedApprovals,
        executor: MigrationExecutor = postgres_executor,
        audit: AuditSink,
        clock: Callable[[], float],
    ) -> None:
        if audit is None:
            raise ValueError("migration runner audit sink is required")
        self._authority = authority
        self._target = target
        self._consumed = consumed
        self._executor = executor
        self._audit = audit
        self._clock = clock

    def _record(
        self, event: str, subject: str, payload: dict[str, object]
    ) -> _AuditAppend:
        """Synchronously append one event without letting sink failure escape.

        Production execution interprets a failed pre-execution append as a hard
        refusal. A post-execution failure is returned explicitly while the
        already-durable intent remains available for reconciliation.
        """

        try:
            seq = self._audit.record_chained(
                event=event,
                subject=subject,
                payload=payload,
                created_at=self._now_iso(),
            )
        except Exception as exc:  # noqa: BLE001 - audit sink is an external boundary
            return _AuditAppend(recorded=False, error_type=type(exc).__name__)
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            return _AuditAppend(recorded=False, error_type="InvalidAuditSequence")
        return _AuditAppend(recorded=True, seq=seq)

    @property
    def target(self) -> DbTarget:
        return self._target

    def execute(
        self, *, approval: Approval, artifact: MigrationArtifact
    ) -> MigrationResult:
        # STEP 1 — verify every bound field before touching anything. A failure
        # here refuses with NO DB contact and NO nonce spent.
        verdict: VerifyResult = self._authority.verify(
            approval,
            artifact=artifact,
            target=self._target.identity,
            now=self._clock(),
        )
        if not verdict.ok:
            audit = self._record(
                "refuse",
                self._target.identity.canonical,
                {
                    "phase": "verify",
                    "reason": verdict.reason,
                    "artifact_sha256": approval.artifact_sha256,
                },
            )
            return MigrationResult(
                executed=False,
                refused=True,
                reason=verdict.reason,
                detail=f"approval rejected: {verdict.reason}; DB not touched",
                audit_recorded=audit.recorded,
            )

        # STEP 2 — spend the nonce atomically. A replay (already spent) loses the
        # race and is refused here, still before the DB.
        try:
            claimed = self._consumed.claim(approval.nonce, self._now_iso())
        except (OSError, RuntimeError, sqlite3.Error) as exc:
            audit = self._record(
                "refuse",
                self._target.identity.canonical,
                {
                    "phase": "spend",
                    "reason": STORE_UNAVAILABLE,
                    "artifact_sha256": approval.artifact_sha256,
                    "error_type": type(exc).__name__,
                },
            )
            return MigrationResult(
                executed=False,
                refused=True,
                reason=STORE_UNAVAILABLE,
                detail="approval store unavailable; DB not touched",
                audit_recorded=audit.recorded,
            )
        if not claimed:
            audit = self._record(
                "refuse",
                self._target.identity.canonical,
                {
                    "phase": "spend",
                    "reason": REPLAY,
                    "artifact_sha256": approval.artifact_sha256,
                },
            )
            return MigrationResult(
                executed=False,
                refused=True,
                reason=REPLAY,
                detail="approval already spent (single-use); DB not touched",
                audit_recorded=audit.recorded,
            )

        # STEP 3 — persist a durable execution intent BEFORE touching the DB.
        # If the required audit sink cannot commit the intent, fail closed. The
        # nonce remains spent: an ambiguous audit write must never be made
        # retryable as a fresh approval.
        intent = self._record(
            "execute_intent",
            self._target.identity.canonical,
            {
                "phase": "execute_intent",
                "artifact_sha256": artifact.sha256,
                "target": self._target.identity.canonical,
            },
        )
        if not intent.recorded:
            return MigrationResult(
                executed=False,
                refused=True,
                reason=AUDIT_UNAVAILABLE,
                detail=(
                    "execution intent could not be recorded; approval spent; "
                    "DB not touched"
                ),
                audit_recorded=False,
            )

        # STEP 4 — authorized, current, bound, first use, durable intent present:
        # run the migration.
        try:
            ok, detail = self._executor(artifact.sql, self._target)
        except Exception as exc:  # noqa: BLE001 - executor is an external boundary
            ok = False
            detail = f"executor raised {type(exc).__name__}"
        outcome = self._record(
            "execute_outcome",
            self._target.identity.canonical,
            {
                "phase": "execute_outcome",
                "intent_seq": intent.seq,
                "artifact_sha256": artifact.sha256,
                "target": self._target.identity.canonical,
                "ok": bool(ok),
                "reason": "ok" if ok else "migration_error",
            },
        )
        if not outcome.recorded:
            migration_state = "succeeded" if ok else f"failed: {detail}"
            return MigrationResult(
                executed=ok,
                refused=False,
                reason=AUDIT_OUTCOME_UNAVAILABLE,
                detail=(
                    f"migration {migration_state}; durable execution intent "
                    f"seq={intent.seq} exists, but outcome audit failed"
                ),
                audit_recorded=False,
            )
        return MigrationResult(
            executed=ok,
            refused=False,
            reason="ok" if ok else "migration_error",
            detail=(
                f"migration applied to {self._target.identity.canonical}"
                if ok
                else f"authorized but migration failed: {detail}"
            ),
            audit_recorded=outcome.recorded,
        )

    def _now_iso(self) -> str:
        # A string stamp for the consumed row; derived from the injected clock so
        # tests stay deterministic.
        return repr(self._clock())

    def close(self) -> None:
        self._consumed.close()

    def __enter__(self) -> BrokeredMigrationRunner:  # noqa: PYI034
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


@dataclass(frozen=True)
class MigrationRuntime:
    """Production gate/runner composition sharing one stable authority."""

    authority: ApprovalAuthority
    runner: BrokeredMigrationRunner

    def close(self) -> None:
        self.runner.close()

    def __enter__(self) -> MigrationRuntime:  # noqa: PYI034
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def build_migration_runtime(
    config: MigrationRunnerConfig,
    *,
    audit: AuditSink,
    executor: MigrationExecutor = postgres_executor,
    clock: Callable[[], float] = time.time,
) -> MigrationRuntime:
    """Build production wiring with a stable key, durable store, and audit."""

    if audit is None:
        raise ValueError("migration runner audit sink is required")
    authority = ApprovalAuthority(key=config.signing_key)
    runner = BrokeredMigrationRunner(
        authority=authority,
        target=config.target,
        consumed=ConsumedApprovals(config.approval_store_path),
        executor=executor,
        audit=audit,
        clock=clock,
    )
    return MigrationRuntime(authority=authority, runner=runner)


def build_migration_runner(
    config: MigrationRunnerConfig,
    *,
    audit: AuditSink,
    executor: MigrationExecutor = postgres_executor,
    clock: Callable[[], float] = time.time,
) -> BrokeredMigrationRunner:
    """Build only the runner side of the required production composition.

    Prefer :func:`build_migration_runtime` when the same process also mints
    approvals, because it exposes the one shared authority without duplicating
    key configuration.
    """

    return build_migration_runtime(
        config, audit=audit, executor=executor, clock=clock
    ).runner
