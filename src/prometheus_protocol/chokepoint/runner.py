"""The brokered migration runner — the exclusive credential holder.

This is the trusted-zone component that alone can touch the target database. It
executes a migration **only** when presented an approval that verifies against
the exact artifact and its own bound target, has not expired, and has never been
spent before. Everything else is refused. An invalid approval causes no database
contact at all; a reconciliation refusal may read the reserved receipt table but
never runs the requested migration.

Order of enforcement in :meth:`execute` (each step fail-closed):

1. re-hash the artifact and verify the approval (signature, artifact, target,
   expiry) — a bound-field failure refuses *before* any DB contact;
2. reconcile any older unfinished intent; ambiguity blocks this approval without
   spending it;
3. atomically **spend** the approval's nonce — a second use of the same approval
   loses the race and is refused as a replay;
4. durably record an execution intent — an unavailable audit sink refuses before
   database contact;
5. only then run the migration and insert its execution receipt in the same
   PostgreSQL transaction;
6. append an outcome linked to that intent. After a crash, the receipt proves
   commit versus rollback before another migration is allowed to run.

The runner is bound to ONE target and ONE credential at construction (like the
git tool is bound to one repo): an approval naming a different target fails step
1, and no method exists that runs SQL without an approval — the agent cannot
hand the runner a bare migration.

The credential lives in the runner's config, sourced from the runner zone —
never from the agent, never from the artifact. The default executor uses the
PostgreSQL wire protocol directly; it never interprets psql meta-commands.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
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
RECONCILIATION_REQUIRED = "reconciliation_required"
RECONCILED_COMMITTED = "reconciled_committed"
RECONCILED_NOT_COMMITTED = "reconciled_not_committed"

RECEIPT_COMMITTED = "committed"
RECEIPT_NOT_FOUND = "not_found"
RECEIPT_IN_PROGRESS = "in_progress"
RECEIPT_UNAVAILABLE = "unavailable"
RECEIPT_CONFLICT = "conflict"

_RECEIPT_SCHEMA = "promethyn_internal"
_RECEIPT_TABLE = "migration_receipts"


@dataclass(frozen=True)
class MigrationResult:
    """What the runner did. ``executed`` is True only when the DB was touched and
    the migration succeeded; ``refused`` is True when the requested migration was
    not run. Exactly one of the two is True, except an authorized migration that
    ran but errored (``executed=False, refused=False``)."""

    executed: bool
    refused: bool
    reason: str
    detail: str = ""
    audit_recorded: bool = False
    execution_id: str | None = None


@dataclass(frozen=True)
class ReceiptStatus:
    """What PostgreSQL can prove about one durable execution intent."""

    state: str
    committed_at: str | None = None
    detail: str = ""


@dataclass(frozen=True)
class ReconciliationResult:
    """Outcome of reconciling one intent that lacks an audit outcome."""

    execution_id: str
    intent_seq: int | None
    state: str
    resolved: bool
    audit_recorded: bool = False
    detail: str = ""


@dataclass(frozen=True)
class _AuditAppend:
    """Internal result of one synchronous audit append."""

    recorded: bool
    seq: int | None = None
    error_type: str = ""


@dataclass(frozen=True)
class DbTarget:
    """Connection coordinates for the target DB. The password is the credential
    the runner exclusively holds; ``identity`` is what an approval binds to.

    ``password`` is excluded from ``repr``. A dataclass renders every field by
    default, so the credential appeared verbatim in any log line, f-string,
    traceback frame or crash report that touched a target — turning "someone can
    read a log" into "someone has the production database credential". Redaction
    is not defence in depth here so much as not handing the blast radius away for
    free; the credential is reached only through the field itself, which the two
    connect sites use and nothing else does.
    """

    host: str
    port: int
    dbname: str
    user: str
    password: str = field(repr=False)
    schema: str = "public"
    #: Optional: fetch the credential per use instead of holding one.
    password_provider: Callable[[], str] | None = field(
        default=None, repr=False, compare=False
    )

    def __str__(self) -> str:
        return self.identity.canonical

    def resolve_password(self) -> str:
        """The credential for ONE connection.

        With a ``password_provider`` the runner holds no standing credential: the
        secret is fetched at the moment of use and referenced only for the length
        of the connect call, so a runner sitting idle — the state it is in almost
        all of the time — has nothing to steal. Without one, the ``password``
        field is used and the credential lives for the process's lifetime; that
        remains the default, and ``docs/threat-model.md`` §2 says so rather than
        implying otherwise.

        No claim is made about erasing it from memory. Python strings are
        immutable and may be copied by the interpreter, so a provider narrows the
        *window* from process-lifetime to call-scope — it does not scrub. Claiming
        a wipe we cannot perform would be the void guard this project is named for.
        """

        if self.password_provider is not None:
            return self.password_provider()
        return self.password

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
    """Required production wiring for the privileged migration runner.

    ``signing_key`` is excluded from ``repr`` for the same reason as the
    password, and with more at stake: the key mints approvals, so a key in a log
    is a total bypass of the gate (threat model §1, A1-1 — the same secret, a
    different exit route). ``bytes`` renders in full by default, so a single
    ``print(config)`` or a config object caught in a traceback published it.
    """

    target: DbTarget
    signing_key: bytes = field(repr=False)
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
    that proves a refusal never reaches the DB. A custom implementation must
    atomically persist the receipt described by its matching ``ReceiptLookup``."""

    def __call__(
        self,
        sql: str,
        target: DbTarget,
        execution_id: str,
        artifact_sha256: str,
    ) -> tuple[bool, str]: ...


class ReceiptLookup(Protocol):
    """Reads the transaction-coupled receipt for one execution intent."""

    def __call__(
        self, execution_id: str, artifact_sha256: str, target: DbTarget
    ) -> ReceiptStatus: ...


class AuditSink(Protocol):
    """A tamper-evident append target for the runner's decisions. Satisfied by
    ``SqliteLedger`` (``record_chained``). A successful return is a durability
    boundary: implementations must return only after the entry is committed.
    Every runner construction requires a sink; tests may supply a recording
    double that honors the same successful-return contract."""

    def record_chained(
        self, *, event: str, subject: str, payload: dict[str, object], created_at: str
    ) -> int: ...

    def chained_events(self) -> list[dict[str, object]]: ...

    def verify_chain(self) -> object: ...


def execution_id_for(
    *, approval: Approval, artifact: MigrationArtifact, target: MigrationTarget
) -> str:
    """Derive a stable, non-secret identifier for one approved execution.

    The nonce is signed by the approval authority and single-use in the durable
    approval store. Committing the target and artifact to the identifier makes a
    receipt collision across security boundaries fail visibly.
    """

    material = json.dumps(
        {
            "artifact_sha256": artifact.sha256,
            "approval_nonce": approval.nonce,
            "target": target.canonical,
            "version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(b"promethyn-execution\x00" + material).hexdigest()


def _starts_transaction_control_statement(sql: str) -> bool:
    """Conservatively find transaction-control at a statement boundary.

    PostgreSQL would honor an artifact-level ``COMMIT`` even when the driver
    began the transaction. That would destroy atomicity with the receipt. This
    scanner ignores quoted text, identifiers, dollar-quoted bodies, and nested
    comments, then rejects transaction-control keywords only when they are the
    first token of a statement. False positives fail closed before DB contact.
    """

    forbidden = {
        "abort",
        "begin",
        "commit",
        "end",
        "prepare",
        "release",
        "rollback",
        "savepoint",
        "start",
    }
    index = 0
    statement_start = True
    length = len(sql)
    while index < length:
        char = sql[index]
        if char.isspace():
            index += 1
            continue
        if sql.startswith("--", index):
            newline = sql.find("\n", index + 2)
            index = length if newline < 0 else newline + 1
            continue
        if sql.startswith("/*", index):
            depth = 1
            index += 2
            while index < length and depth:
                if sql.startswith("/*", index):
                    depth += 1
                    index += 2
                elif sql.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            while index < length:
                if sql[index] == quote:
                    if index + 1 < length and sql[index + 1] == quote:
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            continue
        if char == "$":
            tag_end = sql.find("$", index + 1)
            if tag_end >= 0:
                tag = sql[index : tag_end + 1]
                tag_body = tag[1:-1]
                if not tag_body or (
                    (tag_body[0].isalpha() or tag_body[0] == "_")
                    and all(c.isalnum() or c == "_" for c in tag_body)
                ):
                    close = sql.find(tag, tag_end + 1)
                    index = length if close < 0 else close + len(tag)
                    continue
        if char == ";":
            statement_start = True
            index += 1
            continue
        if char.isalpha() or char == "_":
            end = index + 1
            while end < length and (sql[end].isalnum() or sql[end] in {"_", "$"}):
                end += 1
            if statement_start and sql[index:end].lower() in forbidden:
                return True
            statement_start = False
            index = end
            continue
        statement_start = False
        index += 1
    return False


def _receipt_text(value: object) -> str | None:
    """Normalize one PostgreSQL ``text`` column to ``str`` for comparison.

    A driver may hand a ``text`` column back as ``str`` **or** as ``bytes``
    (psycopg's client encoding / binary result format, and the build in use, all
    influence it). Comparing ``bytes`` to ``str`` in Python is silently always
    unequal — never an error — so a receipt check written against whichever type
    the local driver happened to return is a check that passes for the wrong
    reason, and misclassifies a committed migration as a conflict elsewhere. The
    comparison therefore normalizes explicitly instead of trusting the driver.

    Anything that is not decodable UTF-8 text (or is an unexpected type) yields
    ``None``, which never equals an expected ``str`` — so an unreadable receipt
    stays a mismatch, and the caller fails closed.
    """

    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return None
    return None


def _is_lower_hex_digest(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def postgres_executor(
    sql: str,
    target: DbTarget,
    execution_id: str,
    artifact_sha256: str,
) -> tuple[bool, str]:
    """Apply approved SQL and its receipt in one PostgreSQL transaction.

    This deliberately does *not* shell out to ``psql``. A psql input file has a
    second command language (``\\!``, ``\\connect``, ``\\copy`` and friends) that
    could execute on the privileged runner or switch away from the signed target.
    The driver sends the artifact only as SQL, so those strings are server syntax
    errors rather than client-side escape hatches.

    The bound schema is quoted as exactly one PostgreSQL identifier and installed
    as the transaction-local search path. A server-side statement timeout bounds
    execution after the connection's own timeout has elapsed. The execution ID
    is locked for the connection session, then a receipt is inserted only after
    the artifact succeeds; PostgreSQL commits the migration and receipt together
    or rolls both back. A pre-existing matching receipt makes a retry idempotent,
    while a conflicting receipt fails closed.
    """

    if not _is_lower_hex_digest(execution_id) or not _is_lower_hex_digest(
        artifact_sha256
    ):
        return False, "invalid execution ID or artifact digest"
    if _starts_transaction_control_statement(sql):
        return False, (
            "transaction-control statements are forbidden; migration and receipt "
            "must commit atomically"
        )

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
            password=target.resolve_password(),
            connect_timeout=10,
            autocommit=False,
        ) as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_catalog.pg_advisory_lock("
                "pg_catalog.hashtextextended(%s, 0))",
                (execution_id,),
            )
            cursor.execute(
                "SELECT pg_catalog.pg_advisory_xact_lock("
                "pg_catalog.hashtextextended("
                "'promethyn-receipt-bootstrap-v1', 0))"
            )
            cursor.execute(
                "SELECT pg_catalog.to_regnamespace(%s)", (_RECEIPT_SCHEMA,)
            )
            namespace = cursor.fetchone()
            if namespace is None or namespace[0] is None:
                cursor.execute(f"CREATE SCHEMA {_RECEIPT_SCHEMA}")
            cursor.execute(
                "SELECT pg_catalog.to_regclass(%s)",
                (f"{_RECEIPT_SCHEMA}.{_RECEIPT_TABLE}",),
            )
            relation = cursor.fetchone()
            if relation is None or relation[0] is None:
                cursor.execute(
                    f"CREATE TABLE {_RECEIPT_SCHEMA}.{_RECEIPT_TABLE} ("
                    "execution_id text PRIMARY KEY, "
                    "artifact_sha256 text NOT NULL, "
                    "target_canonical text NOT NULL, "
                    "committed_at timestamptz NOT NULL DEFAULT clock_timestamp())"
                )
            # Commit only the idempotent receipt-schema bootstrap. The session
            # execution lock survives this boundary; the approved migration and
            # its receipt begin afterward and still commit atomically together.
            connection.commit()
            cursor.execute(
                f"SELECT artifact_sha256, target_canonical "
                f"FROM {_RECEIPT_SCHEMA}.{_RECEIPT_TABLE} "
                "WHERE execution_id = %s",
                (execution_id,),
            )
            existing = cursor.fetchone()
            if existing is not None:
                # Normalized: a bytes-vs-str comparison here would report a false
                # conflict on a legitimate retry of the same execution.
                if (
                    _receipt_text(existing[0]) != artifact_sha256
                    or _receipt_text(existing[1]) != target.identity.canonical
                ):
                    return False, "execution receipt conflicts with artifact or target"
                return True, "execution receipt already committed"
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
            cursor.execute(
                f"INSERT INTO {_RECEIPT_SCHEMA}.{_RECEIPT_TABLE} "
                "(execution_id, artifact_sha256, target_canonical) "
                "VALUES (%s, %s, %s)",
                (execution_id, artifact_sha256, target.identity.canonical),
            )
    except psycopg.Error as exc:
        return False, str(exc).strip()[:500]
    return True, ""


def postgres_receipt_lookup(
    execution_id: str, artifact_sha256: str, target: DbTarget
) -> ReceiptStatus:
    """Read a PostgreSQL execution receipt without racing an active transaction.

    The executor holds the same advisory lock until commit/rollback. A lookup
    that cannot acquire it reports ``in_progress`` rather than falsely treating
    an uncommitted receipt as a rollback.
    """

    if not _is_lower_hex_digest(execution_id) or not _is_lower_hex_digest(
        artifact_sha256
    ):
        return ReceiptStatus(
            RECEIPT_CONFLICT,
            detail="intent contains an invalid execution ID or artifact digest",
        )

    try:
        psycopg = import_module("psycopg")
    except ImportError:
        return ReceiptStatus(
            RECEIPT_UNAVAILABLE,
            detail="psycopg is unavailable; execution receipt cannot be checked",
        )

    try:
        with psycopg.connect(
            host=target.host,
            port=target.port,
            dbname=target.dbname,
            user=target.user,
            password=target.resolve_password(),
            connect_timeout=10,
            autocommit=False,
        ) as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_catalog.pg_try_advisory_xact_lock("
                "pg_catalog.hashtextextended(%s, 0))",
                (execution_id,),
            )
            lock_row = cursor.fetchone()
            if lock_row is None or not bool(lock_row[0]):
                return ReceiptStatus(
                    RECEIPT_IN_PROGRESS,
                    detail="execution transaction still holds its receipt lock",
                )
            cursor.execute(
                "SELECT pg_catalog.to_regclass(%s)",
                (f"{_RECEIPT_SCHEMA}.{_RECEIPT_TABLE}",),
            )
            relation = cursor.fetchone()
            if relation is None or relation[0] is None:
                return ReceiptStatus(RECEIPT_NOT_FOUND)
            cursor.execute(
                f"SELECT artifact_sha256, target_canonical, committed_at "
                f"FROM {_RECEIPT_SCHEMA}.{_RECEIPT_TABLE} "
                "WHERE execution_id = %s",
                (execution_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return ReceiptStatus(RECEIPT_NOT_FOUND)
            # Normalized: a bytes-vs-str comparison here would misclassify a
            # COMMITTED migration as a conflict during crash reconciliation.
            if (
                _receipt_text(row[0]) != artifact_sha256
                or _receipt_text(row[1]) != target.identity.canonical
            ):
                return ReceiptStatus(
                    RECEIPT_CONFLICT,
                    detail="receipt exists but does not match the intent",
                )
            return ReceiptStatus(RECEIPT_COMMITTED, committed_at=str(row[2]))
    except psycopg.Error as exc:
        return ReceiptStatus(
            RECEIPT_UNAVAILABLE,
            detail=str(exc).strip()[:500],
        )


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
        receipt_lookup: ReceiptLookup | None = None,
        audit: AuditSink,
        clock: Callable[[], float],
    ) -> None:
        if audit is None:
            raise ValueError("migration runner audit sink is required")
        if receipt_lookup is None:
            if executor is not postgres_executor:
                raise ValueError(
                    "custom migration executor requires a matching receipt lookup"
                )
            receipt_lookup = postgres_receipt_lookup
        self._authority = authority
        self._target = target
        self._consumed = consumed
        self._executor = executor
        self._receipt_lookup = receipt_lookup
        self._audit = audit
        self._clock = clock
        self._execution_lock = threading.RLock()
        self._reconcile_lock = threading.RLock()

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

    @staticmethod
    def _audit_payload(row: dict[str, object]) -> dict[str, object] | None:
        raw = row.get("payload")
        if isinstance(raw, dict):
            return raw
        if not isinstance(raw, str):
            return None
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            return None
        return payload if isinstance(payload, dict) else None

    def reconcile_unfinished(self) -> tuple[ReconciliationResult, ...]:
        """Resolve durable intents that have no audit outcome.

        This is intended for runner startup, after the previous runner process is
        gone. PostgreSQL's execution-specific advisory lock also prevents an
        active transaction from being mistaken for a rollback. A committed
        receipt proves the migration committed; an absent receipt, observed only
        after acquiring that lock, proves PostgreSQL did not commit the atomic
        migration-and-receipt transaction.
        """

        with self._reconcile_lock:
            try:
                verification = self._audit.verify_chain()
                if not bool(getattr(verification, "ok", False)):
                    return (
                        ReconciliationResult(
                            execution_id="",
                            intent_seq=None,
                            state="audit_chain_invalid",
                            resolved=False,
                            detail="audit chain is not valid; reconciliation refused",
                        ),
                    )
                rows = self._audit.chained_events()
            except Exception as exc:  # noqa: BLE001 - audit is an external boundary
                return (
                    ReconciliationResult(
                        execution_id="",
                        intent_seq=None,
                        state=AUDIT_UNAVAILABLE,
                        resolved=False,
                        detail=f"audit history unavailable: {type(exc).__name__}",
                    ),
                )

            outcomes: list[tuple[int | None, dict[str, object]]] = []
            intents: list[tuple[int | None, dict[str, object]]] = []
            for row in rows:
                event = row.get("event")
                payload = self._audit_payload(row)
                if payload is None:
                    return (
                        ReconciliationResult(
                            execution_id="",
                            intent_seq=None,
                            state="audit_payload_invalid",
                            resolved=False,
                            detail="audit payload could not be decoded",
                        ),
                    )
                if event == "execute_outcome":
                    seq = row.get("seq")
                    outcomes.append(
                        (
                            seq
                            if isinstance(seq, int) and not isinstance(seq, bool)
                            else None,
                            payload,
                        )
                    )
                elif event == "execute_intent":
                    seq = row.get("seq")
                    intents.append(
                        (
                            seq
                            if isinstance(seq, int) and not isinstance(seq, bool)
                            else None,
                            payload,
                        )
                    )

            results: list[ReconciliationResult] = []
            target_canonical = self._target.identity.canonical
            for intent_seq, payload in intents:
                if payload.get("target") != target_canonical:
                    continue
                execution_id = payload.get("execution_id")
                artifact_sha256 = payload.get("artifact_sha256")
                matching_outcome = False
                for outcome_seq, outcome_payload in outcomes:
                    if (
                        intent_seq is not None
                        and outcome_seq is not None
                        and outcome_seq <= intent_seq
                    ):
                        continue
                    if (
                        outcome_payload.get("target") != target_canonical
                        or outcome_payload.get("artifact_sha256") != artifact_sha256
                    ):
                        continue
                    outcome_execution_id = outcome_payload.get("execution_id")
                    outcome_intent_seq = outcome_payload.get("intent_seq")
                    if (
                        isinstance(execution_id, str)
                        and execution_id
                        and outcome_execution_id == execution_id
                    ) or (
                        intent_seq is not None
                        and outcome_intent_seq == intent_seq
                    ):
                        matching_outcome = True
                        break
                if matching_outcome:
                    continue
                if not isinstance(execution_id, str) or not execution_id:
                    results.append(
                        ReconciliationResult(
                            execution_id="",
                            intent_seq=intent_seq,
                            state="legacy_intent",
                            resolved=False,
                            detail="intent has no stable execution_id",
                        )
                    )
                    continue
                if not isinstance(artifact_sha256, str) or not artifact_sha256:
                    results.append(
                        ReconciliationResult(
                            execution_id=execution_id,
                            intent_seq=intent_seq,
                            state="invalid_intent",
                            resolved=False,
                            detail="intent has no artifact hash",
                        )
                    )
                    continue

                try:
                    receipt = self._receipt_lookup(
                        execution_id, artifact_sha256, self._target
                    )
                except Exception as exc:  # noqa: BLE001 - DB lookup boundary
                    receipt = ReceiptStatus(
                        RECEIPT_UNAVAILABLE,
                        detail=f"receipt lookup raised {type(exc).__name__}",
                    )
                if receipt.state not in {RECEIPT_COMMITTED, RECEIPT_NOT_FOUND}:
                    results.append(
                        ReconciliationResult(
                            execution_id=execution_id,
                            intent_seq=intent_seq,
                            state=receipt.state,
                            resolved=False,
                            detail=receipt.detail,
                        )
                    )
                    continue

                committed = receipt.state == RECEIPT_COMMITTED
                reason = (
                    RECONCILED_COMMITTED
                    if committed
                    else RECONCILED_NOT_COMMITTED
                )
                outcome = self._record(
                    "execute_outcome",
                    target_canonical,
                    {
                        "phase": "execute_outcome",
                        "intent_seq": intent_seq,
                        "execution_id": execution_id,
                        "artifact_sha256": artifact_sha256,
                        "target": target_canonical,
                        "ok": committed,
                        "reason": reason,
                        "reconciled": True,
                        "receipt_committed_at": receipt.committed_at,
                    },
                )
                results.append(
                    ReconciliationResult(
                        execution_id=execution_id,
                        intent_seq=intent_seq,
                        state=receipt.state,
                        resolved=outcome.recorded,
                        audit_recorded=outcome.recorded,
                        detail=(
                            "PostgreSQL receipt proves the migration committed"
                            if committed
                            else "no PostgreSQL receipt; transaction did not commit"
                        ),
                    )
                )
            return tuple(results)

    def execute(
        self, *, approval: Approval, artifact: MigrationArtifact
    ) -> MigrationResult:
        with self._execution_lock:
            return self._execute_locked(approval=approval, artifact=artifact)

    def _execute_locked(
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

        # STEP 2 — a valid approval cannot proceed while an earlier intent for
        # this target remains ambiguous. Do not spend it: the caller may retry
        # after recovery succeeds.
        reconciliation = self.reconcile_unfinished()
        unresolved = next((item for item in reconciliation if not item.resolved), None)
        if unresolved is not None:
            audit = self._record(
                "refuse",
                self._target.identity.canonical,
                {
                    "phase": "reconcile",
                    "reason": RECONCILIATION_REQUIRED,
                    "execution_id": unresolved.execution_id,
                    "reconciliation_state": unresolved.state,
                },
            )
            return MigrationResult(
                executed=False,
                refused=True,
                reason=RECONCILIATION_REQUIRED,
                detail=(
                    "an earlier execution intent could not be reconciled; "
                    "current approval remains unspent; DB not touched for it"
                ),
                audit_recorded=audit.recorded,
            )

        # STEP 3 — spend the nonce atomically. A replay (already spent) loses the
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

        execution_id = execution_id_for(
            approval=approval,
            artifact=artifact,
            target=self._target.identity,
        )

        # STEP 4 — persist a durable execution intent BEFORE touching the DB.
        # If the required audit sink cannot commit the intent, fail closed. The
        # nonce remains spent: an ambiguous audit write must never be made
        # retryable as a fresh approval.
        intent = self._record(
            "execute_intent",
            self._target.identity.canonical,
            {
                "phase": "execute_intent",
                "execution_id": execution_id,
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
                execution_id=execution_id,
            )

        # STEP 5 — authorized, current, bound, first use, durable intent present:
        # run the migration.
        try:
            ok, detail = self._executor(
                artifact.sql,
                self._target,
                execution_id,
                artifact.sha256,
            )
        except Exception as exc:  # noqa: BLE001 - executor is an external boundary
            ok = False
            detail = f"executor raised {type(exc).__name__}"
        outcome = self._record(
            "execute_outcome",
            self._target.identity.canonical,
            {
                "phase": "execute_outcome",
                "intent_seq": intent.seq,
                "execution_id": execution_id,
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
                execution_id=execution_id,
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
            execution_id=execution_id,
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
    receipt_lookup: ReceiptLookup | None = None,
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
        receipt_lookup=receipt_lookup,
        audit=audit,
        clock=clock,
    )
    return MigrationRuntime(authority=authority, runner=runner)


def build_migration_runner(
    config: MigrationRunnerConfig,
    *,
    audit: AuditSink,
    executor: MigrationExecutor = postgres_executor,
    receipt_lookup: ReceiptLookup | None = None,
    clock: Callable[[], float] = time.time,
) -> BrokeredMigrationRunner:
    """Build only the runner side of the required production composition.

    Prefer :func:`build_migration_runtime` when the same process also mints
    approvals, because it exposes the one shared authority without duplicating
    key configuration.
    """

    return build_migration_runtime(
        config,
        audit=audit,
        executor=executor,
        receipt_lookup=receipt_lookup,
        clock=clock,
    ).runner
