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
2. acquire cross-process execution/recovery ownership and reconcile older
   unfinished intents; contention or ambiguity blocks without spending approval.
   Ownership is an OS file lock on the approval store's own inode — keyed to
   the store's identity, so every alias of the store contends for one lock —
   which is mutual exclusion only on a local filesystem of one host; so the
   parent preflight is followed by classification of the opened store/lock
   descriptor's device and Linux mount identity, rechecked before locking
   (``substrate.py``: a known network filesystem is refused, an unidentified
   one is refused unless explicitly opted out of), a multiply linked store is refused,
   and every intent records the owner's host identity and the identity of the
   lock it held (``ownership.py``), so a recovering runner that cannot establish
   the recorded owner is dead — same kernel AND the same lock object, or a
   reboot — leaves the intent pending instead of declaring it not committed;
3. atomically **spend** the approval's nonce — a second use of the same approval
   loses the race and is refused as a replay;
4. durably record an execution intent — an unavailable audit sink refuses before
   database contact;
5. only then run the migration and insert its execution receipt in the same
   PostgreSQL transaction;
6. append a proven outcome or a nonterminal unknown event linked to that intent,
   then release ownership. Only receipt reconciliation can resolve uncertainty
   before another migration is allowed to run.

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
import logging
import os
import sqlite3
import stat
import sys
import threading
import time

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from importlib import import_module
from pathlib import Path
from types import ModuleType
from typing import Protocol

#: ``flock`` is POSIX-only. Declared as an optional module rather than assigned
#: ``None`` behind a ``# type: ignore[assignment]``: the annotation states the
#: real shape — the module, or nothing — so every use site is checked against
#: it, and the checker (not a comment) is what requires the None branch.
fcntl: ModuleType | None
try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows has no flock; the guard refuses there
    fcntl = None
else:
    fcntl = _fcntl

from prometheus_protocol.chokepoint.admission import (
    CLOCK_MARGIN,
    CLOCK_UNTRUSTED,
    DEFAULT_CLOCK_UNCERTAINTY_S,
    ClockUntrusted,
    ExecutionDeadline,
    InvalidApprovalInterval,
    connect_timeout_s,
    timeout_ms,
)
from prometheus_protocol.chokepoint.approval import (
    INVALID_TIME,
    Approval,
    ApprovalAuthority,
    MigrationArtifact,
    MigrationTarget,
    VerifyResult,
)
from prometheus_protocol.chokepoint.authorization_journal import AuthorizationJournal
from prometheus_protocol.chokepoint.authorization_record import (
    AuthorizationContext,
    execution_evidence,
    recovered_evidence,
)
from prometheus_protocol.chokepoint.ownership import (
    OwnerIdentity,
    assess_owner,
    local_identity,
)
from prometheus_protocol.chokepoint.recorded_authority import RecordedApprovalAuthority
from prometheus_protocol.chokepoint.signer import ApprovalSigner, LocalHmacSigner
from prometheus_protocol.chokepoint.substrate import (
    SubstratePolicy,
    SubstrateReport,
    enforce_substrate,
    probe_opened_substrate,
    probe_substrate,
    resolve_substrate_policy,
)
from prometheus_protocol.core.booleans import parse_env_bool, require_bool
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.core.secrets import Secret

_LOG = logging.getLogger(__name__)

#: The environment gate for external key custody, read here as well as by
#: ``Config.from_env`` so the requirement is the OR of its sources: a
#: programmatic ``require_external_signer=False`` beside the variable does not
#: lower it (threat model §2.6; ``docs/key-custody.md``).
EXTERNAL_SIGNER_REQUIRED_ENV = "PROM_REQUIRE_EXTERNAL_SIGNER"


def external_signer_required(env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return parse_env_bool(
        EXTERNAL_SIGNER_REQUIRED_ENV, env.get(EXTERNAL_SIGNER_REQUIRED_ENV), default=False
    )


REPLAY = "replay"
STORE_UNAVAILABLE = "approval_store_unavailable"
AUDIT_UNAVAILABLE = "audit_unavailable"
AUDIT_OUTCOME_UNAVAILABLE = "audit_outcome_unavailable"
RECONCILIATION_REQUIRED = "reconciliation_required"
RECONCILED_COMMITTED = "reconciled_committed"
RECONCILED_NOT_COMMITTED = "reconciled_not_committed"
EXECUTION_UNKNOWN = "execution_unknown"
#: The migration was never sent. Distinct from ``not_committed`` on purpose:
#: "no statement reached the database" and "a statement ran and was rolled
#: back" are different facts, and F7's phase table requires the terminal
#: outcome to state which one happened. Both are non-commits; only this one
#: also establishes that nothing was attempted.
EXECUTION_NOT_ATTEMPTED = "not_attempted"
EXECUTION_NOT_COMMITTED = "not_committed"
EXECUTION_COMMITTED = "committed"
EXECUTION_BUSY = "execution_busy"
#: A pending intent whose recorded owner is another host (or an owner this
#: runner cannot place): not reconciled, not declared not-committed.
OWNER_UNVERIFIABLE = "owner_unverifiable"

RECEIPT_COMMITTED = "committed"
RECEIPT_NOT_FOUND = "not_found"
RECEIPT_IN_PROGRESS = "in_progress"
RECEIPT_UNAVAILABLE = "unavailable"
RECEIPT_CONFLICT = "conflict"

_RECEIPT_SCHEMA = "promethyn_internal"
_RECEIPT_TABLE = "migration_receipts"

#: Ceilings, not budgets. The value actually installed is the smaller of the
#: cap and the approval validity remaining at that moment (F7): a fixed 60s
#: statement timeout under ten seconds of remaining authorization is a
#: statement that outlives the approval permitting it.
_STATEMENT_TIMEOUT_CAP_MS = 60_000
_LOCK_TIMEOUT_CAP_MS = 30_000


class _Cancellable(Protocol):
    """What the watchdog needs of a connection: the ability to cancel it.

    Named as a Protocol rather than typed ``object`` with an ignore. psycopg's
    ``Connection.cancel`` is documented as safe to call from another thread,
    which is the whole reason the watchdog can exist; stating the requirement
    here says what the watchdog depends on instead of silencing the checker.
    """

    def cancel(self) -> None: ...


def _cancel_at_deadline(
    connection: _Cancellable, budget: float | None
) -> threading.Timer | None:
    """Arm a one-shot cancel of ``connection`` when the remaining budget runs out.

    This is what bounds a MULTI-STATEMENT artifact. ``statement_timeout`` is per
    statement, so an artifact of N statements bounded only by it can run for N
    times the budget; this bounds the artifact as a whole.

    It is a cancellation, and a cancellation is NOT proof of rollback — the
    caller keeps the tri-state and requires an acknowledged rollback or a
    receipt-based reconciliation, exactly as it does for any other error.
    """

    if budget is None or budget <= 0:
        return None

    def cancel() -> None:
        try:
            connection.cancel()
        except Exception:  # noqa: BLE001 - a cancel that cannot fire must not
            pass          # raise inside a timer thread; the wall-clock arm and
            #               statement_timeout both still apply.

    timer = threading.Timer(budget, cancel)
    timer.daemon = True
    timer.start()
    return timer


def _stop_watchdog(watchdog: threading.Timer | None) -> None:
    """Disarm and JOIN. Ownership is released on the promise that no detached
    work continues after the executor returns; an un-joined timer would be
    exactly such work, and would reintroduce the F3 recovery race."""

    if watchdog is None:
        return
    watchdog.cancel()
    watchdog.join(timeout=5.0)


class _OwnershipUnavailable(RuntimeError):
    """The cross-process guard could not be acquired safely."""


class _MultiplyLinkedStore(OSError):
    """The store inode has more than one name. Every name would resolve to the
    same lock object, so this is not itself a bypass — but a store with two
    names is a store being aliased, and it is refused rather than reasoned
    about (finding 2)."""


class _PlatformUnsupported(OSError):
    """Execution ownership needs Linux ``flock`` semantics: an ``flock`` on the
    store's inode that is independent of SQLite's POSIX locks on the same
    file. Elsewhere the guard refuses rather than guesses."""


def _singly_linked(info: os.stat_result) -> bool:
    """One name for one inode. Checked at construction AND before every guard
    acquisition: aliases can be created after construction."""

    return info.st_nlink == 1


@dataclass(frozen=True)
class MigrationResult:
    """What the runner did. ``executed`` is True only when the DB was touched and
    the migration succeeded; ``refused`` is True when the requested migration was
    not run. An authorized operation that errored or has an unknown outcome has
    ``executed=False, refused=False``. Inspect ``execution_state``: False does
    not prove rollback and must never trigger an automatic SQL retry."""

    executed: bool
    refused: bool
    reason: str
    detail: str = ""
    audit_recorded: bool = False
    execution_id: str | None = None
    # None on pre-execution refusals; never infer rollback from executed=False.
    execution_state: str | None = None


@dataclass(frozen=True)
class ExecutorResult:
    """Only an acknowledged commit/rollback is a terminal database outcome."""

    state: str
    detail: str = ""

    def __post_init__(self) -> None:
        if self.state not in {
            EXECUTION_COMMITTED,
            EXECUTION_NOT_COMMITTED,
            EXECUTION_NOT_ATTEMPTED,
            EXECUTION_UNKNOWN,
        }:
            raise ValueError("invalid executor outcome state")


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

    ``password`` is held as a :class:`~prometheus_protocol.core.secrets.Secret`,
    not as a ``str``, and F8 is why. This class already carried
    ``field(repr=False)`` and a ``__str__`` returning the identity — both worked,
    and the credential still came out::

        CANARY in repr(target)                          # False
        CANARY in str(target)                           # False
        CANARY in json.dumps(asdict(target), default=str)   # True   <-- leaked

    ``dataclasses.asdict`` does not consult ``field.repr``; it reads the value.
    So does ``vars``. Redaction that lives in the CONTAINER governs one path at a
    time and has to be remembered on each; redaction that lives in the VALUE
    governs all of them, and keeps governing them for a field somebody adds next
    year. ``__post_init__`` accepts a plain string and normalises it, so every
    existing construction site is unchanged.
    """

    host: str
    port: int
    dbname: str
    user: str
    #: Accepted as ``str`` for convenience, always STORED as ``Secret``.
    password: Secret | str = field(repr=False)
    schema: str = "public"
    #: Optional: fetch the credential per use instead of holding one.
    password_provider: Callable[[], str] | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        # Normalise at the boundary so no caller has to remember. Frozen
        # dataclass, hence object.__setattr__.
        if not isinstance(self.password, Secret):
            object.__setattr__(self, "password", Secret(self.password))

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
        # Narrowed, not asserted. `__post_init__` guarantees the Secret, but an
        # `assert` is stripped under `python -O` — a production invariant must
        # not depend on assertions being enabled. Either branch returns the
        # right value; the invariant itself is proven behaviourally by the
        # canary sweep, which constructs this class and checks what is STORED.
        password = self.password
        if isinstance(password, Secret):
            return password.reveal()
        return password

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

    Exactly one of ``signing_key`` (a local HMAC key — development, and
    **non-protecting against a host-level insider**, who reads it out of the
    process) or ``signer`` (an external KMS / HSM signer whose private key
    never exists on this host; ``docs/key-custody.md``) is given.
    ``require_external_signer`` refuses the local key as a requirement that
    cannot be honoured; it is the OR of this field, ``Config`` and
    ``PROM_REQUIRE_EXTERNAL_SIGNER`` at build time.

    ``signing_key`` and ``signer`` are excluded from ``repr`` for the same
    reason as the password, and with more at stake: the key mints approvals, so
    a key in a log is a total bypass of the gate (threat model §1, A1-1 — the
    same secret, a different exit route). ``bytes`` renders in full by default,
    so a single ``print(config)`` or a config object caught in a traceback
    published it.

    ``require_verified_substrate`` and ``allow_unverified_substrate`` govern
    the filesystem behind ``approval_store_path`` (``substrate.py``): the
    execution guard is an flock there, so a network filesystem is refused
    outright and an unidentified one is refused unless the opt-out is set —
    which the requirement withdraws. Each is the OR of this field, ``Config``
    and its environment variable at build time.
    """

    target: DbTarget
    approval_store_path: str | Path
    #: Accepted as ``bytes`` for convenience, always STORED as a ``Secret``
    #: (F8). ``repr=False`` governed repr alone; asdict and vars read the value.
    signing_key: Secret | bytes | None = field(default=None, repr=False)
    signer: ApprovalSigner | None = field(default=None, repr=False)
    require_external_signer: bool = False
    require_verified_substrate: bool = False
    allow_unverified_substrate: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.target, DbTarget):
            raise TypeError("migration runner target must be a DbTarget")
        if self.signing_key is not None and not isinstance(self.signing_key, Secret):
            object.__setattr__(self, "signing_key", Secret(self.signing_key))
        for flag in (
            "require_external_signer",
            "require_verified_substrate",
            "allow_unverified_substrate",
        ):
            require_bool(getattr(self, flag), name=f"MigrationRunnerConfig.{flag}")
        if (self.signing_key is None) == (self.signer is None):
            raise ValueError(
                "migration runner needs exactly one of signing_key (local, "
                "non-protecting) or signer (external)"
            )
        if self.signing_key is not None and (
            not isinstance(self.signing_key, Secret)
            or not isinstance(self.signing_key.reveal(), bytes)
            or len(self.signing_key) < 32
        ):
            raise ValueError("migration runner signing key must be at least 32 bytes")
        if self.signer is not None and not (
            callable(getattr(self.signer, "sign", None))
            and callable(getattr(self.signer, "verify", None))
        ):
            raise TypeError("migration runner signer must sign and verify")
        if self.require_external_signer and (
            self.signer is None or not getattr(self.signer, "external", False)
        ):
            raise ConfigError(
                "require_external_signer=True cannot be honoured: the configured "
                "signer holds its key on this host (a local HMAC key root can read "
                "and use silently). Configure a KmsSigner, or withdraw the requirement."
            )
        if not isinstance(
            self.approval_store_path, (str, os.PathLike)
        ) or not os.fspath(self.approval_store_path):
            raise ValueError("migration runner approval_store_path is required")
        if self.require_verified_substrate and self.allow_unverified_substrate:
            raise ConfigError(
                "require_verified_substrate=True cannot be honoured alongside "
                "allow_unverified_substrate=True: the opt-out for an unverified "
                "approval-store substrate would never take effect under the "
                "requirement. Withdraw one."
            )
        # Force validation of every canonical target field at configuration time.
        _ = self.target.identity


class MigrationExecutor(Protocol):
    """Runs approved SQL against the target. Injected so tests can supply a spy
    that proves a refusal never reaches the DB. A custom implementation must
    atomically persist the receipt described by its matching ``ReceiptLookup``.
    Execution is synchronous: no detached work may continue after returning.
    Prefer ExecutorResult; legacy (True, detail) acknowledges commit, but legacy
    (False, detail) is UNKNOWN, never proof of rollback."""

    def __call__(
        self,
        sql: str,
        target: DbTarget,
        execution_id: str,
        artifact_sha256: str,
        *,
        deadline: ExecutionDeadline | None = None,
    ) -> ExecutorResult | tuple[bool, str]: ...


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
    *,
    deadline: ExecutionDeadline | None = None,
) -> ExecutorResult:
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

    F7, THE SECOND ADMISSION BOUNDARY. A runner-side check alone does not
    establish "migration SQL cannot begin after expiry", because everything
    above happens BEFORE the migration statement: credential resolution,
    connect and authentication, a BLOCKING session advisory lock and a BLOCKING
    bootstrap transaction advisory lock, schema and relation checks, a bootstrap
    commit, a receipt lookup and search-path setup. The ruled policy is
    **NO PRIVILEGED DATABASE CONTACT AFTER EXPIRY**, so ``deadline`` is checked

      * **2a** before the credentialed connection exists — an expired approval
        opens no connection, resolves no password, takes no lock; and
      * **2b** after the two blocking locks and before any bootstrap WRITE, so
        a lock that blocked past the deadline is caught where it happened
        rather than being allowed to author DDL under a lapsed authorization.

    Both blocking locks additionally carry a ``lock_timeout`` derived from the
    remaining validity, so neither can block past the deadline in the first
    place, and ``connect_timeout`` is derived the same way.

    BOUNDING A MULTI-STATEMENT ARTIFACT. ``statement_timeout`` is PER STATEMENT:
    an artifact of N statements bounded only by it can run for N times the
    budget. So the whole artifact is additionally bounded client-side — a
    watchdog cancels the session when the deadline passes. Neither mechanism is
    proof of rollback: a cancelled statement is UNKNOWN unless an explicit
    rollback is acknowledged, which is exactly how the handler below treats it.
    """

    if not _is_lower_hex_digest(execution_id) or not _is_lower_hex_digest(
        artifact_sha256
    ):
        return ExecutorResult(
            EXECUTION_NOT_COMMITTED, "invalid execution ID or artifact digest"
        )
    if _starts_transaction_control_statement(sql):
        return ExecutorResult(
            EXECUTION_NOT_COMMITTED,
            (
                "transaction-control statements are forbidden; migration and receipt "
                "must commit atomically"
            ),
        )

    # BOUNDARY 2a — before ANY privileged database contact. Past this point the
    # password provider is called and a credentialed connection is opened, so an
    # expired approval must not reach it. Policy (1), ruled for this sprint.
    if deadline is not None:
        admission = deadline.admit()
        if not admission.admitted:
            return ExecutorResult(
                EXECUTION_NOT_ATTEMPTED,
                f"approval not admissible ({admission.reason}); no credential "
                f"was resolved and no connection was opened: {admission.detail}",
            )
        budget = admission.remaining_s
    else:
        budget = None

    try:
        psycopg = import_module("psycopg")
    except ImportError:
        return ExecutorResult(
            EXECUTION_NOT_COMMITTED,
            "psycopg is unavailable; refusing to execute migration",
        )

    confirmed: ExecutorResult | None = None
    try:
        with (
            psycopg.connect(
                host=target.host,
                port=target.port,
                dbname=target.dbname,
                user=target.user,
                password=target.resolve_password(),
                connect_timeout=(
                    10 if budget is None else connect_timeout_s(budget, cap_s=10)
                ),
                autocommit=False,
            ) as connection,
            connection.cursor() as cursor,
        ):
            if budget is not None:
                # Both locks below BLOCK. Without this a lock held by another
                # session outlasts the approval while this one waits, and the
                # boundary check at 2b would be reached long after the deadline
                # instead of at it.
                cursor.execute(
                    "SELECT pg_catalog.set_config('lock_timeout', %s, false)",
                    (str(timeout_ms(budget, cap_ms=_LOCK_TIMEOUT_CAP_MS)),),
                )
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
            # BOUNDARY 2b — the two locks above blocked for an unbounded time
            # from this approval's point of view. Re-check BEFORE the bootstrap
            # DDL below, which is the first WRITE this path performs.
            if deadline is not None:
                admission = deadline.admit()
                if not admission.admitted:
                    return ExecutorResult(
                        EXECUTION_NOT_ATTEMPTED,
                        f"approval not admissible after acquiring the execution "
                        f"locks ({admission.reason}); nothing was written and no "
                        f"migration statement was sent: {admission.detail}",
                    )
                budget = admission.remaining_s
            cursor.execute("SELECT pg_catalog.to_regnamespace(%s)", (_RECEIPT_SCHEMA,))
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
                    return ExecutorResult(
                        EXECUTION_UNKNOWN,
                        "execution receipt conflicts with artifact or target",
                    )
                confirmed = ExecutorResult(
                    EXECUTION_COMMITTED, "execution receipt already committed"
                )
                return confirmed
            cursor.execute(
                "SELECT pg_catalog.set_config("
                "'search_path', pg_catalog.quote_ident(%s), true)",
                (target.schema,),
            )
            # Derived from what is LEFT, not a fixed 60s: a 60-second statement
            # under ten seconds of remaining validity is a statement that
            # outlives its authorization. ``timeout_ms`` never rounds a positive
            # budget down to 0, because 0 DISABLES the timeout.
            cursor.execute(
                "SELECT pg_catalog.set_config('statement_timeout', %s, true)",
                (
                    str(
                        _STATEMENT_TIMEOUT_CAP_MS
                        if budget is None
                        else timeout_ms(budget, cap_ms=_STATEMENT_TIMEOUT_CAP_MS)
                    ),
                ),
            )
            # And the WHOLE artifact, which statement_timeout cannot bound: it
            # is per statement, so N statements get N budgets. The watchdog
            # cancels the session once, at the deadline, and is always joined
            # before this function returns — the executor protocol promises no
            # detached work continues, and ownership is released on that promise.
            watchdog = _cancel_at_deadline(connection, budget)
            try:
                cursor.execute(sql, prepare=False)
                cursor.execute(
                    f"INSERT INTO {_RECEIPT_SCHEMA}.{_RECEIPT_TABLE} "
                    "(execution_id, artifact_sha256, target_canonical) "
                    "VALUES (%s, %s, %s)",
                    (execution_id, artifact_sha256, target.identity.canonical),
                )
            except psycopg.Error as exc:
                # An exception does not establish rollback — and a CANCELLED
                # statement least of all. Require an explicit successful
                # rollback while still holding the receipt lock.
                connection.rollback()
                confirmed = ExecutorResult(
                    EXECUTION_NOT_COMMITTED, str(exc).strip()[:500]
                )
                return confirmed
            finally:
                _stop_watchdog(watchdog)
            # Keep this outside the rollback handler: COMMIT may have succeeded
            # even if its response is lost. A later rollback cannot undo it.
            connection.commit()
            confirmed = ExecutorResult(EXECUTION_COMMITTED)
    except psycopg.Error as exc:
        return confirmed or ExecutorResult(EXECUTION_UNKNOWN, str(exc).strip()[:500])
    return confirmed or ExecutorResult(
        EXECUTION_UNKNOWN, "no confirmed database outcome"
    )


def postgres_receipt_lookup(
    execution_id: str, artifact_sha256: str, target: DbTarget
) -> ReceiptStatus:
    """Read a PostgreSQL execution receipt without racing an active transaction.

    The executor holds the same advisory lock until commit/rollback. A lookup
    that cannot acquire it reports ``in_progress`` rather than falsely treating
    an uncommitted receipt as a rollback. NOT_FOUND alone does not establish
    rollback: the runner must ALSO own the cross-process store guard so an
    earlier owner cannot connect and execute after this lookup returns.
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
        with (
            psycopg.connect(
                host=target.host,
                port=target.port,
                dbname=target.dbname,
                user=target.user,
                password=target.resolve_password(),
                connect_timeout=10,
                autocommit=False,
            ) as connection,
            connection.cursor() as cursor,
        ):
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
    connection.

    The parent directory is preflighted before creation. The opened store's
    descriptor is then classified by device and Linux mount identity before
    SQLite initializes it, and again before every execution guard acquisition.
    A parent refusal creates nothing; an opened-object refusal can leave an
    empty newly created file. The execution guard is an flock, which is mutual
    exclusion only on a local filesystem of one host. A known network or host-shared filesystem is refused
    with ``ConfigError``; a filesystem the probe cannot identify is refused
    unless ``substrate_policy`` (or, when it is not given, the environment)
    carries the explicit opt-out, and is then warned about. ``probe`` and
    ``opened_probe`` are distinct injection seams for metadata unit tests;
    Linux integration uses the actual descriptors and kernel metadata.

    The execution guard itself is keyed to the store's *identity*, not its
    pathname: it is an ``flock`` on a descriptor of this file's own inode,
    opened once here and held for the store's lifetime (``execution_guard``).
    A store with more than one name (a hard link) is refused at construction
    and again before every guard acquisition."""

    def __init__(
        self,
        path: str | Path,
        *,
        substrate_policy: SubstratePolicy | None = None,
        env: Mapping[str, str] | None = None,
        probe: Callable[[str | os.PathLike[str]], SubstrateReport] | None = None,
        opened_probe: Callable[[int], SubstrateReport] | None = None,
    ) -> None:
        raw_path = os.fspath(path)
        if not raw_path or raw_path == ":memory:":
            raise ValueError(
                "consumed-approval store requires a durable filesystem path"
            )
        configured_path = Path(raw_path).expanduser()
        if configured_path.is_symlink():
            raise ValueError("consumed-approval store cannot be a symlink")
        durable_path = configured_path.absolute()
        # A conservative directory preflight before creation, including SQLite
        # sidecar placement. The opened-object check below is still mandatory.
        if substrate_policy is None:
            substrate_policy = resolve_substrate_policy(env=env)
        self._substrate_policy = substrate_policy
        self._opened_probe = opened_probe if opened_probe is not None else probe_opened_substrate
        # Looked up at call time (not bound as a default) so the module-level
        # preflight can be replaced separately from the opened-object probe.
        self.substrate = (probe if probe is not None else probe_substrate)(
            durable_path.parent
        )
        enforce_substrate(self.substrate, substrate_policy)
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
        info = durable_path.stat()
        if not _singly_linked(info):
            raise ValueError(
                "consumed-approval store must be singly linked: a hard link is a "
                "second name for the store, and a store with two names is refused "
                "rather than reasoned about"
            )
        self._file_identity = (info.st_dev, info.st_ino)
        self.path = durable_path
        self._lock = threading.RLock()
        # In-process exclusion for the guard. The flock below is per open file
        # description and this store keeps ONE descriptor, so a second thread
        # re-locking it would succeed; the mutex is what makes two threads of
        # one process contend the way two processes do.
        self._guard_mutex = threading.Lock()
        self._pid = os.getpid()
        self._conn: sqlite3.Connection | None = None
        self._guard_fd: int | None = None
        self._guard_pid: int | None = None
        try:
            self._guard_fd = self._open_guard()
            self._guard_pid = os.getpid()
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

    @property
    def identity(self) -> tuple[int, int]:
        """``(st_dev, st_ino)`` of the store: the lock object's identity."""

        return self._file_identity

    @property
    def lock_id(self) -> str:
        """The lock's identity as recorded in every execution intent, so a
        recovering runner can tell whether the lock it holds is the one the
        intent's owner held. Every alias of the store yields the same value."""

        return f"{self._file_identity[0]}:{self._file_identity[1]}"

    def _open_guard(self) -> int:
        """A descriptor on the store's own inode, for ``flock``.

        The lock object is the inode: a hard link, a file bind mount or a
        symlink to this store opens the same inode, and the kernel evaluates
        ``flock`` conflicts per inode, across processes. That is what makes the
        guard identity-keyed rather than path-keyed. The descriptor is held
        open for the store's lifetime and released with ``LOCK_UN`` rather than
        by closing, because closing any descriptor of a file drops the
        process's POSIX locks on that file — the locks SQLite holds during a
        transaction. ``flock`` locks are independent of those on Linux, which
        is the platform this guard is specified for.
        """

        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(self.path, flags)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != self._file_identity:
                raise OSError("approval store was replaced between validation and open")
            # This descriptor is BOTH the inspected store and FIX-B's lock
            # object. Inspect before SQLite opens/initializes the store.
            self.substrate = self._opened_probe(fd)
            enforce_substrate(self.substrate, self._substrate_policy)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _guard_descriptor(self) -> int:
        if self._guard_fd is None:
            raise RuntimeError("consumed-approval store is closed")
        if os.getpid() != self._guard_pid:
            # Inherited across fork(): the parent's lock lives on the shared
            # open file description, and a child re-locking through it would
            # "succeed". The child contends with a descriptor of its own.
            try:
                os.close(self._guard_fd)
            except OSError:
                pass
            self._guard_fd = None
            self._guard_fd = self._open_guard()
            self._guard_pid = os.getpid()
        return self._guard_fd

    @contextmanager
    def execution_guard(self) -> Iterator[bool]:
        """Exclusive nonblocking ownership across execution AND recovery.

        The lock is an ``flock`` on the store's own inode (``_open_guard``), so
        every runner that names this store by any path contends for ONE lock
        object; before each acquisition the descriptor is re-checked to still
        be the inode at ``path``, singly linked, private and owned. All runners
        must share this store and the audit ledger on one trusted host. The
        guard spans the pre-connection interval without a SQLite write
        transaction. A suspended owner retains the lock; a dead owner's lock
        is released by the kernel; any surviving DB transaction retains its
        receipt lock.

        No lease expiry or time-based takeover is safe here. Do not unlink or
        replace the store while runners exist. Linux only: elsewhere the guard
        refuses (``_PlatformUnsupported``) rather than risk an ``flock`` that
        interacts with SQLite's POSIX locks.
        """
        held = False
        fd = -1
        try:
            if fcntl is None or not sys.platform.startswith("linux"):
                raise _PlatformUnsupported(
                    "execution ownership needs Linux flock semantics"
                )
            with self._lock:
                self._connection()  # Refuse a closed store; refresh after fork.
                fd = self._guard_descriptor()
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != self._file_identity:
                raise OSError("approval store descriptor is not the validated store")
            current = self.path.stat()
            if (current.st_dev, current.st_ino) != self._file_identity:
                raise OSError(
                    "approval store was replaced; execution ownership unavailable"
                )
            if not _singly_linked(info):
                raise _MultiplyLinkedStore(
                    "approval store has more than one name; execution ownership "
                    "unavailable"
                )
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o077
                or info.st_uid != os.geteuid()
            ):
                raise OSError("unsafe approval store")
            # Reinspect the very descriptor about to be flocked, including a
            # descriptor reopened after fork. Never use the constructor's
            # parent preflight or a cached safe report as execution evidence.
            enforce_substrate(self._opened_probe(fd), self._substrate_policy)
            if not self._guard_mutex.acquire(blocking=False):
                owned = False
            else:
                held = True
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    self._guard_mutex.release()
                    held = False
                    owned = False
                else:
                    owned = True
        except (OSError, RuntimeError, ImportError, sqlite3.Error, ConfigError) as exc:
            if held:
                self._guard_mutex.release()
            raise _OwnershipUnavailable(type(exc).__name__) from exc
        try:
            yield owned
        finally:
            if held:
                # LOCK_UN, never close: the descriptor stays open for the
                # store's lifetime (see _open_guard). Process death releases
                # the lock through the kernel.
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    self._guard_mutex.release()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
            # After SQLite: closing a descriptor of the store drops this
            # process's POSIX locks on it, so it must not happen mid-transaction.
            if self._guard_fd is not None:
                try:
                    os.close(self._guard_fd)
                except OSError:
                    pass
                self._guard_fd = None


def _accepts_deadline(executor: Callable[..., object]) -> bool:
    """Does this executor take the F7 ``deadline`` keyword?

    Read from the signature ONCE at construction, never per call, and the answer
    is recorded in the audit payload rather than being allowed to decide
    something silently. An executor with ``**kwargs`` counts: it can forward the
    deadline, and a bespoke executor written to that shape has taken the
    obligation on deliberately.
    """

    import inspect

    try:
        parameters = inspect.signature(executor).parameters
    except (TypeError, ValueError):
        return False
    return any(
        name == "deadline" or parameter.kind is inspect.Parameter.VAR_KEYWORD
        for name, parameter in parameters.items()
    )


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
        identity: OwnerIdentity | None = None,
        clock_uncertainty_s: float = DEFAULT_CLOCK_UNCERTAINTY_S,
        trust_utc: bool = True,
        elapsed: Callable[[], float] | None = None,
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
        # Recorded in every execution intent; compared by any runner that later
        # recovers it (``ownership.py``). Injectable so a test can be "another
        # host" without one.
        self._identity = identity if identity is not None else local_identity()
        self._execution_lock = threading.RLock()
        self._reconcile_lock = threading.RLock()
        self._clock_uncertainty_s = clock_uncertainty_s
        self._trust_utc = trust_utc
        self._elapsed = elapsed
        # F7 boundary 2 lives INSIDE the executor, so it can only be enforced by
        # an executor that receives the deadline. Decided once, here, rather
        # than guessed at each call — and RECORDED in the execution intent, so a
        # ledger reader can see which boundaries were in force for that run
        # instead of assuming both were. ``postgres_executor`` declares it; a
        # bespoke executor that does not is still covered by boundary 1, and its
        # own privileged contact is its own obligation.
        self._executor_enforces_deadline = _accepts_deadline(executor)

    @property
    def identity(self) -> OwnerIdentity:
        return self._identity

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

    def reconcile_unfinished(
        self, *, assume_owner_dead: bool = False
    ) -> tuple[ReconciliationResult, ...]:
        """Resolve pending intents only under cross-process execution ownership.

        An intent whose recorded owner is another host — one whose liveness the
        execution guard cannot establish — is reported ``owner_unverifiable``
        and left pending. ``assume_owner_dead=True`` is the operator's assertion
        that they have established it by other means; it is never implied by
        the runner's own execution path, and the outcome event records it.
        """

        try:
            with self._consumed.execution_guard() as owned:
                if not owned:
                    return (
                        ReconciliationResult(
                            "",
                            None,
                            EXECUTION_BUSY,
                            False,
                            detail="another runner owns execution/recovery",
                        ),
                    )
                return self._reconcile_owned(assume_owner_dead=assume_owner_dead)
        except _OwnershipUnavailable as exc:
            return (
                ReconciliationResult(
                    "",
                    None,
                    STORE_UNAVAILABLE,
                    False,
                    detail=f"execution ownership unavailable: {exc}",
                ),
            )

    def _reconcile_owned(
        self, *, assume_owner_dead: bool = False
    ) -> tuple[ReconciliationResult, ...]:
        """Caller owns the durable store lock; no earlier live owner ON THIS
        KERNEL can resume. Whether the recorded owner was on this kernel is
        what ``assess_owner`` decides per intent; an owner it cannot place is
        left pending unless the operator asserted ``assume_owner_dead``.

        The DB receipt lock separately protects a transaction that outlives a
        dead client. Only after both locks may absence prove non-commit.
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
                    # Old false outcomes included ambiguous connection errors.
                    # Revisit them on upgrade. Only explicitly proven outcomes
                    # (or historical acknowledged successes) resolve an intent.
                    state = outcome_payload.get("execution_state")
                    terminal = (
                        state == EXECUTION_COMMITTED
                        and outcome_payload.get("ok") is True
                    ) or (
                        state == EXECUTION_NOT_COMMITTED
                        and outcome_payload.get("ok") is False
                    )
                    if state is None:
                        terminal = outcome_payload.get("ok") is True
                    if not terminal:
                        continue
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
                    ) or (intent_seq is not None and outcome_intent_seq == intent_seq):
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

                # The F3 race in its multi-host and aliased forms: this runner's
                # guard proves nothing about an owner on another kernel, and
                # nothing about an owner on this kernel unless the lock it held
                # is provably the object this runner now holds. Absence of a
                # receipt may not be read as non-commit until the owner is placed.
                owner = assess_owner(
                    payload, self._identity, lock_id=self._consumed.lock_id
                )
                owner_override = False
                if not owner.established:
                    if not assume_owner_dead:
                        results.append(
                            ReconciliationResult(
                                execution_id=execution_id,
                                intent_seq=intent_seq,
                                state=OWNER_UNVERIFIABLE,
                                resolved=False,
                                detail=owner.detail,
                            )
                        )
                        continue
                    owner_override = True
                    _LOG.warning(
                        "reconciling intent %s on the operator's assertion that "
                        "its owner is dead (assume_owner_dead=True): %s",
                        execution_id,
                        owner.detail,
                    )

                try:
                    receipt = self._receipt_lookup(
                        execution_id, artifact_sha256, self._target
                    )
                except Exception as exc:  # noqa: BLE001 - DB lookup boundary
                    receipt = ReceiptStatus(
                        RECEIPT_UNAVAILABLE,
                        detail=f"receipt lookup raised {type(exc).__name__}",
                    )
                if not isinstance(receipt, ReceiptStatus) or not isinstance(
                    receipt.state, str
                ):
                    receipt = ReceiptStatus(
                        RECEIPT_UNAVAILABLE, detail="invalid receipt lookup response"
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
                try:
                    evidence = recovered_evidence(payload)
                except (TypeError, ValueError, OverflowError):
                    results.append(ReconciliationResult(
                        execution_id=execution_id, intent_seq=intent_seq, state="invalid_intent",
                        resolved=False, audit_recorded=False, detail="invalid persisted approval binding",
                    ))
                    continue
                reason = RECONCILED_COMMITTED if committed else RECONCILED_NOT_COMMITTED
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
                        "execution_state": EXECUTION_COMMITTED
                        if committed
                        else EXECUTION_NOT_COMMITTED,
                        "reason": reason,
                        "reconciled": True,
                        **evidence,
                        "receipt_committed_at": receipt.committed_at,
                        "owner_basis": owner.basis,
                        "owner_override": owner_override,
                        "reconciled_by_host": self._identity.host,
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
                    **execution_evidence(approval),
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

        # F7 — FIX THE INVOCATION DEADLINE HERE, once, from the validity
        # remaining right now. Everything below this line can consume a TTL: the
        # ownership substrate checks, the reconciliation lock, audit chain
        # verification, the per-intent receipt lookup, approval consumption
        # under a 30s busy timeout, the ledger append, and intent anchor
        # publication (four HTTP exchanges against an https anchor). The old
        # code sampled the clock once, at STEP 1, and never looked again — which
        # is how an approval that expired at t=1001 executed at t=5000.
        try:
            deadline = ExecutionDeadline.open(
                issued_at=approval.issued_at,
                expires_at=approval.expires_at,
                clock=self._clock,
                uncertainty_s=self._clock_uncertainty_s,
                trust_utc=self._trust_utc,
                elapsed=self._elapsed,
            )
        except ClockUntrusted as exc:
            audit = self._record(
                "refuse",
                self._target.identity.canonical,
                {
                    "phase": "clock_trust",
                    **execution_evidence(approval),
                    "reason": CLOCK_UNTRUSTED,
                    "detail": str(exc),
                },
            )
            return MigrationResult(
                executed=False,
                refused=True,
                reason=CLOCK_UNTRUSTED,
                detail=f"{exc} Approval unspent; DB not touched.",
                audit_recorded=audit.recorded,
            )
        except InvalidApprovalInterval as exc:
            audit = self._record(
                "refuse",
                self._target.identity.canonical,
                {
                    "phase": "verify",
                    **execution_evidence(approval),
                    "reason": INVALID_TIME,
                    "detail": str(exc),
                },
            )
            return MigrationResult(
                executed=False,
                refused=True,
                reason=INVALID_TIME,
                detail=f"approval interval unusable: {exc}; DB not touched",
                audit_recorded=audit.recorded,
            )

        try:
            with self._consumed.execution_guard() as owned:
                if not owned:
                    audit = self._record("refuse", self._target.identity.canonical, {
                        "phase": "ownership", "reason": RECONCILIATION_REQUIRED,
                        **execution_evidence(approval),
                    })
                    return MigrationResult(
                        False,
                        True,
                        RECONCILIATION_REQUIRED,
                        "another runner owns execution/recovery; approval remains unspent",
                        audit_recorded=audit.recorded,
                    )
                return self._execute_owned(
                    approval=approval, artifact=artifact, deadline=deadline
                )
        except _OwnershipUnavailable as exc:
            audit = self._record(
                "refuse",
                self._target.identity.canonical,
                {
                    "phase": "ownership",
                    **execution_evidence(approval),
                    "reason": STORE_UNAVAILABLE,
                    "error_type": str(exc),
                },
            )
            return MigrationResult(
                False,
                True,
                STORE_UNAVAILABLE,
                f"execution ownership unavailable: {exc}",
                audit_recorded=audit.recorded,
            )

    def _execute_owned(
        self,
        *,
        approval: Approval,
        artifact: MigrationArtifact,
        deadline: ExecutionDeadline,
    ) -> MigrationResult:
        # STEP 2 — a valid approval cannot proceed while an earlier intent for
        # this target remains ambiguous. Do not spend it: the caller may retry
        # after recovery succeeds.
        reconciliation = self._reconcile_owned()
        unresolved = next((item for item in reconciliation if not item.resolved), None)
        if unresolved is not None:
            audit = self._record(
                "refuse",
                self._target.identity.canonical,
                {
                    "phase": "reconcile",
                    **execution_evidence(approval),
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

        # F7 PHASE 1 — BEFORE THE NONCE CLAIM. Reconciliation above is the
        # single largest TTL consumer in the whole path (a remote anchor history
        # read, a full chain recompute, and a receipt lookup per unresolved
        # intent). If it ate the window, refuse with the approval UNSPENT: the
        # caller may legitimately obtain a fresh approval and retry.
        admission = deadline.admit()
        if not admission.admitted:
            audit = self._record(
                "refuse",
                self._target.identity.canonical,
                {
                    "phase": "expiry_before_spend",
                    **execution_evidence(approval),
                    "reason": admission.reason,
                    "detail": admission.detail,
                    "nonce_spent": False,
                    **deadline.as_payload(),
                },
            )
            return MigrationResult(
                executed=False,
                refused=True,
                reason=admission.reason,
                detail=(
                    f"approval no longer admissible before it was spent "
                    f"({admission.detail}); the approval remains UNSPENT and "
                    "the database was not touched"
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
                    **execution_evidence(approval),
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
                    **execution_evidence(approval),
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

        # F7 PHASE 2 — AFTER THE CLAIM, BEFORE THE INTENT. The claim itself runs
        # BEGIN IMMEDIATE under a 30-second busy timeout, which alone exceeds
        # many TTLs. The nonce STAYS SPENT: an approval that reached the store
        # has been used, and making it retryable would turn every slow claim
        # into a replay window. Nothing durable names this execution yet, so
        # there is no intent to reconcile and no outcome to link.
        admission = deadline.admit()
        if not admission.admitted:
            audit = self._record(
                "refuse",
                self._target.identity.canonical,
                {
                    "phase": "expiry_after_spend",
                    **execution_evidence(approval),
                    "reason": admission.reason,
                    "detail": admission.detail,
                    "nonce_spent": True,
                    "execution_id": execution_id,
                    **deadline.as_payload(),
                },
            )
            return MigrationResult(
                executed=False,
                refused=True,
                reason=admission.reason,
                detail=(
                    f"approval no longer admissible after the nonce was spent "
                    f"({admission.detail}); the nonce REMAINS SPENT and must not "
                    "be reused; no execution intent was recorded and the "
                    "database was not touched"
                ),
                audit_recorded=audit.recorded,
                execution_id=execution_id,
                execution_state=EXECUTION_NOT_ATTEMPTED,
            )

        # STEP 4 — persist a durable execution intent BEFORE touching the DB.
        # If the required audit sink cannot commit the intent, fail closed. The
        # nonce remains spent: an ambiguous audit write must never be made
        # retryable as a fresh approval. The intent names its owner (host, boot
        # id, machine id, pid) so a runner that later recovers it can tell
        # whether its own execution guard says anything about that owner.
        intent = self._record(
            "execute_intent",
            self._target.identity.canonical,
            {
                "phase": "execute_intent",
                **execution_evidence(approval),
                "execution_id": execution_id,
                "artifact_sha256": artifact.sha256,
                "target": self._target.identity.canonical,
                **self._identity.as_payload(),
                # Which F7 admission boundaries were in force for this run.
                # Boundary 1 (this runner) always is; boundary 2 lives inside
                # the executor and only an executor that takes the deadline can
                # enforce it. Recorded rather than assumed.
                "executor_enforces_deadline": self._executor_enforces_deadline,
                **deadline.as_payload(),
                # The lock this owner holds: a recovering runner on the same
                # kernel may treat its own exclusive lock as proof the owner
                # is gone only if it is provably this same object.
                "owner_lock_id": self._consumed.lock_id,
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

        # F7 PHASE 3 — AFTER THE DURABLE INTENT, BEFORE THE EXECUTOR. Recording
        # the intent publishes an anchor; against an https anchor that is FOUR
        # HTTP exchanges, each with its own deadline, so four individually
        # successful slow exchanges at the factory's 30s default outlast the 90s
        # default TTL on their own.
        #
        # The intent is durable, so this cannot simply return: an unresolved
        # intent is what makes the NEXT execution refuse for reconciliation. A
        # linked terminal outcome is appended saying exactly what happened —
        # nothing was attempted, nothing committed — which resolves the intent
        # truthfully rather than leaving a phantom for recovery to puzzle over.
        admission = deadline.admit()
        if not admission.admitted:
            outcome = self._record(
                "execute_outcome",
                self._target.identity.canonical,
                {
                    "phase": "expiry_before_executor",
                    **execution_evidence(approval),
                    "execution_id": execution_id,
                    "intent_seq": intent.seq,
                    "reason": admission.reason,
                    "detail": admission.detail,
                    "executed": False,
                    "execution_state": EXECUTION_NOT_ATTEMPTED,
                    "nonce_spent": True,
                    **deadline.as_payload(),
                },
            )
            if not outcome.recorded:
                # The terminal append failed. The nonce stays spent AND the
                # durable intent stays unresolved — both are true, and both must
                # remain visible. Reporting this as settled would tell an
                # operator the ledger says something it does not say.
                return MigrationResult(
                    executed=False,
                    refused=True,
                    reason=AUDIT_UNAVAILABLE,
                    detail=(
                        "the approval expired before the executor was called, "
                        "and the terminal outcome could NOT be recorded. No "
                        "migration was attempted and the database was not "
                        "touched, but the execution intent remains UNRESOLVED "
                        "in the ledger and the nonce remains spent; this "
                        "outcome is not durably settled and reconciliation must "
                        "resolve the intent"
                    ),
                    audit_recorded=False,
                    execution_id=execution_id,
                    execution_state=EXECUTION_NOT_ATTEMPTED,
                )
            return MigrationResult(
                executed=False,
                refused=True,
                reason=admission.reason,
                detail=(
                    f"approval no longer admissible after the execution intent "
                    f"was made durable ({admission.detail}); the executor was "
                    "NOT called, no migration statement was sent, nothing "
                    "committed, and a linked terminal outcome records that"
                ),
                audit_recorded=True,
                execution_id=execution_id,
                execution_state=EXECUTION_NOT_ATTEMPTED,
            )

        # STEP 5 — authorized, current, bound, first use, durable intent present:
        # run the migration. From here on expiry is NOT proof of rollback: the
        # executor may have started, the tri-state is preserved, and only an
        # acknowledged rollback or a receipt-based reconciliation settles it.
        try:
            response = self._executor(
                artifact.sql,
                self._target,
                execution_id,
                artifact.sha256,
                **({"deadline": deadline} if self._executor_enforces_deadline else {}),
            )
            if isinstance(response, ExecutorResult):
                execution = response
            elif (
                type(response) is tuple
                and len(response) == 2
                and type(response[0]) is bool
                and type(response[1]) is str
            ):
                # Alpha custom executors may still return (bool, detail). True
                # acknowledges commit; False NEVER establishes rollback.
                execution = ExecutorResult(
                    EXECUTION_COMMITTED if response[0] else EXECUTION_UNKNOWN,
                    response[1],
                )
            else:
                execution = ExecutorResult(
                    EXECUTION_UNKNOWN, "invalid executor response"
                )
        except Exception as exc:  # noqa: BLE001 - executor is an external boundary
            execution = ExecutorResult(
                EXECUTION_UNKNOWN, f"executor raised {type(exc).__name__}"
            )
        ok = execution.state == EXECUTION_COMMITTED
        detail = execution.detail
        reason = (
            "ok"
            if ok
            else "migration_error"
            if execution.state == EXECUTION_NOT_COMMITTED
            else EXECUTION_UNKNOWN
        )
        outcome = self._record(
            "execute_unknown"
            if execution.state == EXECUTION_UNKNOWN
            else "execute_outcome",
            self._target.identity.canonical,
            {
                "phase": "execute_unknown"
                if execution.state == EXECUTION_UNKNOWN
                else "execute_outcome",
                "intent_seq": intent.seq,
                **execution_evidence(approval),
                "execution_id": execution_id,
                "artifact_sha256": artifact.sha256,
                "target": self._target.identity.canonical,
                "ok": bool(ok),
                "reason": reason,
                "execution_state": execution.state,
            },
        )
        if not outcome.recorded:
            migration_state = "succeeded" if ok else f"{execution.state}: {detail}"
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
                execution_state=execution.state,
            )
        return MigrationResult(
            executed=ok,
            refused=False,
            reason=reason,
            detail=(
                f"migration applied to {self._target.identity.canonical}"
                if ok
                else f"authorized migration {execution.state}: {detail}"
            ),
            audit_recorded=outcome.recorded,
            execution_id=execution_id,
            execution_state=execution.state,
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

    authority: RecordedApprovalAuthority
    runner: BrokeredMigrationRunner

    def close(self) -> None:
        self.runner.close()

    def __enter__(self) -> MigrationRuntime:  # noqa: PYI034
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class SignerRequest(Protocol):
    """What ``resolve_signer`` actually reads: three attributes, no more.

    ``MigrationRunnerConfig`` satisfies this, and so does any other carrier that
    needs a signer resolved — the attestation path builds one. Naming the real
    requirement here is what removed a ``# type: ignore[arg-type]`` at that call
    site: the annotation used to demand the whole runner config for three
    fields, so an honest caller with exactly those three had to silence the
    checker to pass them.
    """

    @property
    def signer(self) -> ApprovalSigner | None: ...

    @property
    def signing_key(self) -> Secret | bytes | None: ...

    @property
    def require_external_signer(self) -> bool: ...


def resolve_signer(
    config: SignerRequest,
    *,
    settings: object | None = None,
    env: Mapping[str, str] | None = None,
) -> ApprovalSigner:
    """The signer this configuration requests — honoured, or refused.

    The requirement for external custody is the OR of its sources: the runner
    config, the runtime ``Config`` (``settings.require_external_signer``) and
    ``PROM_REQUIRE_EXTERNAL_SIGNER``. Under it a local key is refused as a
    requirement that cannot be honoured — never quietly accepted, and there is
    no path here from a configured external signer to a local key. Without it
    a local key is allowed and warned about as non-protecting.
    """

    required = (
        bool(config.require_external_signer)
        or bool(getattr(settings, "require_external_signer", False))
        or external_signer_required(env)
    )
    if config.signer is not None:
        signer = config.signer
    elif config.signing_key is not None:
        # Normalised to a Secret by MigrationRunnerConfig.__post_init__; a
        # bespoke SignerRequest may still hand over raw bytes.
        key = config.signing_key
        # Narrowed in STATEMENT form, not a ternary: the type gate refuses
        # expression-position isinstance because a union narrowed inside an
        # expression is invisible to the reader and to assert_never.
        if isinstance(key, Secret):
            signer = LocalHmacSigner(key.reveal())
        else:
            signer = LocalHmacSigner(key)
    else:
        raise ConfigError("a signer or a signing key is required")
    if required and not getattr(signer, "external", False):
        raise ConfigError(
            "an external approval signer is required "
            f"({EXTERNAL_SIGNER_REQUIRED_ENV}=1 or require_external_signer=True) "
            "and the configured signer holds its key on this host. Configure a "
            "KmsSigner (docs/key-custody.md), or withdraw the requirement."
        )
    if not getattr(signer, "external", False):
        _LOG.warning(
            "approval signing uses a LOCAL key (%s): NON-PROTECTING against a "
            "host-level insider, who reads it from the process and mints "
            "approvals with no record anywhere. Development only; production "
            "signs through an external KMS (docs/key-custody.md).",
            getattr(signer, "key_id", "?"),
        )
    return signer


def build_migration_runtime(
    config: MigrationRunnerConfig,
    *,
    audit: AuditSink,
    authorization: AuthorizationContext | None = None,
    executor: MigrationExecutor = postgres_executor,
    receipt_lookup: ReceiptLookup | None = None,
    clock: Callable[[], float] = time.time,
    settings: object | None = None,
    env: Mapping[str, str] | None = None,
) -> MigrationRuntime:
    """Build production wiring with a stable signer, durable store, and audit.

    ``settings`` is the runtime :class:`~prometheus_protocol.core.config.Config`
    when the caller has one; its ``require_external_signer`` is one of the
    sources of the custody requirement (:func:`resolve_signer`).
    """

    if audit is None:
        raise ValueError("migration runner audit sink is required")
    signer = resolve_signer(config, settings=settings, env=env)
    substrate_policy = resolve_substrate_policy(config, settings=settings, env=env)
    consumed = ConsumedApprovals(
        config.approval_store_path, substrate_policy=substrate_policy
    )
    try:
        if not isinstance(authorization, AuthorizationContext):
            raise ConfigError(
                "production issuance requires an explicit AuthorizationContext"
            )
        from prometheus_protocol.runtime.factory import ledger_anchor_required

        journal = AuthorizationJournal(
            audit,
            substrate_policy=substrate_policy,
            require_anchor=bool(getattr(settings, "require_ledger_anchor", False))
            or ledger_anchor_required(env),
        )
        authority = RecordedApprovalAuthority(
            signer=signer, journal=journal, context=authorization, clock=clock
        )
        runner = BrokeredMigrationRunner(
            authority=authority,
            target=config.target,
            consumed=consumed,
            executor=executor,
            receipt_lookup=receipt_lookup,
            audit=audit,
            clock=clock,
        )
    except Exception:
        consumed.close()
        raise
    return MigrationRuntime(authority=authority, runner=runner)


def build_migration_runner(
    config: MigrationRunnerConfig,
    *,
    audit: AuditSink,
    executor: MigrationExecutor = postgres_executor,
    receipt_lookup: ReceiptLookup | None = None,
    clock: Callable[[], float] = time.time,
    settings: object | None = None,
    env: Mapping[str, str] | None = None,
) -> BrokeredMigrationRunner:
    """Build only the runner side of the required production composition.

    Prefer :func:`build_migration_runtime` when the same process also mints
    approvals, because it exposes the one shared authority without duplicating
    key configuration.
    """

    authority = ApprovalAuthority(
        signer=resolve_signer(config, settings=settings, env=env)
    )
    consumed = ConsumedApprovals(
        config.approval_store_path,
        substrate_policy=resolve_substrate_policy(config, settings=settings, env=env),
    )
    try:
        return BrokeredMigrationRunner(
            authority=authority,
            target=config.target,
            consumed=consumed,
            audit=audit,
            executor=executor,
            receipt_lookup=receipt_lookup,
            clock=clock,
        )
    except Exception:
        consumed.close()
        raise
