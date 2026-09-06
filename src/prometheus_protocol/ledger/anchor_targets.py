"""External anchor targets: one immutable record per tip, on a medium that
refuses to rewrite history.

``FileTipAnchor`` writes one file and overwrites it, so it is worth exactly
what its placement is worth — and the placement most people reach for (next to
the ledger) is worth nothing. The two families here change the shape of the
anchor instead of just its location: every anchored tip becomes its **own
record, created once and never overwritten or deleted by this code**, and the
verifier pins **every record** in that history. Then:

* a genesis rewrite of the ledger cannot be hidden by writing a new record —
  the honest records are still there and still pinned, so the rewritten prefix
  mismatches them (``BROKEN`` at the first anchored seq it disagrees with);
* a forged record appended by someone who holds the anchor's *write*
  credential does not mask the honest ones either — the verifier sees both and
  reports the conflict, naming the anchor history itself as the evidence;
* what the adversary needs instead is authority over the **medium**: to delete
  or replace records. That is what the medium is chosen to refuse — an
  object-lock bucket in compliance mode refuses it to every principal until
  the retention date, a WORM volume refuses it outright, a log run by another
  party refuses it to this host — and it is the exact statement of the trust
  boundary (``docs/threat-model.md`` §3.4).

**What is not claimed.** An adversary with authority over the medium is not
detected: retention that has lapsed, a governance-mode bypass, the deletion of
the whole account, the log operator themselves. That is a passing test, not a
caveat. Nothing here is uncrackable; it converts "undetectable" into
"detectable by a witness the ledger-writer cannot silence", for as long as the
witness stays outside the ledger-writer's authority.

**Object-lock port.** No cloud SDK is bundled; shipping a bucket client the CI
cannot run against a real bucket would be a guard nobody has seen work. The
:class:`ObjectStore` port is three operations, and the mapping to an S3-style
object-lock bucket is one line each:

* ``put_if_absent`` → ``PutObject`` with ``If-None-Match: *`` (fails if the key
  exists), ``ObjectLockMode=COMPLIANCE`` and ``ObjectLockRetainUntilDate``;
* ``versions`` → ``ListObjectVersions`` for the key plus ``GetObject`` per
  version. A versioned bucket keeps every version, and an *unconditional*
  ``PutObject`` by a credential holder adds one rather than replacing — reading
  every version is what makes that forgery visible instead of hiding it behind
  "latest";
* ``list_keys`` → ``ListObjectsV2`` under the prefix.

:class:`MemoryObjectLockStore` is that medium's semantics in memory — the
reference the tests run against, including the adversary's operations
(``overwrite``, ``delete``) and an injectable clock so retention can lapse.
:class:`DirectoryObjectStore` is the same shape on a directory, for a
WORM-mounted volume.
"""

from __future__ import annotations

import errno
import os
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from prometheus_protocol.core.anchor_spec import ANCHOR_FILE, ANCHOR_LOG, ANCHOR_WORM, AnchorSpec
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.core.validation import require_positive
from prometheus_protocol.ledger.audit_chain import ChainTip
from prometheus_protocol.ledger.tip_anchor import (
    AnchorRewind,
    AnchorUnavailable,
    FileTipAnchor,
    TipAnchor,
    check_monotonic,
    decode_record,
    encode_tip,
)

#: Retention requested for each record on an object-lock medium. Ten years: a
#: record is a hundred bytes, and the retention window is exactly the period
#: over which a rewrite stays detectable (threat model §3.4) — a shorter window
#: is the residual, not a saving.
DEFAULT_RETENTION_S = 3650 * 86_400

_KEY_WIDTH = 20
_KEY_PATTERN = re.compile(r"^(?P<seq>\d{20})\.json$")
_SAFE_KEY = re.compile(r"^[A-Za-z0-9._/-]+$")


# ---------------------------------------------------------------------------
# The object-lock family
# ---------------------------------------------------------------------------


class ObjectStoreError(RuntimeError):
    """The medium refused or failed an operation."""


class ObjectExists(ObjectStoreError):
    """A create-if-absent found the key already written."""


class ObjectLocked(ObjectStoreError):
    """A delete or overwrite was refused: retention is in force."""


class ObjectStore(Protocol):
    """The three operations the object-lock anchor needs from a write-once
    medium. See the module docstring for the bucket mapping."""

    def put_if_absent(self, key: str, body: bytes, *, retain_for_s: float) -> None:
        """Create ``key`` with ``body`` under retention; :class:`ObjectExists`
        if any version of ``key`` already exists."""

    def versions(self, key: str) -> list[bytes]:
        """Every version ever written under ``key``, oldest first; ``[]`` if none."""

    def list_keys(self, prefix: str) -> list[str]:
        """Every key under ``prefix``, sorted."""


@dataclass
class _Version:
    body: bytes
    retain_until: float


class MemoryObjectLockStore:
    """An object-lock bucket in compliance mode, in memory.

    The reference semantics the tests run against. Honest operations are the
    port's three. The adversary's operations — modelled here so the tests can
    exercise them, and never called by the anchor — are :meth:`overwrite` (an
    unconditional put: it *adds* a version, the earlier one stays) and
    :meth:`delete` (refused while any version is under retention). The clock is
    injectable so a test can let retention lapse, which is the residual.
    """

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._objects: dict[str, list[_Version]] = {}
        self._clock = clock
        #: Every put the anchor made, in order — for the tests' write-order proof.
        self.writes: list[str] = []

    def put_if_absent(self, key: str, body: bytes, *, retain_for_s: float) -> None:
        if key in self._objects:
            raise ObjectExists(f"{key} already exists; a record is never overwritten")
        self._objects[key] = [_Version(bytes(body), self._clock() + retain_for_s)]
        self.writes.append(key)

    def versions(self, key: str) -> list[bytes]:
        return [version.body for version in self._objects.get(key, [])]

    def list_keys(self, prefix: str) -> list[str]:
        return sorted(key for key in self._objects if key.startswith(prefix))

    # -- the adversary's operations: what a credential holder can and cannot do

    def overwrite(self, key: str, body: bytes, *, retain_for_s: float = 0.0) -> None:
        """An unconditional put. Adds a version; the locked earlier version stays."""

        self._objects.setdefault(key, []).append(
            _Version(bytes(body), self._clock() + retain_for_s)
        )

    def delete(self, key: str) -> None:
        """Delete every version of ``key`` — refused while any is under retention."""

        versions = self._objects.get(key)
        if not versions:
            return
        now = self._clock()
        locked = [version for version in versions if version.retain_until > now]
        if locked:
            raise ObjectLocked(
                f"{key} is under retention for another "
                f"{max(v.retain_until for v in locked) - now:.0f}s; compliance-mode "
                "retention cannot be shortened or bypassed by any principal"
            )
        del self._objects[key]


class DirectoryObjectStore:
    """One file per record in a directory, created once and never overwritten
    or deleted by this code.

    Protecting on a WORM-mounted directory, where the medium refuses the
    deletion this code never attempts. On an ordinary filesystem it is as
    rewritable as the ledger — the ``worm://`` name states the requirement, it
    does not check it, and the anchor cannot tell the difference. Retention is
    the mount's configuration, not a per-file request, so ``retain_for_s`` is
    accepted and ignored here; that is named in ``docs/ledger-integrity.md``.

    Creation is atomic where the filesystem supports hard links (write a
    temporary file, ``link`` it into place — ``EEXIST`` is the refusal), so a
    crash can never leave a half-written record that would make the anchor
    unreadable forever on a medium nobody can clean up. Where ``link`` is
    unsupported the fallback is an ``O_EXCL`` create followed by the write.
    """

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(os.fspath(root))

    def _path(self, key: str) -> Path:
        if not _SAFE_KEY.match(key) or ".." in key.split("/"):
            raise ObjectStoreError(f"refusing key {key!r}")
        return self.root / key

    def put_if_absent(self, key: str, body: bytes, *, retain_for_s: float) -> None:
        path = self._path(key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary = tempfile.mkstemp(
                dir=str(path.parent), prefix=".record-", suffix=".tmp"
            )
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(body)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temporary, 0o400)
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    raise ObjectExists(f"{path} already exists; a record is never overwritten")
                except OSError as exc:
                    if exc.errno not in (errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EXDEV):
                        raise
                    # No hard links on this mount: an exclusive create is the
                    # atomic step, the write follows it.
                    self._create_exclusive(path, body)
            finally:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
        except ObjectStoreError:
            raise
        except OSError as exc:
            raise ObjectStoreError(f"could not write {path}: {exc}") from exc

    @staticmethod
    def _create_exclusive(path: Path, body: bytes) -> None:
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        except FileExistsError:
            raise ObjectExists(f"{path} already exists; a record is never overwritten")
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())

    def versions(self, key: str) -> list[bytes]:
        path = self._path(key)
        try:
            return [path.read_bytes()]
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise ObjectStoreError(f"could not read {path}: {exc}") from exc

    def list_keys(self, prefix: str) -> list[str]:
        try:
            if not self.root.exists():
                return []
            names = []
            for entry in os.scandir(self.root):
                if entry.name.startswith(".record-"):
                    continue  # a temporary from an interrupted write, never a record
                if not entry.name.startswith(prefix):
                    continue
                if not entry.is_file(follow_symlinks=False):
                    # Something that is not a record is sitting in the anchor's
                    # directory. Loud, not skipped: skipping would let a planted
                    # entry shadow nothing and a real one go unread.
                    raise ObjectStoreError(f"{entry.path} is not a regular file")
                names.append(entry.name)
            return sorted(names)
        except OSError as exc:
            raise ObjectStoreError(f"could not list {self.root}: {exc}") from exc


class ObjectLockTipAnchor:
    """A tip anchor that writes one immutable record per tip to an
    :class:`ObjectStore`, keyed by seq, and reads the whole history back."""

    name = "object-lock"
    append_only = True

    def __init__(
        self,
        store: ObjectStore,
        *,
        prefix: str = "",
        retain_for_s: float = DEFAULT_RETENTION_S,
    ) -> None:
        self._store = store
        self._prefix = prefix
        self._retain_for_s = require_positive(retain_for_s, name="retain_for_s")

    def _key(self, seq: int) -> str:
        return f"{self._prefix}{seq:0{_KEY_WIDTH}d}.json"

    def _seq_of(self, key: str) -> int:
        match = _KEY_PATTERN.match(key[len(self._prefix):]) if key.startswith(self._prefix) else None
        if match is None:
            raise AnchorUnavailable(
                f"anchor {self.name} holds an object that is not a record: {key!r}"
            )
        return int(match.group("seq"))

    def _records_at(self, key: str) -> list[ChainTip]:
        seq = self._seq_of(key)
        try:
            bodies = self._store.versions(key)
        except ObjectStoreError as exc:
            raise AnchorUnavailable(f"anchor {self.name} could not read {key}: {exc}") from exc
        tips = []
        for index, body in enumerate(bodies):
            tip = decode_record(body, where=f"{self.name}:{key}#{index}")
            if tip.seq != seq:
                raise AnchorUnavailable(
                    f"anchor {self.name}: the record at {key} claims seq {tip.seq}; "
                    "a record that does not belong at its position is tampering "
                    "or corruption, not something to read past"
                )
            tips.append(tip)
        return tips

    def _keys(self) -> list[str]:
        try:
            return self._store.list_keys(self._prefix)
        except ObjectStoreError as exc:
            raise AnchorUnavailable(f"anchor {self.name} could not be listed: {exc}") from exc

    def history(self) -> list[ChainTip]:
        tips: list[ChainTip] = []
        for key in self._keys():
            tips.extend(self._records_at(key))
        return tips

    def read(self) -> ChainTip | None:
        keys = self._keys()
        if not keys:
            return None
        records = self._records_at(keys[-1])
        return records[-1] if records else None

    def write(self, tip: ChainTip) -> None:
        # The guard needs only the highest anchored seq, so a write reads one
        # key, not the whole history (which grows by one record per append).
        keys = self._keys()
        latest = self._records_at(keys[-1]) if keys else []
        if check_monotonic(latest, tip, where=self.name):
            return  # already anchored exactly; a record is never rewritten
        key = self._key(tip.seq)
        body = encode_tip(tip).encode("utf-8")
        try:
            self._store.put_if_absent(key, body, retain_for_s=self._retain_for_s)
        except ObjectExists:
            # A crash between the medium's write and our return, or a second
            # writer of the same ledger: fine if the record there is this one,
            # a rewrite if it is not.
            try:
                existing = self._store.versions(key)
            except ObjectStoreError as exc:
                raise AnchorUnavailable(f"anchor {self.name} could not read {key}: {exc}") from exc
            if body in existing:
                return
            raise AnchorRewind(
                f"refusing to anchor seq {tip.seq} at {self.name}: a different "
                "record already holds that position"
            )
        except ObjectStoreError as exc:
            raise AnchorUnavailable(
                f"anchor {self.name} could not write seq {tip.seq}: {exc}"
            ) from exc


# ---------------------------------------------------------------------------
# The append-only log family
# ---------------------------------------------------------------------------


class AppendOnlyLog(Protocol):
    """A log this host can only append to. The writer never edits past entries;
    whether anyone else can is the log operator's property, not this code's."""

    def append(self, record: bytes) -> int:
        """Append ``record``; return its index."""

    def entries(self) -> list[bytes]:
        """Every record, oldest first."""

    def latest(self) -> bytes | None:
        """The newest record, or ``None`` when the log is empty."""


class MemoryAppendOnlyLog:
    """An append-only log in memory, with the operator's authority modelled
    separately from the writer's so the residual can be a test."""

    def __init__(self) -> None:
        self._entries: list[bytes] = []

    def append(self, record: bytes) -> int:
        self._entries.append(bytes(record))
        return len(self._entries) - 1

    def entries(self) -> list[bytes]:
        return list(self._entries)

    def latest(self) -> bytes | None:
        return self._entries[-1] if self._entries else None

    def operator_rewrite(self, records: list[bytes]) -> None:
        """What the log's OPERATOR can do and its writers cannot: replace the
        stored history. The residual, not an operation the anchor has."""

        self._entries = [bytes(record) for record in records]


class LogTipAnchor:
    """A tip anchor that appends one record per tip to an :class:`AppendOnlyLog`
    and reads the whole log back."""

    name = "append-only-log"
    append_only = True

    def __init__(self, log: AppendOnlyLog) -> None:
        self._log = log

    def history(self) -> list[ChainTip]:
        try:
            entries = self._log.entries()
        except AnchorUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - the log is an external boundary
            raise AnchorUnavailable(f"anchor {self.name} could not be read: {exc}") from exc
        return [
            decode_record(body, where=f"{self.name}#{index}")
            for index, body in enumerate(entries)
        ]

    def _latest(self) -> ChainTip | None:
        try:
            body = self._log.latest()
        except AnchorUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AnchorUnavailable(f"anchor {self.name} could not be read: {exc}") from exc
        return decode_record(body, where=f"{self.name}#latest") if body is not None else None

    def read(self) -> ChainTip | None:
        history = self.history()
        if not history:
            return None
        # The highest anchored seq; the newest record among equals.
        return max(reversed(history), key=lambda tip: tip.seq)

    def write(self, tip: ChainTip) -> None:
        latest = self._latest()
        if check_monotonic([latest] if latest is not None else [], tip, where=self.name):
            return
        try:
            self._log.append(encode_tip(tip).encode("utf-8"))
        except AnchorUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AnchorUnavailable(
                f"anchor {self.name} could not append seq {tip.seq}: {exc}"
            ) from exc


# ---------------------------------------------------------------------------
# From a parsed spec to a target
# ---------------------------------------------------------------------------


def build_tip_anchor(
    spec: AnchorSpec,
    *,
    token: str | None = None,
    retain_for_s: float = DEFAULT_RETENTION_S,
    timeout_s: float = 10.0,
    max_response_bytes: int | None = None,
    allow_insecure_loopback: bool = False,
) -> TipAnchor:
    """The target a parsed ``PROM_LEDGER_ANCHOR`` names."""

    if spec.kind == ANCHOR_FILE:
        return FileTipAnchor(spec.target)
    if spec.kind == ANCHOR_WORM:
        return ObjectLockTipAnchor(DirectoryObjectStore(spec.target), retain_for_s=retain_for_s)
    if spec.kind == ANCHOR_LOG:
        from prometheus_protocol.ledger.anchor_http import HttpAppendOnlyLog

        options: dict[str, object] = {}
        if max_response_bytes is not None:
            options["max_response_bytes"] = max_response_bytes
        return LogTipAnchor(
            HttpAppendOnlyLog(
                spec.target,
                token=token,
                timeout_s=timeout_s,
                allow_insecure_loopback=allow_insecure_loopback,
                **options,  # type: ignore[arg-type]
            )
        )
    raise ConfigError(f"unknown anchor kind {spec.kind!r}")
