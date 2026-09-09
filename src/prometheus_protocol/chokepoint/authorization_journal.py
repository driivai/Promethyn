"""Durable F11 issuance journal over the existing ledger chain and anchor.

Each operation uses its own SQLite connection, never shared across threads or
inherited across fork. BEGIN IMMEDIATE owns uniqueness and the decision append.
There is deliberately no API that resumes or re-signs a stored decision.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from prometheus_protocol.chokepoint.authorization_record import (
    DECISION_EVENT,
    SIGN_RESULT_EVENT,
    AuthorizationRecord,
    strict_json,
    validate_sign_result,
)
from prometheus_protocol.chokepoint.substrate import (
    SubstratePolicy,
    enforce_substrate,
    probe_file_substrate,
)
from prometheus_protocol.ledger.audit_chain import canonical_json
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.ledger.tip_anchor import anchor_history


class AuthorizationUnavailable(RuntimeError):
    """Issuance evidence could not be durably established; no approval returned."""


@dataclass(frozen=True)
class AuthorizationReceipt:
    ledger_id: str
    seq: int
    entry_hash: str
    authorization_id: str
    authorization_record_hash: str


class AuthorizationJournal:
    def __init__(
        self,
        audit: object,
        *,
        substrate_policy: SubstratePolicy,
        require_anchor: bool = False,
    ) -> None:
        if not isinstance(audit, SqliteLedger) or audit.path == ":memory:":
            raise AuthorizationUnavailable(
                "issuance requires a private file-backed SqliteLedger"
            )
        self.path = Path(audit.path).absolute()
        self._substrate_policy = substrate_policy
        SqliteLedger.check_private_path(self.path)
        self._anchor = audit.tip_anchor
        if require_anchor and (self._anchor is None or not self._anchor.append_only):
            raise AuthorizationUnavailable(
                "issuance requires an external append-only ledger anchor"
            )
        info = self.path.stat()
        self._identity = (info.st_dev, info.st_ino)
        self._check_path()

    def _check_path(self) -> None:
        SqliteLedger.check_private_path(self.path)
        info = self.path.stat()
        if (info.st_dev, info.st_ino) != self._identity:
            raise AuthorizationUnavailable("authorization ledger was replaced")
        # The journal already exists. An inspected O_PATH descriptor, not its
        # parent, establishes placement without interfering with SQLite locks.
        report = probe_file_substrate(self.path)
        if report.device is not None and (report.device, report.inode) != self._identity:
            raise AuthorizationUnavailable("authorization ledger changed during inspection")
        enforce_substrate(report, self._substrate_policy)

    @contextmanager
    def _session(self):
        ledger = None
        try:
            self._check_path()
            ledger = SqliteLedger(self.path, tip_anchor=self._anchor)
            self._check_path()
            ledger._conn.execute("PRAGMA synchronous=FULL")
            if ledger._conn.execute("PRAGMA synchronous").fetchone()[0] != 2:
                raise AuthorizationUnavailable(
                    "authorization ledger cannot honor synchronous durability"
                )
            yield ledger
        except AuthorizationUnavailable:
            raise
        except Exception:  # noqa: BLE001 - an external durability boundary must refuse
            # A sink exception may contain SQL, credentials or response bodies.
            raise AuthorizationUnavailable(
                "authorization journal unavailable"
            ) from None
        finally:
            if ledger is not None:
                ledger.close()

    def _rows(
        self, ledger: SqliteLedger, *, require_coverage: bool = False
    ) -> list[dict]:
        if not ledger.verify_chain().ok:
            raise AuthorizationUnavailable(
                "authorization ledger integrity could not be established"
            )
        rows = ledger.chained_events()
        if require_coverage and self._anchor is not None and rows:
            history = anchor_history(self._anchor)
            if not any(t.seq >= rows[-1]["seq"] for t in history):
                raise AuthorizationUnavailable(
                    "authorization ledger tail is not anchored"
                )
        return rows

    def records(self) -> list[AuthorizationRecord]:
        """Disk-only checked snapshots; never a digest cache or a match verdict."""
        with self._session() as ledger:
            ledger._conn.execute("BEGIN IMMEDIATE")
            rows = self._rows(ledger, require_coverage=True)
            records = self._decisions(rows)
            ledger._conn.rollback()
            return records

    @staticmethod
    def _decisions(rows: list[dict]) -> list[AuthorizationRecord]:
        ids, requests, nonces = set(), set(), set()
        by_id: dict[str, AuthorizationRecord] = {}
        signed = set()
        result = []
        for row in rows:
            if row["event"] == SIGN_RESULT_EVENT:
                decision = by_id.get(row["subject"])
                if decision is None or row["subject"] in signed:
                    raise AuthorizationUnavailable("orphan or duplicate sign result")
                payload = strict_json(row["payload"])
                validate_sign_result(payload, decision)
                if row["created_at"] != payload["observed_at"]:
                    raise AuthorizationUnavailable("sign result time mismatch")
                signed.add(row["subject"])
                continue
            if row["event"] != DECISION_EVENT:
                continue
            record = AuthorizationRecord.from_dict(strict_json(row["payload"]))
            value = record.to_dict()
            if (
                row["subject"] != record.authorization_id
                or row["created_at"] != value["recorded_at"]
            ):
                raise AuthorizationUnavailable("authorization subject mismatch")
            if record.authorization_id in ids or value["request_id"] in requests:
                raise AuthorizationUnavailable("duplicate authorization identity")
            ids.add(record.authorization_id)
            by_id[record.authorization_id] = record
            requests.add(value["request_id"])
            if value["nonce"] is not None:
                nonce_key = (value["approval_key_id"], value["nonce"])
                if nonce_key in nonces:
                    raise AuthorizationUnavailable("duplicate authorization nonce")
                nonces.add(nonce_key)
            result.append(record)
        return result

    def _append(
        self,
        ledger: SqliteLedger,
        *,
        event: str,
        record: AuthorizationRecord,
        payload: dict,
        at: str,
    ) -> AuthorizationReceipt:
        seq = ledger.record_chained(
            event=event, subject=record.authorization_id, payload=payload, created_at=at
        )
        if type(seq) is not int or seq < 1:
            raise AuthorizationUnavailable("invalid authorization append receipt")
        self._check_path()
        fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        rows = self._rows(ledger)
        held = next((row for row in rows if row["seq"] == seq), None)
        if (
            held is None
            or held["event"] != event
            or held["subject"] != record.authorization_id
            or held["created_at"] != at
            or held["payload"] != canonical_json(payload)
        ):
            raise AuthorizationUnavailable("authorization append was not confirmed")
        if self._anchor is not None and not any(
            t.seq >= seq for t in anchor_history(self._anchor)
        ):
            raise AuthorizationUnavailable("authorization append is not anchored")
        return AuthorizationReceipt(
            rows[0]["entry_hash"],
            seq,
            held["entry_hash"],
            record.authorization_id,
            record.record_hash,
        )

    def record_decision(self, record: AuthorizationRecord) -> AuthorizationReceipt:
        with self._session() as ledger:
            ledger._conn.execute("BEGIN IMMEDIATE")
            existing = self._decisions(self._rows(ledger))
            value = record.to_dict()
            for old in existing:
                prior = old.to_dict()
                if (
                    old.authorization_id == record.authorization_id
                    or prior["request_id"] == value["request_id"]
                    or (
                        value["nonce"] is not None
                        and prior["nonce"] == value["nonce"]
                        and prior["approval_key_id"] == value["approval_key_id"]
                    )
                ):
                    raise AuthorizationUnavailable(
                        "authorization ID or nonce already recorded; no re-sign"
                    )
            return self._append(
                ledger,
                event=DECISION_EVENT,
                record=record,
                payload=value,
                at=value["recorded_at"],
            )

    def record_sign_result(
        self, record: AuthorizationRecord, payload: dict
    ) -> AuthorizationReceipt:
        validate_sign_result(payload, record)
        with self._session() as ledger:
            ledger._conn.execute("BEGIN IMMEDIATE")
            rows = self._rows(ledger)
            records = self._decisions(rows)
            if not any(r.record_hash == record.record_hash for r in records):
                raise AuthorizationUnavailable("sign result has no durable decision")
            if any(
                row["event"] == SIGN_RESULT_EVENT
                and row["subject"] == record.authorization_id
                for row in rows
            ):
                raise AuthorizationUnavailable("sign result already recorded")
            return self._append(
                ledger,
                event=SIGN_RESULT_EVENT,
                record=record,
                payload=payload,
                at=payload["observed_at"],
            )
