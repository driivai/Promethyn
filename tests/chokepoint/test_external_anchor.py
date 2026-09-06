"""PIH-1 — the external ledger anchor: a witness the ledger-writer cannot silence.

The worst documented residual of the ledger was that an adversary who can
rewrite the ledger file rewrites it from genesis, recomputes every hash, and
nothing notices. Attacker 3 made a tip anchor operational; its own honest test
(``test_tip_anchor.py``) records that an anchor on the adversary's medium
defends nothing. This sprint changes the SHAPE of the anchor, not just its
location: every anchored tip is its own record on a medium that refuses to
rewrite history, and the verifier pins every record in that history.

Doctrine, stated so the tests can be read against it:

* **Detection, not prevention.** Nothing here stops a rewrite. It converts
  "undetectable" into "detected by an out-of-band witness".
* **Every rewrite is performed for real.** The forged chain is rebuilt with
  correct hashes and asserted VALID on its own terms BEFORE the anchor is
  consulted; a test where the forgery was merely broken proves nothing.
* **The residual is a passing test.** An adversary with authority over the
  anchor *medium* — retention lapsed, the log's own operator — is NOT detected,
  and the tests that say so pass, so the claim cannot quietly grow.
* **Nothing skips.** Every target here runs on every CI runner: the object-lock
  medium is modelled in memory with its exact semantics, the WORM directory is a
  real directory whose exclusive creates are OS-enforced, and the remote log is
  a real HTTP server on loopback.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from prometheus_protocol.chokepoint import (
    RECEIPT_NOT_FOUND,
    ApprovalAuthority,
    BrokeredMigrationRunner,
    ConsumedApprovals,
    DbTarget,
    MigrationArtifact,
    ReceiptStatus,
)
from prometheus_protocol.chokepoint.runner import AUDIT_UNAVAILABLE
from prometheus_protocol.cli.main import main as cli_main
from prometheus_protocol.core.anchor_spec import (
    ANCHOR_FILE,
    ANCHOR_LOG,
    ANCHOR_WORM,
    parse_anchor_spec,
)
from prometheus_protocol.core.config import SECURITY_FIELDS, Config
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.ledger.anchor_http import HttpAppendOnlyLog
from prometheus_protocol.ledger.anchor_targets import (
    DEFAULT_RETENTION_S,
    DirectoryObjectStore,
    LogTipAnchor,
    MemoryAppendOnlyLog,
    MemoryObjectLockStore,
    ObjectExists,
    ObjectLocked,
    ObjectLockTipAnchor,
    ObjectStoreError,
)
from prometheus_protocol.ledger.audit_chain import (
    BROKEN,
    GENESIS_ROOT,
    NOT_VERIFIABLE,
    TRUNCATED,
    VALID,
    ChainTip,
    canonical_json,
    entry_hash,
    verify_rows,
)
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger, verify_ledger_file
from prometheus_protocol.ledger.tip_anchor import (
    AnchorRewind,
    AnchorUnavailable,
    FileTipAnchor,
    encode_tip,
)
from prometheus_protocol.runtime.factory import (
    LEDGER_ANCHOR_REQUIRED_ENV,
    build_execution_controller,
    build_ledger,
    build_tip_anchor_for,
)

CREATED_AT = "2026-01-01T00:00:00Z"
REPO = Path(__file__).resolve().parents[2]
FORGED = [{"step": 0}, {"step": 1}, {"forged": "the migration never happened"}]


# ---------------------------------------------------------------------------
# A witness log on loopback: the https:// target's other party, for real
# ---------------------------------------------------------------------------


class _LogHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args) -> None:  # noqa: D401 - silence the server
        pass

    def _json(self, status: int, payload) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._body(status, body)

    def _body(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self) -> bool:
        server = self.server
        server.seen_auth.append(self.headers.get("Authorization"))
        if server.token is None:
            return True
        return self.headers.get("Authorization") == f"Bearer {server.token}"

    def do_POST(self) -> None:  # noqa: N802
        server = self.server
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        if server.mode == "http500":
            self._json(500, {"error": "boom"})
            return
        if not self._authorised():
            self._json(401, {"error": "unauthorised"})
            return
        try:
            record = json.loads(raw.decode("utf-8"))
        except ValueError:
            self._json(400, {"error": "not json"})
            return
        if not isinstance(record, dict):
            self._json(400, {"error": "not an object"})
            return
        if server.post_mode == "no_store":
            self._json(201, {"index": 0})
            return
        if server.post_mode == "wrong_record":
            record["entry_hash"] = "f" * 64
        with server.lock:
            server.records.append(record)
            index = len(server.records) - 1
            if server.post_mode == "concurrent_append":
                server.records.append({**record, "seq": record["seq"] + 1})
        if server.ack_body is not None:
            self._body(server.post_status, server.ack_body)
        else:
            self._json(server.post_status, {"index": index})

    def do_GET(self) -> None:  # noqa: N802
        server = self.server
        mode = server.mode
        if server.post_mode == "readback_down" and server.records:
            self._json(500, {"error": "read-back unavailable"})
            return
        if mode == "http500":
            self._json(500, {"error": "boom"})
            return
        if mode == "hang":
            server.stop.wait(30)
            return
        if mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if mode == "nonjson":
            body = b"<html>not json</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if mode == "bomb":
            # A body far over the client's ceiling, streamed chunked so there is
            # no Content-Length to refuse up front: the ceiling must hold on
            # the read itself.
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            chunk = b'{"entries": [' + b"x" * 4096
            for _ in range(64):
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            return
        if not self._authorised():
            self._json(401, {"error": "unauthorised"})
            return
        with server.lock:
            records = list(server.records)
        if self.path.rstrip("/").endswith("/latest"):
            self._json(200, {"entry": records[-1] if records else None})
        else:
            self._json(server.get_status, {"entries": records})


class _LogServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _LogHandler)
        self.records: list[dict] = []
        self.seen_auth: list[str | None] = []
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.mode = "ok"
        self.post_mode = "ok"
        self.ack_body: bytes | None = None
        self.post_status = 201
        self.get_status = 200
        self.token: str | None = None
        self._thread = threading.Thread(
            target=self.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self._thread.start()

    def handle_error(self, request, client_address) -> None:  # noqa: D401
        # A client that aborts a bomb or a hang mid-body leaves the handler with
        # a closed socket; that is the client doing its job, not a test failure.
        pass

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}/anchors"

    def operator_rewrite(self, records: list[dict]) -> None:
        """What the log's OPERATOR can do: replace the stored history."""

        with self.lock:
            self.records = list(records)

    def close(self) -> None:
        self.stop.set()
        self.shutdown()
        self.server_close()


@pytest.fixture
def log_server():
    server = _LogServer()
    try:
        yield server
    finally:
        server.close()


# ---------------------------------------------------------------------------
# Targets and helpers
# ---------------------------------------------------------------------------


EXTERNAL = ["memory-worm", "worm-dir", "memory-log", "https-log"]


def _build_target(name: str, tmp_path: Path, log_server: _LogServer):
    if name == "memory-worm":
        return ObjectLockTipAnchor(MemoryObjectLockStore())
    if name == "worm-dir":
        return ObjectLockTipAnchor(DirectoryObjectStore(tmp_path / "worm"))
    if name == "memory-log":
        return LogTipAnchor(MemoryAppendOnlyLog())
    if name == "https-log":
        return LogTipAnchor(
            HttpAppendOnlyLog(log_server.url, allow_insecure_loopback=True, timeout_s=5.0)
        )
    raise AssertionError(name)


@pytest.fixture(params=EXTERNAL)
def external(request, tmp_path, log_server):
    return _build_target(request.param, tmp_path, log_server)


def _ledger(tmp_path: Path, anchor) -> SqliteLedger:
    return SqliteLedger(tmp_path / "ledger.db", tip_anchor=anchor)


def _append(ledger, n: int = 3) -> None:
    for index in range(n):
        ledger.record_chained(
            event="authorize", subject="db://appdb",
            payload={"step": index}, created_at=CREATED_AT,
        )


def _rewrite_chain_from_genesis(path: Path, payloads: list[dict]) -> None:
    """The attack: replace every row with a fresh, internally-consistent chain.

    A *substitution*, not a corruption. The rebuilt chain verifies perfectly on
    its own terms, which is exactly why an out-of-band anchor is the only thing
    that can tell the difference.
    """

    conn = sqlite3.connect(path)
    try:
        conn.execute("DELETE FROM audit_chain")
        prev = GENESIS_ROOT
        for seq, payload in enumerate(payloads, start=1):
            canonical = canonical_json(payload)
            digest = entry_hash(
                seq=seq, created_at=CREATED_AT, event="authorize",
                subject="db://appdb", payload_canonical=canonical, prev_hash=prev,
            )
            conn.execute(
                "INSERT INTO audit_chain (seq, created_at, event, subject, payload, "
                "prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (seq, CREATED_AT, "authorize", "db://appdb", canonical, prev, digest),
            )
            prev = digest
        conn.commit()
    finally:
        conn.close()


def _assert_forgery_is_internally_valid(path: Path) -> ChainTip:
    """The premise of every rewrite test: the forged chain checks out alone."""

    forged = SqliteLedger(path)
    try:
        unanchored = verify_rows(forged.chained_events())
        assert unanchored.status == VALID, (
            "the forged chain was not internally consistent, so this test would "
            f"prove nothing: {unanchored.render()}"
        )
        return forged.chain_tip()
    finally:
        forged.close()


def _truncate(path: Path, keep: int) -> None:
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM audit_chain WHERE seq > ?", (keep,))
    conn.commit()
    conn.close()


# ===========================================================================
# 1. Labels: which targets are append-only, and the file is not
# ===========================================================================


def test_external_targets_are_append_only_and_the_local_file_is_not(tmp_path, log_server):
    for name in EXTERNAL:
        target = _build_target(name, tmp_path, log_server)
        assert target.append_only is True, name
    assert FileTipAnchor(tmp_path / "tip.json").append_only is False
    assert parse_anchor_spec("file:///tmp/tip.json").append_only is False
    assert parse_anchor_spec("worm:///mnt/worm/anchors").append_only is True


# ===========================================================================
# 2. The detection matrix, against every external target
# ===========================================================================


def test_a_clean_chain_is_valid_and_honest_growth_stays_valid(tmp_path, external):
    ledger = _ledger(tmp_path, external)
    _append(ledger, 3)
    assert ledger.verify_chain().status == VALID
    _append(ledger, 4)
    result = ledger.verify_chain()
    assert result.status == VALID and result.length == 7, result.render()
    assert [tip.seq for tip in external.history()] == [1, 2, 3, 4, 5, 6, 7]
    ledger.close()


def test_a_genesis_rewrite_is_detected_by_the_external_anchor(tmp_path, external):
    ledger = _ledger(tmp_path, external)
    _append(ledger, 3)
    honest_tip = ledger.chain_tip()
    ledger.close()

    _rewrite_chain_from_genesis(tmp_path / "ledger.db", FORGED)
    forged_tip = _assert_forgery_is_internally_valid(tmp_path / "ledger.db")
    assert forged_tip.entry_hash != honest_tip.entry_hash, "the rewrite changed nothing"

    result = verify_ledger_file(tmp_path / "ledger.db", tip_anchor=external)
    assert result.status == BROKEN, result.render()
    assert result.broken_index == 3 and "anchored" in result.detail


def test_a_rewrite_that_then_extends_the_chain_is_detected(tmp_path, external):
    """Making the forged chain LONGER than the anchored history is the obvious
    dodge; the anchor pins the entry AT each anchored seq regardless."""

    ledger = _ledger(tmp_path, external)
    _append(ledger, 3)
    ledger.close()

    _rewrite_chain_from_genesis(
        tmp_path / "ledger.db", FORGED + [{"step": 3}, {"step": 4}]
    )
    _assert_forgery_is_internally_valid(tmp_path / "ledger.db")
    result = verify_ledger_file(tmp_path / "ledger.db", tip_anchor=external)
    assert result.status == BROKEN and result.broken_index == 3, result.render()


def test_a_rewrite_of_only_the_first_entry_is_caught_at_the_first_anchored_point(
    tmp_path, external
):
    """Every historical record is pinned, and the earliest disagreement is the
    one reported: a rewrite at seq 1 changes every later hash, so the anchor
    for seq 1 already mismatches."""

    ledger = _ledger(tmp_path, external)
    _append(ledger, 3)
    ledger.close()

    _rewrite_chain_from_genesis(
        tmp_path / "ledger.db", [{"forged": True}, {"step": 1}, {"step": 2}]
    )
    _assert_forgery_is_internally_valid(tmp_path / "ledger.db")
    result = verify_ledger_file(tmp_path / "ledger.db", tip_anchor=external)
    assert result.status == BROKEN and result.broken_index == 1, result.render()


def test_truncating_the_tail_is_detected(tmp_path, external):
    ledger = _ledger(tmp_path, external)
    _append(ledger, 5)
    ledger.close()
    _truncate(tmp_path / "ledger.db", keep=3)

    assert verify_ledger_file(tmp_path / "ledger.db").status == VALID, "premise"
    result = verify_ledger_file(tmp_path / "ledger.db", tip_anchor=external)
    assert result.status == TRUNCATED, result.render()
    assert "anchored tip is seq 5" in result.detail


def test_deleting_the_ledger_is_detected(tmp_path, external):
    """The cheapest attack: remove the file. SQLite recreates it empty and an
    empty chain is internally consistent."""

    ledger = _ledger(tmp_path, external)
    _append(ledger, 3)
    ledger.close()
    (tmp_path / "ledger.db").unlink()

    # A file that is simply gone is could-not-verify, never clean.
    missing = verify_ledger_file(tmp_path / "ledger.db", tip_anchor=external)
    assert missing.status == NOT_VERIFIABLE and not missing.ok, missing.render()

    # The realistic sequel: the runtime reopens the path and SQLite recreates
    # it empty. Without an anchor that reads as valid (0 entries).
    recreated = SqliteLedger(tmp_path / "ledger.db")
    assert recreated.verify_chain().status == VALID and recreated.verify_chain().length == 0
    recreated.close()
    result = verify_ledger_file(tmp_path / "ledger.db", tip_anchor=external)
    assert result.status == TRUNCATED, result.render()


def test_a_rewrite_that_is_also_truncated_reports_the_rewrite(tmp_path, external):
    """One chain can be both rewritten and shortened; the rewrite is the more
    severe finding and is reported first."""

    ledger = _ledger(tmp_path, external)
    _append(ledger, 5)
    ledger.close()
    _rewrite_chain_from_genesis(tmp_path / "ledger.db", FORGED)  # 3 entries, forged
    _assert_forgery_is_internally_valid(tmp_path / "ledger.db")

    result = verify_ledger_file(tmp_path / "ledger.db", tip_anchor=external)
    assert result.status == BROKEN and result.broken_index == 3, result.render()


# ===========================================================================
# 3. Continuous anchoring: after every commit, and after — not before — it
# ===========================================================================


def test_every_append_anchors_the_new_tip(tmp_path, external):
    ledger = _ledger(tmp_path, external)
    for n in range(1, 6):
        _append(ledger, 1)
        history = external.history()
        assert len(history) == n, "an append was not anchored"
        assert history[-1] == ledger.chain_tip()
    ledger.close()


def test_the_tip_is_anchored_after_the_commit_is_durable(tmp_path):
    """The anchored tip never names an entry the ledger does not have: at the
    moment the record is written, a SEPARATE connection already sees the row."""

    path = tmp_path / "ledger.db"

    class _Observing(MemoryObjectLockStore):
        durable_at_write: list[bool] = []

        def put_if_absent(self, key, body, *, retain_for_s):
            seq = json.loads(body)["seq"]
            other = sqlite3.connect(path)
            try:
                row = other.execute(
                    "SELECT COUNT(*) FROM audit_chain WHERE seq = ?", (seq,)
                ).fetchone()
            finally:
                other.close()
            self.durable_at_write.append(row[0] == 1)
            super().put_if_absent(key, body, retain_for_s=retain_for_s)

    store = _Observing()
    ledger = SqliteLedger(path, tip_anchor=ObjectLockTipAnchor(store))
    _append(ledger, 3)
    ledger.close()
    assert store.durable_at_write == [True, True, True]


# ===========================================================================
# 4. A failed anchor write is raised, not swallowed — and the runner fails closed
# ===========================================================================


class _DownStore(MemoryObjectLockStore):
    """The medium is unreachable: every write fails."""

    def put_if_absent(self, key, body, *, retain_for_s):
        raise ObjectStoreError("simulated outage: the bucket is unreachable")


def test_a_failed_anchor_write_is_raised_from_the_append(tmp_path):
    ledger = _ledger(tmp_path, ObjectLockTipAnchor(_DownStore()))
    with pytest.raises(AnchorUnavailable, match="unreachable"):
        _append(ledger, 1)
    # The entry itself is committed (anchoring is after the commit, by design);
    # what is refused is the caller's belief that it was witnessed.
    assert ledger.chain_tip().seq == 1
    ledger.close()


@pytest.mark.parametrize("mode", ["http500", "hang"])
def test_a_failed_remote_append_is_raised_within_the_deadline(tmp_path, log_server, mode):
    log_server.mode = mode
    anchor = LogTipAnchor(
        HttpAppendOnlyLog(log_server.url, allow_insecure_loopback=True, timeout_s=1.0)
    )
    ledger = _ledger(tmp_path, anchor)
    started = time.monotonic()
    with pytest.raises(AnchorUnavailable):
        _append(ledger, 1)
    assert time.monotonic() - started < 4.0, "the failure was not bounded by the deadline"
    ledger.close()


@pytest.mark.parametrize("failure", ["down_store", "empty_ack", "no_store", "wrong_record",
                                     "readback_down"])
def test_the_runner_refuses_to_execute_when_the_intent_cannot_be_anchored(
    tmp_path, log_server, failure,
):
    """Fail-closed on the write, end to end: the chokepoint runner records the
    execution intent through the anchored ledger; when the anchor is down the
    append raises, the runner treats the intent as unrecorded, refuses, and the
    executor is never called."""

    class _Spy:
        calls: list[str] = []

        def __call__(self, sql, target, execution_id, artifact_sha256):
            self.calls.append(execution_id)
            return True, "ok"

    spy = _Spy()
    if failure == "down_store":
        anchor = ObjectLockTipAnchor(_DownStore())
    else:
        if failure == "empty_ack":
            log_server.ack_body = b"{}"
        else:
            log_server.post_mode = failure
        anchor = LogTipAnchor(HttpAppendOnlyLog(log_server.url, allow_insecure_loopback=True))
    audit = SqliteLedger(tmp_path / "audit.db", tip_anchor=anchor)
    authority = ApprovalAuthority()
    target = DbTarget(host="127.0.0.1", port=5432, dbname="appdb", user="migrator", password="s")
    artifact = MigrationArtifact("CREATE TABLE witnessed (id int);")
    approval = authority.mint(artifact_sha256=artifact.sha256, target=target.identity, now=1_000.0)
    runner = BrokeredMigrationRunner(
        authority=authority,
        target=target,
        consumed=ConsumedApprovals(tmp_path / "consumed.db"),
        executor=spy,
        receipt_lookup=lambda execution_id, artifact_sha256, bound: ReceiptStatus(RECEIPT_NOT_FOUND),
        audit=audit,
        clock=lambda: 1_001.0,
    )
    try:
        result = runner.execute(approval=approval, artifact=artifact)
    finally:
        runner.close()
        audit.close()
    assert result.refused and not result.executed
    assert result.reason == AUDIT_UNAVAILABLE, result
    assert spy.calls == [], "the migration ran although its intent was never witnessed"


# ===========================================================================
# 5. Couldn't-verify is not verified-clean, for every target
# ===========================================================================


@pytest.mark.parametrize("ack", [
    b"{}", b'{"index":null}', b'{"index":true}', b'{"index":false}',
    b'{"index":-1}', b'{"index":"0"}', b'{"index":0.0}', b'{"index":[]}',
    b'{"index":999}', b'{"index":0,"index":0}', b'{"index":NaN}',
    b'{"index":Infinity}', b'{"index":0,"extra":1e999}', b"[]", b"not JSON",
])
def test_http_append_refuses_invalid_or_unbound_acknowledgements(log_server, ack):
    log_server.ack_body = ack
    log = HttpAppendOnlyLog(log_server.url, allow_insecure_loopback=True)
    with pytest.raises(AnchorUnavailable):
        log.append(encode_tip(ChainTip(seq=1, entry_hash="a" * 64)).encode())


@pytest.mark.parametrize("mode", ["no_store", "wrong_record", "readback_down"])
def test_http_append_requires_exact_record_readback(log_server, mode):
    log_server.post_mode = mode
    log = HttpAppendOnlyLog(log_server.url, allow_insecure_loopback=True)
    with pytest.raises(AnchorUnavailable):
        log.append(encode_tip(ChainTip(seq=1, entry_hash="a" * 64)).encode())


@pytest.mark.parametrize("record", [b'{"seq":1,"seq":2}', b'{"extra":1e999}'],
                         ids=["duplicate_field", "float_overflow"])
def test_ambiguous_or_unencodable_record_is_refused_before_post(log_server, record):
    log = HttpAppendOnlyLog(log_server.url, allow_insecure_loopback=True)
    with pytest.raises(AnchorUnavailable):
        log.append(record)
    assert log_server.records == []
    assert log_server.seen_auth == []


def test_parser_recursion_failure_is_typed_and_refuses_before_post(log_server, monkeypatch):
    # Interpreter recursion limits differ; inject the actual parser failure
    # rather than assuming a fixed nesting count fails on every Python version.
    def exhausted(*args, **kwargs):
        raise RecursionError("parser exhausted")

    log = HttpAppendOnlyLog(log_server.url, allow_insecure_loopback=True)
    monkeypatch.setattr("prometheus_protocol.ledger.anchor_http.json.loads", exhausted)
    with pytest.raises(AnchorUnavailable):
        log.append(b"{}")
    assert log_server.records == []
    assert log_server.seen_auth == []


def test_http_append_rejects_index_of_an_older_different_record(log_server):
    log = HttpAppendOnlyLog(log_server.url, allow_insecure_loopback=True)
    assert log.append(encode_tip(ChainTip(seq=1, entry_hash="a" * 64)).encode()) == 0
    log_server.ack_body = b'{"index":0}'
    with pytest.raises(AnchorUnavailable, match="not confirmed"):
        log.append(encode_tip(ChainTip(seq=2, entry_hash="b" * 64)).encode())


@pytest.mark.parametrize("status", [200, 201])
@pytest.mark.parametrize("mode", ["ok", "concurrent_append"])
def test_http_append_confirms_index_not_latest_and_canonicalizes_input(log_server, status, mode):
    log_server.post_status = status
    log_server.post_mode = mode
    log = HttpAppendOnlyLog(log_server.url, allow_insecure_loopback=True)
    record = {"version": 1, "seq": 1, "entry_hash": "a" * 64}
    assert log.append(json.dumps(record, indent=2).encode()) == 0
    assert log.entries()[0] == canonical_json(record).encode()
    if mode == "concurrent_append":
        assert log.latest() != log.entries()[0]


@pytest.mark.parametrize("method,status", [("POST", 202), ("POST", 206), ("GET", 201),
                                           ("GET", 202), ("GET", 206)])
def test_anchor_rejects_unexpected_success_status(log_server, method, status):
    log = HttpAppendOnlyLog(log_server.url, allow_insecure_loopback=True)
    log_server.post_status = status if method == "POST" else 201
    log_server.get_status = status if method == "GET" else 200
    with pytest.raises(AnchorUnavailable, match="unexpected HTTP"):
        log.append(encode_tip(ChainTip(seq=1, entry_hash="a" * 64)).encode())


@pytest.mark.parametrize("index", [None, True, False, -1, "0", 0.0, 0, 99])
def test_custom_log_port_cannot_bypass_ack_validation(index):
    class _FalseAck(MemoryAppendOnlyLog):
        def append(self, record):
            return index  # claims success but stores nothing

    with pytest.raises(AnchorUnavailable):
        LogTipAnchor(_FalseAck()).write(ChainTip(seq=1, entry_hash="a" * 64))


def test_custom_log_port_cannot_substitute_record_at_ack_index():
    class _Substituting(MemoryAppendOnlyLog):
        def append(self, record):
            return super().append(encode_tip(ChainTip(seq=1, entry_hash="f" * 64)).encode())

    with pytest.raises(AnchorUnavailable, match="not confirmed"):
        LogTipAnchor(_Substituting()).write(ChainTip(seq=1, entry_hash="a" * 64))


def test_latest_only_claim_does_not_make_a_write_idempotent():
    tip = ChainTip(seq=1, entry_hash="a" * 64)

    class _FalseLatest(MemoryAppendOnlyLog):
        def latest(self):
            return encode_tip(tip).encode()

        def append(self, record):
            return 0  # no entry to back either claim

    with pytest.raises(AnchorUnavailable, match="not confirmed"):
        LogTipAnchor(_FalseLatest()).write(tip)


def test_confirmed_history_makes_retry_idempotent():
    log = MemoryAppendOnlyLog()
    anchor = LogTipAnchor(log)
    tip = ChainTip(seq=1, entry_hash="a" * 64)
    anchor.write(tip)
    anchor.write(tip)
    assert log.entries() == [encode_tip(tip).encode()]


def test_an_unreadable_object_store_is_not_verifiable(tmp_path):
    class _Unlistable(MemoryObjectLockStore):
        def list_keys(self, prefix):
            raise ObjectStoreError("simulated outage")

    ledger = _ledger(tmp_path, ObjectLockTipAnchor(_Unlistable()))
    result = ledger.verify_chain()
    assert result.status == NOT_VERIFIABLE and not result.ok, result.render()
    ledger.close()


def test_a_foreign_object_in_the_worm_directory_is_not_verifiable(tmp_path):
    anchor = ObjectLockTipAnchor(DirectoryObjectStore(tmp_path / "worm"))
    ledger = _ledger(tmp_path, anchor)
    _append(ledger, 2)
    (tmp_path / "worm" / "planted.txt").write_text("not a record", encoding="utf-8")
    result = ledger.verify_chain()
    assert result.status == NOT_VERIFIABLE, result.render()
    ledger.close()


def test_a_garbage_entry_in_the_log_is_not_verifiable(tmp_path):
    log = MemoryAppendOnlyLog()
    ledger = _ledger(tmp_path, LogTipAnchor(log))
    _append(ledger, 2)
    log.append(b'{"version": 1, "seq": 2, "entry_hash": "short"}')
    result = ledger.verify_chain()
    assert result.status == NOT_VERIFIABLE, result.render()
    ledger.close()


@pytest.mark.parametrize("mode", ["http500", "nonjson", "bomb", "redirect"])
def test_a_remote_log_that_cannot_be_read_is_not_verifiable(tmp_path, log_server, mode):
    anchor = LogTipAnchor(
        HttpAppendOnlyLog(
            log_server.url, allow_insecure_loopback=True, timeout_s=2.0,
            max_response_bytes=64 * 1024,
        )
    )
    ledger = _ledger(tmp_path, anchor)
    _append(ledger, 2)
    log_server.mode = mode
    result = ledger.verify_chain()
    assert result.status == NOT_VERIFIABLE and not result.ok, result.render()
    ledger.close()


# ===========================================================================
# 6. The medium refuses to rewrite history — and the anchor never asks it to
# ===========================================================================


def test_the_object_lock_medium_refuses_to_overwrite_a_record():
    store = MemoryObjectLockStore()
    store.put_if_absent("k", b"honest", retain_for_s=DEFAULT_RETENTION_S)
    with pytest.raises(ObjectExists):
        store.put_if_absent("k", b"forged", retain_for_s=DEFAULT_RETENTION_S)
    assert store.versions("k") == [b"honest"]


def test_the_object_lock_medium_refuses_to_delete_under_retention():
    store = MemoryObjectLockStore()
    store.put_if_absent("k", b"honest", retain_for_s=DEFAULT_RETENTION_S)
    with pytest.raises(ObjectLocked):
        store.delete("k")
    assert store.versions("k") == [b"honest"], "the refused delete still removed it"


def test_the_worm_directory_create_is_exclusive_and_os_enforced(tmp_path):
    store = DirectoryObjectStore(tmp_path / "worm")
    store.put_if_absent("00000000000000000001.json", b"honest", retain_for_s=1.0)
    with pytest.raises(ObjectExists):
        store.put_if_absent("00000000000000000001.json", b"forged", retain_for_s=1.0)
    assert store.versions("00000000000000000001.json") == [b"honest"]
    assert not list((tmp_path / "worm").glob(".record-*")), "a temporary was left behind"


def test_the_worm_directory_falls_back_to_an_exclusive_create_without_links(tmp_path, monkeypatch):
    def _no_links(src, dst, *args, **kwargs):
        raise OSError(errno.EPERM, "links not permitted on this mount")

    monkeypatch.setattr(os, "link", _no_links)
    store = DirectoryObjectStore(tmp_path / "worm")
    store.put_if_absent("00000000000000000001.json", b"honest", retain_for_s=1.0)
    with pytest.raises(ObjectExists):
        store.put_if_absent("00000000000000000001.json", b"forged", retain_for_s=1.0)
    assert store.versions("00000000000000000001.json") == [b"honest"]


def test_the_anchor_never_rewrites_a_record_of_its_own(tmp_path, external):
    external.write(ChainTip(seq=5, entry_hash="a" * 64))
    with pytest.raises(AnchorRewind):
        external.write(ChainTip(seq=5, entry_hash="b" * 64))
    with pytest.raises(AnchorRewind):
        external.write(ChainTip(seq=3, entry_hash="c" * 64))
    external.write(ChainTip(seq=5, entry_hash="a" * 64))  # idempotent, not a rewrite
    assert external.history() == [ChainTip(seq=5, entry_hash="a" * 64)]


def test_a_rewound_ledger_cannot_silently_re_anchor(tmp_path, external):
    ledger = _ledger(tmp_path, external)
    _append(ledger, 5)
    ledger.close()
    _truncate(tmp_path / "ledger.db", keep=2)

    reopened = _ledger(tmp_path, external)
    with pytest.raises(AnchorRewind):
        _append(reopened, 1)
    assert external.read().seq == 5, "the anchor was rewound by an append"
    reopened.close()


# ===========================================================================
# 7. A credential holder can append a forgery; the history still convicts
# ===========================================================================


def test_a_forged_record_appended_with_the_write_credential_is_still_caught_on_object_lock(tmp_path):
    store = MemoryObjectLockStore()
    anchor = ObjectLockTipAnchor(store)
    ledger = _ledger(tmp_path, anchor)
    _append(ledger, 3)
    ledger.close()

    _rewrite_chain_from_genesis(tmp_path / "ledger.db", FORGED)
    forged_tip = _assert_forgery_is_internally_valid(tmp_path / "ledger.db")
    # The adversary holds the bucket's write credential and does an unconditional
    # put at seq 3. On a versioned, locked bucket that ADDS a version; the honest
    # one stays. The verifier reads every version.
    store.overwrite("00000000000000000003.json", encode_tip(forged_tip).encode())

    result = verify_ledger_file(tmp_path / "ledger.db", tip_anchor=anchor)
    assert result.status == BROKEN and result.broken_index == 3, result.render()
    assert "two different hashes" in result.detail


def test_a_forged_record_appended_to_the_log_is_still_caught(tmp_path, log_server):
    for name, log in (("memory-log", MemoryAppendOnlyLog()), ("https-log", None)):
        if log is None:
            log = HttpAppendOnlyLog(log_server.url, allow_insecure_loopback=True, timeout_s=5.0)
        path = tmp_path / f"{name}.db"
        anchor = LogTipAnchor(log)
        ledger = SqliteLedger(path, tip_anchor=anchor)
        _append(ledger, 3)
        ledger.close()

        _rewrite_chain_from_genesis(path, FORGED)
        forged_tip = _assert_forgery_is_internally_valid(path)
        # Appending is exactly what the credential permits — and it does not help.
        log.append(encode_tip(forged_tip).encode())

        result = verify_ledger_file(path, tip_anchor=anchor)
        assert result.status == BROKEN and result.broken_index == 3, (name, result.render())
        assert "two different hashes" in result.detail


def test_a_forged_record_at_a_higher_seq_does_not_mask_the_honest_history(tmp_path):
    """Forging a LONGER chain and anchoring its tip (seq 5) leaves the honest
    seq-3 record pinned; the rewritten prefix still mismatches it."""

    store = MemoryObjectLockStore()
    anchor = ObjectLockTipAnchor(store)
    ledger = _ledger(tmp_path, anchor)
    _append(ledger, 3)
    ledger.close()

    _rewrite_chain_from_genesis(tmp_path / "ledger.db", FORGED + [{"step": 3}, {"step": 4}])
    forged_tip = _assert_forgery_is_internally_valid(tmp_path / "ledger.db")
    assert forged_tip.seq == 5
    store.put_if_absent("00000000000000000005.json", encode_tip(forged_tip).encode(), retain_for_s=1.0)

    result = verify_ledger_file(tmp_path / "ledger.db", tip_anchor=anchor)
    assert result.status == BROKEN and result.broken_index == 3, result.render()


# ===========================================================================
# 8. THE HONEST RESIDUAL — passing tests, so the claim cannot grow
# ===========================================================================


def test_an_adversary_with_authority_over_the_medium_is_NOT_detected_once_retention_lapses(tmp_path):
    """Stated as a passing test because it is the residual, not a defect.

    Object-lock retention is the boundary: while it holds, even the principal
    that writes records cannot delete them, and the rewrite is caught. When it
    lapses — or is bypassed by an authority the medium honours — the adversary
    deletes the honest records, writes matching forgeries, and the verifier has
    nothing left to disagree with. The anchor is worth exactly the retention
    window, which is why the default is ten years and shorter is named as the
    hole it is.
    """

    now = [1_000_000.0]
    store = MemoryObjectLockStore(clock=lambda: now[0])
    anchor = ObjectLockTipAnchor(store, retain_for_s=3600.0)
    ledger = _ledger(tmp_path, anchor)
    _append(ledger, 3)
    ledger.close()

    _rewrite_chain_from_genesis(tmp_path / "ledger.db", FORGED)
    _assert_forgery_is_internally_valid(tmp_path / "ledger.db")

    # While retention holds, the medium refuses the adversary and the rewrite is caught.
    with pytest.raises(ObjectLocked):
        store.delete("00000000000000000003.json")
    assert verify_ledger_file(tmp_path / "ledger.db", tip_anchor=anchor).status == BROKEN

    # Retention lapses. The same adversary now has authority over the medium.
    now[0] += 3600.0 + 1
    forged = SqliteLedger(tmp_path / "ledger.db")
    forged_rows = forged.chained_events()
    forged.close()
    for key in store.list_keys(""):
        store.delete(key)
    for row in forged_rows:
        store.put_if_absent(
            f"{row['seq']:020d}.json",
            encode_tip(ChainTip(seq=row["seq"], entry_hash=row["entry_hash"])).encode(),
            retain_for_s=3600.0,
        )

    result = verify_ledger_file(tmp_path / "ledger.db", tip_anchor=anchor)
    assert result.status == VALID, (
        "this documents the residual: once the adversary has authority over the "
        "anchor medium the rewrite is undetectable, and the honest claim is that "
        "detection holds for exactly as long as the medium stays out of reach"
    )


def test_the_log_operator_is_NOT_detected(tmp_path, log_server):
    """The append-only log's boundary is its operator. A writer credential can
    only append (and is caught above); the party running the log can replace
    its storage, and then nothing disagrees. Hence the requirement that the log
    be run by a party the ledger-host adversary is not."""

    memory = MemoryAppendOnlyLog()
    for name, log, rewrite in (
        ("memory-log", memory, memory.operator_rewrite),
        (
            "https-log",
            HttpAppendOnlyLog(log_server.url, allow_insecure_loopback=True, timeout_s=5.0),
            None,
        ),
    ):
        path = tmp_path / f"{name}.db"
        anchor = LogTipAnchor(log)
        ledger = SqliteLedger(path, tip_anchor=anchor)
        _append(ledger, 3)
        ledger.close()

        _rewrite_chain_from_genesis(path, FORGED)
        _assert_forgery_is_internally_valid(path)
        forged = SqliteLedger(path)
        records = [
            {"version": 1, "seq": row["seq"], "entry_hash": row["entry_hash"]}
            for row in forged.chained_events()
        ]
        forged.close()
        if rewrite is not None:
            rewrite([canonical_json(record).encode() for record in records])
        else:
            log_server.operator_rewrite(records)

        result = verify_ledger_file(path, tip_anchor=anchor)
        assert result.status == VALID, (name, "this documents the residual")


def test_a_local_file_anchor_on_the_same_medium_is_NOT_protecting(tmp_path):
    """The theatre case, kept as the control: the same rewrite, the same
    forged-anchor move, and no detection — because a file the adversary can
    write is not a witness. `test_tip_anchor.py` records it in full."""

    anchor = FileTipAnchor(tmp_path / "tip.json")
    ledger = _ledger(tmp_path, anchor)
    _append(ledger, 3)
    ledger.close()
    _rewrite_chain_from_genesis(tmp_path / "ledger.db", FORGED)
    forged_tip = _assert_forgery_is_internally_valid(tmp_path / "ledger.db")
    anchor.path.write_text(encode_tip(forged_tip), encoding="utf-8")
    assert verify_ledger_file(tmp_path / "ledger.db", tip_anchor=anchor).status == VALID


# ===========================================================================
# 9. The verifier pins a whole history (unit)
# ===========================================================================


def _chain(n: int) -> list[dict]:
    rows, prev = [], GENESIS_ROOT
    for seq in range(1, n + 1):
        canonical = canonical_json({"step": seq})
        digest = entry_hash(
            seq=seq, created_at=CREATED_AT, event="e", subject="s",
            payload_canonical=canonical, prev_hash=prev,
        )
        rows.append({
            "seq": seq, "created_at": CREATED_AT, "event": "e", "subject": "s",
            "payload": canonical, "prev_hash": prev, "entry_hash": digest,
        })
        prev = digest
    return rows


def test_verify_rows_pins_every_tip_in_a_history():
    rows = _chain(5)
    tips = [ChainTip(seq=r["seq"], entry_hash=r["entry_hash"]) for r in rows]
    assert verify_rows(rows, expected_tips=tips).status == VALID
    # A single pin still behaves exactly as before.
    assert verify_rows(rows, expected_tip=tips[-1]).status == VALID
    assert verify_rows(rows[:3], expected_tip=tips[-1]).status == TRUNCATED
    # A history with a wrong record at seq 2 convicts at seq 2 even though the
    # newest record (seq 5) matches.
    wrong = tips[:1] + [ChainTip(seq=2, entry_hash="f" * 64)] + tips[2:]
    result = verify_rows(rows, expected_tips=wrong)
    assert result.status == BROKEN and result.broken_index == 2


def test_verify_rows_names_a_conflicting_anchor_history():
    rows = _chain(3)
    tips = [ChainTip(seq=r["seq"], entry_hash=r["entry_hash"]) for r in rows]
    conflicting = tips + [ChainTip(seq=3, entry_hash="e" * 64)]
    result = verify_rows(rows, expected_tips=conflicting)
    assert result.status == BROKEN and result.broken_index == 3
    assert "two different hashes for seq 3" in result.detail


# ===========================================================================
# 10. Configuration: honoured or refused, the OR of its sources, warned when absent
# ===========================================================================


@pytest.mark.parametrize(
    "spec, kind",
    [
        ("file:///var/lib/promethyn/tip.json", ANCHOR_FILE),
        ("worm:///mnt/worm/anchors", ANCHOR_WORM),
        ("https://witness.example/ledgers/prod", ANCHOR_LOG),
        ("https://witness.example/ledgers/prod/", ANCHOR_LOG),
    ],
)
def test_anchor_specs_that_parse(spec, kind):
    parsed = parse_anchor_spec(spec)
    assert parsed.kind == kind
    assert not parsed.target.endswith("/") or parsed.kind != ANCHOR_LOG


@pytest.mark.parametrize(
    "spec",
    [
        "http://witness.example/ledgers/prod",     # plaintext to a remote host
        "http://127.0.0.1:8080/anchors",           # plaintext to loopback without the opt-out
        "ftp://witness.example/anchors",           # not a scheme this takes
        "file://host/tip.json",                    # a host on a local scheme
        "file://relative/tip.json",
        "worm:///",                                # the root is not a directory to anchor in
        "https://user:pw@witness.example/anchors", # a credential in the URL
        "https://witness.example/anchors?x=1",
        "",
    ],
)
def test_anchor_specs_that_are_refused(spec):
    with pytest.raises(ConfigError):
        parse_anchor_spec(spec)


def test_plaintext_loopback_log_needs_the_same_opt_out_as_every_endpoint():
    with pytest.raises(ConfigError):
        parse_anchor_spec("http://127.0.0.1:8080/anchors")
    parsed = parse_anchor_spec("http://127.0.0.1:8080/anchors", allow_insecure_loopback=True)
    assert parsed.kind == ANCHOR_LOG


def test_config_refuses_a_requirement_it_cannot_honour():
    with pytest.raises(ConfigError, match="cannot be honoured"):
        Config(require_ledger_anchor=True)
    with pytest.raises(ConfigError, match="non-protecting"):
        Config(require_ledger_anchor=True, ledger_anchor="file:///tmp/tip.json")
    Config(require_ledger_anchor=True, ledger_anchor="worm:///mnt/worm")
    Config(require_ledger_anchor=True, ledger_anchor="https://witness.example/anchors")


@pytest.mark.parametrize("days", [0, -1, 36_501])
def test_config_refuses_an_unbounded_retention(days):
    # The same ValueError every numeric setting raises at load (threat model §3).
    with pytest.raises(ValueError):
        Config(ledger_anchor_retention_days=days)


def test_config_reads_the_anchor_settings_from_the_environment():
    config = Config.from_env({
        "PROM_LEDGER_ANCHOR": "worm:///mnt/worm/anchors",
        "PROM_LEDGER_ANCHOR_TOKEN": "t0k3n",
        "PROM_LEDGER_ANCHOR_RETENTION_DAYS": "400",
        "PROM_REQUIRE_LEDGER_ANCHOR": "1",
    })
    assert config.ledger_anchor == "worm:///mnt/worm/anchors"
    assert config.ledger_anchor_token == "t0k3n"
    assert config.ledger_anchor_retention_days == 400
    assert config.require_ledger_anchor is True
    assert Config.from_env({}).ledger_anchor is None


def test_the_anchor_settings_are_declared_security_fields():
    for name in ("ledger_anchor", "ledger_anchor_retention_days", "require_ledger_anchor"):
        assert name in SECURITY_FIELDS


def test_the_requirement_is_the_or_of_its_sources(tmp_path):
    # The environment alone raises it: a programmatic Config that says False
    # does not lower it.
    with pytest.raises(ConfigError, match="required"):
        build_ledger(Config(ledger_path=tmp_path / "l.db"), env={LEDGER_ANCHOR_REQUIRED_ENV: "1"})
    with pytest.raises(ConfigError, match="non-protecting"):
        build_ledger(
            Config(ledger_path=tmp_path / "l.db", ledger_anchor=f"file://{tmp_path}/tip.json"),
            env={LEDGER_ANCHOR_REQUIRED_ENV: "1"},
        )
    ledger = build_ledger(
        Config(ledger_path=tmp_path / "l.db", ledger_anchor=f"worm://{tmp_path}/worm"),
        env={LEDGER_ANCHOR_REQUIRED_ENV: "1"},
    )
    assert isinstance(ledger.tip_anchor, ObjectLockTipAnchor)
    ledger.close()


def test_build_ledger_wires_the_configured_target(tmp_path, log_server):
    worm = build_tip_anchor_for(Config(ledger_anchor=f"worm://{tmp_path}/worm"), env={})
    assert isinstance(worm, ObjectLockTipAnchor)
    log = build_tip_anchor_for(
        Config(ledger_anchor=log_server.url, allow_insecure_loopback=True), env={}
    )
    assert isinstance(log, LogTipAnchor)
    assert build_tip_anchor_for(Config(), env={}) is None


def test_the_production_builders_open_an_anchored_ledger(tmp_path):
    """The wiring is the production path, not a test-only convenience: the
    execution controller's ledger carries the configured anchor."""

    config = Config(ledger_path=tmp_path / "ledger.db", ledger_anchor=f"worm://{tmp_path}/worm")
    controller = build_execution_controller(config)
    assert isinstance(controller._ledger.tip_anchor, ObjectLockTipAnchor)


def test_an_unanchored_file_ledger_is_warned_about_and_a_file_anchor_is_called_non_protecting(
    tmp_path, caplog
):
    with caplog.at_level(logging.WARNING, logger="prometheus_protocol.runtime.factory"):
        build_ledger(Config(ledger_path=tmp_path / "l.db"), env={}).close()
    assert any("NO tip anchor" in record.message for record in caplog.records)

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="prometheus_protocol.runtime.factory"):
        build_ledger(
            Config(ledger_path=tmp_path / "l.db", ledger_anchor=f"file://{tmp_path}/tip.json"),
            env={},
        ).close()
    assert any("NON-PROTECTING" in record.message for record in caplog.records)

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="prometheus_protocol.runtime.factory"):
        build_ledger(Config(ledger_path=":memory:"), env={}).close()
    assert not [r for r in caplog.records if "anchor" in r.message], "an in-memory ledger has nothing to anchor"


def test_end_to_end_through_config_to_the_remote_log(tmp_path, log_server):
    log_server.token = "secret-token"
    config = Config(
        ledger_path=tmp_path / "ledger.db",
        ledger_anchor=log_server.url,
        ledger_anchor_token="secret-token",
        allow_insecure_loopback=True,
    )
    ledger = build_ledger(config, env={})
    _append(ledger, 3)
    assert ledger.verify_chain().status == VALID
    assert [record["seq"] for record in log_server.records] == [1, 2, 3]
    assert log_server.seen_auth and all(a == "Bearer secret-token" for a in log_server.seen_auth)
    ledger.close()

    _rewrite_chain_from_genesis(tmp_path / "ledger.db", FORGED)
    _assert_forgery_is_internally_valid(tmp_path / "ledger.db")
    reopened = build_ledger(config, env={})
    assert reopened.verify_chain().status == BROKEN
    reopened.close()


def test_a_wrong_token_is_refused_by_the_log_and_surfaced(tmp_path, log_server):
    log_server.token = "secret-token"
    anchor = LogTipAnchor(
        HttpAppendOnlyLog(log_server.url, token="wrong", allow_insecure_loopback=True, timeout_s=5.0)
    )
    ledger = _ledger(tmp_path, anchor)
    with pytest.raises(AnchorUnavailable, match="HTTP 401"):
        _append(ledger, 1)
    ledger.close()


def test_the_token_is_never_logged(tmp_path, log_server, caplog):
    log_server.token = "secret-token"
    anchor = LogTipAnchor(
        HttpAppendOnlyLog(log_server.url, token="secret-token", allow_insecure_loopback=True, timeout_s=5.0)
    )
    ledger = _ledger(tmp_path, anchor)
    with caplog.at_level(logging.DEBUG):
        _append(ledger, 2)
        ledger.verify_chain()
    assert "secret-token" not in caplog.text
    ledger.close()


def test_the_remote_log_requires_https_for_a_remote_host():
    with pytest.raises(ConfigError, match="https"):
        HttpAppendOnlyLog("http://witness.example/anchors")
    with pytest.raises(ConfigError):
        HttpAppendOnlyLog("http://127.0.0.1:1/anchors")  # loopback needs the opt-out


# ===========================================================================
# 11. The operator's verify entrypoint
# ===========================================================================


def test_the_cli_verifies_against_the_configured_anchor(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PROM_LEDGER_PATH", str(tmp_path / "ledger.db"))
    monkeypatch.setenv("PROM_LEDGER_ANCHOR", f"worm://{tmp_path}/worm")
    ledger = build_ledger(Config.from_env(), env={})
    _append(ledger, 3)
    ledger.close()

    assert cli_main(["audit", "--verify-chain"]) == 0
    out = capsys.readouterr().out
    assert "chain valid (3 entries)" in out and "append-only history" in out

    _rewrite_chain_from_genesis(tmp_path / "ledger.db", FORGED)
    assert cli_main(["audit", "--verify-chain"]) == 2
    assert "BROKEN" in capsys.readouterr().out


def test_the_cli_says_when_nothing_is_anchored(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PROM_LEDGER_PATH", str(tmp_path / "ledger.db"))
    monkeypatch.delenv("PROM_LEDGER_ANCHOR", raising=False)
    SqliteLedger(tmp_path / "ledger.db").close()
    assert cli_main(["audit", "--verify-chain"]) == 0
    assert "NOT detectable" in capsys.readouterr().out


# ===========================================================================
# 12. The docs say what the code does — and what it does not
# ===========================================================================


def test_the_docs_mark_the_local_file_non_protecting_and_name_the_residual():
    integrity = (REPO / "docs" / "ledger-integrity.md").read_text(encoding="utf-8")
    threat = (REPO / "docs" / "threat-model.md").read_text(encoding="utf-8")
    lower = integrity.lower()
    assert "file://" in integrity and "non-protecting" in lower, (
        "docs/ledger-integrity.md must label the file:// target non-protecting"
    )
    assert "retention" in lower, "the retention window is the trust boundary; say so"
    assert "test_an_adversary_with_authority_over_the_medium_is_not_detected_once_retention_lapses" in lower
    assert "test_the_log_operator_is_not_detected" in lower
    assert "test_an_attacker_who_also_controls_the_anchor_is_not_detected" in lower
    assert "prom_ledger_anchor" in lower and "prom_require_ledger_anchor" in lower
    assert "PIH-1" in threat or "external anchor" in threat.lower()
    for text in (integrity, threat):
        for overclaim in ("tamper-proof.", "cannot be defeated", "impossible to rewrite"):
            assert overclaim not in text.lower(), f"overclaim: {overclaim!r}"
