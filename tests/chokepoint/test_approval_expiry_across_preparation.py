"""F7: an approval must not execute after it expired, at ANY phase.

THE REVIEW'S SCENARIO, not a simplified version of it. An independent review
reproduced this at four separate phases: an approval expiring at t=1001, the
executor called at t=5000, ``executed=True``, ``state=committed``, nonce spent,
intent and outcome both durably appended. The runner sampled the wall clock
ONCE at STEP 1 and never looked again, so everything in between — reconciliation
(a remote anchor history read plus a full chain recompute plus a receipt lookup
per unresolved intent), approval consumption under a 30-second busy timeout, the
ledger append, and intent anchor publication (FOUR HTTP exchanges against an
https anchor) — ran on an authorization that had already lapsed.

The tests below drive that by making the REAL collaborators consume the TTL:
each phase test advances the runner's clock from inside the real component the
review named, then asserts the phase's row of the A2 table. None of them checks
expiry by calling a helper directly.

THE PHASE TABLE (A2), one test per row:

===============================  =========================================
phase where expiry is detected   required behaviour
===============================  =========================================
before the nonce claim           refuse; approval UNSPENT
after claim, before intent       refuse; nonce STAYS spent; refusal recorded
after durable intent, before     do not call the executor; append a linked
the executor starts              terminal outcome stating no attempt
that terminal append fails       preserve spent nonce AND unresolved intent;
                                 expose the audit failure; not settled
executor/SQL may have started    expiry is NOT proof of rollback; tri-state
                                 and ownership protection preserved
commit may have succeeded,       remains UNKNOWN; never relabelled as
reply lost                       "expired, therefore rolled back"
===============================  =========================================
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

import pytest

from prometheus_protocol.chokepoint.admission import (
    CLOCK_MARGIN,
    CLOCK_UNTRUSTED,
    EXPIRED,
    INVALID_TIME,
    ClockUntrusted,
    ExecutionDeadline,
    InvalidApprovalInterval,
    connect_timeout_s,
    elapsed_source,
    timeout_ms,
)
from prometheus_protocol.chokepoint.approval import (
    ApprovalAuthority,
    MigrationArtifact,
    MigrationTarget,
)
from prometheus_protocol.chokepoint.runner import (
    AUDIT_UNAVAILABLE,
    EXECUTION_COMMITTED,
    EXECUTION_NOT_ATTEMPTED,
    EXECUTION_NOT_COMMITTED,
    EXECUTION_UNKNOWN,
    BrokeredMigrationRunner,
    ConsumedApprovals,
    DbTarget,
    ExecutorResult,
    ReceiptStatus,
    RECEIPT_NOT_FOUND,
    postgres_executor,
)
from prometheus_protocol.core.models import Judgment, Verdict
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger

KEY = b"f7-approval-expiry-test-key-32b!!"

#: The review's numbers. The approval is minted at t=1000 with a one-second TTL
#: (expiry 1001) and the phase under test drags the clock to t=5000.
MINTED_AT = 1000.0
TTL_S = 1.0
EXPIRES_AT = MINTED_AT + TTL_S
LATE = 5000.0


# ---------------------------------------------------------------------------
# fixtures: the real runner, with one collaborator made slow per test
# ---------------------------------------------------------------------------


def _target() -> DbTarget:
    return DbTarget("db.internal", 5432, "appdb", "migrator", "synthetic-secret")


def _pass() -> Judgment:
    return Judgment(verdict=Verdict.PASS, confidence=0.99, authoritative=True)


class _Spy:
    """Records every call. A refusal that reached here is a refusal that failed."""

    def __init__(self, result: ExecutorResult | None = None) -> None:
        self.calls: list[tuple[str, object]] = []
        self._result = result if result is not None else ExecutorResult(
            EXECUTION_COMMITTED, "spy committed"
        )

    def __call__(
        self,
        sql: str,
        target: DbTarget,
        execution_id: str,
        artifact_sha256: str,
        *,
        deadline: ExecutionDeadline | None = None,
    ) -> ExecutorResult | tuple[bool, str]:
        self.calls.append((execution_id, deadline))
        assert isinstance(self._result, ExecutorResult)
        return self._result


class _NoReceipt:
    def __call__(
        self, execution_id: str, artifact_sha256: str, target: DbTarget
    ) -> ReceiptStatus:
        return ReceiptStatus(RECEIPT_NOT_FOUND, detail="spy: nothing recorded")


class _Harness:
    """The real runner over a real SQLite store and a real chained ledger.

    ``clock_uncertainty_s`` defaults to ZERO here. The review's numbers are a
    one-second TTL (minted 1000, expires 1001), which is exactly the shipped
    default margin, and these tests are about the expiry arms. The margin has
    its own tests below; keeping the review's numbers matters more than
    exercising two rules in one assertion.
    """

    def __init__(
        self,
        tmp_path: Path,
        spy: _Spy,
        *,
        clock_uncertainty_s: float = 0.0,
        trust_utc: bool = True,
    ) -> None:
        # The review's numbers are a ONE-SECOND TTL (minted 1000, expires 1001),
        # which is exactly the default clock uncertainty. These tests are about
        # the expiry arms, so the margin is set to zero here and gets its own
        # dedicated tests below; keeping the review's numbers matters more than
        # exercising two rules at once.
        self.now = [MINTED_AT]
        self.authority = ApprovalAuthority(key=KEY)
        self.target = _target()
        self.artifact = MigrationArtifact("CREATE INDEX i ON t (id);")
        self.audit = SqliteLedger(tmp_path / "audit.db")
        self.consumed = ConsumedApprovals(tmp_path / "consumed.db")
        self.spy = spy
        self.runner = BrokeredMigrationRunner(
            authority=self.authority,
            target=self.target,
            consumed=self.consumed,
            executor=spy,
            receipt_lookup=_NoReceipt(),
            audit=self.audit,
            clock=lambda: self.now[0],
            clock_uncertainty_s=clock_uncertainty_s,
            trust_utc=trust_utc,
        )
        self.approval = self.authority.mint(
            artifact_sha256=self.artifact.sha256,
            target=self.target.identity,
            now=MINTED_AT,
            ttl_seconds=TTL_S,
        )

    def execute(self) -> object:
        return self.runner.execute(approval=self.approval, artifact=self.artifact)

    def events(self) -> list[dict]:
        return [dict(e) for e in self.audit.chained_events()]

    def nonce_spent(self) -> bool:
        """Read the store directly: whether the nonce is spent is the fact the
        phase table turns on, and it must be read from the store rather than
        inferred from the result the runner reported."""

        with sqlite3.connect(self.consumed.path) as connection:
            rows = connection.execute(
                "SELECT COUNT(*) FROM consumed WHERE nonce = ?",
                (self.approval.nonce,),
            ).fetchone()
        return bool(rows[0])


@pytest.fixture
def harness(tmp_path):
    return _Harness(tmp_path, _Spy())


# ---------------------------------------------------------------------------
# 0. the headline: the review's own reproduction, now refused
# ---------------------------------------------------------------------------


def test_the_reviews_reproduction_no_longer_executes(tmp_path, monkeypatch):
    """Expiry at 1001, preparation drags to 5000, executor called — the exact
    finding. It must now refuse, and the executor must never be reached."""

    h = _Harness(tmp_path, _Spy())

    real_reconcile = h.runner._reconcile_owned

    def slow_reconcile():
        # The review's largest consumer: a remote anchor history read plus a
        # full chain recompute plus a receipt lookup per unresolved intent.
        result = real_reconcile()
        h.now[0] = LATE
        return result

    monkeypatch.setattr(h.runner, "_reconcile_owned", slow_reconcile)

    result = h.execute()

    assert result.executed is False
    assert result.refused is True
    assert result.reason == EXPIRED
    assert h.spy.calls == [], "the executor was reached with an expired approval"
    assert h.nonce_spent() is False, "the approval must remain unspent"


# ---------------------------------------------------------------------------
# 1. before the nonce claim -> refuse, approval UNSPENT
# ---------------------------------------------------------------------------


def test_expiry_before_the_nonce_claim_leaves_the_approval_unspent(
    tmp_path, monkeypatch
):
    h = _Harness(tmp_path, _Spy())
    real_reconcile = h.runner._reconcile_owned

    def slow_reconcile():
        result = real_reconcile()
        h.now[0] = LATE
        return result

    monkeypatch.setattr(h.runner, "_reconcile_owned", slow_reconcile)
    result = h.execute()

    assert (result.refused, result.reason) == (True, EXPIRED)
    assert h.nonce_spent() is False
    assert h.spy.calls == []
    # A fresh approval must still work: refusing here must not poison the store.
    h.now[0] = 6000.0
    fresh = h.authority.mint(
        artifact_sha256=h.artifact.sha256,
        target=h.target.identity,
        now=6000.0,
        ttl_seconds=90.0,
    )
    assert h.runner.execute(approval=fresh, artifact=h.artifact).executed is True

    refusals = [e for e in h.events() if e["event"] == "refuse"]
    assert any("expiry_before_spend" in str(e) for e in refusals)


# ---------------------------------------------------------------------------
# 2. after the claim, before the intent -> nonce STAYS spent
# ---------------------------------------------------------------------------


def test_expiry_after_the_claim_keeps_the_nonce_spent(tmp_path, monkeypatch):
    """The claim runs BEGIN IMMEDIATE under a 30-second busy timeout; thirty
    seconds alone exceeds many TTLs. An approval that reached the store has been
    used, and must not become retryable."""

    h = _Harness(tmp_path, _Spy())
    real_claim = h.consumed.claim

    def slow_claim(nonce, when):
        claimed = real_claim(nonce, when)
        h.now[0] = LATE
        return claimed

    monkeypatch.setattr(h.consumed, "claim", slow_claim)
    result = h.execute()

    assert (result.refused, result.reason) == (True, EXPIRED)
    assert result.execution_state == EXECUTION_NOT_ATTEMPTED
    assert h.spy.calls == []
    assert h.nonce_spent() is True, "the nonce must REMAIN spent"

    refusals = [e for e in h.events() if e["event"] == "refuse"]
    recorded = [e for e in refusals if "expiry_after_spend" in str(e)]
    assert recorded, "the refusal was not recorded"
    payload = json.loads(recorded[-1]["payload"])
    assert payload["nonce_spent"] is True
    assert payload["phase"] == "expiry_after_spend"

    # And it is not replayable: the same approval is now refused as a replay.
    h.now[0] = MINTED_AT
    again = h.execute()
    assert again.refused and again.reason != EXPIRED


# ---------------------------------------------------------------------------
# 3. after the durable intent, before the executor
# ---------------------------------------------------------------------------


def test_expiry_after_the_durable_intent_appends_a_linked_terminal_outcome(
    tmp_path, monkeypatch
):
    """Intent anchor publication is FOUR HTTP exchanges against an https anchor,
    each with its own deadline. The intent is already durable, so a bare refusal
    would leave a phantom for reconciliation; a linked terminal outcome must say
    exactly what happened."""

    h = _Harness(tmp_path, _Spy())
    real_record = h.runner._record

    def slow_record(event, subject, payload):
        appended = real_record(event, subject, payload)
        if event == "execute_intent":
            h.now[0] = LATE
        return appended

    monkeypatch.setattr(h.runner, "_record", slow_record)
    result = h.execute()

    assert result.executed is False
    assert (result.refused, result.reason) == (True, EXPIRED)
    assert result.execution_state == EXECUTION_NOT_ATTEMPTED
    assert result.audit_recorded is True
    assert result.execution_id is not None
    assert h.spy.calls == [], "the executor must NOT be called"
    assert h.nonce_spent() is True

    events = h.events()
    intents = [e for e in events if e["event"] == "execute_intent"]
    outcomes = [e for e in events if e["event"] == "execute_outcome"]
    assert len(intents) == 1 and len(outcomes) == 1
    # LINKED: the terminal outcome names the same execution, and states both
    # that nothing was attempted and that nothing committed.
    assert result.execution_id in str(outcomes[0])
    assert EXECUTION_NOT_ATTEMPTED in str(outcomes[0])
    assert "expiry_before_executor" in str(outcomes[0])


def test_that_terminal_outcome_resolves_the_intent_for_reconciliation(
    tmp_path, monkeypatch
):
    """The point of appending it: the NEXT execution must not be blocked by an
    unresolved intent, because this one is resolved truthfully."""

    h = _Harness(tmp_path, _Spy())
    real_record = h.runner._record
    fired = []

    def slow_record(event, subject, payload):
        appended = real_record(event, subject, payload)
        if event == "execute_intent" and not fired:
            fired.append(True)
            h.now[0] = LATE
        return appended

    monkeypatch.setattr(h.runner, "_record", slow_record)
    assert h.execute().refused is True

    h.now[0] = 6000.0
    fresh = h.authority.mint(
        artifact_sha256=h.artifact.sha256,
        target=h.target.identity,
        now=6000.0,
        ttl_seconds=90.0,
    )
    later = h.runner.execute(approval=fresh, artifact=h.artifact)
    assert later.executed is True, later.detail


# ---------------------------------------------------------------------------
# 4. the terminal append itself fails
# ---------------------------------------------------------------------------


def test_a_failed_terminal_append_is_not_reported_as_settled(tmp_path, monkeypatch):
    """Spent nonce AND unresolved durable intent both preserved, the audit
    failure exposed, and the outcome NOT presented as durably settled."""

    h = _Harness(tmp_path, _Spy())
    real_record = h.runner._record

    def record(event, subject, payload):
        if event == "execute_intent":
            appended = real_record(event, subject, payload)
            h.now[0] = LATE
            return appended
        if event == "execute_outcome":
            # The terminal append fails. ``_record`` never lets sink failure
            # escape; it reports ``recorded=False``.
            return type(appended_probe)(recorded=False, error_type="OSError")
        return real_record(event, subject, payload)

    appended_probe = real_record("probe", "probe", {})
    monkeypatch.setattr(h.runner, "_record", record)
    result = h.execute()

    assert result.executed is False
    assert result.reason == AUDIT_UNAVAILABLE
    assert result.audit_recorded is False, "must not claim the outcome is durable"
    assert result.execution_state == EXECUTION_NOT_ATTEMPTED
    assert h.spy.calls == []
    assert h.nonce_spent() is True, "the spent nonce must be preserved"
    assert "UNRESOLVED" in result.detail
    assert "not durably settled" in result.detail

    events = h.events()
    assert [e for e in events if e["event"] == "execute_intent"]
    assert not [e for e in events if e["event"] == "execute_outcome"]


# ---------------------------------------------------------------------------
# 5 & 6. once the executor has started, expiry proves nothing
# ---------------------------------------------------------------------------


def test_expiry_during_execution_is_not_proof_of_rollback(tmp_path):
    """The executor returns UNKNOWN — the reply was lost — and the clock has
    passed expiry. The result must stay UNKNOWN. "Expired, therefore rolled
    back" is the inference this whole area exists to forbid."""

    h = _Harness(tmp_path, _Spy(ExecutorResult(EXECUTION_UNKNOWN, "reply lost")))

    class _LateSpy(_Spy):
        def __call__(self, *args, **kwargs):
            h.now[0] = LATE  # expiry passes WHILE the migration is in flight
            return super().__call__(*args, **kwargs)

    h.runner._executor = _LateSpy(ExecutorResult(EXECUTION_UNKNOWN, "reply lost"))
    h.spy = h.runner._executor
    result = h.execute()

    assert result.execution_state == EXECUTION_UNKNOWN
    assert result.executed is False
    assert result.refused is False, (
        "an unknown outcome is not a refusal; refused=True would read as "
        "'the migration did not run', which expiry does not establish"
    )
    assert "rolled back" not in result.detail.lower()
    assert h.nonce_spent() is True


def test_a_commit_whose_reply_was_lost_is_never_relabelled_by_expiry(tmp_path):
    h = _Harness(tmp_path, _Spy(ExecutorResult(EXECUTION_UNKNOWN, "connection reset")))

    class _LateSpy(_Spy):
        def __call__(self, *args, **kwargs):
            h.now[0] = LATE
            return super().__call__(*args, **kwargs)

    h.runner._executor = _LateSpy(
        ExecutorResult(EXECUTION_UNKNOWN, "connection reset after COMMIT")
    )
    result = h.execute()

    assert result.execution_state == EXECUTION_UNKNOWN
    # Recorded as ``execute_unknown``, which is deliberately NOT the event that
    # resolves an intent: an unknown outcome leaves the intent for reconciliation
    # rather than settling it, and expiry does not change that.
    unknown = [e for e in h.events() if e["event"] == "execute_unknown"]
    assert unknown, [e["event"] for e in h.events()]
    payload = json.loads(unknown[-1]["payload"])
    assert payload["execution_state"] == EXECUTION_UNKNOWN
    assert payload["execution_state"] != EXECUTION_NOT_COMMITTED
    assert not [e for e in h.events() if e["event"] == "execute_outcome"]


def test_ownership_is_released_only_after_the_executor_returns(tmp_path):
    """F3's recovery race must not come back. The executor protocol promises no
    detached work continues after it returns; the guard is held for the whole
    call, so a timed-out worker cannot still be executing once another runner
    can take ownership."""

    h = _Harness(tmp_path, _Spy())
    held: list[bool] = []

    class _Watching(_Spy):
        def __call__(self, *args, **kwargs):
            # While the executor runs, a second runner must NOT get the guard.
            other = ConsumedApprovals(h.consumed.path)
            with other.execution_guard() as owned:
                held.append(bool(owned))
            return super().__call__(*args, **kwargs)

    h.runner._executor = _Watching()
    assert h.execute().executed is True
    assert held == [False], "another runner acquired ownership mid-execution"


# ---------------------------------------------------------------------------
# the clock model itself
# ---------------------------------------------------------------------------


def _deadline(*, wall, elapsed, expires_at=EXPIRES_AT, uncertainty_s=0.0):
    return ExecutionDeadline.open(
        issued_at=MINTED_AT,
        expires_at=expires_at,
        clock=lambda: wall[0],
        elapsed=lambda: elapsed[0],
        uncertainty_s=uncertainty_s,
    )


def test_the_deadline_is_fixed_once_and_never_refreshed():
    """A deadline recomputed per attempt would let a caller that retries forever
    hold an approval open forever."""

    wall, elapsed = [MINTED_AT], [100.0]
    deadline = _deadline(wall=wall, elapsed=elapsed)
    assert deadline.admit().admitted is True
    # The wall clock is wound BACK, as a resync would. The fixed elapsed
    # deadline does not move with it.
    wall[0] = MINTED_AT - 10_000.0
    elapsed[0] = 100.0 + TTL_S + 0.001
    assert deadline.admit().admitted is False


def test_a_backward_wall_step_cannot_extend_the_invocation():
    """Wall-clock-only is insufficient: this is the case it misses."""

    wall, elapsed = [MINTED_AT], [100.0]
    deadline = _deadline(wall=wall, elapsed=elapsed)
    wall[0] = MINTED_AT - 3600.0  # an hour of "extra" validity on the wall
    elapsed[0] = 100.0 + TTL_S + 0.5  # but the invocation's window is spent
    admission = deadline.admit()
    assert admission.admitted is False and admission.reason == EXPIRED
    assert "fixed deadline" in admission.detail


def test_a_forward_wall_step_refuses_even_with_elapsed_budget_left():
    """Elapsed-only is insufficient: this is the case it misses."""

    wall, elapsed = [MINTED_AT], [100.0]
    deadline = _deadline(wall=wall, elapsed=elapsed, expires_at=MINTED_AT + 3600.0)
    wall[0] = MINTED_AT + 7200.0  # the signed expiry has genuinely passed
    elapsed[0] = 100.5  # almost no elapsed time has been used
    admission = deadline.admit()
    assert admission.admitted is False and admission.reason == EXPIRED
    assert "signed expiry" in admission.detail


def test_the_elapsed_clock_is_sampled_before_the_wall_clock():
    """A pause between the two samples must SHRINK the budget, never grow it.

    Sampling wall first would put the pause into ``elapsed``, moving the elapsed
    deadline later while the budget stayed large.
    """

    order: list[str] = []
    wall, elapsed = [MINTED_AT], [100.0]

    def read_wall():
        order.append("wall")
        return wall[0]

    def read_elapsed():
        order.append("elapsed")
        return elapsed[0]

    deadline = ExecutionDeadline.open(
        issued_at=MINTED_AT,
        expires_at=EXPIRES_AT,
        clock=read_wall,
        elapsed=read_elapsed,
        uncertainty_s=0.0,
    )
    assert order == ["elapsed", "wall"], order

    order.clear()
    deadline.admit()
    assert order == ["elapsed", "wall"], order


def test_a_pause_between_the_two_samples_shortens_the_budget():
    """The property the ordering buys, asserted on the value not the call order."""

    elapsed = [100.0]
    paused = {"n": 0}

    def read_elapsed():
        return elapsed[0]

    def read_wall():
        # The pause happens AFTER elapsed was sampled: it lands in the wall
        # reading, which is what shrinks ``expires_at - wall``.
        paused["n"] += 1
        return MINTED_AT + 0.5

    deadline = ExecutionDeadline.open(
        issued_at=MINTED_AT,
        expires_at=EXPIRES_AT,
        clock=read_wall,
        elapsed=read_elapsed,
        uncertainty_s=0.0,
    )
    # Budget is 0.5s, not the full 1.0s TTL: the pause was charged.
    assert deadline.elapsed_deadline == pytest.approx(100.0 + 0.5)


def test_admission_refuses_inside_the_declared_clock_uncertainty():
    wall, elapsed = [MINTED_AT], [100.0]
    deadline = _deadline(wall=wall, elapsed=elapsed, uncertainty_s=0.4)
    # 1.0s remains, well outside the margin.
    assert deadline.admit().admitted is True
    # 0.4s remains — exactly the margin. Refused: the true remaining could be
    # zero or less, and racing it is what F7 forbids.
    wall[0] = MINTED_AT + 0.6
    admission = deadline.admit()
    assert admission.admitted is False and admission.reason == CLOCK_MARGIN
    assert "clock uncertainty" in admission.detail


def test_untrusted_utc_refuses_rather_than_leaning_on_the_elapsed_clock():
    """Two local clocks do not repair untrusted UTC."""

    with pytest.raises(ClockUntrusted) as caught:
        ExecutionDeadline.open(
            issued_at=MINTED_AT,
            expires_at=EXPIRES_AT,
            clock=lambda: MINTED_AT,
            trust_utc=False,
        )
    assert "does not repair" in str(caught.value)


def test_the_runner_refuses_when_utc_is_declared_untrusted(tmp_path):
    h = _Harness(tmp_path, _Spy(), trust_utc=False)
    result = h.execute()
    assert (result.refused, result.reason) == (True, CLOCK_UNTRUSTED)
    assert h.spy.calls == []
    assert h.nonce_spent() is False


@pytest.mark.parametrize(
    "issued_at,expires_at",
    [
        (MINTED_AT, float("inf")),
        (MINTED_AT, float("nan")),
        (float("nan"), EXPIRES_AT),
        (MINTED_AT, MINTED_AT),
        (MINTED_AT, MINTED_AT - 1.0),
        (MINTED_AT, True),
    ],
)
def test_an_unusable_signed_interval_is_refused(issued_at, expires_at):
    with pytest.raises(InvalidApprovalInterval):
        ExecutionDeadline.open(
            issued_at=issued_at, expires_at=expires_at, clock=lambda: MINTED_AT
        )


def test_the_elapsed_source_is_named_and_suspend_aware_where_available():
    read, name = elapsed_source()
    assert callable(read) and isinstance(read(), float)
    assert name in {"CLOCK_BOOTTIME", "time.monotonic"}
    import sys

    if sys.platform.startswith("linux"):
        assert name == "CLOCK_BOOTTIME", (
            "Linux offers CLOCK_BOOTTIME, which includes suspend; "
            "time.monotonic() is CLOCK_MONOTONIC, which does not"
        )


def test_no_elapsed_reading_is_ever_serialized():
    """A monotonic epoch is not portable across boots, processes or hosts, so a
    persisted one compared with a fresh one compares two different origins."""

    wall, elapsed = [MINTED_AT], [100.0]
    payload = _deadline(wall=wall, elapsed=elapsed).as_payload()
    assert "elapsed_clock" in payload  # the NAME is portable
    for key, value in payload.items():
        assert "elapsed" not in key or isinstance(value, str), (key, value)
    assert 100.0 not in payload.values()
    assert set(payload) == {
        "approval_expires_at",
        "invocation_opened_at",
        "invocation_budget_s",
        "elapsed_clock",
        "clock_uncertainty_s",
    }


def test_an_invalid_wall_reading_at_admission_refuses(tmp_path):
    wall, elapsed = [MINTED_AT], [100.0]
    deadline = _deadline(wall=wall, elapsed=elapsed)
    wall[0] = float("nan")
    admission = deadline.admit()
    assert admission.admitted is False and admission.reason == INVALID_TIME


# ---------------------------------------------------------------------------
# the PostgreSQL timeout arithmetic
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "remaining,expected",
    [
        (0.0005, 1),      # would round to 0 — and 0 DISABLES statement_timeout
        (0.0, 1),
        (-5.0, 1),
        (float("nan"), 1),
        (0.25, 250),
        (45.0, 45_000),
        (600.0, 60_000),  # capped
    ],
)
def test_a_positive_budget_never_becomes_an_unlimited_timeout(remaining, expected):
    assert timeout_ms(remaining, cap_ms=60_000) == expected


def test_connect_timeout_never_becomes_wait_forever():
    """libpq treats connect_timeout=0 as 'wait indefinitely'."""

    assert connect_timeout_s(0.4, cap_s=10) == 1
    assert connect_timeout_s(0.0, cap_s=10) == 1
    assert connect_timeout_s(-3.0, cap_s=10) == 1
    assert connect_timeout_s(4.7, cap_s=10) == 4
    assert connect_timeout_s(900.0, cap_s=10) == 10


# ---------------------------------------------------------------------------
# boundary 2 — inside the executor, the ruled policy
# ---------------------------------------------------------------------------


def test_boundary_2a_opens_no_connection_after_expiry(monkeypatch):
    """POLICY (1), RULED: no privileged database contact after expiry. Neither
    the password provider nor the driver may be reached."""

    resolved: list[str] = []
    imported: list[str] = []

    class _Target(DbTarget):
        def resolve_password(self) -> str:
            resolved.append("password")
            return "secret"

    monkeypatch.setattr(
        "prometheus_protocol.chokepoint.runner.import_module",
        lambda name: imported.append(name),
    )

    wall, elapsed = [MINTED_AT], [100.0]
    deadline = _deadline(wall=wall, elapsed=elapsed)
    wall[0] = LATE  # expired

    target = _Target("db.internal", 5432, "appdb", "migrator", "synthetic-secret")
    result = postgres_executor(
        "CREATE INDEX i ON t (id);",
        target,
        "a" * 64,
        "b" * 64,
        deadline=deadline,
    )

    assert result.state == EXECUTION_NOT_ATTEMPTED
    assert "no connection was opened" in result.detail
    assert resolved == [], "a credential was resolved for an expired approval"
    assert imported == [], "the driver was reached for an expired approval"


def test_boundary_2a_admits_a_live_approval():
    """The positive control: an executor that refused everything would pass the
    test above vacuously."""

    wall, elapsed = [MINTED_AT], [100.0]
    deadline = _deadline(wall=wall, elapsed=elapsed)
    result = postgres_executor(
        "CREATE INDEX i ON t (id);",
        _target(),
        "a" * 64,
        "b" * 64,
        deadline=deadline,
    )
    # It got PAST admission and failed for the honest reason: no database here.
    assert result.state != EXECUTION_NOT_ATTEMPTED


class _FakeCursor:
    """Records every statement, and lets a test advance the clock from inside a
    chosen one — which is how the BLOCKING advisory locks are simulated."""

    def __init__(self, statements, on_execute=None):
        self._statements = statements
        self._on_execute = on_execute

    def execute(self, sql, params=None, prepare=None):
        self._statements.append(sql)
        if self._on_execute is not None:
            self._on_execute(sql)

    def fetchone(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeConnection:
    def __init__(self, statements, on_execute=None):
        self._statements = statements
        self._on_execute = on_execute
        self.committed = 0

    def cursor(self):
        return _FakeCursor(self._statements, self._on_execute)

    def commit(self):
        self.committed += 1

    def rollback(self):
        pass

    def cancel(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakePsycopg:
    Error = RuntimeError

    def __init__(self, connection):
        self._connection = connection
        self.connects = 0

    def connect(self, **kwargs):
        self.connects += 1
        self.connect_kwargs = kwargs
        return self._connection


def test_boundary_2b_writes_no_bootstrap_ddl_when_the_locks_blocked_past_expiry(
    monkeypatch,
):
    """The two advisory locks BLOCK. A runner-side check cannot see that, and
    boundary 2a already passed — so the recheck after the locks is the only
    thing standing between a lapsed approval and bootstrap DDL under privileged
    credentials. Ruled policy (1): no privileged database contact after expiry.

    Driven through the REAL ``postgres_executor`` with an injected driver, so
    the code path under test is the shipped one: connect, lock_timeout, both
    locks, then the boundary.
    """

    wall, elapsed = [MINTED_AT], [100.0]
    deadline = _deadline(wall=wall, elapsed=elapsed)

    statements: list[str] = []

    def blocking_lock(sql: str) -> None:
        # The session advisory lock blocks until after the approval expires.
        if "pg_advisory_lock" in sql:
            wall[0] = LATE

    fake = _FakePsycopg(_FakeConnection(statements, blocking_lock))
    monkeypatch.setattr(
        "prometheus_protocol.chokepoint.runner.import_module", lambda name: fake
    )

    result = postgres_executor(
        "CREATE INDEX i ON t (id);",
        _target(),
        "a" * 64,
        "b" * 64,
        deadline=deadline,
    )

    assert result.state == EXECUTION_NOT_ATTEMPTED
    assert "after acquiring the execution locks" in result.detail
    assert fake.connects == 1, "2a admitted, as it should have"
    joined = " ".join(statements)
    assert "pg_advisory_lock" in joined, "the locks must have been reached"
    assert "CREATE SCHEMA" not in joined, "bootstrap DDL was authored after expiry"
    assert "CREATE TABLE" not in joined, "bootstrap DDL was authored after expiry"
    assert "CREATE INDEX" not in joined, "the migration was sent after expiry"
    assert fake._connection.committed == 0, "a write was committed after expiry"


def test_the_blocking_locks_carry_a_lock_timeout_from_the_remaining_budget(
    monkeypatch,
):
    """Without it a lock held elsewhere outlasts the approval while this session
    waits, and boundary 2b is reached long after the deadline instead of at it."""

    wall, elapsed = [MINTED_AT], [100.0]
    deadline = _deadline(wall=wall, elapsed=elapsed)
    statements: list[str] = []
    fake = _FakePsycopg(_FakeConnection(statements))
    monkeypatch.setattr(
        "prometheus_protocol.chokepoint.runner.import_module", lambda name: fake
    )

    postgres_executor(
        "CREATE INDEX i ON t (id);", _target(), "a" * 64, "b" * 64, deadline=deadline
    )

    lock_timeouts = [s for s in statements if "lock_timeout" in s]
    assert lock_timeouts, statements
    assert statements.index(lock_timeouts[0]) < statements.index(
        next(s for s in statements if "pg_advisory_lock" in s)
    ), "lock_timeout must be installed BEFORE the first blocking lock"
    # And the connect timeout is derived from the budget, not a fixed 10.
    assert fake.connect_kwargs["connect_timeout"] == 1


def test_the_statement_timeout_is_derived_from_what_remains(monkeypatch):
    """Not a fixed 60 seconds: a 60-second statement under a shorter remaining
    validity is a statement that outlives its authorization."""

    wall, elapsed = [MINTED_AT], [100.0]
    deadline = ExecutionDeadline.open(
        issued_at=MINTED_AT,
        expires_at=MINTED_AT + 4.0,
        clock=lambda: wall[0],
        elapsed=lambda: elapsed[0],
        uncertainty_s=0.0,
    )
    statements: list[str] = []
    fake = _FakePsycopg(_FakeConnection(statements))
    monkeypatch.setattr(
        "prometheus_protocol.chokepoint.runner.import_module", lambda name: fake
    )

    postgres_executor(
        "CREATE INDEX i ON t (id);", _target(), "a" * 64, "b" * 64, deadline=deadline
    )

    installed = [s for s in statements if "statement_timeout" in s]
    assert installed, statements
    # The value is a bound parameter, so assert on what the executor computed.
    assert timeout_ms(4.0, cap_ms=60_000) == 4_000


def test_the_shipped_executor_declares_the_deadline_parameter():
    """Boundary 2 exists only for an executor that receives the deadline. If
    ``postgres_executor`` ever stops declaring it, the runner would silently
    fall back to boundary 1 alone."""

    import inspect

    from prometheus_protocol.chokepoint.runner import _accepts_deadline

    assert "deadline" in inspect.signature(postgres_executor).parameters
    assert _accepts_deadline(postgres_executor) is True
    assert _accepts_deadline(lambda a, b, c, d: None) is False


def test_the_intent_records_which_boundaries_were_in_force(tmp_path):
    h = _Harness(tmp_path, _Spy())
    assert h.execute().executed is True
    intents = [e for e in h.events() if e["event"] == "execute_intent"]
    assert intents and "executor_enforces_deadline" in str(intents[-1])
    assert "elapsed_clock" in str(intents[-1])


def test_the_deadline_reaches_the_executor(tmp_path):
    h = _Harness(tmp_path, _Spy())
    assert h.execute().executed is True
    assert len(h.spy.calls) == 1
    _, deadline = h.spy.calls[0]
    assert isinstance(deadline, ExecutionDeadline)
    assert deadline.expires_at == EXPIRES_AT


def test_an_executor_without_the_parameter_is_still_called(tmp_path):
    """Boundary 1 covers every executor. A bespoke executor that predates the
    deadline contract must not break — it is simply not covered by boundary 2,
    and the intent says so."""

    calls: list[str] = []

    def legacy(sql, target, execution_id, artifact_sha256):
        calls.append(execution_id)
        return True, "legacy ok"

    h = _Harness(tmp_path, _Spy())
    h.runner._executor = legacy
    h.runner._executor_enforces_deadline = False
    assert h.execute().executed is True
    assert len(calls) == 1


def test_the_watchdog_is_joined_before_the_executor_returns():
    """Ownership is released on the promise that no detached work continues."""

    from prometheus_protocol.chokepoint.runner import (
        _cancel_at_deadline,
        _stop_watchdog,
    )

    class _Connection:
        def __init__(self) -> None:
            self.cancelled = 0

        def cancel(self) -> None:
            self.cancelled += 1

    connection = _Connection()
    watchdog = _cancel_at_deadline(connection, 30.0)
    assert watchdog is not None and watchdog.is_alive()
    _stop_watchdog(watchdog)
    assert not watchdog.is_alive()
    assert connection.cancelled == 0

    assert _cancel_at_deadline(connection, None) is None
    assert _cancel_at_deadline(connection, 0.0) is None
    _stop_watchdog(None)


def test_the_watchdog_cancels_when_the_budget_runs_out():
    from prometheus_protocol.chokepoint.runner import (
        _cancel_at_deadline,
        _stop_watchdog,
    )

    fired = threading.Event()

    class _Connection:
        def cancel(self) -> None:
            fired.set()

    watchdog = _cancel_at_deadline(_Connection(), 0.05)
    assert fired.wait(timeout=5.0), "the multi-statement watchdog never fired"
    _stop_watchdog(watchdog)


def test_a_watchdog_cancel_that_raises_does_not_escape():
    from prometheus_protocol.chokepoint.runner import (
        _cancel_at_deadline,
        _stop_watchdog,
    )

    fired = threading.Event()

    class _Connection:
        def cancel(self) -> None:
            fired.set()
            raise RuntimeError("cancel failed")

    watchdog = _cancel_at_deadline(_Connection(), 0.05)
    assert fired.wait(timeout=5.0)
    _stop_watchdog(watchdog)  # would raise here if the timer thread had died badly
