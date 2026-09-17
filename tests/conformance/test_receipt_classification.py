"""A row the chain never saw is not evidence, and is not a rewrite (F-3).

WHAT THIS EXISTS FOR. Independent review of the first implementation measured
that opening a database written before ``ledger/receipts.py`` existed refused
``executions()``, ``pending_actions()`` AND every production root's
construction alike. Refusing the row as EVIDENCE is the intended behaviour.
Refusing CONSTRUCTION is a different and much larger statement, and it broke
every existing deployment on upgrade.

THE PROVENANCE OF THE FIXTURE, MEASURED RATHER THAN ASSUMED. ``receipts.py``
arrived in commit ``1089815`` (merged as ``9141936``, PR #121). The last commit
without it is ``d2cba9c``. Running that tree's ``SqliteLedger.record_execution``
was observed to write one ``executions`` row and append NOTHING to the chain:

    chain rows: (none)
    executions: [(1, True)]
    verify_chain -> valid

The review brief that commissioned this fix said to build the fixture "with
base 9141936 code". That was measured to be wrong and is not what this module
does: ``9141936`` IS #121, so its ``record_execution`` already chains an
``outcome.execution`` receipt and a ledger it writes opens perfectly well at
this head. The pre-receipt shape comes from ``d2cba9c``, and
``_pre_receipt_execution_row`` reproduces exactly that shape — a plain INSERT,
no chain append — which ``test_the_fixture_is_the_pre_receipt_shape`` pins
against the three observed facts above rather than trusting the comment.
"""

from __future__ import annotations

import ast
import inspect
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from prometheus_protocol.core.config import Config
from prometheus_protocol.ledger import receipts as receipts_module
from prometheus_protocol.ledger.audit_chain import NOT_VERIFIABLE
from prometheus_protocol.ledger.receipts import (
    EXECUTION_TABLE,
    HOLD_TABLE,
    RECEIPT_FINDING_REASONS,
    RECEIPTS_NOT_VERIFIABLE,
    TAMPERED_REASONS,
    UNRECEIPTED_REASONS,
    ReceiptFinding,
    verify_ledger,
    verify_receipts,
)
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.policy.execution import (
    EXECUTION_REFUSAL_REASONS,
    ExecutionNotAuthorized,
)
from prometheus_protocol.runtime import factory
from prometheus_protocol.sandbox.namespace import NamespaceSandbox

SOURCE = Path(receipts_module.__file__)


def _pre_receipt_execution_row(ledger: SqliteLedger, *, detail: str = "pre-upgrade") -> int:
    """One execution row with no chained receipt — the ``d2cba9c`` shape.

    A plain INSERT, exactly as that tree's ``record_execution`` did. NOT a
    ``record_execution`` followed by deleting the chain entry: deleting a
    chained row breaks the hash linkage, which is a DIFFERENT fact (the chain
    itself stops verifying) and would test the wrong branch.
    """

    cur = ledger._conn.execute(
        f"INSERT INTO {EXECUTION_TABLE} "
        "(subject_id, source, executed, refused, sandbox, exit_status, detail, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("legacy-subject", "human", 1, 0, "namespace", 0, detail, "2026-09-15T00:00:00Z"),
    )
    ledger._conn.commit()
    inserted = cur.lastrowid
    # `lastrowid` is `int | None` because a cursor that did not INSERT has no
    # row id. This one just did, so None would mean the write did not happen.
    assert inserted is not None
    return inserted


@pytest.fixture
def legacy_ledger(tmp_path):
    ledger = SqliteLedger(tmp_path / "legacy.db")
    _pre_receipt_execution_row(ledger)
    yield ledger
    ledger.close()


@pytest.fixture
def build_config(tmp_path, monkeypatch):
    monkeypatch.setattr(NamespaceSandbox, "available", classmethod(lambda cls: True))
    return Config(
        sandbox="namespace",
        ledger_path=tmp_path / "legacy.db",
        registry_dir=tmp_path / "skills",
        trust_store_path=tmp_path / "trust.db",
    )


# ---------------------------------------------------------------------------
# 1. the fixture really is the pre-receipt shape
# ---------------------------------------------------------------------------


def test_the_fixture_is_the_pre_receipt_shape(legacy_ledger):
    """Pinned against the three facts observed on ``d2cba9c``, not on trust."""

    assert legacy_ledger.verify_chain().status == "valid"
    assert legacy_ledger._receipt_source().chained_events() == []
    outcomes = legacy_ledger._receipt_source().executions()
    assert [(row["id"], row["executed"]) for row in outcomes] == [(1, True)]


# ---------------------------------------------------------------------------
# 2. F-3: the reproduction, and the rule
# ---------------------------------------------------------------------------


#: WHICH ROOTS ACTUALLY REGRESSED, measured on a pristine export of ``4664dad``
#: against the fixture below — not generalised from one of them:
#:
#:     execution_controller   REFUSED ExecutionNotAuthorized: outcome_entry_missing
#:     workflow_runtime       REFUSED ExecutionNotAuthorized: outcome_entry_missing
#:     orchestrator           BUILT
#:     swarm                  BUILT
#:
#: The review that commissioned this fix said "every runtime root". Two of the
#: four did it, and the reason is structural rather than incidental: only these
#: two construct an ``ExecutionController``, whose ``__init__`` performs the
#: opportunistic sweep that reads. ``test_only_the_sweeping_roots_could_have_
#: regressed`` checks that explanation instead of leaving it as a comment.
SWEEPING_ROOTS = frozenset({"execution_controller", "workflow_runtime"})


def _build(root, config):
    if root == "swarm":
        from prometheus_protocol.provider.mock import MockProvider

        return factory.build_swarm_runtime(config, provider=MockProvider())
    return getattr(factory, "build_" + root)(config)


@pytest.mark.parametrize(
    "root", ["execution_controller", "workflow_runtime", "orchestrator", "swarm"]
)
def test_a_pre_receipt_row_does_not_stop_a_runtime_root_from_opening(build_config, root):
    """F-3, and all four roots because all four must keep opening."""

    seeded = SqliteLedger(build_config.ledger_path)
    _pre_receipt_execution_row(seeded)
    seeded.close()
    assert _build(root, build_config) is not None


@pytest.mark.parametrize(
    "root", ["execution_controller", "workflow_runtime", "orchestrator", "swarm"]
)
def test_only_the_sweeping_roots_could_have_regressed(build_config, root):
    """The structural reason the other two never refused, as a check.

    If a future change gives the orchestrator or the swarm a pending service,
    this reddens and the table above stops being true — which is the point of
    pinning the explanation rather than writing it down.
    """

    from prometheus_protocol.execution.pending import PendingActionService
    from prometheus_protocol.runtime.security_build import _objects

    runtime = _build(root, build_config)
    sweeps = any(isinstance(obj, PendingActionService) for obj in _objects(runtime))
    assert sweeps is (root in SWEEPING_ROOTS)


def test_a_pre_receipt_row_is_still_refused_as_evidence(legacy_ledger):
    """The other half of the rule. Construction proceeds; the ROW never reads."""

    with pytest.raises(ExecutionNotAuthorized) as refused:
        legacy_ledger.executions()
    assert refused.value.reason == "outcome_entry_missing"


def test_a_read_that_cannot_return_the_row_proceeds(legacy_ledger):
    """The scope is the rows a read hands back, not the whole database."""

    assert legacy_ledger.pending_actions() == []
    assert legacy_ledger.human_decisions() == []
    assert legacy_ledger.attempts() == []


def _legacy_decided_hold(ledger: SqliteLedger) -> int:
    """A hold decided the pre-F13 way: the row updated, no decision chained."""

    hold_id = ledger.record_pending_action(
        subject_id="legacy", risk_class="low", reason="r", verdict="pass",
        confidence=0.9, action={"kind": "noop"}, judgment={"verdict": "pass"},
        created_at="2026-09-15T00:00:00Z",
    )
    ledger._conn.execute(
        f"UPDATE {HOLD_TABLE} SET status='approved', decided_by='human', "
        "decided_at='2026-09-15T01:00:00Z', decision_reason='ok' WHERE id = ?",
        (hold_id,),
    )
    ledger._conn.commit()
    return hold_id


def test_a_receipted_row_still_reads_alongside_an_unreceipted_one(tmp_path):
    """THE REAL-WORLD SHAPE, and the one both scopes are load-bearing for.

    An upgraded database has old rows and new ones. A read that returns only
    the receipted hold must proceed; the same reader asked for the unreceipted
    one must refuse. Without the RESULT scope the first refuses; without it the
    second would too, and the distinction would be invisible.
    """

    ledger = SqliteLedger(tmp_path / "mixed.db")
    legacy_id = _legacy_decided_hold(ledger)
    good_id = ledger.record_pending_action(
        subject_id="current", risk_class="low", reason="r", verdict="pass",
        confidence=0.9, action={"kind": "noop"}, judgment={"verdict": "pass"},
        created_at="2026-09-16T00:00:00Z",
    )
    ledger.resolve_pending_action(
        good_id, status="approved", decided_by="human",
        decided_at="2026-09-16T01:00:00Z", decision_reason="ok",
    )

    verification = verify_receipts(ledger)
    assert verification.unreceipted_rows == {HOLD_TABLE: frozenset({legacy_id})}

    assert ledger.pending_action(good_id)["id"] == good_id
    with pytest.raises(ExecutionNotAuthorized) as refused:
        ledger.pending_action(legacy_id)
    assert refused.value.reason == "decision_entry_missing"
    ledger.close()


def test_a_projection_over_an_unrelated_table_still_reads(tmp_path):
    """The TABLE scope stops the fail-closed projection rule over-refusing.

    A ``-> int`` reader of ``attempts`` cannot enumerate its rows, so the
    result scope alone would refuse it while an unreceipted ``executions`` row
    exists — a read with nothing to do with the finding. SQLite's account of
    which table was read is what keeps that read working.
    """

    class FutureLedger(SqliteLedger):
        def attempt_count(self) -> int:
            return int(self._conn.execute("SELECT count(*) FROM attempts").fetchone()[0])

    ledger = FutureLedger(tmp_path / "unrelated.db")
    _pre_receipt_execution_row(ledger)
    assert ledger.attempt_count() == 0
    with pytest.raises(ExecutionNotAuthorized):
        ledger.executions()  # the finding's own table still refuses
    ledger.close()


def test_a_rewritten_row_still_refuses_every_read(tmp_path):
    """CROSS-CONTEXT CONTROL. The same read, the same table, a DIFFERENT kind
    of finding: a receipt that exists and disagrees. That condemns the ledger,
    so even a read whose result excludes the row refuses. If this went green
    the classification would have widened into a bypass."""

    ledger = SqliteLedger(tmp_path / "tampered.db")
    ledger.record_execution(
        subject_id="s", source="human", executed=True, refused=False,
        sandbox_name="namespace", exit_status=0, detail="honest",
        created_at="2026-09-16T00:00:00Z",
    )
    ledger._conn.execute(f"UPDATE {EXECUTION_TABLE} SET detail = 'rewritten'")
    ledger._conn.commit()

    verification = verify_receipts(ledger)
    assert [f.reason for f in verification.tampered] == ["outcome_differs_from_chain_entry"]
    for reader in (ledger.pending_actions, ledger.human_decisions, ledger.executions):
        with pytest.raises(ExecutionNotAuthorized) as refused:
            reader()
        assert refused.value.reason == "outcome_differs_from_chain_entry"
    ledger.close()


def test_a_scalar_projection_cannot_escape_the_unreceipted_refusal(tmp_path):
    """A result that is not built of row mappings cannot demonstrate WHICH rows
    it came from, so it is treated as if it returned every row of the tables it
    read. Fail-closed, and the reason is stated rather than implied."""

    class FutureLedger(SqliteLedger):
        def executed_anything(self) -> bool:
            return bool(
                self._conn.execute(f"SELECT count(*) FROM {EXECUTION_TABLE}").fetchone()[0]
            )

    ledger = FutureLedger(tmp_path / "scalar.db")
    assert ledger.executed_anything() is False  # paired positive: clean ledger reads
    _pre_receipt_execution_row(ledger)
    with pytest.raises(ExecutionNotAuthorized) as refused:
        ledger.executed_anything()
    assert refused.value.reason == "outcome_entry_missing"
    ledger.close()


def test_an_unobservable_read_fails_closed(legacy_ledger):
    """Two independent narrowings, and neither may be trusted alone.

    The TABLE scope says which findings can concern this read; the RESULT scope
    says whether the read handed the row back. A finding is skipped only when
    one of them positively excludes it, so losing either leaves the other
    refusing. The case where BOTH are unknown — SQLite reported nothing and the
    result is a projection — refuses, which is the state doctrine #8 is about.

    This assertion was written the other way round first, claiming an empty
    ``touched`` alone must refuse. That was wrong and the test said so: a read
    that demonstrably returned no rows handed nothing back whatever it touched.
    The claim is corrected here rather than weakened away.
    """

    verification = verify_receipts(legacy_ledger)
    # a scalar result, exactly what a ``-> bool`` reader hands back. ``None``
    # would NOT do here: a reader returning None returned no rows, which is
    # an enumerably empty answer rather than an unenumerable one.
    unknown_reach, projection = set(), True

    # neither scope knows anything: refuse
    reached = SqliteLedger._unreceipted_reached(verification, unknown_reach, projection)
    assert reached is not None and reached.reason == "outcome_entry_missing"

    # the table is known and is not the finding's: the finding cannot apply
    assert SqliteLedger._unreceipted_reached(verification, {HOLD_TABLE}, projection) is None

    # the table is the finding's and the result is a projection: refuse
    assert SqliteLedger._unreceipted_reached(
        verification, {EXECUTION_TABLE}, projection
    ) is not None

    # the result enumerably excludes the row: safe, whatever was touched
    assert SqliteLedger._unreceipted_reached(verification, unknown_reach, []) is None
    assert SqliteLedger._unreceipted_reached(verification, {EXECUTION_TABLE}, []) is None

    # the result enumerably INCLUDES it: refuse
    assert SqliteLedger._unreceipted_reached(
        verification, {EXECUTION_TABLE}, [{"id": 1}]
    ) is not None


def test_a_row_id_in_one_table_does_not_condemn_the_same_id_in_another(legacy_ledger):
    """Row ids collide across tables. Without the table scope, an unreceipted
    ``executions`` row 1 would refuse a ``pending_actions`` read that returned
    hold 1 — a false refusal on an untouched table."""

    verification = verify_receipts(legacy_ledger)
    assert verification.unreceipted_rows == {EXECUTION_TABLE: frozenset({1})}
    assert SqliteLedger._unreceipted_reached(
        verification, {HOLD_TABLE}, [{"id": 1}]
    ) is None


# ---------------------------------------------------------------------------
# 3. the auditor's verdict still refuses, and now says which kind
# ---------------------------------------------------------------------------


def test_the_verdict_distinguishes_unreceipted_from_rewritten(legacy_ledger):
    verification = verify_receipts(legacy_ledger)
    assert verification.status == RECEIPTS_NOT_VERIFIABLE
    assert verification.ok is False, "NOT VERIFIABLE has never been ok and is not now"
    assert verify_ledger(legacy_ledger).status == RECEIPTS_NOT_VERIFIABLE
    assert verify_ledger(legacy_ledger).ok is False
    assert "never saw" in verification.render()


def test_a_clean_ledger_is_valid_and_ok(tmp_path):
    """The positive control for the whole module: without a pre-receipt row the
    verdict is VALID, so the refusals above are the finding and not the floor."""

    ledger = SqliteLedger(tmp_path / "clean.db")
    ledger.record_execution(
        subject_id="s", source="human", executed=True, refused=False,
        sandbox_name="namespace", exit_status=0, detail="honest",
        created_at="2026-09-16T00:00:00Z",
    )
    verification = verify_receipts(ledger)
    assert verification.status == "valid" and verification.ok is True
    assert len(ledger.executions()) == 1
    ledger.close()


# ---------------------------------------------------------------------------
# 4. the classification is a MEMBERSHIP, derived from the source and exact
# ---------------------------------------------------------------------------


def _emitted_reasons() -> set[str]:
    """Every reason actually passed to ``ReceiptFinding(...)`` in the module.

    Read off the source, resolving module-level constants, so the pin measures
    what the code emits rather than what a second list says it emits. Same
    two-source shape as ``_set_columns_in_writers`` in test_receipt_derivation.
    """

    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    constants = {
        target.id: node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        for target in node.targets
        if isinstance(target, ast.Name) and isinstance(node.value.value, str)
    }
    emitted: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id != "ReceiptFinding" or len(node.args) < 2:
            continue
        reason = node.args[1]
        if isinstance(reason, ast.Constant) and isinstance(reason.value, str):
            emitted.add(reason.value)
        elif isinstance(reason, ast.Name) and reason.id in constants:
            emitted.add(constants[reason.id])
        else:
            pytest.fail(f"unresolvable ReceiptFinding reason at line {node.lineno}")
    return emitted


def test_every_reason_the_module_emits_is_classified_exactly():
    """EXACT, not a floor. Both directions matter: a new finding that nothing
    classified would read as a rewrite and condemn every read of an ordinary
    ledger; a classified reason that stopped being emitted would leave the
    sets describing a population that no longer exists."""

    assert _emitted_reasons() == set(RECEIPT_FINDING_REASONS)


def test_the_two_classifications_partition_the_population():
    assert UNRECEIPTED_REASONS & TAMPERED_REASONS == frozenset()
    assert UNRECEIPTED_REASONS | TAMPERED_REASONS == RECEIPT_FINDING_REASONS
    assert UNRECEIPTED_REASONS and TAMPERED_REASONS, "an empty side proves nothing"


def test_every_finding_reason_is_in_the_closed_refusal_set():
    """These reasons reach a caller as ``ExecutionNotAuthorized.reason``, so
    they must be members of the vocabulary that set is closed over."""

    assert RECEIPT_FINDING_REASONS <= set(EXECUTION_REFUSAL_REASONS)


def test_an_unclassified_finding_is_reported_as_a_rewrite_not_ignored():
    """The fail-closed direction of the classification itself: a finding whose
    reason is in neither set is NOT unreceipted, so it condemns the ledger."""

    assert ReceiptFinding("execution:1", "a_future_reason").unreceipted is False
    assert ReceiptFinding("execution:1", "outcome_entry_missing").unreceipted is True


# ---------------------------------------------------------------------------
# 5. the table names are one population, shared by the query and the findings
# ---------------------------------------------------------------------------


def test_the_receipted_tables_exist_and_are_what_the_snapshot_queries(tmp_path):
    ledger = SqliteLedger(tmp_path / "tables.db")
    present = {
        row[0]
        for row in ledger._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {HOLD_TABLE, EXECUTION_TABLE} <= present
    source = inspect.getsource(SqliteLedger._receipt_source)
    assert "{HOLD_TABLE}" in source and "{EXECUTION_TABLE}" in source, (
        "the snapshot query must name the tables through the shared constants, "
        "not through a second spelling"
    )
    ledger.close()


def test_sqlite_reports_the_table_each_guarded_reader_reads(tmp_path):
    """The read scope is DERIVED from SQLite's own authorizer, not from a
    reader-name -> table list. Pinned per reader, exactly."""

    from prometheus_protocol.ledger.readers import reader_methods

    ledger = SqliteLedger(tmp_path / "scope.db")
    arguments = {"pending_id": 1, "threshold": 0.5, "workflow_id": "w"}
    observed: dict[str, set[str]] = {}
    for name in reader_methods(SqliteLedger):
        descriptor = inspect.getattr_static(SqliteLedger, name)
        function = descriptor.fget if isinstance(descriptor, property) else descriptor
        inner = getattr(function, "__wrapped__", function)
        supplied = {
            parameter: arguments[parameter]
            for parameter, spec in inspect.signature(inner).parameters.items()
            if parameter != "self" and spec.default is inspect.Parameter.empty
        }
        seen: set[str] = set()

        def observe(action, first, second, database, trigger, _seen=seen):
            if action == sqlite3.SQLITE_READ and first:
                _seen.add(first)
            return sqlite3.SQLITE_OK

        ledger._conn.set_authorizer(observe)
        try:
            inner(ledger, **supplied)
        finally:
            ledger._conn.set_authorizer(None)
        observed[name] = seen

    assert observed == {
        "attempts": {"attempts"},
        "authoritative_pass_below": {EXECUTION_TABLE},
        "chained_events": {"audit_chain"},
        "executions": {EXECUTION_TABLE},
        "executions_below_confidence": {EXECUTION_TABLE},
        "executions_for_pending": {EXECUTION_TABLE},
        "human_decisions": {HOLD_TABLE},
        "pending_action": {HOLD_TABLE},
        "pending_actions": {HOLD_TABLE},
        "promotions": {"promotions"},
        "workflow_steps": {"workflow_steps"},
    }
    ledger.close()


def test_the_authorizer_still_reports_after_the_statement_cache_is_warm(tmp_path):
    """A read whose statement was already prepared must still be observed, or
    the scope would silently become empty and — via the fail-closed branch —
    turn every guarded read into a refusal on a legacy ledger."""

    ledger = SqliteLedger(tmp_path / "warm.db")
    inner = SqliteLedger.executions.__wrapped__
    for _ in range(5):
        inner(ledger)  # warm the cache with NO authorizer installed
    seen: set[str] = set()

    def observe(action, first, second, database, trigger):
        if action == sqlite3.SQLITE_READ and first:
            seen.add(first)
        return sqlite3.SQLITE_OK

    ledger._conn.set_authorizer(observe)
    try:
        inner(ledger)
    finally:
        ledger._conn.set_authorizer(None)
    assert seen == {EXECUTION_TABLE}
    ledger.close()


def test_a_guarded_read_leaves_the_connection_usable(tmp_path):
    """Clearing the authorizer must not deny everything afterwards.

    Measured across this repository's three supported interpreters:
    ``set_authorizer(None)`` removes the callback on 3.11 and 3.12 and, on
    3.10, installs one returning ``None`` — which SQLite reads as DENY, so the
    next statement raises ``sqlite3.DatabaseError: not authorized``. The 3.10
    matrix job caught it while 3.11 and 3.12 were green through all 51 steps,
    which is the whole reason the matrix has three versions. This runs on all
    three.
    """

    ledger = SqliteLedger(tmp_path / "usable.db")
    assert ledger.executions() == []          # a guarded read installs and clears
    ledger.record_execution(                  # a WRITE on the same connection
        subject_id="s", source="human", executed=True, refused=False,
        sandbox_name="namespace", exit_status=0, detail="after the guarded read",
        created_at="2026-09-16T00:00:00Z",
    )
    assert len(ledger.executions()) == 1      # and a second guarded read
    assert ledger.verify_chain().ok           # and an unguarded diagnostic
    ledger.close()


# ---------------------------------------------------------------------------
# A corrupted ledger must be DIAGNOSABLE, not a crash (reported on #123)
# ---------------------------------------------------------------------------


def _corrupt_a_json_column(ledger: SqliteLedger) -> None:
    """One row's JSON column is no longer JSON — a corrupted or tampered file."""

    ledger.record_pending_action(
        subject_id="s", risk_class="low", reason="r", verdict="pass",
        confidence=0.9, action={"kind": "noop"}, judgment={"verdict": "pass"},
        created_at="2026-09-16T00:00:00Z",
    )
    ledger._conn.execute(f"UPDATE {HOLD_TABLE} SET action = ?", ("{not json",))
    ledger._conn.commit()


def test_a_malformed_row_does_not_crash_the_chain_verifier(tmp_path):
    """The verdict is the product. ``verify_chain`` walks ``audit_chain`` and
    nothing else, so a malformed column in an unrelated table cannot reach it.

    Before the fix this raised ``json.JSONDecodeError`` out of ``verify_chain``:
    the snapshot it borrowed decoded ``pending_actions`` and ``executions`` too,
    and the surrounding ``sqlite3.DatabaseError`` handler does not catch that.
    """

    ledger = SqliteLedger(tmp_path / "corrupt.db")
    _corrupt_a_json_column(ledger)
    assert ledger.verify_chain().status == "valid"
    ledger.close()


def test_a_malformed_row_makes_the_file_verifier_report_not_verifiable(tmp_path):
    """``verify_ledger_file`` is the documented programmatic entry point and the
    one the CLI audit uses. On a ledger it cannot read it must say so."""

    from prometheus_protocol.ledger.sqlite_ledger import verify_ledger_file

    ledger = SqliteLedger(tmp_path / "corrupt.db")
    _corrupt_a_json_column(ledger)
    ledger.close()
    verdict = verify_ledger_file(tmp_path / "corrupt.db")
    assert verdict.status == NOT_VERIFIABLE
    assert verdict.ok is False, "couldn't-read has never been ok and is not now"


def _reader_names() -> list[str]:
    """EVERY guarded reader, derived, because "every" is a membership.

    A hand-listed five was the first shape of this parametrisation and it was
    wrong on its own terms: it named readers rather than enumerating them, so a
    reader added later would have been covered by the sentence and not by the
    proof. ``reader_methods`` is the same derivation the authorizer-scope pin
    above uses, so the two cannot disagree about what a reader is.
    """

    from prometheus_protocol.ledger.readers import reader_methods

    return sorted(reader_methods(SqliteLedger))


@pytest.mark.parametrize("reader", _reader_names())
def test_every_guarded_reader_refuses_an_undecodable_row_in_the_typed_vocabulary(
    tmp_path, reader
):
    """Not a raw decoder error. The guard exists to refuse in a closed
    vocabulary, and both decoding points are covered — the reader's own
    projection and the snapshot, which decodes all three tables whatever the
    reader touched, so a reader of an unrelated table refuses too."""

    arguments = {"pending_id": 1, "threshold": 0.5, "workflow_id": "w"}
    ledger = SqliteLedger(tmp_path / "corrupt.db")
    _corrupt_a_json_column(ledger)
    descriptor = inspect.getattr_static(SqliteLedger, reader)
    function = descriptor.fget if isinstance(descriptor, property) else descriptor
    inner = getattr(function, "__wrapped__", function)
    assert inner is not function, f"{reader} is not wrapped by the read guard"
    supplied = {
        parameter: arguments[parameter]
        for parameter, spec in inspect.signature(inner).parameters.items()
        if parameter != "self" and spec.default is inspect.Parameter.empty
    }
    with pytest.raises(ExecutionNotAuthorized) as refused:
        getattr(ledger, reader)(**supplied)
    assert refused.value.reason == "ledger_rows_unreadable"
    assert refused.value.reason in EXECUTION_REFUSAL_REASONS
    ledger.close()


def test_the_undecodable_verdict_is_not_checked_rather_than_clean(tmp_path):
    """``checked=False`` is the couldn't-check state, and it is never ``ok``.
    Reporting no findings would read downstream as a clean ledger."""

    ledger = SqliteLedger(tmp_path / "corrupt.db")
    _corrupt_a_json_column(ledger)
    verification = verify_receipts(ledger)
    assert verification.checked is False
    assert verification.findings == ()
    assert verification.ok is False, "no findings is not the same as clean"
    assert verification.status == NOT_VERIFIABLE
    ledger.close()


def test_a_readable_ledger_still_verifies_and_reads(tmp_path):
    """The positive control for this section: without the corruption the same
    calls return their ordinary answers, so the refusals above are caused by the
    malformed column and not by the guard refusing everything."""

    from prometheus_protocol.ledger.sqlite_ledger import verify_ledger_file

    ledger = SqliteLedger(tmp_path / "clean.db")
    ledger.record_pending_action(
        subject_id="s", risk_class="low", reason="r", verdict="pass",
        confidence=0.9, action={"kind": "noop"}, judgment={"verdict": "pass"},
        created_at="2026-09-16T00:00:00Z",
    )
    assert ledger.verify_chain().status == "valid"
    assert len(ledger.pending_actions()) == 1
    assert verify_receipts(ledger).checked is True
    ledger.close()
    assert verify_ledger_file(tmp_path / "clean.db").ok is True
