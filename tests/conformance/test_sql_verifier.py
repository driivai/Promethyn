"""Conformance: the SQL domain verifier and the full loop closing in SQL.

The first non-code domain. The verifier's verdict semantics mirror the code
HARD verifier's fault attribution exactly; the loop-closure tests prove the
same chain — propose, verify, judge, gate, halt-if-unsure, execute, record —
runs in the new domain with nothing forked. Needs the isolation runtime
(skips without, FAILs under PROM_REQUIRE_SANDBOX=1).
"""

from __future__ import annotations

import os

import pytest

from prometheus_protocol.core.models import Tier, Verdict
from prometheus_protocol.gate.promotion import (
    OUTCOME_APPROVE,
    OUTCOME_BLOCK,
    OUTCOME_ROUTE,
)
from prometheus_protocol.sandbox import NamespaceSandbox
from prometheus_protocol.sandbox.unsafe import NullSandbox
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.sql import SqlTask, SqlVerifier
from prometheus_protocol.benchmarks.sql_items import run_reliability
from prometheus_protocol.benchmarks.sql_loop_demo import run_loop

_REQUIRE = (os.environ.get("PROM_REQUIRE_SANDBOX", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}

_TASK = SqlTask(
    id="sql/conf",
    prompt="Each city's total order value.",
    schema_sql="CREATE TABLE o (city TEXT, total REAL);",
    fixture_sql="INSERT INTO o VALUES ('a', 1.5), ('a', 2.5), ('b', 4.0), (NULL, 3.0);",
    reference_query="SELECT city, SUM(total) FROM o GROUP BY city",
)
_ORDERED_TASK = SqlTask(
    id="sql/conf-ordered",
    prompt="Cities by total, descending.",
    schema_sql=_TASK.schema_sql,
    fixture_sql=_TASK.fixture_sql,
    reference_query=(
        "SELECT city, SUM(total) AS s FROM o "
        "WHERE city IS NOT NULL GROUP BY city ORDER BY s DESC"
    ),
    ordered=True,
)


def _require_runtime() -> None:
    if not NamespaceSandbox.available():
        reason = "namespace isolation runtime (unprivileged user namespaces) unavailable"
        if _REQUIRE:
            pytest.fail(f"PROM_REQUIRE_SANDBOX=1 but {reason}")
        pytest.skip(reason)


# -- verdict semantics mirror the code HARD verifier --------------------------


def test_matching_results_pass_and_differing_results_fail():
    _require_runtime()
    verifier = SqlVerifier()
    good = verifier.verify(
        code="SELECT city, SUM(total) AS t FROM o GROUP BY city", task=_TASK
    )
    assert good.verdict == Verdict.PASS and good.tier == Tier.HARD
    bad = verifier.verify(
        code="SELECT city, COUNT(total) FROM o GROUP BY city", task=_TASK
    )
    assert bad.verdict == Verdict.FAIL


def test_query_error_on_valid_schema_is_the_candidates_fail():
    _require_runtime()
    evidence = SqlVerifier().verify(code="SELECT missing FROM o", task=_TASK)
    assert evidence.verdict == Verdict.FAIL
    assert "errored" in evidence.detail


def test_sandbox_fault_is_abstain_not_a_verdict():
    evidence = SqlVerifier(sandbox=NullSandbox()).verify(
        code="SELECT 1", task=_TASK
    )
    assert evidence.verdict == Verdict.ABSTAIN
    assert "sandbox did not start" in evidence.detail


def test_unsound_reference_is_abstain_never_pinned_on_the_candidate():
    _require_runtime()
    broken = SqlTask(
        id="sql/broken", prompt="x", schema_sql=_TASK.schema_sql,
        fixture_sql=_TASK.fixture_sql, reference_query="SELECT nope FROM o",
    )
    evidence = SqlVerifier().verify(code="SELECT city FROM o", task=broken)
    assert evidence.verdict == Verdict.ABSTAIN
    assert "reference query failed" in evidence.detail


def test_runaway_candidate_query_abstains_via_the_wall_clock():
    _require_runtime()
    verifier = SqlVerifier(timeout_s=3.0)
    evidence = verifier.verify(
        code=(
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) "
            "SELECT COUNT(*) FROM c"
        ),
        task=_TASK,
    )
    assert evidence.verdict == Verdict.ABSTAIN
    assert evidence.timed_out


def test_ordered_task_enforces_order_and_unordered_does_not():
    _require_runtime()
    verifier = SqlVerifier()
    reordered = (
        "SELECT city, SUM(total) AS s FROM o "
        "WHERE city IS NOT NULL GROUP BY city ORDER BY s ASC"
    )
    assert verifier.verify(code=reordered, task=_ORDERED_TASK).verdict == Verdict.FAIL
    assert verifier.verify(code=reordered, task=_TASK).verdict == Verdict.FAIL  # rows differ (filter)
    unordered_ok = (
        "SELECT city, SUM(total) FROM o GROUP BY city ORDER BY city DESC"
    )
    assert verifier.verify(code=unordered_ok, task=_TASK).verdict == Verdict.PASS


# -- the measured reliability of the whole task set ---------------------------


def test_task_set_reliability_is_clean():
    _require_runtime()
    summary = run_reliability(out=lambda line: None)
    assert summary["tasks"] == 32
    assert not summary["abstains"]
    assert not summary["self_fail"]
    assert not summary["deviations"]
    assert summary["wrong_fail"] == summary["wrong_total"] == 37
    assert summary["correct_pass"] == summary["correct_total"] == 2


# -- the loop closes in the new domain ----------------------------------------


def test_full_loop_closes_in_the_sql_domain():
    _require_runtime()
    summary = run_loop(out=lambda line: None)
    assert summary["sql/03-paid-revenue"] == OUTCOME_APPROVE
    assert summary["sql/04-customers-with-orders"] == OUTCOME_BLOCK
    assert summary["sql/05-customers-without-orders"] == OUTCOME_ROUTE
    assert summary["executed"] == 2 and summary["blocked"] == 1
    assert len(summary["decisions"]) == 1
    assert summary["decisions"][0]["decided_by"] == "demo-operator"


def test_abstaining_sql_evidence_never_authorizes(monkeypatch):
    _require_runtime()
    # An ABSTAIN is not authoritative: the bank's judgment cannot pass the
    # gate, so a verification the harness could not run never executes.
    evidence = SqlVerifier(sandbox=NullSandbox()).verify(code="SELECT 1", task=_TASK)
    bank = VerifierBank()
    bank.register(SqlVerifier.VERIFIER_ID, Tier.HARD)
    judgment = bank.judge([evidence])
    assert not judgment.authoritative
    from prometheus_protocol.gate.authorization import ActionGate

    decision = ActionGate(escalate_below=0.75, route_high_risk=True).decide(
        judgment, risk_class="medium", subject_id="sql/abstain"
    )
    assert decision.outcome == OUTCOME_BLOCK and not decision.approved
