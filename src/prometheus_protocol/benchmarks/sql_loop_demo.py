"""The full Promethyn loop closing in the SQL domain, end to end.

Three beats, all through the REAL chain — the same frozen offline model
proposing, the new HARD SQL verifier verifying, the same bank fusing, the same
gate authorizing, the same controller/executor/ledger executing and recording.
Nothing is forked for the domain; only the verifier (and its task type) is new.

1. A correct proposal verifies PASS, the bank judges it authoritative at high
   confidence, the gate approves, and the query executes inside the sandbox
   with the run recorded in the ledger.
2. A plausible-but-wrong proposal (a missing join condition — cartesian bloat)
   verifies FAIL and the gate BLOCKS it: a human is never asked to
   rubber-stamp a failure, and nothing executes.
3. A correct proposal on a HIGH-RISK ask (exporting customer identities) is
   ROUTED to a human despite passing verification (INV-EXEC-3 in the new
   domain); the operator approves, execution happens through the same
   at-most-once approval path, and the audit query shows the decision.

Run: python -m prometheus_protocol.benchmarks.sql_loop_demo
"""

from __future__ import annotations

import argparse
from typing import Callable, Sequence

from prometheus_protocol.core.models import (
    ACTION_PYTHON_CODE,
    ExecutableAction,
    Tier,
    Verdict,
)
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.executor import SandboxExecutor
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.gate.promotion import OUTCOME_APPROVE, OUTCOME_BLOCK, OUTCOME_ROUTE
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.provider.mock import MockProvider
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.sql import SqlTask, SqlVerifier
from prometheus_protocol.benchmarks.sql_items import build_sql_tasks

#: The frozen model's scripted proposals, keyed by task id found in the prompt.
#: Beat 2's proposal is deliberately the classic missing-join-condition bug.
_SCRIPTED_PROPOSALS = {
    "sql/03-paid-revenue": "SELECT SUM(total) FROM orders WHERE status = 'paid'",
    "sql/04-customers-with-orders": "SELECT DISTINCT c.name FROM customers c, orders o",
    "sql/05-customers-without-orders": (
        "SELECT c.name FROM customers c "
        "LEFT JOIN orders o ON o.customer_id = c.id WHERE o.id IS NULL"
    ),
}


def demo_provider() -> MockProvider:
    def responder(prompt: str, system: str | None) -> str:
        for task_id, query in _SCRIPTED_PROPOSALS.items():
            if task_id in prompt:
                return query
        return ""

    return MockProvider(responder=responder)


def _action_for(task: SqlTask, query: str) -> ExecutableAction:
    """The approved query as an in-sandbox action: run it, print the rows.

    Self-contained (schema + fixture + query embedded), so the existing
    python-code executor runs it unchanged in its own sandbox workspace.
    """

    code = (
        "import sqlite3\n"
        f"conn = sqlite3.connect(':memory:')\n"
        f"conn.executescript({task.schema_sql!r})\n"
        f"conn.executescript({task.fixture_sql!r})\n"
        f"for row in conn.execute({query!r}).fetchall():\n"
        "    print(row)\n"
    )
    return ExecutableAction(kind=ACTION_PYTHON_CODE, code=code)


def run_loop(*, out: Callable[[str], None] = print) -> dict:
    tasks = {t.id: t for t in build_sql_tasks()}
    provider = demo_provider()
    verifier = SqlVerifier()
    bank = VerifierBank()
    bank.register(verifier.verifier_id, Tier.HARD)
    ledger = SqliteLedger(":memory:")
    controller = ExecutionController(
        gate=ActionGate(escalate_below=0.75, route_high_risk=True),
        executor=SandboxExecutor(),
        ledger=ledger,
    )
    summary: dict = {}

    def beat(task_id: str, *, risk_class: str) -> None:
        task = tasks[task_id]
        proposal = provider.generate(
            prompt=f"[{task.id}] {task.prompt} Reply with one SQL query.",
            system="You write SQL.",
        )
        out(f"[loop] {task.id} ({risk_class} risk)")
        out(f"[loop]   proposed : {proposal}")
        evidence = verifier.verify(code=proposal, task=task)
        out(f"[loop]   verified : {evidence.verdict.value.upper()} — {evidence.detail}")
        judgment = bank.judge([evidence])
        out(f"[loop]   judged   : {judgment.verdict.value} "
            f"(confidence {judgment.confidence:.2f}, "
            f"authoritative={judgment.authoritative})")
        outcome = controller.submit(
            judgment=judgment,
            action=_action_for(task, proposal),
            risk_class=risk_class,
            subject_id=task.id,
        )
        if outcome.outcome == OUTCOME_APPROVE:
            out(f"[loop]   gate     : APPROVED -> executed in sandbox "
                f"{outcome.execution.sandbox_name!r} "
                f"(exit {outcome.execution.exit_status})")
            out(f"[loop]   output   : {outcome.execution.stdout.strip()!r}")
        elif outcome.outcome == OUTCOME_ROUTE:
            out(f"[loop]   gate     : ROUTED to a human (pending #{outcome.pending.id}) "
                f"— {outcome.decision.reason}")
            result = controller.approve(
                outcome.pending.id, identity="demo-operator",
                reason="export reviewed and accepted",
            )
            out(f"[loop]   human    : APPROVED by demo-operator -> executed "
                f"(exit {result.exit_status})")
            out(f"[loop]   output   : {result.stdout.strip()!r}")
        else:
            out(f"[loop]   gate     : BLOCKED — {outcome.decision.reason}")
            out("[loop]   executed : never (blocked actions cannot execute)")
        summary[task_id] = outcome.outcome

    out("=== beat 1: correct proposal, ordinary risk ===")
    beat("sql/03-paid-revenue", risk_class="medium")
    out("")
    out("=== beat 2: plausible-but-wrong proposal (cartesian join) ===")
    beat("sql/04-customers-with-orders", risk_class="medium")
    out("")
    out("=== beat 3: correct proposal, HIGH-RISK ask (identity export) ===")
    beat("sql/05-customers-without-orders", risk_class="high")
    out("")
    out("=== audit (from the ledger, not from memory) ===")
    for row in ledger.human_decisions():
        out(f"[audit] hold #{row['id']} {row['subject_id']}: {row['status']} "
            f"by {row['decided_by']} ({row['decision_reason']})")
    executed = [r for r in ledger.executions() if r["executed"]]
    blocked = [r for r in ledger.executions() if r["source"] == "blocked"]
    out(f"[audit] executions recorded: {len(ledger.executions())} "
        f"(executed {len(executed)}, blocked {len(blocked)})")
    summary["executed"] = len(executed)
    summary["blocked"] = len(blocked)
    summary["decisions"] = ledger.human_decisions()
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    argparse.ArgumentParser(
        prog="python -m prometheus_protocol.benchmarks.sql_loop_demo",
        description="Close the propose-verify-gate-execute-record loop in SQL.",
    ).parse_args(argv)
    summary = run_loop()
    ok = (
        summary.get("sql/03-paid-revenue") == OUTCOME_APPROVE
        and summary.get("sql/04-customers-with-orders") == OUTCOME_BLOCK
        and summary.get("sql/05-customers-without-orders") == OUTCOME_ROUTE
        and summary.get("executed") == 2
        and summary.get("blocked") == 1
    )
    print("")
    print("[demo] loop closed cleanly in the SQL domain"
          if ok else "[demo] UNEXPECTED loop shape — inspect the beats above")
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover - exercised via main() in tests
    raise SystemExit(main())
