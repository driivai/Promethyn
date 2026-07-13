"""The first non-code domain verifier: SQL result equivalence.

A candidate SQL query is correct iff, executed against a known fixture
database, it returns a result set equivalent to the one the authoritative
reference query returns. Ground truth is therefore *executed*, never
hand-labelled: the reference query runs through exactly the same sandboxed
path as the candidate, every time.

This is a HARD-tier verifier — the SQL analogue of the subprocess code
verifier, not a soft model judge. It emits the same tier-tagged
:class:`Evidence` the bank consumes, with the same fault attribution:

* **PASS** — the candidate's result set is equivalent to the reference's;
* **FAIL** — the results differ, or the candidate query errors on the valid
  fixture schema (its own fault, like a candidate crash in the code domain);
* **ABSTAIN** — a genuine "no opinion after running": the *reference* query
  itself failed, so the task is unsound (a broken task is never pinned on the
  candidate), or the candidate started and then ran past the wall clock. An
  ABSTAIN feeds no calibration;
* **Unavailable** (a non-verdict, not an abstention) — the check could **not**
  execute: the sandbox did not start, a timeout before the run was confirmed to
  start, the fixture could not be built, or the reference could not be run at
  all. An authoritative check that could not execute must never silently degrade
  into an abstention, so this is a distinct type carrying no ``verdict``.

Comparison semantics (deliberate, documented, and enforced by tests):

* **order-independent multiset equality by default** — row order is not part
  of SQL semantics unless asked for; duplicates DO count (a bag, not a set);
* **ordered equality when the task says so** (``ordered=True``, for asks that
  specify ORDER BY) — same rows in a different order then FAIL;
* **column names are ignored; column count and position are enforced** — a
  projection's aliases vary legitimately, its arity and order do not;
* **NULLs compare positionally as values** (SQL's NULL != NULL applies inside
  queries, not to grading their outputs); numeric values compare with a 1e-9
  tolerance so an arithmetically equal float path is not punished.

Honest limit, inherited from execution-based verification generally: a wrong
query that happens to return the right rows on this fixture is
indistinguishable from a right one — exactly as a wrong function that passes
every hidden test is in the code domain. Fixtures are built to make that
coincidence hard, and the limit is documented rather than papered over.

Untrusted queries are contained exactly like untrusted code: the runner
executes ONE statement against an in-memory database inside the sandbox
(network denied, filesystem read-only outside the workspace, resources
bounded). A destructive statement can vandalise only its own throwaway copy.
"""

from __future__ import annotations

import json
import math
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from prometheus_protocol.core.models import (
    SPLIT_TRAIN,
    SPLITS,
    Evidence,
    Tier,
    Unavailability,
    Unavailable,
    Verdict,
)
from prometheus_protocol.sandbox import Limits, Sandbox, build_sandbox

_RESULT_FILE = "result.json"
_RUNNER_FILE = "_sql_runner.py"

# The in-sandbox runner: builds the fixture database in memory, executes ONE
# statement, and writes the result (or a classified error) to a file kept off
# stdout so query output cannot be forged by prints.
_RUNNER_TEMPLATE = '''\
import json
import sqlite3

SCHEMA = {schema!r}
FIXTURE = {fixture!r}
QUERY = {query!r}
RESULT_PATH = {result!r}


def _write(payload):
    with open(RESULT_PATH, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)


def _jsonable(value):
    if isinstance(value, bytes):
        return "0x" + value.hex()
    return value


def main():
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(SCHEMA)
        if FIXTURE.strip():
            conn.executescript(FIXTURE)
    except sqlite3.Error as exc:
        _write({{"setup_error": str(exc)}})
        return
    try:
        cursor = conn.execute(QUERY)
        columns = [d[0] for d in cursor.description] if cursor.description else []
        rows = [[_jsonable(v) for v in row] for row in cursor.fetchall()]
    except sqlite3.Error as exc:
        _write({{"query_error": str(exc)}})
        return
    _write({{"columns": columns, "rows": rows}})


main()
'''


@dataclass(frozen=True)
class SqlTask:
    """A SQL-domain unit of work.

    The code-domain :class:`Task` is code-shaped (entry point, hidden cases),
    so the SQL domain carries its own task type; what stays domain-general is
    the verifier's *output* — tier-tagged Evidence — which is all the bank
    ever consumes. ``prompt`` is the natural-language ask (the only field a
    proposer may see); the schema, fixture data, and reference query are
    evaluation-side ground truth. ``ordered`` marks asks whose answer is a
    sequence (they specify an ordering), switching the comparator to ordered
    equality.

    ``split`` mirrors the code-domain :class:`Task` partition exactly and with
    the same meaning: ``train`` tasks are what the forge may learn from;
    ``heldout`` tasks exist only for the promotion gate's firewalled
    generalisation check and must never be visible to a proposer's learning.
    The value is validated like the code domain's. ``cluster`` is the optional
    failure-concept label the forge groups training failures by.
    """

    id: str
    prompt: str
    schema_sql: str
    fixture_sql: str
    reference_query: str
    split: str = SPLIT_TRAIN
    ordered: bool = False
    cluster: str | None = None

    def __post_init__(self) -> None:
        if self.split not in SPLITS:
            raise ValueError(
                f"task {self.id!r} has unknown split {self.split!r}; "
                f"expected one of {SPLITS}"
            )


# --------------------------------------------------------------------------
# the comparator (pure; the leak surface, so it is unit-tested adversarially)
# --------------------------------------------------------------------------


def _type_rank(value) -> int:
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return 1
    if isinstance(value, str):
        return 2
    return 3


def _sort_canon(value):
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return round(float(value), 9)
    if isinstance(value, str):
        return value
    return repr(value)


def _row_key(row) -> tuple:
    return tuple((_type_rank(v), _sort_canon(v)) for v in row)


def _value_equal(a, b) -> bool:
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-9)
    return a == b


def _row_equal(a, b) -> bool:
    return len(a) == len(b) and all(_value_equal(x, y) for x, y in zip(a, b))


def results_equivalent(
    reference: dict, candidate: dict, *, ordered: bool = False
) -> tuple[bool, str]:
    """Whether two result payloads are equivalent under the task's semantics.

    Column names are ignored; column count is enforced. Rows compare as an
    order-independent multiset by default, or as an exact sequence when
    ``ordered`` is set. Returns (equivalent, reason).
    """

    ref_cols = reference.get("columns", [])
    cand_cols = candidate.get("columns", [])
    if len(ref_cols) != len(cand_cols):
        return False, (
            f"column count differs: expected {len(ref_cols)}, got {len(cand_cols)}"
        )
    ref_rows = reference.get("rows", [])
    cand_rows = candidate.get("rows", [])
    if len(ref_rows) != len(cand_rows):
        return False, (
            f"row count differs: expected {len(ref_rows)}, got {len(cand_rows)}"
        )
    if ordered:
        ref_seq, cand_seq = ref_rows, cand_rows
    else:
        ref_seq = sorted(ref_rows, key=_row_key)
        cand_seq = sorted(cand_rows, key=_row_key)
    for index, (ref_row, cand_row) in enumerate(zip(ref_seq, cand_seq)):
        if not _row_equal(ref_row, cand_row):
            mode = "ordered row" if ordered else "row (order-independent)"
            return False, (
                f"{mode} {index} differs: expected {ref_row!r}, got {cand_row!r}"
            )
    mode = "ordered" if ordered else "order-independent multiset"
    return True, f"result sets equivalent ({mode})"


# --------------------------------------------------------------------------
# the verifier
# --------------------------------------------------------------------------


class SqlVerifier:
    """HARD-tier SQL verifier: sandboxed execution + result equivalence."""

    VERIFIER_ID = "sql-result-equivalence"
    TIER = Tier.HARD

    def __init__(self, *, sandbox: Sandbox | None = None, timeout_s: float = 10.0) -> None:
        self.sandbox = sandbox if sandbox is not None else build_sandbox()
        self.timeout_s = timeout_s
        self.verifier_id = self.VERIFIER_ID
        self.tier = self.TIER

    def _limits(self) -> Limits:
        return Limits(
            wall_time_s=self.timeout_s,
            cpu_time_s=int(self.timeout_s),
            memory_bytes=0,
            max_processes=16,
        )

    def _execute(self, task: SqlTask, query: str):
        """Run one query in the sandbox; return (payload | None, SandboxResult)."""

        with tempfile.TemporaryDirectory(prefix="prom-sql-") as tmp:
            tmp_path = Path(tmp)
            result_path = tmp_path / _RESULT_FILE
            runner = _RUNNER_TEMPLATE.format(
                schema=task.schema_sql,
                fixture=task.fixture_sql,
                query=query,
                result=str(result_path),
            )
            (tmp_path / _RUNNER_FILE).write_text(runner, encoding="utf-8")
            run = self.sandbox.run(
                argv=[sys.executable, "-I", _RUNNER_FILE],
                workspace=tmp,
                limits=self._limits(),
            )
            try:
                payload = json.loads(result_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                payload = None
        return payload, run

    def _evidence(
        self, verdict: Verdict, *, detail: str, duration_s: float, run=None
    ) -> Evidence:
        return Evidence(
            passed=(verdict == Verdict.PASS),
            total=1,
            passed_count=1 if verdict == Verdict.PASS else 0,
            failures=() if verdict == Verdict.PASS else (detail,),
            stdout=(run.stdout if run is not None else ""),
            stderr=(run.stderr if run is not None else ""),
            duration_s=duration_s,
            timed_out=bool(run.timed_out) if run is not None else False,
            verifier_id=self.verifier_id,
            verdict=verdict,
            tier=self.tier,
            cost=duration_s,
            latency_ms=duration_s * 1000.0,
            detail=detail[:1000],
        )

    def _unavailable(self, *, reason: Unavailability, detail: str) -> Unavailable:
        """A could-not-execute outcome — a non-verdict this HARD check emits when
        it could not run the check at all (see the module docstring)."""

        return Unavailable(
            verifier_id=self.verifier_id, tier=self.tier, reason=reason, detail=detail[:1000]
        )

    def verify(self, *, code: str, task: SqlTask) -> Evidence | Unavailable:
        started = time.monotonic()

        def done(verdict: Verdict, detail: str, run=None) -> Evidence:
            return self._evidence(
                verdict, detail=detail, duration_s=time.monotonic() - started, run=run
            )

        def unavailable(reason: Unavailability, detail: str) -> Unavailable:
            return self._unavailable(reason=reason, detail=detail)

        # Ground truth first: the reference must run cleanly, every time. A
        # task whose reference fails is a harness/task fault — never a verdict.
        ref_payload, ref_run = self._execute(task, task.reference_query)
        if not ref_run.started_ok:
            # Isolation could not start: could-not-execute, never an abstention.
            return unavailable(
                Unavailability.POLICY_REFUSAL
                if ref_run.policy_refusal
                else Unavailability.INFRA_FAULT,
                f"sandbox did not start: {ref_run.detail}",
            )
        if ref_run.timed_out:
            # The reference could not be run to completion, so we have no ground
            # truth to judge against: could-not-execute (infra), not an abstention.
            return unavailable(
                Unavailability.INFRA_FAULT, "reference query timed out; could not verify"
            )
        if ref_payload is None:
            return unavailable(
                Unavailability.INFRA_FAULT, "reference produced no result; harness fault"
            )
        if "setup_error" in ref_payload or "query_error" in ref_payload:
            # The reference SANDBOX ran fine and the reference QUERY errored: the
            # task itself is unsound. This is a genuine "ran, and there is nothing
            # sound to check" — ABSTAIN (category C), unchanged.
            reason = ref_payload.get("setup_error") or ref_payload.get("query_error")
            return done(
                Verdict.ABSTAIN, f"reference query failed ({reason}); task is unsound"
            )

        cand_payload, cand_run = self._execute(task, code)
        if not cand_run.started_ok:
            return unavailable(
                Unavailability.POLICY_REFUSAL
                if cand_run.policy_refusal
                else Unavailability.INFRA_FAULT,
                f"sandbox did not start: {cand_run.detail}",
            )
        if cand_run.timed_out:
            if cand_run.candidate_started:
                # The candidate started and then ran past the wall clock: its own
                # hang. Unchanged "no opinion after running" (ABSTAIN), not
                # could-not-execute.
                return done(
                    Verdict.ABSTAIN,
                    f"candidate query timed out after {self.timeout_s}s; could not verify",
                    cand_run,
                )
            # Timed out before the candidate was confirmed to start: a harness
            # fault, could-not-execute.
            return unavailable(
                Unavailability.INFRA_FAULT,
                f"timed out after {self.timeout_s}s before the candidate was "
                "confirmed to start",
            )
        if cand_payload is None:
            # The runner always writes unless the candidate's own resource use
            # killed it. Mirror the code domain's fault attribution: a confirmed
            # start with no result is the candidate's own crash.
            if cand_run.candidate_started:
                return done(
                    Verdict.FAIL,
                    "candidate run produced no result "
                    f"(exit {cand_run.exit_status}); treated as the candidate's crash",
                    cand_run,
                )
            return unavailable(
                Unavailability.INFRA_FAULT,
                "no result and the run was not confirmed to start; harness fault",
            )
        if "setup_error" in cand_payload:
            # The fixture already built cleanly for the reference above, so a
            # candidate-side setup failure is a transient/infra fault, not the
            # candidate's and not task-unsoundness: could-not-execute.
            return unavailable(
                Unavailability.INFRA_FAULT,
                f"fixture setup failed ({cand_payload['setup_error']}); harness fault",
            )
        if "query_error" in cand_payload:
            return done(
                Verdict.FAIL,
                f"candidate query errored on the fixture schema: "
                f"{cand_payload['query_error']}",
                cand_run,
            )

        equivalent, why = results_equivalent(
            ref_payload, cand_payload, ordered=task.ordered
        )
        return done(Verdict.PASS if equivalent else Verdict.FAIL, why, cand_run)
