"""The authoritative SQL task set, and the verifier reliability measurement.

Thirty-two tasks over three small schemas. Each task is a natural-language ask
plus an authoritative reference query; ground truth is only ever produced by
EXECUTING the reference in the sandbox (the verifier does this on every
verification — nothing is hand-labelled). Tasks are chosen so plausible-but-
wrong queries exist: missing join conditions (cartesian bloat), wrong
aggregates, HAVING/WHERE boundary mistakes, NULL-handling errors (``= NULL``,
COALESCE-vs-ignore, all-NULL groups), missing DISTINCT, LIMIT off-by-one,
duplicate-vs-distinct ranking, and ordered asks where direction matters.

Each task also carries designed PROBES — correct variants and designed-wrong
queries — used by the reliability run (``python -m
prometheus_protocol.benchmarks.sql_items``): every reference must self-verify
PASS, every correct variant must PASS, and every designed-wrong probe must
FAIL. A designed-wrong probe that PASSes is a comparator leak or a fixture
coincidence and fails the run loudly. This is the execution verifier's
measured false-PASS on designed-wrong inputs; the residual limit — a wrong
query returning coincidentally right rows on this fixture — is documented, not
hidden (it is the same bound hidden tests have in the code domain).
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from typing import Sequence

from prometheus_protocol.core.models import Verdict
from prometheus_protocol.verifier.sql import SqlTask, SqlVerifier

SQL_TASK_SET_VERSION = "sql-v1 (32 tasks)"

_SHOP_SCHEMA = """
CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT NOT NULL, city TEXT);
CREATE TABLE orders (
  id INTEGER PRIMARY KEY, customer_id INTEGER NOT NULL,
  total REAL NOT NULL, status TEXT NOT NULL, created_day INTEGER NOT NULL);
CREATE TABLE order_items (
  order_id INTEGER NOT NULL, product TEXT NOT NULL,
  qty INTEGER NOT NULL, price REAL NOT NULL);
"""

_SHOP_FIXTURE = """
INSERT INTO customers VALUES
  (1, 'Ada', 'Riga'), (2, 'Brik', 'Oslo'), (3, 'Cato', 'Riga'),
  (4, 'Dena', NULL), (5, 'Eryn', 'Bern'), (6, 'Falk', 'Oslo');
-- Falk (6) has no orders; Ada and Brik have several.
INSERT INTO orders VALUES
  (101, 1, 40.0, 'paid', 3), (102, 1, 15.5, 'refunded', 5),
  (103, 2, 22.0, 'paid', 7), (104, 2, 60.0, 'paid', 10),
  (105, 3, 10.0, 'pending', 10), (106, 4, 35.0, 'paid', 12),
  (107, 5, 18.0, 'refunded', 14), (108, 1, 55.0, 'paid', 15),
  (109, 3, 27.5, 'paid', 16);
INSERT INTO order_items VALUES
  (101, 'lamp', 2, 10.0), (101, 'cord', 1, 20.0),
  (103, 'lamp', 1, 22.0), (104, 'desk', 2, 30.0),
  (105, 'cord', 1, 10.0), (106, 'lamp', 3, 5.0), (106, 'desk', 1, 20.0),
  (108, 'chair', 5, 11.0), (109, 'cord', 2, 5.0), (109, 'lamp', 1, 17.5);
"""

_HR_SCHEMA = """
CREATE TABLE departments (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE employees (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL,
  dept_id INTEGER, salary INTEGER NOT NULL, manager_id INTEGER);
"""

_HR_FIXTURE = """
INSERT INTO departments VALUES
  (1, 'Engineering'), (2, 'Sales'), (3, 'Archive');
-- Archive (3) has no employees. Salaries: avg of all is exactly 200.
-- Two employees share the top salary (320); Hana has a NULL department.
-- Id order is deliberately NOT alphabetical (Lena first, Gil last), so a
-- bare SELECT cannot coincide with an ORDER BY name ask.
INSERT INTO employees VALUES
  (1, 'Lena', 1, 320, NULL), (2, 'Hana', NULL, 200, 1),
  (3, 'Ivo',  1, 120, 1),    (4, 'Jun',  2, 320, 1),
  (5, 'Kei',  2, 80,  4),    (6, 'Gil',  1, 160, 4);
"""

_EVENTS_SCHEMA = """
CREATE TABLE events (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
  kind TEXT NOT NULL, day INTEGER NOT NULL, duration INTEGER);
"""

_EVENTS_FIXTURE = """
-- User 9's only durations are NULL; day 4 has exactly 2 events; day 5 has 3.
INSERT INTO events VALUES
  (1, 7, 'login',    1, 5),    (2, 7, 'purchase', 1, 30),
  (3, 8, 'login',    2, 4),    (4, 8, 'login',    4, 6),
  (5, 9, 'call',     4, NULL), (6, 7, 'login',    5, 7),
  (7, 8, 'purchase', 5, 45),   (8, 9, 'call',     5, NULL),
  (9, 7, 'call',     6, 12),   (10, 8, 'call',    6, 20),
  (11, 9, 'login',   6, NULL), (12, 7, 'login',   7, 3);
"""


@dataclass(frozen=True)
class SqlProbe:
    """A designed candidate for one task: a correct variant or a known-wrong."""

    query: str
    expect_pass: bool
    note: str


def _shop(task_id: str, prompt: str, ref: str, *, ordered: bool = False) -> SqlTask:
    return SqlTask(id=task_id, prompt=prompt, schema_sql=_SHOP_SCHEMA,
                   fixture_sql=_SHOP_FIXTURE, reference_query=ref, ordered=ordered)


def _hr(task_id: str, prompt: str, ref: str, *, ordered: bool = False) -> SqlTask:
    return SqlTask(id=task_id, prompt=prompt, schema_sql=_HR_SCHEMA,
                   fixture_sql=_HR_FIXTURE, reference_query=ref, ordered=ordered)


def _ev(task_id: str, prompt: str, ref: str, *, ordered: bool = False) -> SqlTask:
    return SqlTask(id=task_id, prompt=prompt, schema_sql=_EVENTS_SCHEMA,
                   fixture_sql=_EVENTS_FIXTURE, reference_query=ref, ordered=ordered)


def build_sql_tasks() -> tuple[SqlTask, ...]:
    return (
        _shop("sql/01-distinct-cities",
              "List the distinct non-NULL cities customers live in.",
              "SELECT DISTINCT city FROM customers WHERE city IS NOT NULL"),
        _shop("sql/02-orders-per-status",
              "For each order status, how many orders have it?",
              "SELECT status, COUNT(*) FROM orders GROUP BY status"),
        _shop("sql/03-paid-revenue",
              "What is the total value of paid orders?",
              "SELECT SUM(total) FROM orders WHERE status = 'paid'"),
        _shop("sql/04-customers-with-orders",
              "Names of customers who have placed at least one order (each once).",
              "SELECT DISTINCT c.name FROM customers c "
              "JOIN orders o ON o.customer_id = c.id"),
        _shop("sql/05-customers-without-orders",
              "Names of customers who have never placed an order.",
              "SELECT c.name FROM customers c "
              "LEFT JOIN orders o ON o.customer_id = c.id WHERE o.id IS NULL"),
        _shop("sql/06-top3-orders",
              "The ids and totals of the three largest orders, largest first.",
              "SELECT id, total FROM orders ORDER BY total DESC LIMIT 3",
              ordered=True),
        _shop("sql/07-avg-paid-per-city",
              "Average paid-order total per customer city (paid orders only).",
              "SELECT c.city, AVG(o.total) FROM customers c "
              "JOIN orders o ON o.customer_id = c.id "
              "WHERE o.status = 'paid' GROUP BY c.city"),
        _shop("sql/08-qty-per-product",
              "Total quantity sold per product.",
              "SELECT product, SUM(qty) FROM order_items GROUP BY product"),
        _shop("sql/09-revenue-per-order",
              "The line-item revenue (quantity times price) of each order id.",
              "SELECT order_id, SUM(qty * price) FROM order_items GROUP BY order_id"),
        _shop("sql/10-early-orders",
              "How many orders were created on day 10 or earlier?",
              "SELECT COUNT(*) FROM orders WHERE created_day <= 10"),
        _shop("sql/11-busy-statuses",
              "Which statuses appear on more than one order?",
              "SELECT status FROM orders GROUP BY status HAVING COUNT(*) > 1"),
        _shop("sql/12-order-counts-with-zero",
              "Every customer's name with their order count, including zero.",
              "SELECT c.name, COUNT(o.id) FROM customers c "
              "LEFT JOIN orders o ON o.customer_id = c.id GROUP BY c.name"),
        _hr("sql/13-above-average",
            "Names of employees earning strictly more than the overall average salary.",
            "SELECT name FROM employees "
            "WHERE salary > (SELECT AVG(salary) FROM employees)"),
        _hr("sql/14-empty-departments",
            "Names of departments with no employees.",
            "SELECT d.name FROM departments d "
            "LEFT JOIN employees e ON e.dept_id = d.id WHERE e.id IS NULL"),
        _hr("sql/15-headcount-per-department",
            "Each department name with its employee count, including empty ones.",
            "SELECT d.name, COUNT(e.id) FROM departments d "
            "LEFT JOIN employees e ON e.dept_id = d.id GROUP BY d.name"),
        _hr("sql/16-no-manager",
            "Names of employees who have no manager.",
            "SELECT name FROM employees WHERE manager_id IS NULL"),
        _hr("sql/17-max-salary-per-dept",
            "The highest salary in each department id (employees with a department only).",
            "SELECT dept_id, MAX(salary) FROM employees "
            "WHERE dept_id IS NOT NULL GROUP BY dept_id"),
        _hr("sql/18-managers",
            "Names of employees who manage at least one other employee (each once).",
            "SELECT DISTINCT m.name FROM employees m "
            "JOIN employees e ON e.manager_id = m.id"),
        _hr("sql/19-second-highest-salary",
            "The second-highest DISTINCT salary.",
            "SELECT MAX(salary) FROM employees "
            "WHERE salary < (SELECT MAX(salary) FROM employees)"),
        _hr("sql/20-engineering-payroll",
            "The total salary of the department named 'Engineering'.",
            "SELECT SUM(e.salary) FROM employees e "
            "JOIN departments d ON d.id = e.dept_id WHERE d.name = 'Engineering'"),
        _hr("sql/21-names-alphabetical",
            "All employee names in alphabetical order.",
            "SELECT name FROM employees ORDER BY name", ordered=True),
        _hr("sql/22-distinct-salaries",
            "How many distinct salary values are there?",
            "SELECT COUNT(DISTINCT salary) FROM employees"),
        _ev("sql/23-events-per-kind",
            "How many events of each kind are there?",
            "SELECT kind, COUNT(*) FROM events GROUP BY kind"),
        _ev("sql/24-duration-per-user",
            "Total recorded duration per user, for users with at least one "
            "recorded (non-missing) duration.",
            "SELECT user_id, SUM(duration) FROM events "
            "WHERE duration IS NOT NULL GROUP BY user_id"),
        _ev("sql/25-busy-days",
            "Which days had more than two events?",
            "SELECT day FROM events GROUP BY day HAVING COUNT(*) > 2"),
        _ev("sql/26-login-users",
            "The distinct users who have a 'login' event.",
            "SELECT DISTINCT user_id FROM events WHERE kind = 'login'"),
        _ev("sql/27-latest-day-per-user",
            "Each user's most recent event day.",
            "SELECT user_id, MAX(day) FROM events GROUP BY user_id"),
        _ev("sql/28-first-two-events",
            "The ids and days of the first two events, ordered by day then id.",
            "SELECT id, day FROM events ORDER BY day, id LIMIT 2", ordered=True),
        _ev("sql/29-day5-count",
            "How many events happened on day 5 exactly?",
            "SELECT COUNT(*) FROM events WHERE day = 5"),
        _ev("sql/30-both-kinds",
            "Users who have BOTH a 'login' and a 'purchase' event.",
            "SELECT user_id FROM events WHERE kind = 'login' "
            "INTERSECT SELECT user_id FROM events WHERE kind = 'purchase'"),
        _ev("sql/31-avg-call-duration",
            "The average duration of 'call' events, ignoring missing durations.",
            "SELECT AVG(duration) FROM events WHERE kind = 'call'"),
        _ev("sql/32-distinct-kind-days",
            "The distinct (kind, day) pairs that occur.",
            "SELECT DISTINCT kind, day FROM events"),
    )


#: Designed probes per task id. ``expect_pass=False`` entries are the
#: plausible-but-wrong queries the verifier must FAIL; any that PASS is a
#: comparator leak or fixture coincidence and fails the reliability run.
SQL_PROBES: dict[str, tuple[SqlProbe, ...]] = {
    "sql/01-distinct-cities": (
        SqlProbe("SELECT city FROM customers WHERE city IS NOT NULL",
                 False, "missing DISTINCT keeps duplicate cities"),
        SqlProbe("SELECT DISTINCT city FROM customers",
                 False, "keeps the NULL city"),
    ),
    "sql/02-orders-per-status": (
        SqlProbe("SELECT status, COUNT(DISTINCT customer_id) FROM orders GROUP BY status",
                 False, "counts customers, not orders"),
    ),
    "sql/03-paid-revenue": (
        SqlProbe("SELECT SUM(total) FROM orders",
                 False, "forgets the paid filter"),
        SqlProbe("SELECT ROUND(SUM(total), 6) FROM orders WHERE status = 'paid'",
                 True, "arithmetically identical variant"),
    ),
    "sql/04-customers-with-orders": (
        SqlProbe("SELECT c.name FROM customers c JOIN orders o ON o.customer_id = c.id",
                 False, "missing DISTINCT duplicates multi-order customers"),
        SqlProbe("SELECT DISTINCT c.name FROM customers c, orders o",
                 False, "missing join condition: cartesian product"),
    ),
    "sql/05-customers-without-orders": (
        SqlProbe("SELECT c.name FROM customers c "
                 "LEFT JOIN orders o ON o.customer_id = c.id WHERE o.id = NULL",
                 False, "= NULL matches nothing"),
        SqlProbe("SELECT name FROM customers WHERE id NOT IN "
                 "(SELECT customer_id FROM orders)",
                 True, "NOT IN variant (safe here: customer_id never NULL)"),
    ),
    "sql/06-top3-orders": (
        SqlProbe("SELECT id, total FROM orders ORDER BY total ASC LIMIT 3",
                 False, "wrong direction"),
        SqlProbe("SELECT id, total FROM orders ORDER BY total DESC LIMIT 4",
                 False, "LIMIT off by one"),
    ),
    "sql/07-avg-paid-per-city": (
        SqlProbe("SELECT c.city, AVG(o.total) FROM customers c "
                 "JOIN orders o ON o.customer_id = c.id GROUP BY c.city",
                 False, "forgets the paid filter"),
    ),
    "sql/08-qty-per-product": (
        SqlProbe("SELECT product, COUNT(*) FROM order_items GROUP BY product",
                 False, "counts rows instead of summing quantities"),
    ),
    "sql/09-revenue-per-order": (
        SqlProbe("SELECT order_id, SUM(price) FROM order_items GROUP BY order_id",
                 False, "ignores quantity"),
    ),
    "sql/10-early-orders": (
        SqlProbe("SELECT COUNT(*) FROM orders WHERE created_day < 10",
                 False, "boundary: drops day-10 orders"),
    ),
    "sql/11-busy-statuses": (
        SqlProbe("SELECT status FROM orders GROUP BY status HAVING COUNT(*) >= 1",
                 False, "boundary: every status qualifies"),
    ),
    "sql/12-order-counts-with-zero": (
        SqlProbe("SELECT c.name, COUNT(*) FROM customers c "
                 "LEFT JOIN orders o ON o.customer_id = c.id GROUP BY c.name",
                 False, "COUNT(*) turns the zero-order customer into 1"),
    ),
    "sql/13-above-average": (
        SqlProbe("SELECT name FROM employees "
                 "WHERE salary >= (SELECT AVG(salary) FROM employees)",
                 False, "boundary: includes the exactly-average employee"),
    ),
    "sql/14-empty-departments": (
        SqlProbe("SELECT d.name FROM departments d "
                 "JOIN employees e ON e.dept_id = d.id "
                 "GROUP BY d.name HAVING COUNT(*) = 0",
                 False, "inner join can never see an empty department"),
    ),
    "sql/15-headcount-per-department": (
        SqlProbe("SELECT d.name, COUNT(e.id) FROM departments d "
                 "JOIN employees e ON e.dept_id = d.id GROUP BY d.name",
                 False, "inner join drops the empty department"),
    ),
    "sql/16-no-manager": (
        SqlProbe("SELECT name FROM employees WHERE manager_id = NULL",
                 False, "= NULL matches nothing"),
    ),
    "sql/17-max-salary-per-dept": (
        SqlProbe("SELECT dept_id, MAX(salary) FROM employees GROUP BY dept_id",
                 False, "keeps the NULL-department group"),
    ),
    "sql/18-managers": (
        SqlProbe("SELECT m.name FROM employees m "
                 "JOIN employees e ON e.manager_id = m.id",
                 False, "missing DISTINCT duplicates multi-report managers"),
    ),
    "sql/19-second-highest-salary": (
        SqlProbe("SELECT salary FROM employees ORDER BY salary DESC LIMIT 1 OFFSET 1",
                 False, "duplicate top salary: OFFSET lands on the tie, not the "
                        "next distinct value"),
    ),
    "sql/20-engineering-payroll": (
        SqlProbe("SELECT SUM(salary) FROM employees",
                 False, "sums every department"),
    ),
    "sql/21-names-alphabetical": (
        SqlProbe("SELECT name FROM employees",
                 False, "insertion order is not alphabetical order"),
        SqlProbe("SELECT name FROM employees ORDER BY salary",
                 False, "ordered by the wrong column"),
    ),
    "sql/22-distinct-salaries": (
        SqlProbe("SELECT COUNT(salary) FROM employees",
                 False, "counts duplicates"),
    ),
    "sql/23-events-per-kind": (
        SqlProbe("SELECT kind, COUNT(DISTINCT user_id) FROM events GROUP BY kind",
                 False, "counts users, not events"),
    ),
    "sql/24-duration-per-user": (
        SqlProbe("SELECT user_id, SUM(duration) FROM events GROUP BY user_id",
                 False, "keeps the all-NULL-duration user (NULL total)"),
    ),
    "sql/25-busy-days": (
        SqlProbe("SELECT day FROM events GROUP BY day HAVING COUNT(*) >= 2",
                 False, "boundary: includes the exactly-two-event day"),
    ),
    "sql/26-login-users": (
        SqlProbe("SELECT user_id FROM events WHERE kind = 'login'",
                 False, "missing DISTINCT duplicates repeat logins"),
    ),
    "sql/27-latest-day-per-user": (
        SqlProbe("SELECT user_id, MIN(day) FROM events GROUP BY user_id",
                 False, "earliest, not latest"),
    ),
    "sql/28-first-two-events": (
        SqlProbe("SELECT id, day FROM events ORDER BY day DESC, id LIMIT 2",
                 False, "wrong direction"),
        SqlProbe("SELECT id, day FROM events ORDER BY day, id LIMIT 3",
                 False, "LIMIT off by one"),
    ),
    "sql/29-day5-count": (
        SqlProbe("SELECT COUNT(*) FROM events WHERE day BETWEEN 5 AND 6",
                 False, "BETWEEN drags in day 6"),
    ),
    "sql/30-both-kinds": (
        SqlProbe("SELECT DISTINCT user_id FROM events "
                 "WHERE kind = 'login' OR kind = 'purchase'",
                 False, "OR is either-kind, not both-kinds"),
    ),
    "sql/31-avg-call-duration": (
        SqlProbe("SELECT AVG(COALESCE(duration, 0)) FROM events WHERE kind = 'call'",
                 False, "coalescing NULL to 0 drags the average down"),
    ),
    "sql/32-distinct-kind-days": (
        SqlProbe("SELECT kind, day FROM events",
                 False, "missing DISTINCT keeps duplicate pairs"),
    ),
}


def run_reliability(*, out=print) -> dict:
    """Verify every reference (self-check) and every probe; report deviations."""

    verifier = SqlVerifier()
    tasks = build_sql_tasks()
    abstains: list[str] = []
    self_fail: list[str] = []
    deviations: list[str] = []
    probe_counts = {"correct_pass": 0, "correct_total": 0,
                    "wrong_fail": 0, "wrong_total": 0}

    for task in tasks:
        evidence = verifier.verify(code=task.reference_query, task=task)
        if evidence.verdict == Verdict.ABSTAIN:
            abstains.append(f"{task.id} (self-check): {evidence.detail}")
            continue
        if evidence.verdict != Verdict.PASS:
            self_fail.append(f"{task.id}: reference does not verify against itself")
        for probe in SQL_PROBES.get(task.id, ()):
            got = verifier.verify(code=probe.query, task=task)
            if got.verdict == Verdict.ABSTAIN:
                abstains.append(f"{task.id} ({probe.note}): {got.detail}")
                continue
            key = "correct" if probe.expect_pass else "wrong"
            probe_counts[f"{key}_total"] += 1
            expected = Verdict.PASS if probe.expect_pass else Verdict.FAIL
            if got.verdict == expected:
                probe_counts[
                    "correct_pass" if probe.expect_pass else "wrong_fail"
                ] += 1
            else:
                deviations.append(
                    f"{task.id}: probe [{probe.note}] expected "
                    f"{expected.value}, got {got.verdict.value} — {got.detail}"
                )

    out(f"# SQL verifier reliability ({SQL_TASK_SET_VERSION})")
    out("")
    out(f"tasks                : {len(tasks)}")
    out(f"reference self-check : {len(tasks) - len(self_fail)}/{len(tasks)} PASS")
    out(f"correct-variant pass : {probe_counts['correct_pass']}/"
        f"{probe_counts['correct_total']}")
    out(f"designed-wrong FAIL  : {probe_counts['wrong_fail']}/"
        f"{probe_counts['wrong_total']}")
    fp = probe_counts["wrong_total"] - probe_counts["wrong_fail"]
    out(f"false-PASS on designed-wrong probes: {fp}/{probe_counts['wrong_total']}")
    out(f"abstains             : {len(abstains)}")
    for line in abstains + self_fail + deviations:
        out(f"  DEVIATION: {line}")
    ok = not (abstains or self_fail or deviations)
    out("verdict              : " + ("CLEAN — every reference self-verifies, every "
        "designed-wrong probe FAILs" if ok else "DEVIATIONS FOUND (see above)"))
    return {
        "tasks": len(tasks),
        "abstains": abstains,
        "self_fail": self_fail,
        "deviations": deviations,
        **probe_counts,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m prometheus_protocol.benchmarks.sql_items",
        description="SQL task-set reliability: self-checks + designed probes.",
    )
    parser.parse_args(argv)
    summary = run_reliability()
    clean = not (summary["abstains"] or summary["self_fail"] or summary["deviations"])
    return 0 if clean else 1


if __name__ == "__main__":  # pragma: no cover - exercised via main() in tests
    raise SystemExit(main())
