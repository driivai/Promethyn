# The SQL domain: the first crossing out of code

SQL is the smallest real step outside the code domain: a candidate query has
near-authoritative ground truth — run it against a known database and compare
result sets — without being a program with hidden test cases. This document
records what the SQL verifier is, its exact comparison semantics, its measured
reliability, how the full loop closed in the domain, and what execution-based
verification can and cannot claim.

## The verifier

`SqlVerifier` (`verifier/sql.py`) is a **HARD-tier** domain verifier behind
the same shape the bank consumes: `verify(code, task) -> Evidence`. It
executes both the authoritative reference query and the candidate inside the
sandbox (one statement, in-memory database built from the task's schema and
fixture; network denied, resources bounded — untrusted queries are contained
exactly like untrusted code) and compares the result sets.

Fault attribution mirrors the code verifier exactly:

| outcome | verdict |
|---|---|
| result sets equivalent | PASS |
| result sets differ | FAIL |
| candidate query errors on the valid schema | FAIL (its own fault) |
| candidate blows its resource limits (confirmed start, no result) | FAIL |
| sandbox missing / did not start | ABSTAIN (no calibration sample) |
| run timed out | ABSTAIN |
| the *reference* query fails (unsound task) | ABSTAIN — never pinned on the candidate |

## Comparison semantics (deliberate, and adversarially tested)

* **Order-independent multiset equality by default.** Row order is not part
  of SQL semantics unless asked for; duplicates DO count (a bag, not a set).
* **Ordered equality when the task says so** (`ordered=True`, for asks that
  specify an ordering): same rows in a different order FAIL.
* **Column names are ignored; column count and position are enforced.**
  Aliases vary legitimately; arity and projection order do not.
* **NULLs compare positionally as values** (SQL's `NULL != NULL` governs
  queries, not the grading of their outputs). `NULL` never equals `0` or `''`.
* **Numeric tolerance 1e-9**, so an arithmetically identical float path is
  not punished; int and float compare cross-type.

The comparator is a pure function (`results_equivalent`) attacked directly by
unit tests: right-shape-wrong-content, order sensitivity both ways,
bag-vs-set duplicates, NULL edge cases, swapped columns, numeric tolerance.

## The task set and the measured reliability

`benchmarks/sql_items.py` — `sql-v1 (32 tasks)` over three schemas (a shop, an
HR tree with an empty department and NULL managers, an event log with NULL
durations). Ground truth is only ever produced by executing the reference in
the sandbox. Each task carries designed probes: correct variants and
plausible-but-wrong queries (cartesian joins, wrong aggregates, `= NULL`,
HAVING/WHERE boundaries, missing DISTINCT, LIMIT off-by-one,
duplicate-vs-distinct ranking, COALESCE-vs-ignore NULL handling).

Reliability run (`python -m prometheus_protocol.benchmarks.sql_items`),
2026-07-04, verbatim result:

```
tasks                : 32
reference self-check : 32/32 PASS
correct-variant pass : 2/2
designed-wrong FAIL  : 37/37
false-PASS on designed-wrong probes: 0/37
abstains             : 0
verdict              : CLEAN — every reference self-verifies, every designed-wrong probe FAILs
```

The measurement earned its keep immediately: the first run caught a fixture
coincidence (employee names accidentally inserted in alphabetical order made
a no-ORDER-BY probe pass by luck) which was fixed by breaking the coincidence,
not by deleting the probe. This run is enforced in conformance, so the set
cannot silently rot.

## The loop, closed

`python -m prometheus_protocol.benchmarks.sql_loop_demo` runs three beats
through the REAL chain — the same frozen offline model proposing, the bank
fusing, the gate authorizing, the controller/executor/ledger executing and
recording; nothing forked for the domain:

1. a correct proposal → PASS → authoritative judgment (confidence 0.95) →
   approved → executed in the sandbox → recorded;
2. a plausible-but-wrong proposal (cartesian join) → FAIL → **blocked** (a
   human is never asked to rubber-stamp a failure) → never executed;
3. a correct proposal on a **high-risk** ask (identity export) → **routed to
   a human** despite passing (INV-EXEC-3 holds in the new domain) → operator
   approval recorded → executed through the same at-most-once path.

An ABSTAIN-grounded judgment is non-authoritative and cannot pass the gate —
fail-closed carries over to the domain unchanged (tested).

## Honest limits

* **Result equivalence cannot distinguish a lucky-wrong query from a right
  one.** A query with wrong logic that returns the right rows *on this
  fixture* verifies PASS — the same bound hidden tests have in the code
  domain. Fixtures are built to make coincidences hard (the probes prove the
  designed ones all fail), but the bound is structural. Verification here
  means "indistinguishable from correct on the evidence", not "proven correct
  for all databases".
* **One dialect.** Ground truth executes on SQLite; a query relying on
  another dialect's semantics is out of scope.
* **`ordered` is task metadata.** The comparator trusts the task author to
  say when order matters; a mislabeled task grades with the wrong semantics.
* **The task model resisted, mildly.** The code-domain `Task` (entry point,
  hidden cases) did not fit SQL; the domain carries its own `SqlTask`. What
  proved domain-general is the *Evidence* contract the bank consumes — the
  port boundary sat exactly where the architecture claimed it would. SQL
  tasks are not yet wired into the promotion/held-out learning loop; when
  they are, `SqlTask` needs a split field and the firewall applies as-is.
* **Harder domains stay out.** SQL still has executable ground truth. Domains
  whose truth is not executable (prose quality, policy judgment) need
  verifiers this sprint says nothing about.
