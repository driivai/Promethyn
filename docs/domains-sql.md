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

## The learn loop: verified SQL wins become a promoted, reversible skill

`python -m prometheus_protocol.benchmarks.sql_learn_demo` closes the LEARN
loop for the domain through the **shared promotion pipeline** — the same
`Orchestrator` sequencing, the same `LessonForge`, the same `PromotionGate`
behind the same held-out firewall (`gate/promotion.py` has a **zero-line
diff** in this change), the same markdown skill registry and ledger the code
domain uses. The model stays frozen throughout: a promoted skill changes the
*context* a proposal is made in, never any weights.

### Held-out semantics, mirrored exactly

`SqlTask` carries the same validated `split` partition as the code `Task`
(`train` / `heldout`, same constants, same meaning): the forge may learn from
`train` failures only (it refuses anything else), and `heldout` tasks exist
solely for the gate's firewalled generalisation check. Invariant **I1** is
stated over task *ids* and is therefore domain-general; the SQL conformance
suite re-proves both halves on SQL tasks — the unmodified gate raises
`FirewallError` on an id overlap before a single query is scored, and the
unmodified forge refuses held-out SQL attempts. One deliberate ergonomic
difference, documented rather than hidden: `split` defaults to `train`
(`SqlTask` predates learning and has verifier-only uses, e.g. ad-hoc
verification); the default is the fail-safe direction — held-out membership
is always an explicit authorial act, and nothing can *implicitly* join the
privileged held-out set.

The sql-v1 corpus is explicitly partitioned (18 train / 14 held-out), with
concept families spanning both splits so a mined lesson can be tested on
held-out members it never saw. Two families carry mining labels:
`sql-distinct-shortcut` (dedup asks; the trap is a missing DISTINCT) and
`sql-null-absence` (absence asks; the trap is `= NULL` / NULL in aggregates).

### One cycle, both gate outcomes, then a rollback (verbatim, 2026-07-06)

```
[learn] corpus: 5 train / 5 held-out tasks
[learn] firewall: train and held-out id sets verified disjoint
[learn] held-out baseline rate: 20%
[learn] train run: 4/5 verified failures -> forge mines from them (train split only)
[learn]   candidate skill-sql-distinct-shortcut (triggers: each once, distinct)
[learn]   candidate skill-sql-null-absence (triggers: never, no manager, missing)
[gate] skill-sql-distinct-shortcut: held-out 20% -> 60% : PROMOTED
[gate] skill-sql-null-absence: held-out 60% -> 60% : REFUSED (zero marginal lift — the lesson fits its training tasks only)
[gate]   (scored against the re-based baseline 60%, not the 20% cycle start — an earlier promotion's lift is never credited to a later candidate)
[learn] held-out rate after promotion: 60%
[learn] promoted skill on disk: skill-sql-distinct-shortcut.md (versioned markdown row — reviewable, deletable)
[learn] rollback: removed skill-sql-distinct-shortcut; held-out rate restored to 20%
[audit] promotions ledger (in order):
[audit]   #1 promote skill-sql-distinct-shortcut: 20% -> 60%
[audit]   #2 rollback skill-sql-distinct-shortcut: 60% -> 20%
[demo] learn loop closed: earned promotion, free-riding overfit refused on marginal lift, rollback exact
```

Every pass/fail above is the HARD verifier executing queries in the sandbox;
both gate decisions are the unmodified `PromotionGate`. Promotion is earned
the same way as in code: repeated verified train failures mine the candidate,
and only a measured held-out improvement promotes it.

The refusal doubles as the demonstration of **marginal-lift accounting**
(`run_cycle`): candidates are evaluated in the forge's deterministic order
(sorted cluster names), and after a promotion lands the baseline is
re-measured before the next candidate is scored. The overfit candidate — a
deliberate construction whose held-out members' improved queries are the same
wrong queries, simulating a lesson that fixed only what it was mined from —
is scored *after* the genuine promotion, against the re-based 60% baseline,
and shows zero marginal lift. Under the earlier cycle-start-baseline
accounting this exact candidate measured 20% → 60% and would have been
promoted on lift the other skill produced; the demo used to sidestep that by
evaluation order, and now exercises the fixed path instead. Single-candidate
cycles (the code domain's benchmark) never re-base and are bit-identical to
the old accounting.

### What a promoted SQL skill actually is

A markdown lesson (`Skill`) mined from verified train failures: a title,
trigger phrases, guidance prose, and provenance listing the train tasks it
came from — never a held-out task. Its value claim is exactly its measured
**marginal** held-out lift — held-out performance with it versus the current
baseline at its evaluation, including any promotions earlier in the same
cycle — nothing more; the promotion ledger row records precisely that pair. It is scoped by retrieval relevance (its
triggers and domain-prefixed cluster tag occur in SQL absence-asks and in no
code-benchmark prompt — pinned by unit test, and conformance shows the code
baseline bit-identical with the SQL skill sitting in the registry). It is
reversible by construction: one registry row to delete, one ledger `rollback`
record, and the pre-promotion held-out rate returns exactly.

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
  proved domain-general is the *Evidence* contract the bank consumes — and,
  with the learn loop closed, the `LearnableTask` port (`id`, `prompt`,
  `split`, `cluster`): the promotion pipeline runs both domains through the
  same classes, and the only generalisation the wiring needed was treating
  `entry_point` as optional code-domain metadata in the orchestrator and the
  forge's provenance renderer.
* **Skill scoping is retrieval relevance, not a hard wall.** A promoted SQL
  skill stays out of code-domain proposals because its triggers and tags
  occur in no code prompt (pinned by test), not because the registry enforces
  a domain boundary. A trigger phrase that crossed domains would cross with
  it. A structural scope field is a possible follow-up; today the honest
  statement is "scoped in measured practice".
* **Marginal attribution is sequential and order-conditional.** (The
  cycle-start-baseline mis-attribution flagged here previously is fixed:
  the baseline is re-measured after each promotion, so a later candidate is
  never credited with an earlier promotion's lift — conformance pins both
  directions, free-rider refused and genuinely-marginal promoted.) What
  remains true and deliberate: candidates are evaluated greedily in the
  forge's deterministic order, so a candidate's recorded lift is conditional
  on the promotions before it, and two complementary lessons that only help
  **together** would each show zero marginal lift alone and neither would
  promote. Subset search over candidates is a possible future extension; the
  greedy order is documented, deterministic, and auditable from the ledger.
* **The lesson book is a simulation.** As in the code domain, the frozen
  provider's improved-when-relevant behaviour is scripted; the demo measures
  the *pipeline* (mining, firewall, earned promotion, refusal, rollback), not
  any real model's ability to learn SQL. The verifier's verdicts are the only
  part that grades real execution.
* **Harder domains stay out.** SQL still has executable ground truth. Domains
  whose truth is not executable (prose quality, policy judgment) need
  verifiers this sprint says nothing about.
