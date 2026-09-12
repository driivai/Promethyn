# Audit observability

The ledger records the full decision chain — attempts, judgments, gate
decisions, pending human holds, human decisions, and executions. This document
covers how that chain is made **queryable**. It is additive observability: it
changes nothing about what the system decides or does. The recorded *values* are
identical to before; they are simply also written into first-class columns and
read back through audit queries.

## Judgment columns (F6 resolved)

The fused `Judgment` (verdict + calibrated confidence) used to live only inside a
JSON column, so you could not `WHERE`-clause on confidence. It is now promoted to
first-class, indexed columns **alongside** the JSON, which remains the source of
record:

| Table        | Added columns                                   | JSON source of record        |
| ------------ | ----------------------------------------------- | ---------------------------- |
| `attempts`   | `verdict`, `confidence`                          | `evidence.judgment`          |
| `executions` | `verdict`, `confidence`, `authoritative`, `judgment` | `judgment` (this column) |

The write path fills the columns and the JSON from the **same** `Judgment`
object, so they cannot diverge (a conformance test asserts equality). The
`confidence` and `verdict` columns are indexed for range/equality queries.

Columns are nullable: an attempt with no fused judgment, or an execution that
predates observability, leaves them `NULL`.

`executions` also carries a `pending_id` link (additive, ensured on open like
the columns above): the pending hold an execution resolves, filled for
human-approved and retried executions. It is what makes "this approved hold has
never executed" answerable from the ledger alone (`executions_for_pending`),
which the `retry-execution` verb's eligibility check relies on; `NULL` for
auto-approved/blocked rows and for rows written before the link existed.

`executions.authorization` (additive, PHASE-1.2c TASK 6) is the versioned
authorization record the outcome was decided under — the policy and its
version, the requirements it resolved, and the coverage report saying which
implementation answered each one and which could not
(`docs/execution-authorization-record.md`). For a human-approved or retried
execution it is the hold's PINNED record, byte for byte; blocked and
unavailable rows carry it too, so a refusal says which coverage row refused.
`pending_actions` gains `invalidated_at` / `invalidated_reason` (flat columns)
for holds voided by a policy rotation, separable from expiry. `NULL` for rows
written before records existed.

## What `detail` contains, and what it deliberately does not (F8)

A judge result's `Evidence.detail` used to be the model's reply, verbatim. It is
now a bounded classification:

```
judge_verdict verdict=PASS response_chars=412 confidence=0.9
```

and a failure is a reason code plus non-attacker-influenced context
(`unavailable operation=judge.assess error_type=ProviderTimeout`, `timeout
elapsed_ms=30000`, `http_unauthorized status=401 endpoint=https://api.example`).
The reason: the judge feeds candidate text to a remote endpoint and its reply
was being written into a permanent, signed, replicated record — an endpoint that
echoed the `Authorization` header put the bearer token into the ledger. See
`docs/security-model.md`, "Threat: a secret reaching a diagnostic".

**For queries this is a gain, not a loss.** The parts an operator filtered on —
the verdict and the confidence — are first-class columns as described above, and
the `detail` string is now a stable, greppable, closed vocabulary rather than
free prose. `verdict=` and `confidence=` are parsed at the boundary, so
calibration reads a number this process range-checked rather than re-parsing
remote text.

**What is gone: the model's actual words.** If you were reading `detail` to see
*why* a judge said FAIL, that is no longer there and is not recoverable from the
ledger. Diagnosing a specific judgement means reproducing the call against the
endpoint, where the reply is not being written into a permanent record. Rows
written before this change still hold raw text; the format change is not
retroactive, and a ledger with history from both sides of it contains both.

## Migration and backfill

Opening the ledger ensures the columns and indexes exist (an additive, idempotent
schema sync — it `ALTER TABLE ADD COLUMN`s on ledgers that predate them). The
data **backfill** for historical rows is a separate, explicit step:

```bash
prometheus-protocol migrate
```

`migrate` parses each historical row's JSON and fills the columns. It is
idempotent (only `NULL` columns are touched, so re-running is a no-op), and it is
robust: a row with malformed or missing JSON is left `NULL` and counted, never
fatal. Historical `executions` rows written before observability carry no
judgment JSON, so they are counted as skipped (there is nothing to recover).

The migration is **forward-only and additive**. SQLite column drops are not used,
so there is no destructive down-migration; reverting means ignoring the columns,
which are additive and safe to leave in place.

## Audit queries

Read-only. They mutate nothing; each is a ledger method and a CLI verb.

| Question                                             | Ledger method                         | CLI                               |
| ---------------------------------------------------- | ------------------------------------- | --------------------------------- |
| Which executed actions ran below confidence *X*?     | `executions_below_confidence(x)`      | `audit --executed-below X`        |
| Which authoritative-PASS actions ran below *X*?      | `authoritative_pass_below(x)`         | `audit --auth-pass-below X`       |
| What did humans decide (approve / reject / expire)?  | `human_decisions()`                   | `audit --human-log`               |

```bash
prometheus-protocol audit --executed-below 0.5
prometheus-protocol audit --auth-pass-below 0.5
prometheus-protocol audit --human-log
```

## The authoritative-PASS-with-low-confidence case

A judgment can be an **authoritative PASS** (a hard/human verifier binds the
verdict) while its *fused* confidence is low. This is worth watching because
**escalation is deliberately gated to non-authoritative verdicts**: the verifier
bank only escalates when no authoritative reference decided the verdict
(`VerifierBank.needs_escalation` returns `True` only for non-authoritative
judgments). An authoritative PASS therefore binds the verdict regardless of how
much the advisory signal weakened confidence — so a low-confidence authoritative
PASS is **not** auto-escalated by the bank.

`audit --auth-pass-below X` surfaces exactly these executed actions for human
review. This is **observability only** — it reports the case; it does not newly
escalate or block it.

Whether to *escalate* authoritative-but-low-confidence verdicts is a separate,
deliberate policy decision (it would change what routes to a human, which is a
behavior change, not observability). It is intentionally **not** implemented
here; see the follow-up note below.

## Follow-ups

- **Escalation policy for authoritative-low-confidence verdicts** — deferred. It
  is a behavior change (it would route more actions to a human) and belongs in a
  separate, deliberate decision, not in this observability sprint.
- **Backfill of historical executions** — rows written before observability have
  no captured judgment JSON, so their columns stay `NULL`. Only forward rows and
  JSON-bearing tables (attempts) backfill.
