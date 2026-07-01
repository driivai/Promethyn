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
