# The execution authorization record, and the pinned hold

**Status: IMPLEMENTED** (PHASE-1.2c TASK 6 and TASK 5). `policy/record.py`
writes the record; `execution/pending.py` pins it and binds it into the audit
chain; `execution/controller.py` carries it onto every `executions` row. Proofs:
`tests/conformance/test_execution_authorization_record.py` and
`tests/conformance/test_hold_pinning.py`, pinned in `ci.yml` at 15 + 7 with zero
skips; executed mutations in `scripts/phase_1_2c_record_revert_proofs.py`.

Not to be confused with `docs/authorization-record.md`, which is the chokepoint's
durable *migration* authorization journal (PROM-F11). This document is about the
execution controller's human-hold and execution rows.

## 1. Why

Enforcement without a record decides correctly and cannot show that it did. The
execution descriptor seam (`docs/execution-descriptor.md`) re-resolves the
selected policy and refuses a mismatch, so a decision is *made* under a known
policy. Measured before this work, nothing persisted WHICH policy, WHICH
requirements, or WHAT answered them:

| where | what was persisted |
|---|---|
| `pending_actions.authorization` | seven identity fields: `snapshot_digest`, `policy_id`, `policy_digest`, `artifact_sha256`, `target_canonical`, `action_class`, `attempt_id` |
| `executions` | the `Judgment` (verdict/confidence/authoritative) and no authorization at all |

So the hold knew what it was bound to; the execution row — the one that records
a side effect actually happening — did not. Neither carried the resolved
requirements (R5) or the coverage report (R6): `CoverageSatisfied` carried
`answered_by` and `recorded_unavailable`, and `judge_covered` dropped both before
the assessment existed, so a reviewer could see that B answered and never that A
was down.

## 2. The record

One versioned JSON object, written to `pending_actions.authorization` at hold
creation and never rewritten, and to a new `executions.authorization` column for
every executor outcome — executed, refused, blocked and unavailable alike.

```jsonc
{
  "record_version": 1,

  // what this decision was made under
  "snapshot_digest":  "<64 hex>",
  "attempt_id":       "attempt-1",
  "policy_id":        "baseline",
  "policy_digest":    "<64 hex>",
  "policy_version":   1,               // VerificationPolicy.version, the human handle
  "action_class":     "sandbox.execute",
  "artifact_sha256":  "<64 hex>",
  "target_canonical": "sandbox://...",

  // R5 — the requirements the SELECTED policy resolved, in canonical order
  "requirements": [
    {"check_id": "executable.cases", "permitted": ["subprocess-tests"]}
  ],

  // R6 — the coverage report
  "coverage": {
    "recorded":     true,              // false only for the test forge (no validation behind it)
    "answered_by":  {"executable.cases": "subprocess-tests"},
    "unavailable":  [{"check_id": "...", "implementation": "..."}],
    "refusal":      null,              // or {"reason": "coverage.<row>", "check_id": "...", "detail": "..."}
    "outcome_kind": "judgment",        // or "unavailable"
    "verdict": "pass", "confidence": 0.95, "contributing": ["subprocess-tests"],
    "unavailable_reason": null,        // or "infra_fault" | "policy_refusal"
    "detail": "..."
  },

  "pinned_at": "2026-09-12T00:00:00+00:00"   // hold creation; authorization time for a hold-less execution
}
```

Every value is read off the seam-minted `AuthorizedExecution` — the requirements
and policy version off the seam's OWN re-resolution of the selected policy, the
coverage report off the assessment the bank minted — and never off anything a
caller supplied.

Two flat columns beside it, so a rotation sweep does not parse every row:

```sql
ALTER TABLE pending_actions ADD COLUMN invalidated_at     TEXT;
ALTER TABLE pending_actions ADD COLUMN invalidated_reason TEXT;
```

Added on open like every other additive column. A hold voided by a rotation is
`status = 'invalidated'`, `decided_by = 'system:policy-rotation'`, with the
timestamp and the reason in those columns — separable in the ledger from
`expired` (lapsed) and from a human decision.

### What the approved schema had and this does not

`policy_epoch`, the "opaque rotation marker". It had no source independent of
`policy_digest` — the supplier hands over a policy VALUE and nothing else — so
it would have been a field that records nothing, which is this repository's own
definition of a void guard. The rotation marker IS `policy_digest`;
`policy_version` is its handle. Dropped, and said so.

## 3. The three decisions worth arguing with

**Requirements are stored, not recomputed.** A reader could re-resolve the
policy named by `policy_id`/`policy_digest`. That works only while that policy is
still retrievable, which is exactly the case a rotation breaks — and the rotated
case is when a reviewer most needs to know what was required.

**`policy_version` is carried even though `policy_digest` already pins content.**
The digest is the authority; the version is the human handle. The redundancy is
checkable: the digest commits to the version.

**Approval compares against the pinned resolution — and STILL re-resolves.** The
brief framed pinning as "removing re-resolution from the approval path". It does
not, here, and deliberately: *re-resolve, don't re-digest* is the load-bearing
move of Checkpoint B, and taking it off the approval path would reintroduce R1
exactly (a hold approved against whatever its own record says). What pinning
adds is in front of the re-resolution, in this order:

1. **chain binding** — the row's record must equal its audit-chain entry, and the
   chain must verify;
2. **pinned policy** — the deployment must still select the policy the hold is
   pinned to (`policy_id` and `policy_digest`); otherwise the hold is refused as
   `PinnedPolicySuperseded` — a distinct refusal — and voided;
3. **the seam** — the record is decoded inside `ExecutionAuthorizer.restore_persisted`,
   which re-resolves the (now confirmed) selected policy for the concrete
   action and compares the snapshot digest and every identity, exactly as at
   hold time.

Before this, `PendingActionService._revalidate` re-resolved the CURRENT policy at
approval, so a hold created under A and approved after a rotation to B was
evaluated against B with nobody saying so — bad in both directions. Now a
rotation is named, the hold is voided, and verification is re-run by
re-submitting under B.

## 4. Tamper evidence — where the record's integrity comes from

The pinned requirements are trusted because they are in the record, so the
record cannot be a JSON column anyone with a database handle can rewrite. At
`hold`, the record is appended to the tamper-evident audit chain
(`docs/ledger-integrity.md`) under event `pending.hold`, subject
`pending:<id>`. At approval and retry:

| what the adversary changed | what approval sees | result |
|---|---|---|
| the row's `requirements` (R1's shape, one layer down) | row ≠ chain entry | **refused**: "does not match its tamper-evident chain entry"; chain still VALID; hold left pending |
| the row AND the chain entry's payload | row = entry, chain hash broken at that seq | **refused**: "did not verify" (`BROKEN`) |
| the row, the entry, AND every later `prev_hash`/`entry_hash` | a self-consistent chain | **not detected without an anchor** — the named limit; **`BROKEN` and refused with an external anchor** |
| the row relabelled to the NEW policy after a rotation, chain re-hashed | pinned check satisfied; the seam re-resolves the new policy and the assessment's snapshot digest (which commits to the OLD requirements) does not match | **refused**: "re-resolved" |

Each row is a test in `test_execution_authorization_record.py` and
`test_hold_pinning.py`, including the limit as a passing test. Note what the
lying record buys an adversary in the undetected case: a reviewer misled, and
nothing executed that the seam would not have authorized anyway, because
enforcement re-resolves the selected policy rather than reading the list. The
record's INTEGRITY is what the anchor restores. The threat-model position is
`docs/threat-model.md` §3.6.

## 5. The refusing path exercises coverage

Every Checkpoint-B proof that refuses does so before `judge_covered` runs, which
is how a positional `Evidence` construction that put the implementation name
into `stdout` survived every refusal test and surfaced only when a positive
control expected coverage to hold. The record's proofs run coverage to
completion on both sides:

| case | coverage row | what the row records |
|---|---|---|
| satisfied, one permitted implementation unavailable | — | `answered_by`, `unavailable: [{run, runner-b}]`, executed |
| the result names one implementation and the evidence another | `coverage.invalid_evidence` | `unavailable` row, `refusal.reason`, nothing executed |
| the required check abstained | `coverage.abstained` | same shape |
| no result for the required check | `coverage.incomplete` (`infra_fault`) | same shape |
| the only PASS is advisory | `coverage.advisory_only` | same shape |
| the required check FAILED | `coverage.unsatisfactory` | `blocked` row, `verdict: fail` |

## 6. Rotation and the TTL

`ExecutionController.invalidate_superseded_holds()` voids every pending hold whose
pinned policy is no longer the selected one and leaves the rest — the explicit
half; approval refuses such a hold regardless, marking it as it does. A retry of
an approved-but-unexecuted hold after a rotation is refused the same way and the
human's approval record is untouched (decided stays decided). The TTL is
unchanged: `pending_ttl_seconds`, `sweep`, and the approval-time stale guard
(`tests/conformance/test_execution_expiry.py`).

## 7. What the record still will not do

- It records what the policy REQUIRED and what ANSWERED. It does not record the
  evidence itself; a reviewer still cannot re-run the check from the row.
- `answered_by` names the implementation the coverage layer credited. It does
  not prove that implementation is what actually ran — the tier-provenance
  residual; registration remains the control.
- Nothing here measures the running code. A modified interpreter writes the
  same row.
- Detection, not prevention, and bounded by the chain's own limit (§4).
