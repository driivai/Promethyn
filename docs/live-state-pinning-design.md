# Re-observation at execution — revision 4: PHASE 1 IMPLEMENTED for `branch.delete`

**Status: the mechanism is built for ONE action class.** `branch.delete` is
re-observed end to end — captured at hold creation, compared before the
approval is recorded, and re-read immediately before the executor is called —
and `sandbox.execute` and `database.migrate` are **opted out by name**, which
is a value in the record rather than an absence. Everything below revision 3's
heading is the design as ruled; this section records what landed, what it is
allowed to claim, and what it does not do.

## WHAT SHIPPED, AND WHY THIS CLASS FIRST

`branch.delete`'s live-state check already existed — the merge proof counts
commits reachable from the branch and absent from the base
(`tools/git.py:141-158`) — so the staleness gap is demonstrable rather than
hypothetical, and the reproduction is a real one. It is kept as a passing test:
`test_the_gap_without_reobservation_a_delete_executes_on_replayed_evidence`
wires the controller with no re-observation, lets the branch gain a commit
after review, and shows the executor reached with an approved decision whose
evidence says the delete is lossless.

| piece | where |
|---|---|
| the covered set, derived from a frozen dataclass | `policy/target_state.py` — `BranchDeleteState`, three aspects, `aspects_of` reads the field names off the class |
| the digest, reusing the snapshot encoder under its **own** domain | `policy/target_state.py` — `prom-target-state-v1`, with the state type's name committed inside the preimage |
| the observer, the same reader the merge proof uses | `tools/git.py` — `GitBranchStateObserver` over `GitTool` |
| the registry, total over `ACTION_CLASSES`, opt-out per class | `policy/reobservation.py` — `ReObservation` |
| capture at hold creation | `execution/pending.py` — `_capture_target_state`, into the pinned record's `target_state` |
| comparison one, before the approval is recorded | `execution/pending.py` — `_require_state_unmoved_before_approval` |
| comparison two, immediately before the executor | `execution/controller.py` — in `_execute`, after the claim |
| the terminal transition out of `APPROVED` | `ledger/sqlite_ledger.py` — `mark_state_moved`, guarded on `status = 'approved'` |
| the observation record, chained, keyed on the execution attempt | `policy/reobservation.py` + `execution/pending.py` — `_compare_now` |

## WHAT THE DOCS MAY CLAIM — the exact sentence

> **The pinned aspects have not changed since review, and here is the aspect
> list.**

That is the whole of it. **Never "the reviewed assumptions hold."** The
difference is not stylistic: the aspect list is what this code read, and the
reviewer's assumptions are a larger set nobody has enumerated. Schema rehearsal
is the successor feature that would narrow the gap between them, and until it
exists the narrow sentence is the only true one. The aspect list travels in
both records precisely so the claim can be checked rather than believed.

## THE TOCTOU RESIDUAL — bounded, not closed

Recorded verbatim, and it now describes a **read-to-execute** window rather
than an approve-to-execute one:

> *A state comparison immediately before execution narrows the window to the
> gap between two statements in one transaction at READ COMMITTED. It does not
> eliminate it. A session that commits DDL inside that window is not detected.
> The control against that is a lock on the target, which this design does not
> take.*

**What bounds it here.** The re-read runs after the execution claim is taken
(`claim_pending_execution`), so no concurrent driver of this system can slip an
execution between the read and the executor call; and it runs with nothing
between it and `executor.execute`. For `branch.delete` the residual is a third
party committing to the branch in that window — a person at a shell, or another
tool — which nothing in this design excludes. Narrower than it was, not zero.

## THE HUMAN-FACING CONSEQUENCE — both failures, and an operator will hit the second

**Failure one: the approval is refused at the moment it is given.** A reviewer
reads the plan, decides yes, clicks approve, and is told the approval was not
recorded because the target moved while they were deciding. Their decision is
discarded — not deferred, not queued — because it was predicated on a state
that no longer exists. The hold stays PENDING and can be re-reviewed against
the current state.

**Failure two: an approval that SUCCEEDED, followed by a terminal execution
refusal.** This is the one an operator will hit and the one the interface has
to explain. The hold reads `state_moved_after_approval`. It did not expire and
no policy rotated. The approval is still on the record, with the approver's
name and time, because it was a correct decision on the state it was shown;
what cannot stand is executing on it. The hold is not retryable by any verb —
`retry_decision` refuses it like any other non-approved status, and the
execution claim is deliberately not released. The remedy is a NEW hold with a
NEW approval, which means the whole review again, against the new state.

An operator who reads "refused" on something they approved and is not told why
will retry, find they cannot, and then remove the requirement. That is the G21
road, and it is why all three of these are obligations on the interface rather
than notes: the refusal must say **what moved** (the aspect list is what makes
that possible), it must say **the approval stands as a record**, and it must
name **the remedy**.

## WHAT PHASE 1 DOES NOT DO

- **Two of three action classes are opted out**, by name, in the deployment the
  tests wire. The opt-out is real machinery and its reason is in the record;
  it is not coverage.
- **The opt-out is not in the attested posture.** It is a constructor argument
  at the composition root, not a `Config` field on `SECURITY_FIELDS`, so it is
  not in the configuration-attestation digest. A deployment's choice is in
  every hold's record and is not in its posture attestation. Named here rather
  than discovered; moving it into `Config` is its own change with its own
  attestation re-pin.
- **The state pin is not a `PolicyRequirement`.** §3.1 framed it as one so that
  unavailability would flow through coverage. The claim was verified and is
  TRUE — an `Unavailable` in a `BoundResult` is recorded at
  `policy/coverage.py:331-334` and refused as `coverage.incomplete` at `:388` —
  but it is not the path used, because §2.1 ruled the capture point at **hold
  creation**, which is downstream of assessment and therefore downstream of
  coverage. Unavailability at capture, at approval and at execution therefore
  halts by its own path (`StateUnreadable`), which is the same ruled behaviour
  reached without pretending a requirement carried it. Making the capture
  itself coverage-validated is a follow-up, and it would additionally put the
  observer under the implementation registry.
- **A deployment that wires nothing gets nothing** — and its records say so.
  `target_state` is present in every v2 record with `observed: false` and the
  reason, because an absent block and a passing comparison would be the same
  bytes.
- `database.migrate` re-observation, schema rehearsal, `REPEATABLE READ` and a
  target-keyed advisory lock are all still out.

---

# Revision 3 — the design as ruled

**Status at revision 3: design. Nothing of re-observation was implemented.**
Revision 3
records four rulings from the owner (§7.1's second comparison, §3.4's opt-out
scope, §2.2's record key, and a correction to the owner's own Q2 answer),
generalises the fifth finding's exclusion into a principle and sweeps the
covered set under it (§1.5), and marks the one true prerequisite — the
implementation registry, G26 — as **landed in the same change** (§3.1).

**Doctrine #10, applied for the first time here** (`docs/threat-model.md`):
every claim this document makes about EXISTING behaviour carries a `path:line`
or is marked UNVERIFIED. Line numbers are as of the tree this revision was
committed to. Findings 3 and 4 of the rev-1 review were the same error twice —
existing machinery claimed to cover something without reading it, in the
document arguing against that — and this is the mechanic that error earned.

The roadmap claim under review: *"catches destructive changes and refuses
execution when reviewed assumptions have become stale."*

**Scope, ruled by the owner: RE-OBSERVATION AT EXECUTION, GENERALLY** — not
migrations only. §0.1 measured that the gap is in the *replay* path, so every
action class has it, and `branch.delete`'s merge proof is a concrete data-loss
path today. It is also the more honest claim: *"evidence is re-observed before
execution"* is a property of the seam, which is what the product sells.

---

## WHAT CHANGED IN REVISION 3

| # | rev-2 position | rev-3 ruling or correction | where |
|---|---|---|---|
| 6 | §7.1 left open: a pre-execution re-read that mismatches hits finding 2's problem again; three options, I would refuse the advisory one | **RULED: refuse the execution AND make the hold terminal.** A distinct terminal state, `state_moved_after_approval`, not expiry and not rotation-invalidation. Re-verification is a NEW hold with a NEW approval. Not advisory — a recorded mismatch that does not stop execution is the "state verified" receipt this design exists to prevent | §4.4 (new), §6.2, §7.1 |
| 7 | §3.4 left open: per-action-class or global opt-out | **RULED: per action class.** A global switch is what a deployment reaches for under pressure, and nothing in the record distinguishes it from "this class doesn't need it". Per class forces the opt-out to name what it opts out of, and the record names it | §3.4 |
| 8 | §2.2 left open: the observation record's subject key | **RULED: keyed on the EXECUTION ATTEMPT**, not the hold, not the action. Measured consequence recorded rather than smoothed over: a retry re-drives the SAME hold with the SAME verification attempt (`execution/controller.py:244-290`), so "execution attempt" needs an identity the code does not mint today, or a retry's observation would overwrite the first — which the ruling forbids | §2.2, §6.2 |
| 9 | §1.2/§1.3: per-session settings excluded, as a case | **Generalised to a principle:** the covered set excludes not only what cannot be meaningfully compared but what THE ACT OF EXECUTING CHANGES. Sweeping the remaining aspects under it found a second member of the class: the runner's own receipt schema and table are CREATED on the way in (`chokepoint/runner.py:842-862`) | §1.2, §1.3, §1.5 (new) |
| 10 | §2.1: "Q2 — schema rehearsal is a PREREQUISITE" | **CORRECTED BY THE OWNER.** The answer was incoherent: it called rehearsal a prerequisite and then explained it as a constraint on the CLAIM. The claim constraint stands; rehearsal is a SUCCESSOR feature, not an ordering prerequisite. Rev 2 transcribed the answer without flagging the incoherence, which the reading discipline of doctrine #10 should have caught | §2.1 |
| 11 | §3.1: implementation-registry validation "a stated prerequisite, filed as G26" | **LANDED, in the same change.** `policy/implementations.py` declares each identity once; `PolicyRequirement.__post_init__` refuses an undeclared permitted name with `implementation_not_registered` and an empty registry with `implementation_registry_empty` (`policy/profile.py:168-192`); after review (PR #111), `load_profile` and the resolver also verify each declared site resolves and reports its identity (`implementation_site_unresolved`). This design's `CHECK_TARGET_STATE` implementation will be declared there like any other. What the registry does NOT cover was also found by that review and is G27: a policy permitting the wrong registered implementation for a check | §3.1, §7.5 |
| — | `audit_chain.record_chained` cited as the append-only write | **Citation corrected.** `record_chained` is a Ledger port method (`core/interfaces.py:389`, implemented at `ledger/sqlite_ledger.py:849`); `ledger/audit_chain.py` holds `ChainTip`/`ChainVerification`. A wrong citation is the reverse of doctrine #10's rule, and it was found only by applying the rule | §0.2, §2.2 |

---

## WHAT CHANGED IN REVISION 2, AND WHAT I GOT WRONG

Recorded here rather than silently replaced.

| # | rev-1 ruling | why it was wrong | rev-2 ruling |
|---|---|---|---|
| 1 | §2: the observed digest joins **the pinned record** at execution | **A record written once and required byte-equal to its chain payload cannot carry a value only known at execution.** `_require_chain_binding` compares `stored != pending.record` over the *whole* record (`execution/pending.py:655`). Writing the observation into it would break the binding it was meant to be protected by | A **separate append-only chained execution-observation record**. Two records, two moments, both chained. §2, §6 |
| 2 | §4: a mismatch **invalidates** the hold, following rotation | `invalidate_pending_action` is `WHERE id = ? AND status = ?` with `_PENDING_STATUS` (`ledger/sqlite_ledger.py:536-555`) — **pending rows only** — and an execution-time comparison runs after `approve()` has written APPROVED (`execution/pending.py:344-350`). The mismatch would refuse and leave an **approved, retry-eligible** hold: worse than either option, because it will be retried against a state that already failed | The comparison runs **before approval is recorded**. Not a new post-approval transition. §4 |
| 3 | §3.3: refuse-vs-route "is already a policy property" | **Measured false.** `ActionGate.decide` handles `Unavailable` *before* `_outcome` and returns a terminal `OUTCOME_UNAVAILABLE` (`gate/authorization.py:137-149`; `_outcome` is `:168`); `submit()` records it and halts, deliberately **not** as an approvable hold (`execution/controller.py:165-186`). The routing logic is never reached | Unavailability **always halts**. The claim is deleted. §3 |
| 4 | §3.1: a requirement nothing can satisfy "is already refused at policy construction" | **Measured false** (on the tree before this change). `PolicyRequirement.__post_init__` validated identity normalisation, `applies_to` shape, non-emptiness, known action classes and duplicates — and **never** that an implementation exists or is registered | An implementation-registry validation step is a **stated prerequisite**, and the underlying defect gets its own entry, **G26**. §3.1 — now landed, see rev-3 row 11 |
| 5 | §1.2: "server version and relevant settings" — `lock_timeout`, `statement_timeout`, `search_path` — are IN the pinned state | **The executor SETS those itself**, per session (`chokepoint/runner.py:815-818, 885-903`), and `statement_timeout` is derived from the approval's *remaining budget* (`:894-903`). A review-time reader necessarily uses another session and cannot reproduce them. Included, they make an **unchanged target mismatch** and invalidate valid holds — §4.2's frequency risk turned into a certainty. A fifth finding the brief did not list; it is correct | Per-session mutable values are **OUT**. Stable server configuration is IN, read by `context`/`source` from `pg_settings`, never via `current_setting()`. §1.2, §1.3 |

Findings 3 and 4 are the same error twice: I claimed existing machinery covered
something without reading it. That is the shape this repository keeps naming,
and it arrived here in the document arguing against it. It is now doctrine #10.

Finding 5 is a different error and worth its own sentence: **the digest was
measuring the executor's own effect on the target.** The instrument included
values that the thing it was checking sets on the way in. Same family as the
adapter collector that counted test doubles (PR #108) — an instrument whose
answer depends on who is asking is not measuring the subject. Rev 3 turns that
sentence into §1.5's principle and finds it applies once more.

---

## 0. WHAT ALREADY EXISTS — measured 2026-09-15, citations re-read for rev 3

### 0.1 The gap is in the replay path, so every action class has it

**Nothing in the tree reads a migration target's schema.** Every `pg_catalog`
call on the execution path in `chokepoint/runner.py` is a session setting
(`:815-818`, `:885-889`, `:894-903`), an advisory lock (`:819-828`; a second
connection for the receipt lookup takes the same lock at `:977-983`), or an
existence check for the runner's **own** receipt schema and table (`:842-851`).
The migration is `cursor.execute(sql, prepare=False)` at `:911`, sent
unexamined.

**And the gap is not migration-specific.** At approval and execution, coverage
is **replayed from the persisted record** — `restore_coverage(record)` at
`execution/pending.py:621`, defined at `policy/record.py:180` — and nothing in
`execution/pending.py`, `execution/controller.py` or `execution/executor.py`
calls a verifier (measured: a search of `src/prometheus_protocol/execution/` for
`.verify(`, `verifier.` and `Verifier` returns nothing). Every action class
executes against evidence recorded at assessment time. A `branch.delete` held
for review can gain commits between the merge check (`tools/git.py:150`,
`rev-list --count`) and the approval, and the delete (`:338`, `branch -D`)
executes on the replayed "zero unmerged commits".

That is why the owner scoped this to re-observation generally.

### 0.2 What exists that is reusable

| asset | reusable as |
|---|---|
| **`tools/git.py`** — reads live state, and already gets the doctrine right: `unmerged_commits: int \| None` (`:92`), `provably_merged` only on a definite zero (`:95`), and a count it could not establish is an `Unavailable` (`:204-205`) | The pattern for §3, and the first action class to get re-observation |
| **`chokepoint/reconcile_gate.py`** — `PRAGMA query_only=ON`, `trusted_schema=OFF` (`:115-116`), a progress-handler deadline, explicit size bounds that raise (`:133`, *"gate snapshot exceeds bounds"*) rather than truncate | The pattern for a bounded state read |
| **The `BoundRequirements` encoder** (`policy/snapshot.py`) — type-tagged, length-prefixed, domain-separated, with `test_type_tags_keep_lookalike_values_apart` (`tests/conformance/test_bound_requirements_encoding.py:223`), `test_a_sequence_cannot_be_confused_with_its_concatenation` (`:233`), `test_a_value_cannot_forge_a_field_boundary` (`:240`) | The encoder the state digest **must reuse**, with its own domain |
| **`_DESCRIPTOR_FIELDS = tuple(f.name for f in dataclasses.fields(ExecutionDescriptor))`** (`policy/execution.py:145`) | The derivation precedent for §1 |
| **The Ledger port's `record_chained`** (`core/interfaces.py:389`; SQLite implementation `ledger/sqlite_ledger.py:849`; the hold's own entry is written under `_hold_subject(pending_id)`, `execution/pending.py:181, 269`) | The append-only chained write for §2's second record |
| **`policy/implementations.py`** (new, G26) — one declaration per implementation identity, consumed by reference at every site; `PolicyRequirement` refuses an undeclared name (`policy/profile.py:168-192`) | Where `CHECK_TARGET_STATE`'s implementation is declared, so a stub cannot answer under a free string (§7.5) |

### 0.3 Presuppositions in the original brief that did not hold

1. **"reversibility analysis, rewrite counting"** — neither exists. UNVERIFIED
   beyond a search of `src/` for those phrases, which returns nothing.
2. **"any schema read" in the live-PG step** — none (§0.1).
3. **"`branch.delete`'s protected-target refusal"** — there is none. What it has
   is a `PolicyRequirement` for a merge proof (`policy/profile.py:401-425`, the
   baseline's `CHECK_MERGE_PROOF`). This supports the §5 prior.
4. **"the sandbox rehearsal for `database.migrate`"** — there is none.
   `database.migrate` carries one requirement, `CHECK_EXECUTABLE_CASES` /
   `IMPL_SUBPROCESS` (`policy/profile.py:401-413`), the same generic "untrusted
   code was run" check as `sandbox.execute`. It says nothing about a database.

---

## 1. WHAT IS "THE STATE"? — RULING (principle generalised in rev 3)

### 1.1 The covered set is DERIVED, not hand-listed

A digest over table names that misses a column type change is an enumeration
wearing an allowlist's clothes. The cautionary case is `_DESCRIPTOR_FIELDS`:
three hand-written copies of six names that agreed only because a person kept
them agreeing, replaced by the derived form at `policy/execution.py:145`.

**Ruling: the covered set is the field set of a frozen dataclass.**

```
TargetState                                            # one field per ASPECT
STATE_ASPECTS = tuple(f.name for f in dataclasses.fields(TargetState))
```

with three properties carried over:

1. the encoder iterates `STATE_ASPECTS`, so a new aspect is covered by
   construction;
2. a test asserts the encoded aspect set equals the dataclass fields
   (`test_the_encoded_field_set_equals_the_dataclass_fields`,
   `tests/conformance/test_bound_requirements_encoding.py:160`, is the precedent);
3. a test asserts **every aspect moves the digest**
   (`test_every_field_actually_moves_the_digest`, `:173`, is the precedent). An
   aspect collected but not hashed is not covered.

**The honest limit.** Derivation makes the *encoding* total over the aspects. It
does not make the *aspect list* total over what the target can vary — that list
is still written by a person. §6's `aspects` field makes the gap legible rather
than invisible.

### 1.2 IN the pinned state

table/column existence, names, types, nullability, defaults · constraints ·
indexes **including validity** · triggers · views and dependent objects ·
extensions and enum members · permissions and role grants · migration-version
table state · **server major version and STABLE server configuration** ·
partitioning topology — **all of it read outside the runner's own namespace**
(§1.5: `promethyn_internal`, `chokepoint/runner.py:166`).

**"Stable server configuration" is a rule, not a list, because the list is how
finding 5 happened.** A setting is in the pinned state only if it is read from
`pg_settings` with a `source` that is not the session — `default`,
`configuration file`, `override`, `command line`, `environment variable` — and
a `context` that a session cannot change for itself. It is read from
`pg_settings`, **never** via `current_setting()`, which returns whatever the
executing session has set. The aspect that collects it carries that filter as
part of its known-answer test (§7.5), so the filter cannot drift back to "read
the session".

For `branch.delete` the equivalent `TargetState` is the merge-proof subject:
the branch tip, the base tip, and the unmerged-commit count
(`tools/git.py:150`).

### 1.3 OUT, as named limits

| out | why | the limit left |
|---|---|---|
| row count / table size | Changes on every write; including it refuses on almost every comparison — §4's failure in its purest form | Size affects how long a rewrite holds locks. A migration reviewed against 1k rows and executed against 100M is *correct* and may still cause an outage. Not covered. A size-bound check is a separate feature |
| data content | Unbounded; a digest over content is a digest over the database | A migration whose safety depends on data (a `NOT NULL` backfill assuming no nulls) is not covered. That is a data precondition and belongs in the migration's own checks |
| replication topology | Not a property of the schema; a property of *which server answered* | Handled in §7.3 by a different control |
| **per-session mutable settings** — `lock_timeout`, `statement_timeout`, `search_path` as the executor sets them | **The executor changes these itself** (`chokepoint/runner.py:815-818, 885-903`), and `statement_timeout` is computed from the approval's remaining budget at execution time (`:894-903`). A review-time reader cannot reproduce a value that does not exist yet. Pinning them guarantees a mismatch on an unchanged target — the design invalidating its own valid holds. (Finding 5, PR #109) | Whether the *executing session's* effective settings are what the reviewer assumed is not covered by the digest. It is covered by something better: the executor sets them **deterministically from the approval**, so they are a function of the record rather than an observation of the target. The record already carries the budget they derive from |
| **the runner's own receipt namespace** — schema `promethyn_internal`, table `migration_receipts` (`chokepoint/runner.py:166-167`) — NEW in rev 3, found by §1.5's sweep | **The executor CREATES these on the way in**: `CREATE SCHEMA` at `:845`, `CREATE TABLE` at `:852-858`, committed at `:862`, all BEFORE the migration statement at `:911`. Against any target the runner has never executed on, the review-time read sees no such schema and the pre-execution re-read sees one: a guaranteed mismatch on an unchanged target, on the first execution, every time | A change hidden inside `promethyn_internal` is not detected by the digest. It is the runner's own namespace, written only by the runner, and its receipt rows are what reconciliation reads (`:863-884`); an adversary who can write there can write the receipts too, which is a different control's problem (`docs/chokepoint-threat-model.md`) |

### 1.4 Q1 — ANSWERED BY THE OWNER: the covered set is FIXED, not per-policy

> *A customer narrowing it with no signal turns an allowlist back into an
> enumeration.*

**And finding 4 is why this is the right call rather than merely the safer one.**
A customer-supplied policy has no shipped-profile constants protecting it. Until
G26 the `IMPL_*` names in `policy/profile.py` were bare strings whose comments
said they were "read off `SubprocessVerifier.VERIFIER_ID`" — correct because a
person copied them correctly, not because anything checked. G26 closed that for
implementation names (`policy/profile.py:396-398` are now references to the
declarations, and `:168-192` refuses an undeclared one); a per-policy covered
set would hand the same unchecked surface to the aspect list, where a typo or a
narrowing is indistinguishable from a deliberate choice.

### 1.5 THE PRINCIPLE (rev 3): the set excludes what THE ACT OF EXECUTING CHANGES

Finding 5 was a case. The rule it belongs to: **the covered set excludes not
only what cannot be meaningfully compared, but what the act of executing changes
on the way in** — because a digest that can never match refuses every execution,
which reads as broken rather than secure and trains an operator to remove the
requirement. That is the G21 failure (a control removed because it fires on
noise) reached by a different road.

**The sweep, aspect by aspect, against what the executor does before the
migration statement** (`chokepoint/runner.py:806-911`, and for `branch.delete`
`tools/git.py:150-338`):

| aspect | changed by the act of executing, before the comparison? | ruling |
|---|---|---|
| table/column existence, names, types, nullability, defaults; constraints; indexes; triggers; views | **YES, for one namespace.** The runner creates `promethyn_internal` and `promethyn_internal.migration_receipts` (`:842-858`) and commits them (`:862`) before `:911`. Nothing else: the only DDL on the path is those two statements | IN, **excluding the runner's own namespace by name** (§1.3, new row) |
| extensions and enum members; permissions and role grants; partitioning topology | **No.** No `CREATE EXTENSION`, no `GRANT`, no partition DDL on the path (measured by searching `runner.py` for them: none) | IN |
| migration-version table state | **Changed by executing, but AFTER both comparisons.** The receipt `INSERT` is at `:912-917`, after the migration statement, in the same transaction. At the pre-execution re-read it has not happened. A retry of a committed execution returns *already committed* at `:869-884` without re-executing | IN, read as the set of receipted execution ids outside the current execution. A comparison placed after `:912` would be measuring the execution itself — the placement is load-bearing and §7.5 must pin it |
| server major version; stable server configuration | **No.** The runner sets only session- and transaction-scoped values (`set_config(..., false)` at `:816`, `set_config(..., true)` at `:887, :895`); `pg_settings` rows with a non-session `source` do not move | IN (§1.2's rule) |
| per-session settings | YES (finding 5) | OUT (§1.3) |
| the advisory locks (`:819-828`) | Taken by the act of executing | Not an aspect; `pg_locks` is not in the set, and must not be |
| `branch.delete`: branch tip, base tip, unmerged count | **No.** The merge check is `rev-list --count` (`:150`), read-only; the executor runs no `fetch`, `prune`, `update-ref` or `push` before `branch -D` (`:338`) (measured by searching `tools/git.py`: none) | IN, unchanged |

**What the sweep does not close.** It covers what the executor does *today*. An
executor that later writes something else on the way in — a lock table, an
audit row in the target — re-enters this class, and no test can anticipate it.
The mitigation is §7.2's two-sessions-equal-digest test, which catches the
*class* (a digest unstable under no change) without enumerating its members —
provided the test's second read runs after the first session has done everything
the executor does before `:911`. That ordering is a requirement on the test, and
it is stated here so the test is not written the easy way.

---

## 2. CAPTURE, BINDING, AND THE EXECUTION OBSERVATION — RULING (rev 3: keyed on the attempt)

### 2.1 Capture point, and Q2 as corrected by the owner

- **(a) at rehearsal** — does not exist today (§0.3), and is a **SUCCESSOR
  feature**, not a prerequisite.
- **(b) at review / hold creation** — available; this is the capture point.
- **(c) both, compared** — the end state once (a) exists.

**Q2 — the owner's answer, and the owner's correction of it.** Rev 2 recorded:
*"schema rehearsal is a PREREQUISITE"*. The owner's correction: that answer was
incoherent — it called rehearsal a prerequisite and then explained it as a
constraint on the *claim*. The claim constraint stands, verbatim:

> *Ship "the pinned aspects have not changed since review, and here is the
> aspect list" — never "the reviewed assumptions hold."*

Rehearsal itself is a successor feature. **The only prerequisite this design
names is the implementation registry, and it has landed** (§3.1). Rev 2
transcribed the incoherent answer without flagging it; recorded here because
"the owner said so" is not a reading either.

### 2.2 TWO RECORDS, TWO MOMENTS, BOTH CHAINED — keyed on the execution attempt

**This replaced rev 1's §2 ruling, which was wrong.** Rev 1 put the observed
digest into the pinned authorization record at execution. That cannot work, and
the reason is the mechanism that makes the record trustworthy in the first
place: `_require_chain_binding` compares `stored != pending.record` over the
**whole** record against its chain payload (`execution/pending.py:655`). A
record written once and required byte-equal to its chain entry **cannot carry a
value only known later**. Writing the observation in would either break the
binding or require mutating a chained payload — and mutating a chained payload
is the thing the chain exists to detect.

| record | written | says | chained | keyed on |
|---|---|---|---|---|
| **Pinned authorization record** (exists today, `policy/record.py`) | once, at hold creation | what was **authorized**: requirements, policy version, coverage, and **the pinned state digest + aspect list** | yes, unchanged mechanism (`execution/pending.py:269` writes it under `_hold_subject(pending_id)`) | the hold, and within it the verification `attempt_id` (`policy/record.py:147`) |
| **Execution-observation record** (new) | at each comparison (§4.4: two) | what was **found**: pinned and observed digests, the result, or the unavailable reason | yes, its own append-only chained entries | **the execution attempt** (ruled) |

Both are append-only. Neither is mutated. The pinned record's byte-equality
check is untouched, so this adds a record without weakening the one that exists.

**Not outside the chain.** An observation in a plain column would be trusted
because it is in the record and covered by nothing — the exact split Block 1a
closed when integrity moved from re-resolution to the record.

**What still holds from rev 1:** the pinned *state digest* does go inside the
pinned record, because it is known at hold creation. `RECORD_VERSION`
(`policy/record.py:87`) bumps 1 → 2, so every pre-existing hold becomes
`reverification_required` (`policy/execution.py:57`) — correct fail-closed
behaviour, and an operational event for the release note rather than a
discovery for an operator.

**RULED (rev 3): the observation record is keyed on the EXECUTION ATTEMPT.**
Not the hold, not the action. The owner's reasoning: the attempt is what the
pinned record already binds to, so keying the observation the same way makes
the pairing structural rather than a join someone has to get right; and a
retry creating a new attempt gets a new observation record rather than
overwriting, which matters under §4.4's terminal-state ruling because the
history of what moved is what an assessor reads.

**The measurement the ruling has to survive, stated rather than smoothed over.**
What the pinned record binds is the *verification* attempt: `attempt_id` at
`policy/record.py:147`, resolved into the snapshot (`policy/snapshot.py:263`).
A retry does **not** create a new one. `retry_execution`
(`execution/controller.py:244-290`) calls `retry_decision`
(`execution/pending.py:386-405`), which "re-materialises an approval a human
already recorded" for the SAME hold with the SAME pinned record, and drives
`_execute` again (`:284-290`). The at-most-once guard is
`claim_pending_execution` (`ledger/sqlite_ledger.py:557-572`), and after a
refused, side-effect-free execution the claim is released
(`release_pending_execution`, `:574-586`; called at `controller.py:359`) so the
hold is retry-eligible. So today an "execution attempt" has no identity of its
own: two executions of one hold share every identifier the record carries.

**Design consequence:** an execution-attempt identity is minted at the claim —
the moment `execution_committed_at` is written (`sqlite_ledger.py:567-568`) —
as an ordinal per hold (the first claim is 1, a re-claim after release is 2) or
a fresh id stored beside the timestamp, and the observation record's subject is
`(attempt_id, execution_attempt)`. The verification attempt keeps the pairing
structural, as the owner ruled; the execution ordinal keeps a retry from
overwriting, as the owner also ruled. Under §4.4 a state-moved refusal never
releases the claim, so a second execution attempt on one hold arises only from
a refused-by-sandbox execution, and it gets its own record. Which form the
identity takes — ordinal or id — is mine to rule and revisable; the two
properties are not.

---

## 3. WHAT IF THE STATE CANNOT BE READ? — RULING (rev 3: prerequisite landed; opt-out ruled)

### 3.1 The mechanism: a policy requirement, and the prerequisite that has landed

**Ruling (unchanged): the state pin is a `PolicyRequirement` satisfied by a
permitted implementation**, like `CHECK_MERGE_PROOF` (`policy/profile.py:401-425`).
`Unavailable` then flows through machinery that already exists: the bank turns
it into `coverage.incomplete` (`policy/coverage.py:331-334` records it, `:388`
refuses), which is a refusal, in a closed vocabulary where every reason already
has an end-to-end row.

**WITHDRAWN in rev 2, and now moot: rev 1's claim that "a requirement nothing
can satisfy is already refused at policy construction."** On the tree before
this change, `PolicyRequirement.__post_init__` validated identity normalisation,
that `applies_to` was a non-empty sequence of known action classes, and that it
had no duplicates — and never that an implementation named in `permitted`
existed. A typo constructed cleanly and failed only as incomplete coverage on
every assessment, which read as a runtime outage rather than a configuration
error.

**THE PREREQUISITE HAS LANDED (G26, same change).** `policy/implementations.py`
declares each implementation identity once, and every site that reports under
one consumes the declaration by reference. `PolicyRequirement.__post_init__`
(`policy/profile.py:152-192`) now refuses a permitted name the registry has not
declared with `PolicyError(reason="implementation_not_registered")` (`:178-192`),
carrying the offending `implementation` and its `check_id`, and refuses an EMPTY
registry first and distinctly with `reason="implementation_registry_empty"`
(`:169-177`). "No such implementation" is a configuration error at
construction; "exists but unavailable right now" is doctrine #1's `Unavailable`
at assessment (`policy/coverage.py:331-334`), and the two vocabularies are
disjoint (`tests/conformance/test_implementation_registry.py`,
`test_no_such_implementation_and_implementation_unavailable_are_different_refusals`).

**The second check, added after review (PR #111, P2).** A declaration is a
claim. `load_profile` and the trusted resolver (`policy/resolver.py`) verify
that every permitted name's declared site resolves and reports the identity,
refusing with `implementation_site_unresolved`; a declaration made with the
class in hand is verified at the declaration. So a deployment that misdeclares
its own implementation gets a configuration error at first use, not incomplete
coverage on every assessment — the G26 failure one layer up, closed the same
way.

**What this buys the design.** `CHECK_TARGET_STATE`'s implementation is declared
in the registry like `git-merge-check` is; a policy naming a misspelling of it,
or a declaration of it that points nowhere, is refused when the policy is
constructed or first used, not on every assessment thereafter. The registry's
own stated limits carry over: registered means "the code at this site reports
this identity", not that the code does what the check means — a stub reporting
the real identity is caught by implementation identity at coverage
(`policy/coverage.py:272-284`) and the trust store's fixed tier, not by
registration — and a policy that permits the WRONG registered implementation
for `CHECK_TARGET_STATE` is caught by nothing today (OPEN-GAPS G27: no
implementation-to-check binding exists). The state-pin requirement's permitted
set is therefore a shipped-profile constant, not a customer-editable field,
until G27 is ruled on.

### 3.2 The four cases

| case | outcome |
|---|---|
| **Read fails entirely** (unreachable, auth refused, timeout) | `Unavailable` with the reason. **Halts.** `tools/git.py:204-205`'s existing shape |
| **Read partially succeeds** | **`Unavailable`. A partial digest is NEVER compared.** A digest over the readable half is a different measurement wearing the same name, and would compare equal while the unreadable half moved. The refusal names which aspects could not be read |
| **Subject exceeds bounds** | `Unavailable`, following `chokepoint/reconcile_gate.py:133`: *"gate snapshot exceeds bounds"* raises rather than truncating. A truncated read is a partial read |
| **Read succeeds** | Compare. §4 governs |

### 3.3 UNAVAILABILITY ALWAYS HALTS

**This replaced rev 1's §3.3, which was too clever and factually wrong.**

Rev 1 said refuse-vs-route "is already a policy property" decided by risk class
and `escalate_below`. **Measured false.** `ActionGate.decide` handles
`Unavailable` *before* `_outcome` is ever called and returns a terminal
`OUTCOME_UNAVAILABLE` (`gate/authorization.py:137-149`; `_outcome` at `:168`;
`escalate_below` consulted only there, `:184-185`). `submit()` records it
distinctly and halts (`execution/controller.py:165-186`), and the existing
comment says why (`:169-172`):

> *It is deliberately NOT parked as an approvable hold: a human must not be able
> to approve execution of an action whose HARD verification never ran.*

**Ruling: unavailability always halts. There is no routing path and none is to
be added.** A human asked to approve an action whose live state could not be
read is being asked to approve on no information — which is the same thing the
existing comment refuses, for the same reason.

The existing code already implements this ruling. What rev 1 got wrong was
claiming it as *configurable*; it is not, and it should not become so.

**Note for §4:** an execution-time re-read never reaches the gate at all, so it
cannot produce `OUTCOME_UNAVAILABLE` by that route. Its unavailability must be
handled where the comparison happens — §4.1 places the first comparison before
approval, §4.4 the second immediately before the statement; both refuse, and
§6.2's record carries the reason as a field that is present on every record,
not only on failures.

### 3.4 Q3 — ANSWERED BY THE OWNER: YES to a named opt-out — RULED (rev 3): PER ACTION CLASS

> *"Remove the requirement" is indistinguishable from never having had it;
> G21's deliberate-unbounded is the precedent. A named opt-out appears in the
> record.*

Overturned my rev-1 lean. The reasoning is G21's exactly (`docs/OPEN-GAPS.md`
G21): a posture reached by *absence* states nothing — it is what an unset
variable and a deliberate choice both look like. The opt-out is a named value
that appears in the record and in the posture, so "this deployment chose not to
re-observe" is legible rather than inferred from a missing requirement.

**RULED (rev 3): the opt-out is PER ACTION CLASS, not global.** The owner's
reasoning: a global switch disables re-observation everywhere, which is what a
deployment reaches for under pressure and which nothing in the record
distinguishes from "this class doesn't need it". Per action class forces the
opt-out to name what it is opting out of, and the record names it. Same
argument as G21's deliberate unbounded, whose three neutralizable bounds are
per-field, not one switch: the choice must be visible and specific.

**Design consequence.** The posture field is a mapping, action class → named
reason, from the closed `ACTION_CLASSES` (`policy/snapshot.py:150-156`); a
class absent from the mapping is re-observed. A hold's pinned record carries
`target_state.opted_out = <reason>` for its own class when opted out, so the
record says it rather than the reader inferring it from a missing digest — the
present-or-absent rule of §6.2 applied to the opt-out itself. An opt-out for a
class not in `ACTION_CLASSES` is refused at load, like any other unknown class.

---

## 4. WHAT A MISMATCH MEANS — RULING (rev 3: two comparisons, two consequences)

### 4.1 The FIRST comparison runs BEFORE approval is recorded

**This replaced rev 1's §4 ruling, which was wrong.**

Rev 1 ruled that a mismatch **invalidates** the hold, following rotation. That
does not work at execution time, and the review's reasoning is confirmed by
measurement:

- `invalidate_pending_action` is `UPDATE … WHERE id = ? AND status = ?` with
  `_PENDING_STATUS` (`ledger/sqlite_ledger.py:536-555`; the constant is `:184`),
  returning `rowcount == 1` — **it only touches rows still pending**, by the
  same deliberate guard that stops a rotation re-opening a decided hold;
- `approve()` writes `resolve_pending_action(status=APPROVED)`
  (`execution/pending.py:344-350`) before returning the `GateDecision` the
  executor runs (`:354-362`), so **an execution-time comparison runs after
  APPROVED is set**;
- a mismatch there would refuse and leave an **approved hold that was never
  claimed** — `claim_pending_execution` sets `execution_committed_at` only when
  NULL (`sqlite_ledger.py:566-570`) — i.e. **approved and retry-eligible, against
  a state that already failed**. Worse than either option in rev 1's table.

**Ruling: the first comparison runs BEFORE recording approval.** Not a new
post-approval invalidation transition.

Two invariants make this the right shape rather than merely the working one:

1. **The human's approval is recorded only if the state it was predicated on
   still holds.** An approval on record is an approval that meant something.
2. **"An approved hold is executable" stays an invariant** — with §4.4's one
   terminal exception, which is an *exit* from approved, not an approved hold
   that is refusable.

Placement: the comparison belongs beside `_revalidate(pending)`
(`execution/pending.py:334`), which measured **already runs before the TTL
check (`:338`) and before the APPROVED write (`:344`)**. A refusal there leaves
the hold PENDING, which is a state the system already understands and which
rotation's invalidation can still act on.

### 4.2 THE CONSEQUENCE THIS CREATES — what the human sees at approval

Stated because it is a real cost and the owner asked for it explicitly.

**The approval is refused at the moment it is given.** A reviewer reads the plan,
reads the diff, decides yes, clicks approve — and is told the approval was not
recorded because the target moved while they were deciding. Their decision is
discarded. Not deferred, not queued: discarded, because it was predicated on a
state that no longer exists.

Three things follow, and they are design obligations rather than side effects:

1. **The refusal must say what moved**, not "state mismatch". A reviewer told
   only that something changed cannot tell a consequential change from an
   unrelated index. §6's aspect list is what makes this possible; without it the
   message is exactly the G17 shape — a refusal named for enforcement that
   conveys nothing.
2. **The remedy must be one step, not a restart.** Re-pin against the current
   state and present the reviewer the *difference*, so the second decision is
   informed by what the first one missed. A remedy that discards the review
   entirely trains people to approve twice without reading.
3. **Frequency is the real risk.** If this fires often, reviewers learn that
   approval sometimes just fails and click again. §4.3's any-difference ruling
   makes it fire more often than scope-limiting would, and that trade is
   deliberate — but **the frequency should be measured in a real deployment
   before the ruling is treated as settled.** I would rather be told the number
   than argue it from first principles. §1.5 is what keeps this number from
   being *every execution*.

### 4.3 Refuse on any difference in the covered set

| option | cost |
|---|---|
| any difference | Simple and provable. Refuses on unrelated drift, which trains overrides |
| within touched scope | Precise. Needs a second analysis deriving touched scope from the artifact; does not exist; **fails open** when the derivation is wrong |
| any difference + explicit re-review that re-pins | Conservative, with the release valve named and recorded rather than an override |

**Ruling: option 3.** The re-pin is a new human decision, recorded and chained,
distinguishable from the original — not a flag that suppresses the check.

Scope-limiting is a later, separately-ruled refinement. If built: undeterminable
scope must fall back conservative, and the scope derivation must itself be a
permitted implementation answering a requirement, so "scope could not be
derived" is an `Unavailable` rather than an empty set. **An instrument returning
an empty set reads downstream as a pass.**

**Typed reasons** join `EXECUTION_REFUSAL_REASONS` (`policy/execution.py:54-66`),
distinct from `reverification_required` and from `chain_did_not_verify` so none
can stand in for another: `target_state_moved_before_approval` for §4.1's
refusal, and `state_moved_after_approval` for §4.4's.

### 4.4 THE SECOND COMPARISON: the pre-execution re-read — RULED (rev 3)

**Ruling: a mismatch on the pre-execution re-read REFUSES THE EXECUTION AND
MAKES THE HOLD TERMINAL.** Not advisory. The owner's reasoning, recorded as the
ruling's ground: the two comparisons answer different questions and both are
needed — the pre-approval comparison makes the APPROVAL meaningful, the
pre-execution re-read makes the EXECUTION meaningful. When the second fails, the
state moved after a human looked at it, so the approval is stale as a matter of
fact, and retrying cannot make it fresh. A recorded mismatch that does not stop
execution is the "state verified" receipt this design exists to prevent.

**The terminal state, and why it is a new one.** Today a hold leaves PENDING by
exactly four transitions (`execution/models.py:19-33`): APPROVED (`:30`),
REJECTED (`:31`), EXPIRED (`:32`, the TTL, via `_is_lapsed`
`execution/pending.py:504` and `_expire` `:510`), INVALIDATED (`:33`, a policy
rotation, via `_invalidate` `:567` and `invalidate_pending_action`
`sqlite_ledger.py:526-555`). The new state is entered FROM APPROVED, which no
existing transition does — `resolve_pending_action` and
`invalidate_pending_action` both guard `WHERE … status = 'pending'`
(`sqlite_ledger.py:508`, `:541`), deliberately, so a decided hold is never
rewritten. So this is a **new ledger operation with the opposite guard**
(`WHERE status = 'approved'`), a new `PendingStatus` member,
`STATE_MOVED_AFTER_APPROVAL`, and a distinct `decision_reason` naming what moved.
Distinct from expiry (time passed) and from rotation-invalidation (the policy
changed), because the cause differs and the record must say which.

**What it must and must not do to the claim.** The execution was claimed before
the re-read (`claim_pending_execution`, `controller.py:315-317`). After a
state-moved refusal the claim is **not released**: `release_pending_execution`
(`sqlite_ledger.py:574-586`) exists for refused, side-effect-free executions so
the hold stays retry-eligible, and retry-eligible is exactly the outcome the
owner ruled against. `retry_decision` (`pending.py:386-405`) refuses rejected,
expired and invalidated holds; it refuses the terminal state the same way, so
"retry" cannot re-open it by any verb.

**Re-verification means a NEW hold with a NEW approval.** The human sees the new
state and decides about it; they do not re-approve the old decision. The new
hold's pinned record carries the new digest; the terminal hold's observation
record carries what moved. Nothing links them except the reader — which is the
same as rotation today, and is a limit to state rather than a join to invent.

**Three obligations, stated rather than left to be discovered:**

- **(a) The observation record carries BOTH comparisons**, each with its
  digest, its capture moment and its result. One receipt must show that state
  was checked twice and what moved. §6.2 rules the shape: an entry at each
  comparison, and the final entry restates the first so it stands alone.
- **(b) The TOCTOU residual is bounded, not closed**, and the window is now
  read-to-execute rather than approve-to-execute. What bounds it: the re-read
  runs on the runner's own connection (§7.3's hard invariant), inside the same
  transaction as the migration at default isolation (`autocommit=False`,
  `runner.py:806`; READ COMMITTED), AFTER the runner's advisory locks are held
  (`:819-828`) and AFTER the receipt bootstrap has committed (`:862`), and
  immediately before `:911` with nothing but the session-setting statements
  between. §7.1 records the residual verbatim, as rev 1 did.
- **(c) The human-facing consequence, for BOTH failures.** §4.2 states the
  first. The second is a different experience and an operator will hit it: an
  approval that SUCCEEDED, followed by an execution that was refused and a hold
  that reads terminal. The operator sees a hold they approved, marked
  `state_moved_after_approval` with the aspects that moved, not executed and
  not retryable; the approval was valid when given and the record says so; the
  remedy is a new hold, which means the whole review again, against the new
  state. The refusal must say what moved (as in §4.2), must say that the
  approval stands as a record of a correct decision on the state it was given,
  and must name the remedy. An operator who reads "refused" on something they
  approved and is not told why will retry, find they cannot, and then remove the
  requirement — which is the G21 road again.

---

## 5. DESTRUCTIVE-CHANGE DETECTION — SCOPING NOTE ONLY

Not designed here; a different feature.

**What exists: nothing.** No migration SQL analyser, no operation
classification, no protected-target list (§0.3).

**What a classifier would need to cover:** `DROP TABLE`/`COLUMN`/`CONSTRAINT`;
`ALTER COLUMN TYPE` with a narrowing cast; `TRUNCATE`; `DELETE` without `WHERE`;
`SET NOT NULL` on a column with nulls; `DROP INDEX` a constraint depends on;
anything under `CASCADE`; and the same reachable through `DO $$ … $$`, a
function call, or dynamic SQL. **That last item is why a code-side classifier
loses**: an enumeration of forbidden shapes over a Turing-complete input, which
is the failure C1–C3 measured.

**The measurement supports the owner's prior.** The existing mechanism for "this
is irreversible, require the proof that makes it safe" is already a
`PolicyRequirement` in customer-editable policy (`policy/profile.py:415-425`). A
permitted-operations allowlist per program is the same shape.

**The residual, so agreeing does not hide it:** an operation allowlist still has
to decide *what operation this SQL performs* — the same analysis problem one
layer up. The difference is the failure direction: an allowlist that cannot
classify refuses, a detector that cannot classify permits. **That difference is
the argument, and it should be recorded as an argument, not as a claim that
policy dissolves the problem.**

---

## 6. WHAT THE RECORDS MUST SAY — RULING (rev 3: two comparisons, attempt-keyed)

*A record saying "state verified" without naming its coverage is the same class
as a guard named for enforcement that checks spelling.* That is G17 restated.

### 6.1 The pinned authorization record — what was AUTHORIZED

| field | why |
|---|---|
| `target_state.digest` | The pinned digest, known at hold creation |
| `target_state.capture_point` | Which moment it describes (`review` today; `rehearsal` when the successor feature lands) |
| `target_state.aspects` | **The anti-G17 field.** The covered set *as actually encoded*, so a record written by an older version names its own narrower set instead of being read under today's |
| `target_state.observed_at` | When the pinned read happened |
| `target_state.opted_out` | Present, with the named reason, when this hold's action class is opted out (§3.4). A record with no digest and no opt-out is malformed, not "opted out" |

### 6.2 The execution-observation record — what was FOUND

Chained entries under the subject `(attempt_id, execution_attempt)` (§2.2):
one at the pre-approval comparison, one at the pre-execution re-read. The
second **restates** the first — its digest, capture moment and result — so the
final entry stands alone as the one receipt showing state was checked twice
(§4.4 obligation a), and a test must show that a final entry whose restated
values differ from the first entry is refused (a restatement is a copy, and a
copy is checked against its source the way `_require_chain_binding` checks a
row against its entry, `execution/pending.py:655`).

| field | why |
|---|---|
| `comparison` — `pre_approval` \| `pre_execution` | Which of the two this entry is |
| `pinned_digest` | What it was compared against — so the record stands alone rather than requiring the reader to join two rows correctly |
| `observed_digest` | What was found |
| `observed_at` | The capture moment |
| `matched` | The result |
| `aspects` | The covered set at observation time. If it differs from the pinned record's, that itself is a finding: the two digests are not comparable |
| `unavailable` — `{reason, aspects_unread}` or an explicit `null` | When the read could not run. **Present or absent is not enough**: a record that omits the field on failure is indistinguishable from one where the check passed |
| `outcome` | `matched` \| `target_state_moved_before_approval` \| `state_moved_after_approval` \| `unavailable` — the typed reason, so the entry says what happened to the hold without the reader inferring it from `matched` and `comparison` together |
| `prior` — the restated `pre_approval` entry | On the `pre_execution` entry only. Obligation (a): one receipt shows both |
| `subject` | `(attempt_id, execution_attempt)` — the link to its hold and to the execution it describes, structural (§2.2) |

### 6.3 What the records must NOT contain

**The state itself** — only digests and aspect lists. A catalog dump in the
ledger is an unbounded persisted blob, and `verifier/model_judge.py`'s F8 defect
(the raw model response reaching `Evidence.detail`, putting a bearer token in
the ledger beside a PASS; the corrected line is `:97`) is the measured precedent.

---

## 7. ADVERSARIAL PASS

Both known attack classes — **deletion AND cross-context substitution** — against
every instrument. The composition pins shipped with deletion proofs only and the
substitution case was found by review (G25); the distinction does not transfer
by itself. G26's registry shipped with both, this time (its proof module's
docstring lists them).

### 7.1 TOCTOU — the answer and the measured residual

Measured from `chokepoint/runner.py`:

- the connection is `autocommit=False` (`:806`) at **default isolation, READ
  COMMITTED** — each statement takes a fresh snapshot;
- `pg_advisory_lock(hashtextextended(execution_id))` (`:819-823`) is
  session-scoped and keyed on the **execution id** — it serialises *this
  runner's* executions;
- `pg_advisory_xact_lock('promethyn-receipt-bootstrap-v1')` (`:824-828`) is
  keyed on a **constant** and released by the `connection.commit()` at `:862`;
- **neither lock is keyed on the target objects.**

Nothing today excludes third-party DDL between any two statements.

| bound | strength | cost |
|---|---|---|
| 1. Compare immediately before execution, same transaction, READ COMMITTED | Narrows to the gap between two statements. **Does not eliminate it** | None |
| 2. `REPEATABLE READ` for the apply transaction | Read and apply share one snapshot | Changes the runner's isolation; **own ruling, not folded in here (owner)** |
| 3. Advisory lock keyed on the **target** | Excludes other Promethyn sessions | Does nothing about a DBA at a psql prompt; **own ruling, not folded in here (owner)** |
| 4. `LOCK TABLE … ACCESS EXCLUSIVE` | Genuinely excludes concurrent DDL | Needs the touched set — §4.3's deferred scope derivation, in a harder form |

**Ruling: (1) now; (2) and (3) are separate rulings the owner has reserved;
(4) is unavailable.**

**The residual, as it must appear in the docs, verbatim from rev 1:** *a state
comparison immediately before execution narrows the window to the gap between
two statements in one transaction at READ COMMITTED. It does not eliminate it. A
session that commits DDL inside that window is not detected. The control against
that is a lock on the target, which this design does not take.*

**Rev 3: the window is read-to-execute, and what bounds it is stated.** With
§4.1 moving the first comparison before approval, approval-to-execution can be
long, so the design needs **both** comparisons — the pre-approval one for the
approval invariant, and the pre-execution re-read (bound 1) for the window. The
re-read's placement is the bound (§4.4 b): after the locks at `:819-828`, after
the bootstrap commit at `:862`, immediately before `:911`. The window that
remains is the gap between the re-read statement and the migration statement,
and it is not zero.

**The open question of rev 2 is answered by §4.4** — refuse and terminal, never
advisory — and is no longer open.

### 7.2 A digest stable under a change it should catch

| shape | closed? |
|---|---|
| Aspect collected but not encoded | **Closed by construction.** The encoder iterates `STATE_ASPECTS`; the every-aspect-moves-the-digest test catches a collected-and-ignored aspect |
| Aspect encoded but **type-collapsed** — `"True"` vs `True`, or `["a","bc"]` vs `["ab","c"]` | **Closed by reuse.** The existing encoder type-tags and length-prefixes, with the three named tests (`test_bound_requirements_encoding.py:223, 233, 240`). This design **must reuse that encoder**; a second encoder is the hand-enumeration failure again |
| The aspect list is **incomplete** | **NOT closed. Named limit** (§1.1). The single largest residual, and no test can close it — a test cannot know what nobody thought of. §6's `aspects` field is the mitigation: it makes the gap legible |
| **The inverse: a digest UNSTABLE under no change** — an aspect that varies between two reads of the same target, so an unchanged target mismatches | **Closed for the two cases found, named as a class.** Finding 5 was one (per-session settings the executor sets); §1.5's sweep found the second (the receipt namespace the executor creates). The rule in §1.2 excludes session-sourced values and the runner's namespace. The class is wider than both — anything the executor mutates on the way in, or that varies by connection (`pg_backend_pid()`, transaction snapshot ids, `now()`) — and **a test must read the same target twice from two sessions and require equal digests**, with the second read taken after the first session has done everything the runner does before `:911`, which catches this class without enumerating it |

### 7.3 A target readable but served by a replica

A read replica has the same schema and produces a matching digest while the
primary — where the migration executes — has moved. **The digest cannot close
this**, which is why §1.3 keeps replication topology out of it.

**Q4 — ANSWERED BY THE OWNER: same-connection is a HARD INVARIANT.**

> *If it cannot be, that is a finding, not a configuration.*

The reader is handed the runner's cursor with no way to pass another connection —
the same shape as `AuthorizedExecution` (`policy/execution.py:155`) being
mintable only by the seam: a capability that cannot be constructed elsewhere
needs no check that it was not. A `pg_is_in_recovery()` assertion is then belt,
not the mechanism.

**And the owner's second clause is the load-bearing half.** If the architecture
turns out not to permit a hard invariant — if some path must read on a different
connection — that is a **finding to report**, not a configuration switch to add.
The receipt-lookup path at `runner.py:977-983` opens a second connection today;
it reads the runner's own receipts, not the target's state, and the re-read must
not be placed there.

### 7.4 Concurrent migrations from another source

Partly covered by 7.1; the remainder is the migration-version-table aspect,
which catches "another migration landed" **if** the other source uses the same
version table.

**Named limit:** out-of-band DDL that touches nothing in the covered set is not
detected. After §1.5, that explicitly includes DDL inside `promethyn_internal`.

### 7.5 Both attack classes against every instrument

| instrument | **deletion** | **cross-context substitution** |
|---|---|---|
| `TargetState` / `STATE_ASPECTS` | An aspect removed narrows the digest silently. **Needs a pinned aspect count plus the aspect list in the record** | An aspect **renamed** keeps the count and changes the preimage. Worse: an aspect whose *collection query* is repointed at a different object — same field name, different subject — yields a valid-looking digest of the wrong thing. **Needs a known-answer test per aspect** binding the name to what it reads, including the `promethyn_internal` exclusion and the `pg_settings` source filter |
| The state digest encoder | Field dropped from the preimage. Caught by the existing test **if the encoder is reused** | Reusing the *requirements* domain separator would let a requirements preimage and a state preimage collide. `test_the_domain_is_not_shared_with_the_posture_digest` (`test_bound_requirements_encoding.py:146`) is the precedent; **the state digest needs its own domain and its own version of that test** |
| `CHECK_TARGET_STATE` requirement | Removed from the policy → no check. Visible in the policy digest, which is in the record | A **different implementation** answering it. Three shapes, and the registry covers two: a stub under an UNDECLARED name is refused at construction; a declaration whose site does not report the identity is refused at first use; a second site claiming the identity is refused by the registry (`policy/implementations.py`). The third — the policy itself permitting a **wrong registered** implementation for the check — is caught by nothing (OPEN-GAPS G27, found by review of PR #111; the earlier version of this row claimed it was covered). Until G27 is ruled on, the permitted set for this requirement ships as a profile constant and the record carries the policy digest that fixed it |
| **The execution-observation record** | Not written → no observation. **A missing record must be a refusal, not an absence**: §6.2's rule that omitting the unavailable field is indistinguishable from passing applies to omitting the whole record, and to omitting the `pre_execution` entry after the `pre_approval` one | **Written against the wrong subject** — a valid observation record chained under another attempt's key, or a `pre_execution` entry whose restated `prior` differs from the `pre_approval` entry. The key is structural (§2.2); the restatement is checked against its source (§6.2); a test must show each is refused |
| The comparison, twice | Deleted → nothing compares. Either comparison deleted → the other still runs and the record shows one entry where two are required | **Compared against the wrong capture** — the observed digest against itself, which always matches. **This passes every deletion probe** and is the shape the composition pins shipped with. Any implementation sprint must prove it with a substitution mutation, for BOTH comparisons |
| The placement of the re-read (§1.5) | Moved before the bootstrap → matches on a fresh target only by luck of ordering | Moved after `:912` → measures the execution itself and mismatches on every run. **A known-answer test pins the statement it runs before** |
| The per-class opt-out (§3.4) | Removed from the posture → the class is re-observed, which is the safe direction | **Widened** — a class name outside `ACTION_CLASSES`, or a mapping value that is not a named reason — refused at load, like every other unknown class; a test must show the widening refused rather than ignored |

---

## SUMMARY

**Ruled by the owner:**

- **Scope: re-observation at execution, generally** — not migrations only.
- **Q1** covered set **fixed**; **Q2** rehearsal is a **successor feature**, not
  a prerequisite (the owner's own correction), and the claim is *"the pinned
  aspects have not changed since review, and here is the aspect list"*; **Q3**
  **yes** to a named opt-out, **per action class**; **Q4** same-connection is a
  **hard invariant**, and if it cannot be, that is a finding.
- **Two chained records**, not one mutated record; the observation record keyed
  on the **execution attempt**.
- **Two comparisons**: before approval is recorded, and immediately before the
  statement. A mismatch on the second **refuses the execution and makes the hold
  terminal** (`state_moved_after_approval`); re-verification is a new hold with a
  new approval. Never advisory.
- **Unavailability always halts.**
- **Not in this design:** `REPEATABLE READ` and a target-keyed advisory lock are
  separate rulings; G24 and G22 await rulings and are not implemented.

**Ruled by me, revisable:**

- §1 derived covered set, ten aspects in, **five** out as named limits — the
  fifth (the runner's own receipt namespace) found by §1.5's sweep under the
  generalised principle, with a two-sessions-equal-digest test required whose
  second read post-dates everything the runner does before `:911`.
- §2.2 the execution-attempt identity is minted at the claim, as an ordinal per
  hold or a fresh id, and the subject is `(attempt_id, execution_attempt)`.
- §4.3 refuse on any difference, with an explicit re-review that re-pins;
  scope-limiting deferred and must fail conservative.
- §4.4 the terminal transition is a new ledger operation guarded on `approved`,
  the claim is not released, and `retry_decision` refuses the state.
- §6 the records name their covered set and never the state itself; the
  `pre_execution` entry restates the `pre_approval` entry and the restatement
  is checked.
- §7.1 bound (1) now.

**Prerequisite — LANDED in this change:**

- **G26** — `policy/implementations.py` and `PolicyRequirement.__post_init__`
  (`policy/profile.py:168-192`). The tracker entry records the registry's
  population, its derivation and its executed mutations.

**Open, for the owner:**

- **§2.2** — the *form* of the execution-attempt identity (ordinal vs fresh id).
  Mine to rule and ruled above; flagged because it is the one place a
  retry's history is keyed.
- **§6.2** — whether the `pre_approval` entry is written at approval (ruled
  above: yes, so a crash between approval and execution loses nothing) or
  carried in memory and written only with the `pre_execution` entry.
- **§4.2 / §4.4 (c)** — the frequency of both refusals in a real deployment,
  which nothing here can measure.

**Implementation of re-observation starts after this revision is accepted;
§3.1's prerequisite no longer blocks it.**
