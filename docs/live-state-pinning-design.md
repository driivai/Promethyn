# Re-observation at execution — DESIGN ONLY, revision 2

**Status: design. Nothing here is implemented.** Revision 2 incorporates four
findings from the review of revision 1 (PR #109), **two of which overturn
rulings I made**, and the owner's answers to the four open questions.

The roadmap claim under review: *"catches destructive changes and refuses
execution when reviewed assumptions have become stale."*

**Scope, ruled by the owner: RE-OBSERVATION AT EXECUTION, GENERALLY** — not
migrations only. §0.1 measured that the gap is in the *replay* path, so every
action class has it, and `branch.delete`'s merge proof is a concrete data-loss
path today. It is also the more honest claim: *"evidence is re-observed before
execution"* is a property of the seam, which is what the product sells.

---

## WHAT CHANGED IN REVISION 2, AND WHAT I GOT WRONG

Recorded here rather than silently replaced.

| # | rev-1 ruling | why it was wrong | rev-2 ruling |
|---|---|---|---|
| 1 | §2: the observed digest joins **the pinned record** at execution | **A record written once and required byte-equal to its chain payload cannot carry a value only known at execution.** `_require_chain_binding` compares `stored != pending.record` over the *whole* record. Writing the observation into it would break the binding it was meant to be protected by | A **separate append-only chained execution-observation record**. Two records, two moments, both chained. §2, §6 |
| 2 | §4: a mismatch **invalidates** the hold, following rotation | `invalidate_pending_action` is `WHERE id = ? AND status = ?` with `_PENDING_STATUS` — **pending rows only** — and an execution-time comparison runs after `approve()` has written APPROVED. The mismatch would refuse and leave an **approved, retry-eligible** hold: worse than either option, because it will be retried against a state that already failed | The comparison runs **before approval is recorded**. Not a new post-approval transition. §4 |
| 3 | §3.3: refuse-vs-route "is already a policy property" | **Measured false.** `ActionGate.decide` handles `Unavailable` *before* `_outcome` and returns a terminal `OUTCOME_UNAVAILABLE`; `submit()` records it and halts, deliberately **not** as an approvable hold. The routing logic is never reached | Unavailability **always halts**. The claim is deleted. §3 |
| 4 | §3.1: a requirement nothing can satisfy "is already refused at policy construction" | **Measured false.** `PolicyRequirement.__post_init__` validates identity normalisation, `applies_to` shape, non-emptiness, known action classes and duplicates — and **never** that an implementation exists or is registered | An implementation-registry validation step is a **stated prerequisite**, and the underlying defect gets its own entry, **G26**. §3.1 |

Findings 3 and 4 are the same error twice: I claimed existing machinery covered
something without reading it. That is the shape this repository keeps naming,
and it arrived here in the document arguing against it.

---

## 0. WHAT ALREADY EXISTS — measured 2026-09-15

### 0.1 The gap is in the replay path, so every action class has it

**Nothing in the tree reads a migration target's schema.** Every `pg_catalog`
call in `chokepoint/runner.py` is a session setting (`lock_timeout`,
`search_path`, `statement_timeout`), an advisory lock, or an existence check for
the runner's **own** receipt schema. The migration is
`cursor.execute(sql, prepare=False)` at line 911, sent unexamined.

**And the gap is not migration-specific.** At approval and execution, coverage
is **replayed from the persisted record** — `restore_coverage(record)` in
`execution/pending.py:621` — and nothing in `pending.py`, `controller.py` or
`executor.py` calls a verifier. Every action class executes against evidence
recorded at assessment time. A `branch.delete` held for review can gain commits
between the merge check and the approval, and the delete executes on the
replayed "zero unmerged commits".

That is why the owner scoped this to re-observation generally.

### 0.2 What exists that is reusable

| asset | reusable as |
|---|---|
| **`tools/git.py`** — reads live state, and already gets the doctrine right: *"a merge check that could not run is an `Unavailable`"*, `unmerged_commits: int \| None`, `provably_merged` only on a definite zero | The pattern for §3, and the first action class to get re-observation |
| **`chokepoint/reconcile_gate.py:108-145`** — `mode=ro`, `PRAGMA query_only=ON`, `trusted_schema=OFF`, a progress-handler deadline, explicit size bounds that raise rather than truncate | The pattern for a bounded state read |
| **The `BoundRequirements` encoder** — type-tagged, length-prefixed, domain-separated, with `test_type_tags_keep_lookalike_values_apart`, `test_a_sequence_cannot_be_confused_with_its_concatenation`, `test_a_value_cannot_forge_a_field_boundary` | The encoder the state digest **must reuse**, with its own domain |
| **`_DESCRIPTOR_FIELDS = tuple(f.name for f in dataclasses.fields(ExecutionDescriptor))`** | The derivation precedent for §1 |
| **`audit_chain.record_chained`** | The append-only chained write for §2's second record |

### 0.3 Presuppositions in the original brief that did not hold

1. **"reversibility analysis, rewrite counting"** — neither exists.
2. **"any schema read" in the live-PG step** — none.
3. **"`branch.delete`'s protected-target refusal"** — there is none. What it has
   is a `PolicyRequirement` for a merge proof. This supports the §5 prior.
4. **"the sandbox rehearsal for `database.migrate`"** — there is none.
   `database.migrate` carries one requirement, `CHECK_EXECUTABLE_CASES` /
   `IMPL_SUBPROCESS`, the same generic "untrusted code was run" check as
   `sandbox.execute`. It says nothing about a database.

---

## 1. WHAT IS "THE STATE"? — RULING (unchanged from rev 1)

### 1.1 The covered set is DERIVED, not hand-listed

A digest over table names that misses a column type change is an enumeration
wearing an allowlist's clothes. The cautionary case is `_DESCRIPTOR_FIELDS`:
three hand-written copies of six names that agreed only because a person kept
them agreeing.

**Ruling: the covered set is the field set of a frozen dataclass.**

```
TargetState                                            # one field per ASPECT
STATE_ASPECTS = tuple(f.name for f in dataclasses.fields(TargetState))
```

with three properties carried over:

1. the encoder iterates `STATE_ASPECTS`, so a new aspect is covered by
   construction;
2. a test asserts the encoded aspect set equals the dataclass fields
   (`test_the_encoded_field_set_equals_the_dataclass_fields` is the precedent);
3. a test asserts **every aspect moves the digest**
   (`test_every_field_actually_moves_the_digest` is the precedent). An aspect
   collected but not hashed is not covered.

**The honest limit.** Derivation makes the *encoding* total over the aspects. It
does not make the *aspect list* total over what the target can vary — that list
is still written by a person. §6's `aspects` field makes the gap legible rather
than invisible.

### 1.2 IN the pinned state

table/column existence, names, types, nullability, defaults · constraints ·
indexes **including validity** · triggers · views and dependent objects ·
extensions and enum members · permissions and role grants · migration-version
table state · server version and relevant settings · partitioning topology.

For `branch.delete` the equivalent `TargetState` is the merge-proof subject:
the branch tip, the base tip, and the unmerged-commit count.

### 1.3 OUT, as named limits

| out | why | the limit left |
|---|---|---|
| row count / table size | Changes on every write; including it refuses on almost every comparison — §4's failure in its purest form | Size affects how long a rewrite holds locks. A migration reviewed against 1k rows and executed against 100M is *correct* and may still cause an outage. Not covered. A size-bound check is a separate feature |
| data content | Unbounded; a digest over content is a digest over the database | A migration whose safety depends on data (a `NOT NULL` backfill assuming no nulls) is not covered. That is a data precondition and belongs in the migration's own checks |
| replication topology | Not a property of the schema; a property of *which server answered* | Handled in §7.3 by a different control |

### 1.4 Q1 — ANSWERED BY THE OWNER: the covered set is FIXED, not per-policy

> *A customer narrowing it with no signal turns an allowlist back into an
> enumeration.*

**And finding 4 is why this is the right call rather than merely the safer one.**
A customer-supplied policy has no shipped-profile constants protecting it. The
`IMPL_*` names in `policy/profile.py` are bare strings whose docstrings say they
were "read off `SubprocessVerifier.VERIFIER_ID`" — correct because a person
copied them correctly, not because anything checks. A per-policy covered set
would hand the same unchecked surface to the aspect list, where a typo or a
narrowing is indistinguishable from a deliberate choice.

---

## 2. CAPTURE, BINDING, AND THE EXECUTION OBSERVATION — RULING (REWRITTEN)

### 2.1 Capture point

- **(a) at rehearsal** — does not exist today (§0.3).
- **(b) at review / hold creation** — available.
- **(c) both, compared** — the correct end state.

**Q2 — ANSWERED BY THE OWNER: schema rehearsal is a PREREQUISITE.**

> *Ship "the pinned aspects have not changed since review, and here is the
> aspect list" — never "the reviewed assumptions hold."*

So the claim this feature is allowed to make is fixed in advance, and it is the
narrow one. My rev-1 inclination was the opposite and the owner's reasoning
against it is mine turned around: shipping the broad sentence while building the
narrow thing is how G17 and G23 happened.

### 2.2 TWO RECORDS, TWO MOMENTS, BOTH CHAINED

**This replaces rev 1's §2 ruling, which was wrong.**

Rev 1 put the observed digest into the pinned authorization record at execution.
That cannot work, and the reason is the mechanism that makes the record
trustworthy in the first place: `_require_chain_binding` compares
`stored != pending.record` over the **whole** record against its chain payload.
A record written once and required byte-equal to its chain entry **cannot carry
a value only known later**. Writing the observation in would either break the
binding or require mutating a chained payload — and mutating a chained payload
is the thing the chain exists to detect.

**Ruling — the remedy from the review, adopted:**

| record | written | says | chained |
|---|---|---|---|
| **Pinned authorization record** (exists today) | once, at hold creation | what was **authorized**: requirements, policy version, coverage, and **the pinned state digest + aspect list** | yes, unchanged mechanism |
| **Execution-observation record** (new) | once, at the comparison | what was **found**: the observed digest, the comparison result, or the unavailable reason | yes, its own append-only chained entry |

Both are append-only. Neither is mutated. The pinned record's byte-equality
check is untouched, so this adds a record without weakening the one that exists.

**Not outside the chain.** An observation in a plain column would be trusted
because it is in the record and covered by nothing — the exact split Block 1a
closed when integrity moved from re-resolution to the record.

**What still holds from rev 1:** the pinned *state digest* does go inside the
pinned record, because it is known at hold creation. `RECORD_VERSION` bumps
1 → 2, so every pre-existing hold becomes `reverification_required` — correct
fail-closed behaviour, and an operational event for the release note rather than
a discovery for an operator.

**Open, minor:** the observation record needs a subject key linking it to its
hold. `_hold_subject(pending.id)` is the existing convention; an
`_observation_subject(pending.id, attempt)` beside it is the obvious shape. Not
ruled here because it depends on whether a hold may ever be observed twice —
which §4's ruling makes "no", so a single-observation key is probably right.

---

## 3. WHAT IF THE STATE CANNOT BE READ? — RULING (REWRITTEN)

### 3.1 The mechanism: a policy requirement, with a prerequisite

**Ruling (unchanged): the state pin is a `PolicyRequirement` satisfied by a
permitted implementation**, like `CHECK_MERGE_PROOF`. `Unavailable` then flows
through machinery that already exists: the bank turns it into
`coverage.incomplete`, which is a refusal, in a closed vocabulary where every
reason already has an end-to-end row.

**WITHDRAWN: rev 1's claim that "a requirement nothing can satisfy is already
refused at policy construction."** Measured — `PolicyRequirement.__post_init__`
validates identity normalisation, that `applies_to` is a non-empty sequence of
**known action classes**, and that it has no duplicates. It **never** validates
that an implementation named in `permitted` exists or is registered. A typo
constructs cleanly and fails only as incomplete coverage on every assessment,
which reads as a runtime outage rather than a configuration error.

**PREREQUISITE, not part of this feature: an implementation-registry validation
step.** Policy construction must resolve every name in `permitted` against a
registry of implementations that exist, and refuse an unknown one. Filed
separately as **OPEN-GAPS G26** — it is a defect in the existing policy model
that this design surfaced, not a live-state issue, and folding it in would hide
a general defect inside a feature.

### 3.2 The four cases

| case | outcome |
|---|---|
| **Read fails entirely** (unreachable, auth refused, timeout) | `Unavailable` with the reason. **Halts.** `tools/git.py`'s existing shape |
| **Read partially succeeds** | **`Unavailable`. A partial digest is NEVER compared.** A digest over the readable half is a different measurement wearing the same name, and would compare equal while the unreadable half moved. The refusal names which aspects could not be read |
| **Subject exceeds bounds** | `Unavailable`, following `reconcile_gate.py`: *"gate snapshot exceeds bounds"* raises rather than truncating. A truncated read is a partial read |
| **Read succeeds** | Compare. §4 governs |

### 3.3 UNAVAILABILITY ALWAYS HALTS

**This replaces rev 1's §3.3, which was too clever and factually wrong.**

Rev 1 said refuse-vs-route "is already a policy property" decided by risk class
and `escalate_below`. **Measured false.** `ActionGate.decide` handles
`Unavailable` *before* `_outcome` is ever called and returns a terminal
`OUTCOME_UNAVAILABLE`; the routing logic is not reached. `submit()` records it
distinctly and halts, and the existing comment says why:

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
handled where the comparison happens — which §4 places before approval.

### 3.4 Q3 — ANSWERED BY THE OWNER: YES to a named opt-out

> *"Remove the requirement" is indistinguishable from never having had it;
> G21's deliberate-unbounded is the precedent. A named opt-out appears in the
> record.*

Overturns my rev-1 lean. The reasoning is G21's exactly: a posture reached by
*absence* states nothing — it is what an unset variable and a deliberate choice
both look like. The opt-out is a named value that appears in the record and in
the posture, so "this deployment chose not to re-observe" is legible rather than
inferred from a missing requirement.

**Open:** whether the opt-out is per-action-class or global. G21's three
neutralizable bounds are per-field, which suggests per-action-class.

---

## 4. WHAT A MISMATCH MEANS — RULING (REWRITTEN)

### 4.1 The comparison runs BEFORE approval is recorded

**This replaces rev 1's §4 ruling, which was wrong.**

Rev 1 ruled that a mismatch **invalidates** the hold, following rotation. That
does not work at execution time, and the review's reasoning is confirmed by
measurement:

- `invalidate_pending_action` is `UPDATE … WHERE id = ? AND status = ?` with
  `_PENDING_STATUS`, returning `rowcount == 1` — **it only touches rows still
  pending**, by the same deliberate guard that stops a rotation re-opening a
  decided hold;
- `approve()` writes `resolve_pending_action(status=APPROVED)` before returning
  the `GateDecision` the executor runs, so **an execution-time comparison runs
  after APPROVED is set**;
- a mismatch there would refuse and leave an **approved hold that was never
  claimed** — `claim_pending_execution` sets `execution_committed_at` only when
  NULL — i.e. **approved and retry-eligible, against a state that already
  failed**. Worse than either option in rev 1's table.

**Ruling: move the comparison BEFORE recording approval.** Not a new
post-approval invalidation transition.

Two invariants make this the right shape rather than merely the working one:

1. **The human's approval is recorded only if the state it was predicated on
   still holds.** An approval on record is an approval that meant something.
2. **"An approved hold is executable" stays an invariant.** Rev 1's design broke
   it — approved-but-refusable is a state nothing else in this system has, and
   every consumer that reads "approved" would have had to learn about it.

Placement: the comparison belongs beside `_revalidate(pending)`, which measured
**already runs before the TTL check and before the APPROVED write**. A refusal
there leaves the hold PENDING, which is a state the system already understands
and which rotation's invalidation can still act on.

### 4.2 THE CONSEQUENCE THIS CREATES — what the human sees

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
   than argue it from first principles.

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

**A new typed reason** joins `EXECUTION_REFUSAL_REASONS`: `target_state_moved`,
distinct from `reverification_required` and from `chain_did_not_verify` so none
can stand in for another.

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
`PolicyRequirement` in customer-editable policy. A permitted-operations
allowlist per program is the same shape.

**The residual, so agreeing does not hide it:** an operation allowlist still has
to decide *what operation this SQL performs* — the same analysis problem one
layer up. The difference is the failure direction: an allowlist that cannot
classify refuses, a detector that cannot classify permits. **That difference is
the argument, and it should be recorded as an argument, not as a claim that
policy dissolves the problem.**

---

## 6. WHAT THE RECORDS MUST SAY — RULING (REWRITTEN FOR TWO RECORDS)

*A record saying "state verified" without naming its coverage is the same class
as a guard named for enforcement that checks spelling.* That is G17 restated.

### 6.1 The pinned authorization record — what was AUTHORIZED

| field | why |
|---|---|
| `target_state.digest` | The pinned digest, known at hold creation |
| `target_state.capture_point` | Which moment it describes (`review` today; `rehearsal` when Q2's prerequisite lands) |
| `target_state.aspects` | **The anti-G17 field.** The covered set *as actually encoded*, so a record written by an older version names its own narrower set instead of being read under today's |
| `target_state.observed_at` | When the pinned read happened |

### 6.2 The execution-observation record — what was FOUND

A separate append-only chained entry, written once at the comparison:

| field | why |
|---|---|
| `pinned_digest` | What it was compared against — so the record stands alone rather than requiring the reader to join two rows correctly |
| `observed_digest` | What was found |
| `matched` | The result |
| `aspects` | The covered set at observation time. If it differs from the pinned record's, that itself is a finding: the two digests are not comparable |
| `unavailable` — `{reason, aspects_unread}` | When the read could not run. **Present or absent is not enough**: a record that omits the field on failure is indistinguishable from one where the check passed |
| `subject` | The link to its hold |

### 6.3 What the records must NOT contain

**The state itself** — only digests and aspect lists. A catalog dump in the
ledger is an unbounded persisted blob, and `verifier/model_judge.py`'s F8 defect
(the raw model response reaching `Evidence.detail`, putting a bearer token in
the ledger beside a PASS) is the measured precedent.

---

## 7. ADVERSARIAL PASS

Both known attack classes — **deletion AND cross-context substitution** — against
every instrument. The composition pins shipped with deletion proofs only and the
substitution case was found by review; the distinction does not transfer by
itself.

### 7.1 TOCTOU — the answer and the measured residual

Measured from `chokepoint/runner.py`:

- the connection is `autocommit=False` at **default isolation, READ
  COMMITTED** — each statement takes a fresh snapshot;
- `pg_advisory_lock(hashtextextended(execution_id))` is session-scoped and keyed
  on the **execution id** — it serialises *this runner's* executions;
- `pg_advisory_xact_lock('promethyn-receipt-bootstrap-v1')` is keyed on a
  **constant** and released by the `connection.commit()` at line 862;
- **neither lock is keyed on the target objects.**

Nothing today excludes third-party DDL between any two statements.

| bound | strength | cost |
|---|---|---|
| 1. Compare immediately before execution, same transaction, READ COMMITTED | Narrows to the gap between two statements. **Does not eliminate it** | None |
| 2. `REPEATABLE READ` for the apply transaction | Read and apply share one snapshot | Changes the runner's isolation; own ruling, own tests |
| 3. Advisory lock keyed on the **target** | Excludes other Promethyn sessions | Does nothing about a DBA at a psql prompt |
| 4. `LOCK TABLE … ACCESS EXCLUSIVE` | Genuinely excludes concurrent DDL | Needs the touched set — §4.3's deferred scope derivation, in a harder form |

**Ruling: (1) now; (2) and (3) deserve separate rulings; (4) is unavailable.**

**The residual, as it must appear in the docs:** *a state comparison immediately
before execution narrows the window to the gap between two statements in one
transaction at READ COMMITTED. It does not eliminate it. A session that commits
DDL inside that window is not detected. The control against that is a lock on
the target, which this design does not take.*

**Interaction with §4's ruling, which is new in rev 2 and matters.** Moving the
comparison before approval *widens* the TOCTOU window relative to rev 1:
approval-to-execution can be long. So the design needs **both** — the
pre-approval comparison (§4, for the approval invariant) **and** a
pre-execution re-read (§7.1 bound 1, for the window). Two comparisons, and the
execution-observation record (§6.2) carries the second.

**This is an open question the owner should rule on.** If the pre-execution
re-read finds a mismatch, the hold is APPROVED and finding 2's problem returns —
approved, unclaimed, retry-eligible. Options: (i) refuse and let the claim
mechanism mark it consumed, so it cannot be retried; (ii) allow a post-approval
invalidation transition after all, scoped only to this case; (iii) treat the
pre-execution re-read as advisory and record it without refusing — **which I
would refuse**, because a recorded mismatch that does not stop execution is the
"state verified" receipt this whole design exists to avoid.

### 7.2 A digest stable under a change it should catch

| shape | closed? |
|---|---|
| Aspect collected but not encoded | **Closed by construction.** The encoder iterates `STATE_ASPECTS`; the every-aspect-moves-the-digest test catches a collected-and-ignored aspect |
| Aspect encoded but **type-collapsed** — `"True"` vs `True`, or `["a","bc"]` vs `["ab","c"]` | **Closed by reuse.** The existing encoder type-tags and length-prefixes, with the three named tests. This design **must reuse that encoder**; a second encoder is the hand-enumeration failure again |
| The aspect list is **incomplete** | **NOT closed. Named limit** (§1.1). The single largest residual, and no test can close it — a test cannot know what nobody thought of. §6's `aspects` field is the mitigation: it makes the gap legible |

### 7.3 A target readable but served by a replica

A read replica has the same schema and produces a matching digest while the
primary — where the migration executes — has moved. **The digest cannot close
this**, which is why §1.3 keeps replication topology out of it.

**Q4 — ANSWERED BY THE OWNER: same-connection is a HARD INVARIANT.**

> *If it cannot be, that is a finding, not a configuration.*

The reader is handed the runner's cursor with no way to pass another connection —
the same shape as `AuthorizedExecution` being mintable only by the seam: a
capability that cannot be constructed elsewhere needs no check that it was not.
A `pg_is_in_recovery()` assertion is then belt, not the mechanism.

**And the owner's second clause is the load-bearing half.** If the architecture
turns out not to permit a hard invariant — if some path must read on a different
connection — that is a **finding to report**, not a configuration switch to add.

### 7.4 Concurrent migrations from another source

Partly covered by 7.1; the remainder is the migration-version-table aspect,
which catches "another migration landed" **if** the other source uses the same
version table.

**Named limit:** out-of-band DDL that touches nothing in the covered set is not
detected.

### 7.5 Both attack classes against every instrument

| instrument | **deletion** | **cross-context substitution** |
|---|---|---|
| `TargetState` / `STATE_ASPECTS` | An aspect removed narrows the digest silently. **Needs a pinned aspect count plus the aspect list in the record** | An aspect **renamed** keeps the count and changes the preimage. Worse: an aspect whose *collection query* is repointed at a different object — same field name, different subject — yields a valid-looking digest of the wrong thing. **Needs a known-answer test per aspect** binding the name to what it reads |
| The state digest encoder | Field dropped from the preimage. Caught by the existing test **if the encoder is reused** | Reusing the *requirements* domain separator would let a requirements preimage and a state preimage collide. `test_the_domain_is_not_shared_with_the_posture_digest` is the precedent; **the state digest needs its own domain and its own version of that test** |
| `CHECK_TARGET_STATE` requirement | Removed from the policy → no check. Visible in the policy digest, which is in the record | A **different implementation** answering it — a stub returning a constant digest. Covered by the implementation-identity rule (`coverage.invalid_evidence`) **only once G26's registry exists**; today the name is a free string |
| **The execution-observation record** (new in rev 2) | Not written → no observation. **A missing record must be a refusal, not an absence**: §6.2's rule that omitting the unavailable field is indistinguishable from passing applies to omitting the whole record | **Written against the wrong hold** — a valid observation record chained under another hold's subject. The subject key must bind to the hold *and* the attempt, and a test must show a correct-looking record under the wrong subject is refused |
| The comparison | Deleted → nothing compares | **Compared against the wrong capture** — the observed digest against itself, which always matches. **This passes every deletion probe** and is the shape the composition pins shipped with. Any implementation sprint must prove it with a substitution mutation |

---

## SUMMARY

**Ruled by the owner:**

- **Scope: re-observation at execution, generally** — not migrations only.
- **Q1** covered set **fixed**; **Q2** rehearsal is a **prerequisite**, and the
  claim is *"the pinned aspects have not changed since review, and here is the
  aspect list"*; **Q3** **yes** to a named opt-out; **Q4** same-connection is a
  **hard invariant**, and if it cannot be, that is a finding.
- **Two chained records**, not one mutated record.
- **Comparison before approval is recorded.**
- **Unavailability always halts.**

**Ruled by me, revisable:**

- §1 derived covered set, ten aspects in, three out as named limits.
- §4.3 refuse on any difference, with an explicit re-review that re-pins;
  scope-limiting deferred and must fail conservative.
- §6 the records name their covered set and never the state itself.
- §7.1 bound (1) now; (2) and (3) need separate rulings.

**Prerequisite, filed separately:**

- **G26** — `PolicyRequirement` never validates that an implementation exists or
  is registered. A typo constructs and fails as incomplete coverage on every
  assessment. This feature needs the registry; the defect is the policy model's,
  not this feature's.

**Open, for the owner:**

- **§7.1** — with the comparison moved before approval, a *second* pre-execution
  re-read is needed for the TOCTOU window, and a mismatch there hits finding 2's
  problem again. Three options in §7.1; I would refuse the advisory one.
- **§3.4** — is the named opt-out per-action-class or global?
- **§2.2** — the observation record's subject key, if a hold may ever be
  observed more than once.
