# Live-state pinning — DESIGN ONLY, awaiting a ruling

**Status: design. Nothing here is implemented.** Sections 1–4 and 6 carry a
ruling; section 5 is a scoping note; section 7 attacks the design. Every open
question is stated as a question with its options and their costs. Where a
decision is the owner's rather than mine, it says so.

The roadmap claim under review: *"catches destructive changes and refuses
execution when reviewed assumptions have become stale."*

---

## 0. WHAT ALREADY EXISTS — measured 2026-09-15

### 0.1 The stale-assumptions half does not exist, and the gap is wider than migrations

**Confirmed: nothing in the tree reads the migration target's schema.** Every
`pg_catalog` call in `chokepoint/runner.py` is one of three things, none of them
a read of the target:

| line | call | what it is |
|---|---|---|
| 816, 886, 895 | `set_config('lock_timeout' / 'search_path' / 'statement_timeout')` | session settings |
| 820, 825, 982 | `pg_advisory_lock`, `pg_advisory_xact_lock`, `pg_try_advisory_xact_lock` | locking |
| 842, 847, 993 | `to_regnamespace`, `to_regclass` | existence of the runner's **own** receipt schema/table |

The migration itself is `cursor.execute(sql, prepare=False)` at line 911. The
artifact SQL goes to the server unexamined, and no catalog state is read before,
during or after.

**The gap is not migration-specific.** Measured: at approval and execution,
coverage is **replayed from the persisted record** —
`restore_coverage(record)` in `execution/pending.py:621` — and nothing in
`pending.py`, `controller.py` or `executor.py` calls a verifier. So *every*
action class executes against evidence recorded at assessment time. A
`branch.delete` held for a human review can gain commits between the merge check
and the approval, and the delete will execute on the replayed "zero unmerged
commits". **That is the same defect this sprint is about, on the action class
that already has a live-state check.** It should be considered in scope for the
ruling even though the roadmap names migrations.

### 0.2 What exists that is reusable

| asset | what it is | reusable as |
|---|---|---|
| **`tools/git.py`** | Reads live target state (`git rev-list --count base..branch`), classifies, and gets the doctrine right already: *"a merge check that could not run is an `Unavailable` — could-not-verify"*; `unmerged_commits: int \| None`, `provably_merged` only on a definite zero | **The pattern for §3.** A live-state reader that fails closed into `Unavailable` rather than into a verdict |
| **`chokepoint/reconcile_gate.py:108-145`** | Reads a SQLite schema read-only, with `mode=ro`, `PRAGMA query_only=ON`, `PRAGMA trusted_schema=OFF`, a `set_progress_handler` deadline, and explicit size bounds that raise when exceeded | **The pattern for a bounded state read.** A read that cannot hang, cannot write, and refuses rather than truncating when the subject is too large |
| **The policy requirement mechanism** | `PolicyRequirement(check_id=…, permitted=(…), applies_to=(…))`, with coverage refusals in a closed vocabulary (`coverage.incomplete`, `.abstained`, `.invalid_evidence`, `.ambiguous`, `.advisory_only`, `.unsatisfactory`) | **The mechanism this feature should extend.** See §3 |
| **The authorization record + chain binding** | `policy/record.py` builds the record; `_require_chain_binding` compares the whole record against its chain entry | **The binding for §2.** See §2.2 |
| **`_DESCRIPTOR_FIELDS = tuple(f.name for f in dataclasses.fields(ExecutionDescriptor))`** | The derivation that replaced three hand-written copies of a field list | **The derivation precedent for §1** |

### 0.3 Presuppositions in the brief that do not hold

Reporting these rather than working around them, per the standing rule.

1. **"reversibility analysis, rewrite counting"** — neither exists. Grep for
   reversibility/rewrite/destructive analysis over `src/` returns only prose in
   docstrings and one unrelated use in `sandbox/container.py`. There is no
   analyser of migration SQL anywhere in the tree.
2. **"the live-PG step … any schema read"** — the live-PG step
   (`PROM_REQUIRE_PG=1`, `PROM_CHOKEPOINT_PG_HOST`) exercises the *chokepoint's
   own* machinery against a real server. It does not read a migration target's
   schema, because nothing does.
3. **"beyond `branch.delete`'s protected-target refusal"** — **there is no
   protected-target refusal.** Grep for `protected` in `tools/git.py` and
   `execution/executor.py` returns nothing. What `branch.delete` has is a
   POLICY REQUIREMENT: `PolicyRequirement(check_id=CHECK_MERGE_PROOF,
   permitted=(IMPL_GIT_MERGE_CHECK,), applies_to=("branch.delete",))`. This
   matters for §5, and it supports the owner's prior rather than undercutting it.
4. **"the sandbox rehearsal for `database.migrate`"** — there is no rehearsal
   against a schema. `database.migrate` carries exactly one requirement,
   `CHECK_EXECUTABLE_CASES` permitted to `IMPL_SUBPROCESS` — the same generic
   "untrusted code was actually run" check as `sandbox.execute`. It establishes
   that code ran under isolation. It does not establish anything about a
   database.

**Consequence for §2:** capture point (a) — *the state the candidate was
rehearsed against* — **does not exist and cannot be captured today.** §2 rules
under that constraint.

---

## 1. WHAT IS "THE STATE"? — RULING

### 1.1 The covered set is DERIVED, not hand-listed

The failure named in the brief is exactly right and this project has already
shipped it twice: a digest over table names that misses a column type change is
an enumeration wearing an allowlist's clothes. The cautionary case is
`_DESCRIPTOR_FIELDS` — three hand-written copies of six field names that agreed
only because a person kept them agreeing, where a seventh field would have been
covered by none of them.

**Ruling: the covered set is the field set of a frozen dataclass, derived the
way `_DESCRIPTOR_FIELDS` is derived.**

```
TargetState          # a frozen dataclass, one field per ASPECT
STATE_ASPECTS = tuple(f.name for f in dataclasses.fields(TargetState))
```

with three properties carried over from the existing encoding work:

1. The digest encoder iterates `STATE_ASPECTS`, so an aspect added to the
   dataclass is in the digest by construction.
2. A conformance test asserts the encoded aspect set equals the dataclass
   fields — the precedent is `test_the_encoded_field_set_equals_the_dataclass_fields`,
   which already exists for the requirements encoding.
3. A conformance test asserts **every aspect actually moves the digest** — the
   precedent is `test_every_field_actually_moves_the_digest`. An aspect that is
   collected but does not change the hash is an aspect that is not covered.

**What this does NOT solve, stated because it is the honest limit.** Deriving
the field set from the dataclass makes the *encoding* total over the aspects.
It does not make the *aspect list* total over what Postgres can vary — that
list is still written by a person. The derivation moves the risk from "three
copies disagree" to "the list is incomplete", which is smaller and is
addressable by §6's requirement that the record names its covered set. A digest
that says what it spans is an honest partial; one that does not is the defect.

### 1.2 IN the pinned state

| aspect | why it is in |
|---|---|
| table and column existence, names, types, nullability, defaults | The core of what a migration assumes. A type change under an `ALTER` is the canonical stale-assumption failure |
| constraints | A check or FK added since review can make the migration fail mid-way, or make it succeed with a different meaning |
| indexes, **including validity** | An `INVALID` index from a failed `CREATE INDEX CONCURRENTLY` changes what a subsequent statement does. Validity is part of the state, not metadata about it |
| triggers | A trigger added since review makes the migration's writes do something the reviewer did not see |
| views and dependent objects | A `DROP`/`ALTER` behaves differently, or cascades differently, depending on dependents |
| extensions, enum members | An enum gaining a member changes what a `CHECK` or a cast accepts |
| permissions and role grants on the target | A revoked grant turns a reviewed migration into a mid-way failure; a *widened* grant changes who else could have altered the target |
| migration-version table state / other pending migrations | The single most likely thing to have moved. If another migration landed since review, the reviewed plan was written against a schema that no longer exists |
| server version and relevant settings | `lock_timeout`, `statement_timeout`, `search_path`, and the server major version change what the same SQL does |
| **partitioning topology** | Partitioning is schema. A table that became partitioned since review takes different locks and rewrites differently |

### 1.3 OUT, as named limits

| aspect | why it is out | the limit this leaves |
|---|---|---|
| **row count / table size** | Changes on every write. Including it would make the digest differ on almost every comparison, which is §4's "refuse constantly" failure in its purest form | **Named limit:** size affects how long a rewrite holds its locks. A migration reviewed against a 1k-row table and executed against a 100M-row one is correct and may still cause an outage. The state pin does not catch that. If lock-duration risk needs bounding, it is a *separate* feature (a size-bound check), not an aspect of this digest |
| **data content** | Unbounded, changes constantly, and is not what a schema review assumed. A digest over content would be a digest over the database | **Named limit:** a migration whose safety depends on data (a `NOT NULL` backfill assuming no nulls) is not covered. That is a data precondition, and it belongs in the migration's own checks |
| **replication topology** | Not a property of the target's schema; it is a property of *which server you are talking to*. Folding it into the digest would conflate two questions | Handled in §7 as the replica attack, which needs a different control |

### 1.4 OPEN QUESTION — the owner's call

**Q1. Is the covered set fixed, or per-policy?**

- **Fixed** — one `TargetState` for everyone. Simple; the digest is comparable
  across deployments; a customer who does not care about, say, grants still
  gets refused when a grant changes.
- **Per-policy** — the policy names which aspects are pinned. Precise; but it
  makes the covered set a customer-editable security parameter, and a customer
  who narrows it to table names has rebuilt the enumeration this design exists
  to avoid — with no signal that they did.

My inclination is **fixed**, with §6's record naming the covered set so a
narrower one could be added later without the record becoming ambiguous. But a
customer with a noisy schema may find a fixed set unusable, and that is a
product judgement about who this is for.

---

## 2. CAPTURE POINT AND BINDING — RULING

### 2.1 Capture point

The brief's three candidates, against what was measured in §0:

- **(a) at rehearsal** — **not available.** There is no schema rehearsal for
  `database.migrate`. Ruling (a) today would be ruling on a capture point that
  does not exist.
- **(b) at review / hold creation** — available. The record is already built at
  hold creation and already carries `target_canonical`.
- **(c) both, compared** — the correct end state, and currently unbuildable.

**Ruling: capture at (b) now, and design the record so (a) can be added without
a record-shape change.** Concretely: the state entry is
`{"captured_at": "<capture point>", "digest": …, "aspects": […]}` — a *list* of
captures, not a single digest — so adding a rehearsal capture later is an
additional element, not a schema migration of the record.

**The gap this leaves, named explicitly and not deferred silently.** The brief
puts it exactly right: *if (a) and (b) differ, the human reviewed a plan
rehearsed against a state that had already moved, which is the same class of
gap one step earlier.* With (a) absent, there is no rehearsal state to differ
from — but that is not the gap being closed, it is the gap being **unmeasurable**.
A migration today is never rehearsed against the target's schema at all, so the
reviewer is reading a plan whose relationship to the live schema nothing has
checked. **State pinning at (b) does not fix that**; it only guarantees the
schema has not moved since the human looked.

**Q2 — the owner's call.** Is schema rehearsal for `database.migrate` a
prerequisite for this feature, or a successor to it?
- **Prerequisite:** the feature is honest only when (a) and (b) can be
  compared. Larger, and it needs a shadow/copy database, which is a
  deployment-model decision.
- **Successor:** ship (b) now — it closes a real window (review → execute) and
  the record is shaped for (a) — and file the rehearsal gap. Cheaper, and the
  claim must then be worded as *"the schema has not changed since review"*, not
  *"the reviewed assumptions hold"*.

I lean **successor**, with the claim narrowed to what it covers. But shipping a
feature whose roadmap sentence overstates it is how this repository got G17 and
G23, so the wording is not a detail.

### 2.2 Binding — the chain can carry it unchanged

**Confirmed by reading the code.** `_require_chain_binding` compares
`stored != pending.record` — the **whole record**, canonically serialised, is
the chain payload (`audit_chain.canonical_json`, `sort_keys=True`). So any field
added to `policy/record.py`'s returned mapping is inside the tamper-evident
chain by construction. **No chain change is required.**

Two consequences that must be handled rather than discovered:

1. **`RECORD_VERSION` must bump from 1 to 2.** `is_versioned_record` refuses a
   record whose version differs, and `_from_row` turns a non-record into `None`,
   which `_revalidate` refuses with `reason="reverification_required"`. So every
   hold created before the change becomes un-approvable and must be re-verified.
   **That is the correct fail-closed behaviour** and it is the same treatment a
   pre-record blob already gets — but it is an operational event (pending holds
   go stale on deploy) and should be stated in the release note, not discovered
   by an operator.
2. **The state digest must be in the record, not in a column.** Same ruling as
   Block 1a: integrity moved from re-resolution to the record, so anything
   trusted because it is in the record must be covered by the chain. A column
   beside the record would be trusted and uncovered.

---

## 3. WHAT IF THE STATE CANNOT BE READ? — RULING

This is the section that decides whether the feature is honest, and the brief is
right that a design where an unreadable target silently proceeds is the exact
defect this product exists to name.

### 3.1 The mechanism: a policy requirement, not a bespoke check

**Ruling: the state pin is a `PolicyRequirement`, satisfied by a permitted
implementation, exactly like `CHECK_MERGE_PROOF`.**

```
PolicyRequirement(
    check_id=CHECK_TARGET_STATE,
    permitted=(IMPL_PG_CATALOG_READ,),
    applies_to=("database.migrate",),
)
```

This is the "extend the pinning mechanism that already works" instruction taken
seriously, and it buys the whole doctrine for free:

- a read that **could not run** produces `Unavailable`, which the bank already
  turns into `coverage.incomplete` — **a refusal**, never a pass;
- the closed refusal vocabulary already exists and every reason already has an
  end-to-end row (`test_every_refusal_reason_in_the_closed_set_has_an_end_to_end_row`);
- a requirement nothing can satisfy is already refused at policy construction,
  so a deployment cannot half-configure it;
- `IMPL_*` identity is already what coverage is keyed on, so a *different*
  implementation answering the requirement is already `invalid_evidence`.

Building a bespoke state check beside this would be a second refusal path with
its own vocabulary, which is the shape G17 and the composition pins both warn
about.

### 3.2 The four cases, explicitly

| case | outcome |
|---|---|
| **Read fails entirely** (unreachable, auth refused, timeout) | `Unavailable` with the reason. Coverage reports `incomplete`. **Refuses.** Nothing executes. This is `tools/git.py`'s existing shape: `unmerged_commits: int \| None`, never "assume merged" |
| **Read partially succeeds** (some objects readable, some not) | **`Unavailable`. A partial digest is NEVER compared.** A digest over the readable half is a different measurement wearing the same name, and it would compare equal while the unreadable half moved. The refusal names which aspects could not be read |
| **Read succeeds but the subject exceeds bounds** (catalog too large to read within the deadline / size cap) | `Unavailable`, following `reconcile_gate.py`'s precedent: *"gate snapshot exceeds bounds"* raises rather than truncating. A truncated read is a partial read |
| **Read succeeds** | Compare. §4 governs the outcome |

**Is a partial digest ever compared? No.** That is the ruling, and it is the one
I would defend hardest: partial-compared-as-whole is precisely
couldn't-verify collapsing into verified-clean, which is the failure G21 was
checked against and the failure this section exists to prevent.

### 3.3 Does Unavailable refuse, or route to a human?

**Ruling: it refuses, and whether a refusal can be routed is already a policy
property, not a new one.** Under §3.1 an `Unavailable` state read is
`coverage.incomplete`, and the existing gate decides refuse-vs-route from the
action's risk class and `escalate_below` — machinery that already exists and is
already tested. Adding a state-check-specific routing switch would be a second
policy mechanism for a decision the first one already makes.

**Q3 — the owner's call.** Should an operator be able to configure *"proceed
without the state check"* at all?
- **No** — the requirement is either in the policy or it is not; a deployment
  that does not want it removes the requirement, which is visible in the policy
  digest and therefore in the record.
- **Yes, as an explicit named opt-out** — like `allow_unverified_substrate`:
  logged at every construction, refused beside its own requirement, and in the
  posture record.

I lean **no**, because "remove the requirement from the policy" already is the
opt-out and it is the one that shows up in the record. An additional flag would
be a second way to say the same thing, and G21's lesson is that two spellings of
one posture is how the weaker one gets chosen by accident.

---

## 4. WHAT A MISMATCH MEANS — RULING

### 4.1 Refuse on any difference in the covered set

The three options and their costs, as the brief frames them:

| option | cost |
|---|---|
| **any difference** | Simple, and the comparison is provably what it says. Will refuse whenever anything in the covered set moved — including an unrelated table gaining an index — which **trains operators to override**. That is a real security cost, not a usability complaint |
| **differences within touched scope** | Precise. Requires deriving touched scope from the migration SQL: a second analysis, which can be wrong, and which does not exist today (§0.3). A wrong scope derivation fails *open* — it decides a change was out of scope when it was in |
| **any difference + explicit re-review that re-pins** | Refuses conservatively, and gives the release valve a name and a record entry instead of an override |

**Ruling: option 3 — refuse on any difference in the covered set, with an
explicit re-review that re-pins.** The re-pin is a new human decision, recorded,
chained, and distinguishable in the record from the original — not a flag that
suppresses the check.

Scope-limiting is a **later, separately-ruled refinement**, and if it is ever
built: undeterminable scope must fall back to the conservative behaviour, and
the scope derivation must itself be a permitted implementation answering a
requirement, so that "scope could not be derived" is an `Unavailable` rather
than an empty set. **An instrument returning an empty set reads downstream as a
pass** — doctrine #8, and the reason a scope analyser is a genuinely risky
addition rather than an obvious improvement.

### 4.2 Mismatch INVALIDATES the hold, following rotation

**Ruling: invalidate, like `PinnedPolicySuperseded`, not refuse-and-leave-pending.**

The precedent is exact. A hold pinned to a superseded policy is *invalidated*
and the human's decision is left untouched, because the human approved something
that no longer exists. A state mismatch is the same situation with a different
subject: the human approved a plan against a schema that is gone. Leaving it
PENDING invites re-approval of a decision whose premise has changed, which is
what rotation's invalidation exists to prevent.

This also reuses a tested path: `test_a_hold_pinned_to_a_superseded_policy_is_refused_and_invalidated`,
`test_a_retry_after_rotation_is_refused_and_the_human_decision_is_untouched`,
and `test_relabelling_a_hold_to_the_new_policy_does_not_get_it_approved` are the
shape the state equivalents should take — including the last one, which is the
substitution case.

**A new typed reason** joins `EXECUTION_REFUSAL_REASONS`:
`target_state_moved`, distinct from `reverification_required` so a test can tell
"the schema changed" from "this is a legacy hold", and distinct from
`chain_did_not_verify` so neither can stand in for the other.

---

## 5. DESTRUCTIVE-CHANGE DETECTION — SCOPING NOTE ONLY

Not designed here. The brief is right that it is a different feature.

**What exists: nothing.** No migration SQL analyser, no operation
classification, no protected-target list. §0.3 records that `branch.delete`'s
control is a *policy requirement* for a merge proof, not a protected-target
refusal — the brief's phrasing presupposed a mechanism that is not there.

**What a classifier would need to cover**, if it were built as code:
`DROP TABLE` / `DROP COLUMN` / `DROP CONSTRAINT`; `ALTER COLUMN TYPE` with a
narrowing cast; `TRUNCATE`; `DELETE` without a `WHERE`; `ALTER … SET NOT NULL`
on a column with nulls; `DROP INDEX` on an index a constraint depends on;
anything under `CASCADE`; and — the hard part — the same reachable through
`DO $$ … $$`, a function call, or dynamic SQL. **That last item is why a
code-side classifier is a losing proposition**: it is an enumeration of
forbidden shapes over a Turing-complete input, and this repository's own
measured experience (C1–C3, the `if False:` probe) is that enumerations lose.

**The measurement supports the owner's prior.** The existing mechanism for
"this operation is irreversible, require the proof that makes it safe" is
already a `PolicyRequirement` in customer-editable policy, not a detector. A
permitted-operations allowlist per program is the same shape: an allowlist over
what is PERMITTED, keyed on operation identity, refusing everything else —
which is the doctrine, where a detector would be its inverse.

**The residual that a policy model does not remove**, stated so agreeing with
the prior does not hide it: an operation allowlist still has to decide *what
operation this SQL performs*, and that is the same analysis problem one layer
up. The difference is the failure direction — an allowlist that cannot classify
refuses, a detector that cannot classify permits — and that difference is the
whole argument. **It should be recorded as the argument, not as a claim that
policy makes the problem go away.**

---

## 6. WHAT THE RECORD MUST SAY — RULING

The brief's standard is the right one: *a record saying "state verified" without
naming its coverage is the same class as a guard named for enforcement that
checks spelling.* That is G17 restated, and this record must not repeat it.

**Ruling: the record carries all five of the following, and the field names say
what they are.**

| field | why |
|---|---|
| `target_state.captures[]` — each `{capture_point, digest, observed_at}` | A list, not a scalar, so a rehearsal capture (§2.1) is an addition rather than a migration |
| `target_state.aspects` — the covered set, **as the list that was actually encoded** | The anti-G17 field. A reader can see what the digest spanned. Derived from `STATE_ASPECTS` at capture time, so a record written by an older version names its own narrower set rather than being read under today's |
| `target_state.comparison` at execution — `{observed_digest, matched: bool}` | The relationship between what was reviewed and what executed, which is the receipt's whole job |
| `target_state.unavailable` — `{reason, aspects_unread}` when the check could not run | Names *that* it could not run and *why*, per §3. A record that omits the field when the check failed is indistinguishable from one where it passed |
| `target_state.record_version` semantics | Covered by the existing `RECORD_VERSION` bump (§2.2) |

**One thing the record must NOT say.** It must not contain the state itself —
only the digest and the aspect list. A catalog dump in the ledger is an
unbounded persisted blob, and `verifier/model_judge.py`'s F8 defect (the raw
model response reaching `Evidence.detail` and putting a bearer token in the
ledger) is the measured precedent for what happens when unbounded external
content is persisted.

---

## 7. ADVERSARIAL PASS ON THIS DESIGN

Applying both known attack classes — **deletion AND cross-context
substitution** — to every instrument proposed, because the composition pins
shipped with deletion proofs only and the substitution case was found by review.
The distinction did not transfer to a new instrument by itself and will not
transfer to this one either.

### 7.1 TOCTOU — the answer, and the measured residual

**This needs an answer, not a mention.** Measured, from `chokepoint/runner.py`:

- the connection is `autocommit=False`, at **default isolation — READ
  COMMITTED**, so each statement takes a fresh snapshot;
- `pg_advisory_lock(hashtextextended(execution_id))` is **session-scoped and
  keyed on the execution id** — it serialises *this runner's* executions;
- `pg_advisory_xact_lock('promethyn-receipt-bootstrap-v1')` is keyed on a
  **constant** and is released by the `connection.commit()` at line 862;
- **neither lock is keyed on the migration's target objects.**

So today nothing excludes a third-party session from committing DDL on the
target between any two statements.

**What bounds the window, in increasing strength:**

1. **Comparison immediately before `cursor.execute(sql)`, same transaction,
   READ COMMITTED** — narrows the window to the gap between two statements.
   Does **not** eliminate it: another session's DDL can commit in between, and
   READ COMMITTED means the apply sees it.
2. **`REPEATABLE READ` for the apply transaction** — the catalog read and the
   apply share one snapshot, so the comparison describes the snapshot the
   migration runs in. Cost: changes the runner's isolation, which affects
   existing behaviour and needs its own ruling and its own tests.
3. **An advisory lock keyed on the TARGET** rather than on the execution id —
   excludes other *Promethyn* sessions from the same target. Does nothing about
   a DBA at a psql prompt.
4. **Explicit `LOCK TABLE … IN ACCESS EXCLUSIVE MODE` on the touched tables** —
   genuinely excludes concurrent DDL, and requires knowing the touched set,
   which is §4's scope-derivation problem returning in a harder form.

**Ruling: (1) now, and record the residual as a named limit.** (2) and (3) are
real improvements that touch the runner's transaction semantics and deserve
separate rulings. **(4) is not available** without scope derivation.

**The residual, stated as it must appear in the docs:** *a state comparison
immediately before execution narrows the window to the gap between two
statements in one transaction at READ COMMITTED. It does not eliminate it. A
session that commits DDL inside that window is not detected. The control against
that is a lock on the target, which this design does not take.*

### 7.2 A digest stable under a change it should catch

The most likely way this design fails silently. Three concrete shapes:

| shape | does the design close it? |
|---|---|
| An aspect is collected but not encoded — present in `TargetState`, absent from the preimage | **Closed by construction.** The encoder iterates `STATE_ASPECTS`, and the test that every aspect moves the digest catches an aspect that is collected and ignored. Precedent exists and works |
| An aspect is encoded but **type-collapsed** — e.g. `nullable` rendered as a string so `"True"` and `True` share a preimage, or a sequence concatenated so `["a","bc"]` and `["ab","c"]` collide | **Closed by reuse, not by new work.** The existing encoder already type-tags and length-prefixes, with tests named `test_type_tags_keep_lookalike_values_apart`, `test_a_sequence_cannot_be_confused_with_its_concatenation`, `test_a_value_cannot_forge_a_field_boundary`. This design **must use that encoder**, not a new one. Writing a second encoder is the enumeration-by-hand failure again |
| The aspect list is **incomplete** — Postgres varies something nobody listed | **NOT closed. Named limit** (§1.1). This is the design's single largest residual and no test can close it, because a test cannot know what nobody thought of. §6's `aspects` field is the mitigation: it makes the gap *legible* to a reader instead of invisible |

### 7.3 A target readable but served by a replica

**Not closed by the digest, and the digest cannot close it.** A read replica has
the same schema and will produce a matching digest while the primary — where the
migration executes — has moved.

This is why §1.3 keeps replication topology *out* of the digest: it is not a
property of the schema, it is a property of *which server answered*. The control
is a different one: assert the read and the apply happen on the **same
connection**, and that the connection is not in recovery
(`pg_is_in_recovery()`). Both are cheap.

**Q4 — the owner's call.** Is "the state read must use the execution connection"
a hard invariant of the implementation, or a checked precondition?
- **Hard invariant** (the reader is handed the runner's cursor, with no way to
  pass another connection): unforgeable by construction, and couples the state
  reader to the runner.
- **Checked precondition** (the reader asserts `pg_is_in_recovery()` is false
  and that the connection matches): testable in isolation, and is an assertion
  someone can later weaken.

I lean **hard invariant**, for the same reason `AuthorizedExecution` is minted
only by the seam: a capability that cannot be constructed elsewhere does not
need a check that it was not.

### 7.4 Concurrent migrations from another source

Another Promethyn instance, a CI job, or a human running `psql`. Partly covered
by 7.1's advisory lock discussion; the remainder is **the migration-version
table aspect in §1.2**, which catches "another migration landed" as a state
difference — *if* the other source uses the same version table. A migration
applied out-of-band by a human updates no version table and is caught only if it
changed something else in the covered set.

**Named limit:** out-of-band DDL that touches nothing in the covered set is not
detected. Under §1.2's coverage that is a narrow residual, but it is not zero.

### 7.5 Both attack classes against every proposed instrument

| instrument | **deletion** | **cross-context substitution** |
|---|---|---|
| `TargetState` / `STATE_ASPECTS` | An aspect removed from the dataclass silently narrows the digest. **Needs a pinned aspect COUNT plus the aspect list in the record**, so a narrowed set is visible in the receipt rather than only in the source | An aspect **renamed** keeps the count and changes the preimage. Worse: an aspect whose *collection query* is repointed at a different object — same field name, different subject — produces a valid-looking digest of the wrong thing. **Needs a known-answer test per aspect** binding the field name to what it reads, not just that it reads something |
| The state digest encoder | Deleting a field from the preimage. Caught by the existing "every field moves the digest" test **if this design reuses that encoder** | Reusing the *requirements* domain separator for the *state* digest would let a requirements preimage and a state preimage collide. The existing `test_the_domain_is_not_shared_with_the_posture_digest` is the precedent and **the state digest needs its own domain and its own version of that test** |
| The `CHECK_TARGET_STATE` requirement | Removed from the policy → no state check. Visible in the policy digest, which is in the record. **Covered by existing machinery** | A **different implementation** answering the requirement — a stub that returns a constant digest. Covered by the existing implementation-identity rule (`coverage.invalid_evidence` for an unpermitted implementation), and this is the strongest argument for §3.1's ruling: building the check outside the requirement mechanism would forfeit this |
| The comparison at execution | Deleted → nothing compares. Needs a mutation proof that removing it reddens a named test | **Compared against the wrong capture** — e.g. against the digest just observed rather than the pinned one, which always matches. This is the substitution case for this instrument and it is the one I would expect to survive a deletion-only proof round |

**That last cell is the point of this table.** "Compare the observed digest to
the observed digest" passes every deletion probe and is exactly the shape the
composition pins shipped with. Any implementation sprint must prove it with a
substitution mutation, not only a deletion one.

---

## SUMMARY OF RULINGS AND OPEN QUESTIONS

**Ruled** (mine, revisable by the owner):

1. Covered set **derived** from a frozen dataclass's fields, with the
   every-aspect-moves-the-digest test; ten aspects in, three out as named limits.
2. Capture at **review/hold creation**; record shaped as a *list* of captures so
   rehearsal can be added later; chain carries it **with no change**, at the cost
   of a `RECORD_VERSION` bump that stales existing holds.
3. Implemented as a **`PolicyRequirement`**, so `Unavailable` is already a
   refusal. **Partial reads are never compared.** Unavailable refuses.
4. Mismatch **invalidates** the hold (rotation's precedent), refusing on any
   difference in the covered set, with an explicit re-review that re-pins. Scope
   limiting deferred and, if built, must fail conservative.
6. The record names its **covered set**, both digests, the match result, and the
   unavailable reason — and never the state itself.

**Open, and the owner's to rule:**

- **Q1** — covered set fixed, or per-policy? (§1.4)
- **Q2** — is schema rehearsal a prerequisite or a successor? This one changes
  what the feature is allowed to claim. (§2.1)
- **Q3** — should there be a named opt-out beyond "remove the requirement"? (§3.3)
- **Q4** — same-connection as a hard invariant or a checked precondition? (§7.3)

**And one that is a product decision before it is a design one:** §0.1 measured
that coverage is replayed rather than re-observed for **every** action class, so
`branch.delete` has the same staleness gap as `database.migrate`. Whether this
feature is scoped to migrations or to *re-observation at execution generally* is
a scoping call I should not make alone.
