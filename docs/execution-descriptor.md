# The trusted execution descriptor

**Status: IMPLEMENTED.** The design below is enforced by the Checkpoint B code and
its behavioural and executed-mutation proofs.

## 1. What this closes

An independent review of PHASE-1.2a through Checkpoint 3, pinned at `458fb4b6`,
found the two original failure patterns closed for the tested, correctly
resolved policy path, and the larger claim — *every consequential authorization
necessarily represents the selected policy, this action, and this verification
attempt* — not enforced end to end. Its three High findings are one missing
thing seen from three sides:

> Nothing establishes that the snapshot in hand is the one trusted configuration
> selected, or that its action is the one the gate later executes.

All three were reproduced against `458fb4b6` before this design was written.
The measurements, not the claims:

| # | what was run | what happened |
|---|---|---|
| R1 | `dataclasses.replace` on a legitimate two-requirement snapshot, dropping `check.b`, then `bank.assess` | `policy_id` and `policy_digest` PRESERVED; assessment MINTED; gate `approved=True` |
| R2a | `ActionGate.decide(assessment_for_artifact_A, action=code_B)` | `approved=True`; the executed code's real digest never matched the assessment's |
| R2b | `ActionGate.decide(sandbox_execute_assessment, action=git_delete_branch)` | `approved=True` |
| R3 | hand-built routed `GateDecision` carrying `Judgment(FAIL, 1.0, authoritative=True)` → `pending.hold` → `controller.approve` | held, approved, **executed — `executor_calls == 1`**, ledger row `human-approved` |
| R4 | every reference to `Config.verification_profile` | consumed only by `build_verification_policy`, whose only caller in the tree is a test |

R1 is the reason R2 and R3 are not merely "add a comparison": there would be
nothing trustworthy to compare *to*. All four are one seam.

## 2. The descriptor

A single frozen value describing **one attempt at one consequential action**:

```
ExecutionDescriptor
    artifact_sha256    the artifact under verification
    action_class       the consequence class (one of the THREE)
    target_canonical   the target / executor principal
    attempt_id         the verification attempt identity
    policy_id          the SELECTED policy's identity
    policy_digest      the SELECTED policy's content digest
```

Those are the same six fields a `BoundRequirements` snapshot commits to, and
that is deliberate: the descriptor is the *question*, the snapshot is the
*answer*, and the seam's job is to check that the answer in hand answers this
question, under the policy this deployment actually selected.

**The descriptor is not caller-supplied trust.** It is built only by a builder
constructed at a composition root and holding the deployment's policy supplier.
`policy_id` and `policy_digest` are read OFF the supplier's policy, never
accepted as arguments — the same discipline `policy.assessment.mint` already
uses for reading its fields off the snapshot, and for the same reason: there is
then no parameter through which they can disagree.

## 3. The seam

One function. Every production entry point reaches it, and nothing reaches the
executor without it:

```
authorize(descriptor, assessment, action) -> AuthorizedExecution
    raises ExecutionNotAuthorized
```

It performs five checks, in this order, and each is a separate named refusal so
an operator sees which one failed:

1. **Re-select the policy.** Ask the *configured supplier* for the policy — not
   the one the descriptor names. Check its content digest equals
   `descriptor.policy_digest` and its id equals `descriptor.policy_id`. A
   disagreement means the descriptor describes a policy this deployment did not
   select, and is refused.
2. **Re-resolve, do not re-digest.** Run the trusted resolver over that policy
   VALUE and the descriptor's five action fields, producing the snapshot this
   deployment's configuration *requires* for this action.
3. **Compare the re-resolved digest with the assessment's.**
   `snapshot_digest(expected) == assessment.snapshot_digest`. This is what
   closes R1: a weakened snapshot digests honestly to its own weakened content,
   so a *recomputation* proves nothing — but it cannot match a fresh resolve of
   the real policy, because the requirement it dropped is back.
4. **Compare the descriptor with the assessment, field by field.** Redundant
   with (3), since the digest commits to all six, and kept anyway: a digest
   mismatch says only "something differs", and a field comparison says which.
   Diagnostics, not enforcement — and labelled as such so no later reader
   mistakes it for the control.
5. **Compare the descriptor with the CONCRETE ACTION about to run.**
   `artifact_digest_of(action) == descriptor.artifact_sha256` and
   `consequence_class_of(action) == descriptor.action_class`. This is what
   closes R2, and it is the only check in the list that looks at the action
   rather than at paperwork about the action.

`artifact_digest_of` and `consequence_class_of` are trusted, **total** functions
over `ExecutableAction`. Total matters: an action kind with no mapping must
raise, never fall back to a default class. A default here would be the omission
attack wearing a new-feature commit — the shape already recorded in the threat
model.

`AuthorizedExecution` is the returned value and the thing downstream surfaces
require. It carries the descriptor, the assessment, and a validation stamp taken
by the seam. It is minted the way `PolicyAssessment` is minted, with the token
consumed in `__post_init__`, because `dataclasses.replace` forged a
`PolicyAssessment` exactly once before that line existed and there is no reason
to relearn it.

## 4. A1 — where the selected policy comes from

The trusted source is a **`PolicySupplier`** injected at the composition root:
an object answering "the policy this deployment selected", whose default
implementation reads `Config.verification_profile` through `load_profile`. R1 of
PHASE-1.2a says the resolver takes a policy VALUE and nothing downstream reaches
for a profile table; a supplier keeps that, because a customer-supplied
digest-pinned policy becomes another supplier rather than a rewrite.

The seam consults the supplier at step (1) **every time**, and does not cache
the resolved policy across attempts. A cache would make the control depend on
when it was warmed.

### Insufficient fixes, and why each is rejected

The brief names six. Each is rejected here with the reason, rather than left
unmentioned:

- *"Rejecting only an empty snapshot."* The reproduced attack removes ONE of two
  requirements. A non-empty check passes it unchanged.
- *"Checking the digest is well-formed."* Measured: the weakened snapshot's
  digest is a perfectly well-formed 64-hex value. Well-formedness is a property
  of the encoding, not of the requirement set.
- *"Recomputing the digest of the weakened snapshot."* This is the subtle one
  and the reason step (2) says **re-resolve, not re-digest**. Recomputing
  `snapshot_digest(weakened)` yields exactly the value the assessment carries,
  because the digest honestly describes whatever it is given. A self-consistent
  forgery stays self-consistent under recomputation.
- *"Making `PolicyAssessment` more frozen."* The assessment was never mutated.
  It was legitimately minted by `VerifierBank.assess` from a snapshot that had
  been weakened before minting. Hardening the assessment hardens the wrong
  object — the snapshot is an ordinary frozen dataclass and `replace` on it is
  not an attack on the assessment at all.
- *"Hiding mint."* Minting was not abused; `bank.assess` did what it is supposed
  to do with the input it was given. Obscurity here would remove the audit
  sweep's target while changing nothing about the gap.
- *"Checking only artifact and target."* The reproduced attack changes neither.
  Both fields are identical between the legitimate and weakened snapshots; only
  the requirement tuple differs.

## 5. A2 — what the gate compares

`ActionGate.decide` now calls `ExecutionAuthorizer` before it reads the outcome.
The authorizer derives artifact and consequence class from the concrete action,
uses the gate's composition-root target and the caller's mandatory attempt
identity, and returns the `AuthorizedExecution` carried in `GateDecision`.

### Insufficient fixes, and why each is rejected

- *"A type annotation."* Annotations are not enforcement; the type gate checks
  spellings, not runtime values. R2 is a value comparison or it is nothing.
- *"`isinstance`."* Every reproduced case passed a real, correctly minted
  `PolicyAssessment`. `isinstance` returns True for all of them.
- *"Merely carrying a digest."* The assessment already carries one. Carrying is
  what it does today; comparing is what is missing.
- *"Comparing the assessment with its OWN snapshot."* Self-consistent by
  construction — `mint` reads every field off the snapshot, so this comparison
  can never fail and would be a test that cannot go red.
- *"Checking code hash but omitting class/target/policy/attempt."* Closes R2a
  and leaves R2b open: the `git_delete_branch` case needs the CLASS comparison,
  and a migration against the wrong principal needs the TARGET one.
- *"Fixing only `ExecutionController` while direct swarm calls to `ActionGate`
  remain."* The swarm calls the gate directly. A fix one layer above the gate
  leaves the gate reachable, which is the "migrated some paths, not others"
  shape this repository keeps correcting.

## 6. A3 — the human path consumes the same proof

The historical reproduction entered through `PendingActionService.hold`: a
routed decision carrying a FAIL was held, approved and executed. The implemented
human path consumes the **same** `AuthorizedExecution`:

- `hold` takes the `AuthorizedExecution` and **persists the descriptor with the
  hold**, so the record says what was held and under which policy and attempt.
- `approve` **re-validates before executing**. Re-validation, not a stored "was
  valid" flag: a hold outlives the process, the policy may have been changed or
  withdrawn in the interval, and a human approving a stale authorization is the
  case the TTL exists for but does not cover.
- `retry_execution` re-drives the same validated path and can approve nothing,
  which it already cannot.

Persisting the descriptor is also what makes R5 (the deferred audit work)
possible, and that is not a coincidence — an authorization record that cannot
say what it was decided under is unreviewable regardless of how well the
decision was made.

### Insufficient fixes, and why each is rejected

- *"Guarding submit only."* `submit` is already migrated, and the reproduction
  never calls it. It enters at `pending.hold`.
- *"Requiring a raw `Judgment` to say PASS."* This reinstates the
  unbound-judgment route PHASE-1.2b closed: a `Judgment` saying PASS still says
  nothing about whether a policy required the evidence behind it.
- *"Renaming hold."* A rename moves the entry point without removing it.
- *"Changing a type annotation."* As in A2 — not enforcement.
- *"Checking only hold TTL."* The reproduction approves immediately, well inside
  any TTL. TTL bounds how long a valid hold stays valid; it says nothing about
  whether it was ever valid.

## 7. A4 — wired at the ACTUAL composition roots

Before Checkpoint B, `build_verification_policy` had no production caller and
the supported roots referenced no selected policy. Every production entry point
now constructs the descriptor builder from the configured supplier: `build_orchestrator`, `build_execution_controller`,
`build_migration_runtime`, the swarm runtime, the workflow runtime, and the Git
tool path.

### Insufficient fixes, and why each is rejected

- *"Another getter."* A second function nobody calls is the defect, doubled.
  The finding is the absent CALL, not an absent definition.
- *"Validating only the standalone helper."* This is precisely what
  `test_policy_enforcement_regression.py` does today — it calls
  `build_verification_policy(config)` directly and passes, while no production
  path does. The test is green and the wiring is absent, which is how the gap
  survived four sprints.
- *"A static field-read sweep."* A sweep proving `config.verification_profile`
  is read somewhere would go green on the existing helper. Reading is not
  wiring; the assertion has to be behavioural — select a non-default profile,
  drive a real entry point, observe the requirement that profile adds being
  enforced.
- *"Testing baseline only."* Under the baseline, a correctly wired runtime and
  an unwired one behave identically, because the unwired default IS the
  baseline. The test is only capable of failing if the selected profile differs
  from the default.

## 8. A5 — the canonical encoding is not a substitute

Checkpoint 1 pinned the snapshot encoding, with a known-answer vector rebuilt by
hand from the docstring. That work is a **precondition** of this design and not
a substitute for it.

What it gives: two distinct requirement sets cannot produce the same digest, so
step (3)'s equality test means set equality rather than "probably the same".
Without it, step (3) would be comparing values that could collide, and the whole
seam would rest on an encoding nobody had pinned.

What it does not give: a digest is a function of its input. It makes a
requirement set *identifiable*; it cannot make one *trusted*, and it compares
nothing. The weakened snapshot from R1 digests correctly, encodes canonically,
and round-trips — every property the encoding promises holds, and the gap is
untouched. Trust arrives only when the digest is compared against one derived
independently from the selected policy, which is step (2).

## 9. A6 — remaining trusted composition obligations

Named here rather than discovered later:

1. **The composition root must actually be used.** An application that
   constructs `ActionGate()` and an executor by hand bypasses the supplier, the
   builder and the seam. This design makes the *supported* path safe; it does
   not make the library unbypassable by its own embedder.
2. **The policy supplier must be trustworthy.** The seam checks the policy's
   content digest against the descriptor's, which proves internal consistency,
   not that the deployment chose a good policy. A supplier returning a permissive
   policy is honoured exactly as written.
3. **Tier provenance stays with registration.** Unchanged by this sprint: an
   unregistered verifier's claimed tier is believed, and registration is the
   control (§ *Advisory evidence* in `docs/security-model.md`).
4. **Caller completeness stays the caller's contract.** Coverage validates the
   evidence it is GIVEN; a caller that never constructs a result for a check it
   ran looks like a check that never ran, and coverage refuses — the safe
   direction, but still the caller's obligation.
5. **In-process arbitrary code reaches past all of it.** `object.__setattr__`
   defeats `frozen=True`, and the validation stamp is an importable module
   global exactly as `_MINT` is. The control against arbitrary in-process code
   remains the process boundary. The stamp makes an accidental authorization
   impossible and a deliberate one a deliberate act; it is not a security
   boundary and this document does not claim it is one.
6. **Time-of-check to time-of-use on the artifact.** The seam digests the action
   it is handed and the executor runs the action it is handed. Anything able to
   mutate the action object between those two points is in class (5).

## 10. What Checkpoint B implements

The seam, plus tests reproducing every scenario above and a positive control per
finding. Negative tests alone would pass against a seam that refuses everything.

| finding | refusal tests | positive control |
|---|---|---|
| R1 | (a) `replace`-weakened snapshot; (b) assessment resolved under a policy the supplier did not select | a correctly resolved snapshot under the selected policy authorizes |
| R2 | (a) assessment for code A vs action code B; (b) `sandbox.execute` assessment vs `git_delete_branch`; (c) the same, entering at `ActionGate` directly as the swarm does | a matching artifact, class and target authorizes |
| R3 | (a) unvalidated decision presented to `hold`; (b) held-then-approved; (c) `retry_execution` on such a hold | a validated routed action holds, approves and executes |
| R4 | (a) a non-default profile selected and its extra requirement enforced at `build_execution_controller`; (b) the same at the swarm runtime | the default profile still authorizes what it always did |

Plus the do-not-regress set: the eight-state matrix; `bank_decision_surface.json`
byte-identical at
`2ff59e4554418721c1da4b423f084063101be1aeaf47fd4e6ae09edb1097eb80` with 240
rows; R3 interchangeable siblings; the permitted set's SIZE never reaching a
decision; `resolve` never consulting the plan; and the five PHASE-1.2b surfaces
still taking no `Judgment` parameter.

## 11. What this does not close

- **R5 and R6, deferred.** The authorization record still will not carry the
  snapshot digest, attempt id and requirements (R5), and the structured coverage
  report — `answered_by`, `recorded_unavailable` — is still dropped before the
  assessment exists (R6). **These are the AUDIT consequences of this same gap
  and must follow promptly**: enforcement without a record leaves a system that
  decides correctly and cannot show that it did.
- **R7, the mint-sweep alias.** `_resolve_bindings` resolves imports, not
  assignments, so `_m = mint` is invisible to the sweep. Queued behind R5/R6.
- Everything in § A6.

## Checkpoint B implementation

`policy.execution.ExecutionAuthorizer` is now the single assessment-to-execution
seam.  It constructs an immutable `ExecutionDescriptor`, loads the selected
policy through the composition-root supplier, **re-resolves** that policy for
the concrete artifact, consequence class, target principal and attempt, and
compares the resulting snapshot and all six identities with the assessment.
It never re-digests a caller-provided requirement set.  Successful validation
mints the otherwise-unconstructable `AuthorizedExecution` carried by
`GateDecision`; the sandbox, recording-swarm and Git executors reject decisions
without it.

`VerifierBank.assess` performs the same trusted re-resolution before minting a
`PolicyAssessment`.  A bank used for authorization therefore requires a policy
supplier; `SwarmRuntime` binds its explicit policy value and production
factories bind `Config.verification_profile`.  The committed
`defense-in-depth` non-baseline profile adds structural verification to sandbox
execution, making selection observable rather than testing the baseline default
against itself.

Human review resolves only the risk decision.  `PendingActionService.hold`
accepts only a routed decision already carrying `AuthorizedExecution`, refuses
an action argument different from the validated action, and persists the full
binding.  Approval, reload and retry restore that context and re-run the same
authorizer against the currently selected policy before producing an approving
decision.  Legacy rows without an authorization binding are refused with
"re-verification required": manufacturing a completed mandatory check from a
human click would collapse two different authorities.

Production migration issuance also invokes the same authorizer before the
recorded authority may sign.  Unknown profiles are loaded at supported factory
construction, so configuration errors refuse startup rather than silently
falling back to baseline.
