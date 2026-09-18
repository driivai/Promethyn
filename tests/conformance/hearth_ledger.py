"""The Hearth ledger: the SANCTIONED CONTENT of every frozen file.

WHAT THIS REPLACES, AND WHY. Four conformance modules froze the Hearth by
diffing the working tree against ``origin/main`` and rejecting any changed path
that was not in a permitted set — ``_EX1_CHANGED | _HARDEN4_CHANGED |
_TYPE_GATE_CHANGED``. That has the shape of an allowlist and none of the effect,
because the permitted set was over PATHS while what varies is CONTENT. Two
consequences, both real and both found by independent review:

1. **A file sanctioned once was sanctioned forever.** ``gate/authorization.py``
   entered ``_EX1_CHANGED`` in PR #52. From that moment every future edit to the
   authorization gate — the single component that decides whether an action is
   permitted — was invisible to all four guards. Not "reviewed and allowed":
   invisible. The same held for the other nine EX-1 files, the two HARDEN-4
   files and the two TYPE-GATE files.

2. **On main the guard asserted nothing at all.** ``git diff origin/main`` is
   empty once the remote ref points at the same commit, so the moment a sprint
   merged, its Hearth guard went vacuous — passing not because the Hearth was
   intact but because there was nothing to compare. The guard was loudest
   exactly when it was least needed and silent afterwards.

WHAT THIS IS INSTEAD. A digest per protected file, of the content that is
sanctioned. The guard hashes the file on disk and compares. Any edit to any
protected file fails, ``gate/authorization.py`` included, until the digest here
is updated in the same change — which puts the new content in the diff, next to
the reason for it, where a reviewer sees it. A file that was sanctioned once is
not sanctioned forever; a specific STATE was sanctioned, and it stays sanctioned
only while it is that state.

WHAT THE PERMITTED SET IS OVER: the bytes of each protected file. What varies is
the bytes, and every one of them is covered — that is what a digest is.

WHAT CAN STILL VARY THAT THIS DOES NOT CONSTRAIN, stated rather than left to be
found:

* **The file list.** Deleting an entry from a guard's tuple would unfreeze that
  file. ``test_hearth_ledger.py`` pins the union of all four tuples against this
  ledger's key set and against a count, so a dropped file fails.
* **This ledger itself.** Whoever can edit the Hearth can edit these digests.
  That is true of every in-repository guard and is not fixable from inside the
  repository; what the ledger buys is that the edit is a visible, reviewable line
  in the same diff, which the path sets did not buy. (See §"receipt" in
  ``scripts/type_gate.py`` for the same limit stated about the type gate.)
* **Semantics.** A digest proves the bytes are unchanged, not that they are
  correct. The behavioural suites are what prove the Hearth still does its job.

There is deliberately NO git in this module. The comparison reference is the
ledger, not a remote branch, so the guard asserts exactly as much in a fresh
clone, in a worktree, on a feature branch, and on main after merge. The four
guards no longer carry ``skipif origin/main is unresolvable`` — that skip was how
they silently stopped running under a shallow checkout, and it is gone with the
dependency that required it.
"""

from __future__ import annotations

import hashlib
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[2]

#: The Hearth core as ``test_composition.py`` freezes it: the trusted verifier,
#: gate and execution path, plus the orchestration skeleton from PR #46.
COMPOSITION_FILES = (
    "src/prometheus_protocol/verifier/bank.py",
    "src/prometheus_protocol/verifier/aggregate.py",
    "src/prometheus_protocol/verifier/trust.py",
    "src/prometheus_protocol/gate/promotion.py",
    "src/prometheus_protocol/gate/authorization.py",
    "src/prometheus_protocol/execution/executor.py",
    "src/prometheus_protocol/execution/controller.py",
    "src/prometheus_protocol/execution/pending.py",
    "src/prometheus_protocol/forge/miner.py",
    "src/prometheus_protocol/core/models.py",
    "src/prometheus_protocol/core/interfaces.py",
    "src/prometheus_protocol/orchestration/runtime.py",
    "src/prometheus_protocol/orchestration/gateway.py",
    "src/prometheus_protocol/orchestration/messages.py",
    "src/prometheus_protocol/orchestration/workflow.py",
)

#: What ``test_extension_surface.py`` freezes: the Hearth plus the three
#: verifiers a new domain plugs in beside.
EXTENSION_SURFACE_FILES = (
    "src/prometheus_protocol/verifier/bank.py",
    "src/prometheus_protocol/gate/promotion.py",
    "src/prometheus_protocol/gate/authorization.py",
    "src/prometheus_protocol/execution/executor.py",
    "src/prometheus_protocol/execution/controller.py",
    "src/prometheus_protocol/forge/miner.py",
    "src/prometheus_protocol/core/models.py",
    "src/prometheus_protocol/verifier/runner.py",
    "src/prometheus_protocol/verifier/sql.py",
    "src/prometheus_protocol/verifier/grounding.py",
)

#: What ``test_orchestration.py`` freezes: the Hearth core the orchestration
#: layer must not reach into.
ORCHESTRATION_FILES = (
    "src/prometheus_protocol/verifier/bank.py",
    "src/prometheus_protocol/gate/promotion.py",
    "src/prometheus_protocol/gate/authorization.py",
    "src/prometheus_protocol/execution/executor.py",
    "src/prometheus_protocol/execution/controller.py",
    "src/prometheus_protocol/execution/pending.py",
    "src/prometheus_protocol/forge/miner.py",
    "src/prometheus_protocol/core/models.py",
    "src/prometheus_protocol/core/interfaces.py",
)

#: What ``test_soft_levers.py`` freezes: the Hearth plus the DEFAULT soft-judge
#: path, because the levers are opt-in wrappers and not edits to it.
SOFT_LEVER_FILES = (
    "src/prometheus_protocol/verifier/bank.py",
    "src/prometheus_protocol/verifier/aggregate.py",
    "src/prometheus_protocol/verifier/trust.py",
    "src/prometheus_protocol/gate/promotion.py",
    "src/prometheus_protocol/gate/authorization.py",
    "src/prometheus_protocol/execution/executor.py",
    "src/prometheus_protocol/execution/controller.py",
    "src/prometheus_protocol/forge/miner.py",
    "src/prometheus_protocol/core/models.py",
    "src/prometheus_protocol/core/interfaces.py",
    "src/prometheus_protocol/verifier/model_judge.py",
    "src/prometheus_protocol/verifier/grounding.py",
    "src/prometheus_protocol/benchmarks/judge_eval.py",
    "src/prometheus_protocol/benchmarks/grounding_eval.py",
)

#: F-12. THE TWO GUARDS THEMSELVES, which were outside the protected set while
#: guarding everything in it. `security_build.py` is the build guard -- the
#: module that decides whether a requested security property was applied -- and
#: `ledger/readers.py` derives the authoritative reader population. A silent
#: edit to either changes what every other guard's verdict MEANS, and nothing
#: was watching them.
#:
#: The exclusion was recorded as chosen for `sqlite_ledger.py` and `receipts.py`
#: (G35's limit, still open). It was never chosen for these two; they were
#: simply never added. Added here.
SECURITY_GUARD_FILES = (
    "src/prometheus_protocol/runtime/security_build.py",
    "src/prometheus_protocol/ledger/readers.py",
)

#: Every protected file, across all four guards plus the two guard modules.
#: Pinned by count in ``test_hearth_ledger.py`` so shrinking a guard's tuple
#: cannot pass unnoticed.
PROTECTED_FILES = tuple(sorted(
    set(COMPOSITION_FILES)
    | set(EXTENSION_SURFACE_FILES)
    | set(ORCHESTRATION_FILES)
    | set(SOFT_LEVER_FILES)
    | set(SECURITY_GUARD_FILES)
))

EXPECTED_PROTECTED_FILES = 23

#: SHA-256 of the sanctioned content of each protected file.
#:
#: The sanctioned state is the one on main at d0819bb, which is the accumulation
#: of the deltas the four guards used to name by path:
#:
#: * **EX-1 (PR #52)** — a HARD verifier that cannot execute must not abstain.
#:   Changed ``core/models.py``, ``core/interfaces.py``, ``verifier/runner.py``,
#:   ``verifier/sql.py``, ``verifier/bank.py``, ``gate/authorization.py``,
#:   ``benchmarks/judge_eval.py``, ``orchestration/runtime.py``,
#:   ``execution/controller.py``, ``execution/pending.py``.
#: * **PROM-HARDEN-MAX attacker 4** — a provider that cannot be reached returns
#:   ``Unavailable``, not an ``ABSTAIN`` Evidence. Changed
#:   ``verifier/model_judge.py`` and ``verifier/grounding.py``.
#: * **TYPE-GATE** — ``gate/promotion.py`` (``ScoreFn`` corrected to
#:   ``Sequence[LearnableTask]``, which the gate already forwarded, plus the
#:   caller-side ``OUTCOME_UNAVAILABLE`` marker the gate never returns;
#:   ``approved``, the one field the executor reads, untouched);
#:   ``benchmarks/grounding_eval.py`` (a ``.verdict`` read off an
#:   ``Evidence | Unavailable`` replaced by ``judged=None`` +
#:   ``judge_unavailable=True``); ``verifier/bank.py`` (four ratcheted
#:   ``# type: ignore[arg-type]`` replaced by ``Evidence.decided``, which states
#:   the ``__post_init__`` guarantee the ``Verdict | None`` field type could not
#:   — the fused verdict, the confidence arithmetic and the calibration writes
#:   unchanged).
#:
#: * **PROD-FIX-2 (F8)** — ``verifier/model_judge.py``. Two changes, both about
#:   what reaches a PERSISTED record. On the SUCCESS path the judge wrote the
#:   RAW MODEL RESPONSE into ``Evidence.detail``, so an endpoint reflecting the
#:   Authorization header put a bearer token into the ledger with a PASS beside
#:   it; it now writes a bounded classification (the parsed verdict and the
#:   response length). On the failure path the ``Unavailable.detail`` quoted the
#:   provider exception's text; it now names a reason code and the exception
#:   TYPE. The judge's decision logic — the prompt, ``_parse_verdict``, the
#:   Evidence fields the bank reads — is untouched.
#:
#:   ``benchmarks/judge_eval.py`` changed with it, and had to: ``parse_confidence``
#:   read the confidence back OUT of the raw reply, so the calibration metrics
#:   depended on the remote text this sprint removes. The confidence is now
#:   parsed at the judge and carried as an explicit field; this function reads
#:   that field, and still reads the legacy first-line form for any custom
#:   verifier that writes a reply into ``detail``. No metric changed.
#:
#:
#: * **PHASE-1.2a (the trusted verification-policy model)** — ``verifier/bank.py``.
#:   The sprint the net-diff-empty guard was holding this file for. ``judge`` is
#:   UNCHANGED — the decision surface in ``bank_decision_surface.json`` did not
#:   move by a single row, and that is the point: fusion was not re-tuned. What is
#:   added is ``judge_covered``, a NEW entry point in front of it that validates
#:   required coverage against the resolved policy snapshot BEFORE fusing, and
#:   refuses when a required check has no valid, satisfactory, correctly bound
#:   result. ``judge`` remains for callers that have not migrated, which is a
#:   NAMED EXPOSURE rather than an oversight: closing it means a raw
#:   ``Judgment(PASS, authoritative=True)`` must stop being sufficient for
#:   authorization, a breaking interface change and the next sprint's subject.
#:
#:
#: * **PHASE-1.2b (closing the downstream bypass)** — five files, one change.
#:   Checkpoint 2 built coverage enforcement and named its own exposure: a raw
#:   authoritative ``Judgment`` still authorized. Four surfaces took one and asked
#:   it a question a ``Judgment`` can answer with no policy ever resolved, so the
#:   system was policy-enforced on the migrated paths and unenforced everywhere
#:   else. Each of these files loses the parameter an unbound verdict arrived
#:   through, and gains one that takes a ``PolicyAssessment`` instead:
#:
#:   - ``verifier/bank.py`` — ADDS ``assess``, which wraps what ``judge_covered``
#:     already returned in a snapshot-bound assessment. ``judge`` and
#:     ``judge_covered`` are untouched; the 240-row decision surface does not move.
#:   - ``gate/authorization.py`` — ``ActionGate.decide`` takes an assessment.
#:   - ``execution/controller.py`` — ``submit`` takes ``assessment=``. The old
#:     ``judgment=`` keyword is REMOVED rather than deprecated: leaving it would
#:     leave the bypass reachable by a caller that never migrated.
#:   - ``orchestration/gateway.py`` — ``route_action`` and the ``SubmitFn``
#:     protocol carry an assessment. The gateway still authorizes nothing.
#:   - ``orchestration/runtime.py`` — resolves a snapshot per action and binds the
#:     grader's evidence, so a caller-chosen grader can no longer authorize a
#:     sandbox execution by being present.
#:
#:
#: * **PHASE-1.2c COMMIT ONE (correcting the docstrings)** —
#:   ``gate/authorization.py`` and ``execution/controller.py``. **Comment-only.
#:   No statement, signature, parameter or branch changed in either file**; both
#:   diffs are additions to a docstring. They are here because an independent
#:   review found the docstrings claiming properties the code does not have, and
#:   a false claim in the file a reader opens first is the failure mode this
#:   repository keeps correcting — so it is corrected BEFORE the sprint that
#:   makes the claims true, not in the same commit.
#:
#:   - ``gate/authorization.py`` — ``ActionGate.decide`` now records that it
#:     reads ``assessment.outcome`` and NOTHING else: ``action`` is never
#:     compared with ``artifact_sha256`` or ``action_class``, and
#:     ``snapshot_digest`` is compared with nothing. Measured: an assessment for
#:     artifact A approves code B, and a ``sandbox.execute`` assessment approves
#:     a ``git_delete_branch``.
#:   - ``execution/controller.py`` — ``submit`` now records that it is one door
#:     and not the door. ``PendingActionService.hold`` takes a ``GateDecision``
#:     and no assessment; measured, a routed decision carrying
#:     ``Judgment(FAIL, 1.0, authoritative=True)`` is held, approved and
#:     executed (one executor call).
#:
#:   The digests move because the bytes moved. Nothing either file DOES moved,
#:   which is the whole reason this sanction is a small one.
#:
#: * **PHASE-1.2c CHECKPOINT B (trusted execution descriptor)** — the bank,
#:   action gate, controller, pending service, real executors, orchestration
#:   gateway/runtime and Ledger port now carry one seam-minted authorization.
#:   The selected policy is re-resolved before assessment minting and again on
#:   hold admission/reload/approval/retry; the concrete action, trusted target
#:   and mandatory attempt identity are compared before execution. These files
#:   legitimately move together because sanctioning only one side would leave
#:   the direct-gate, human-hold or executor join open.
#:
#:
#: * **PHASE-1.2c REMEDIATION (Evidence by construction)** — ``core/models.py``.
#:   One decorator: ``@dataclass(frozen=True)`` became
#:   ``@dataclass(frozen=True, kw_only=True)`` on ``Evidence``. No field, no
#:   default, no method and no ``__post_init__`` changed; the class's behaviour
#:   is identical for every correctly-constructed instance.
#:
#:   What it removes is a SHAPE. ``Evidence`` carries fourteen fields with four
#:   optional ones between the commonly-set ones, so
#:   ``Evidence(True, 1, 1, (), "runner", Verdict.PASS, tier=Tier.HARD)`` reads
#:   as though "runner" is the verifier id when it is ``stdout``. Nothing raises:
#:   the value lands in a plausible slot and ``verifier_id`` keeps its default.
#:   Measured — that spelling was live in the Checkpoint B proofs and invisible,
#:   because every path it sat on refused BEFORE coverage compared the result's
#:   implementation with the evidence's verifier id. It surfaced only when a
#:   positive control expected coverage to hold.
#:
#:   A mis-slotted field here is a policy input set by accident, so the fix is at
#:   the constructor rather than at the call sites: there is no positional form
#:   left to miscount, including in code nobody has written yet. A sweep for the
#:   same shape across every dataclass of six or more fields found 59 positional
#:   constructions; they are reported rather than converted, because converting
#:   twenty-odd classes is a separate change and this one is load-bearing.
#:
#:   FOLLOW-UP, same file: ``Judgment`` is now kw_only too. It is the value the
#:   #95 raw-Judgment bypass was about and the one R3's human path carries, and
#:   its first three fields are ``verdict, confidence, authoritative`` — a
#:   reorder or a miscount there mis-assigns a VERDICT, which is the field the
#:   gate reads. Eleven positional call sites converted, all in tests. Measured
#:   blast radius before converting: Judgment 17 failures, SignEvent 104,
#:   DbTarget 95. The latter two are filed rather than forced through in the
#:   same commit; a 200-site mechanical sweep is its own change with its own
#:   verification, not a rider on this one.
#:
#: * **PHASE-1.2c TASK 5/6 (the authorization record and the pinned hold)** —
#:   four files, one seam widened on the audit side and one refusal added on
#:   the approval side. No fusion decision moved: ``bank_decision_surface.json``
#:   is unchanged at 240 rows.
#:
#:   - ``verifier/bank.py`` — ``assess`` keeps the coverage REPORT (which
#:     implementation answered, which could not, which row refused) beside the
#:     outcome and mints it into the assessment; the validate-then-fuse body
#:     moves from ``judge_covered`` into ``_judge_with_coverage`` and
#:     ``judge_covered`` delegates to it. Same validation, same outcome; only
#:     what is reported grew. (R6)
#:   - ``core/interfaces.py`` — ``record_execution`` takes the authorization
#:     record; the port gains ``invalidate_pending_action`` and the audit-chain
#:     trio (``record_chained``, ``chained_events``, ``verify_chain``), because
#:     the pending service binds every hold's record into the chain and a
#:     ledger that could hold an action but not chain its record would leave
#:     the record in a JSON column, trusted because it is there.
#:   - ``execution/pending.py`` — ``hold`` writes the versioned record and its
#:     chain entry; approval and retry check the row against the entry on a
#:     chain that verifies, then the pinned policy against the selected one (a
#:     rotation is refused as ``PinnedPolicySuperseded`` and the hold voided,
#:     in either direction), and only then decode the record inside the seam,
#:     which re-resolves exactly as before. Loading a row no longer
#:     re-authorizes it, so listing holds after a rotation works and approval
#:     can name the rotation rather than a bare mismatch. ``invalidate_superseded``
#:     is the explicit half. The TTL path is untouched.
#:   - ``execution/controller.py`` — every ``executions`` row carries the record
#:     (the hold's PINNED record for human-approved and retried executions);
#:     ``invalidate_superseded_holds`` delegates to the pending service.
#:
#:   Proven in ``test_execution_authorization_record.py`` (17) and
#:   ``test_hold_pinning.py`` (7), with six executed mutations in
#:   ``scripts/phase_1_2c_record_revert_proofs.py``. The Checkpoint-B mutation
#:   "hold-policy-re-resolution-removed" is re-expressed as
#:   "hold-pinned-policy-comparison-removed" against the code that now carries
#:   that property.
#:
#: * **PHASE-1.2c FINAL (a withdrawn claim, and the TTL written down)** — one
#:   file, ``execution/pending.py``, DOCSTRING ONLY. No statement, expression or
#:   import changed; ``git diff`` on this sanction touches nothing but the module
#:   docstring, and the behaviour it describes is the behaviour that was already
#:   there. Two reasons, both about what the file CLAIMS:
#:
#:   - The first clause of the approval order said "pinning removes
#:     re-resolution from the approval path" while step 3 of the same list, and
#:     the code, re-resolved. A reader who believed the first clause would think
#:     the stored requirements were authoritative on their own, which is exactly
#:     the direction that reintroduces R1 one layer down. The claim is withdrawn
#:     in place, and what pinning does NOT do is now stated explicitly, because
#:     the same assumption has arrived twice from outside.
#:   - The TTL's semantics were spread across three method docstrings and
#:     ``_is_lapsed``. Now said once: evaluated at BOTH decision time and by the
#:     sweep, the boundary inclusive (``elapsed >= ttl_seconds``), and a hold
#:     that has lapsed but not been swept still reads ``pending`` while being
#:     unapprovable — the state that had no test and now has two.
#:
#: * **PR #106 P1 (the unbounded sentinel must reach the adapter)** — one file,
#:   ``verifier/runner.py``. ``SubprocessVerifier``'s three caps now accept
#:   ``UNBOUNDED`` in addition to an int and CARRY it into ``Limits`` instead of
#:   flattening it to ``0``. Nothing about verdicts, evidence or the sandbox
#:   boundary changed; ``0`` still means "no limit" and every existing caller
#:   passing one is unaffected.
#:
#:   The reason it had to change at all: the Codex review found that resolving
#:   the sentinel before the adapter saw it made ``ContainerSandbox`` turn a
#:   named "no memory cap" into a **16 MiB cap**, via a ``max(bytes, 16 MiB)``
#:   floor that predates the change. A verifier that flattens the posture cannot
#:   be fixed downstream, so the carrying had to start here. ``core/bounds.py``
#:   holds the vocabulary and the full account.
#:
#: * **CODEX REVIEW REMEDIATION (typed execution refusal reasons)** — two files,
#:   ``verifier/bank.py`` and ``execution/pending.py``. Both changes attach a
#:   ``reason=`` from the closed ``EXECUTION_REFUSAL_REASONS`` set to refusals
#:   that already existed. No branch was added, removed or re-ordered; no
#:   message text changed; every refusal fires on exactly the input it fired on
#:   before. ``pending.py`` also gains a docstring paragraph recording that
#:   revalidation runs BEFORE the TTL check, which narrows the literal
#:   "expired on the spot" claim without changing the ordering.
#:
#:   The reason it had to change: four materially different integrity states —
#:   the chain did not verify, a legacy record needs re-verification, there is
#:   not exactly one chain entry, the record differs from its chain entry — were
#:   distinguished only by prose, so a test asserting WHICH one fired had to
#:   match a message. That is the third instance of this class in the arc, and
#:   the one in ``test_execution_authorization_record.py`` sat in the same file
#:   where Block 1a nearly closed on the wrong evidence.
#:
#: * **G26 (the implementation registry)** — four files, the SAME two-line
#:   change in each: ``verifier/runner.py``, ``verifier/sql.py``,
#:   ``verifier/grounding.py``, ``verifier/model_judge.py``. One import from
#:   ``policy/implementations.py`` and ``VERIFIER_ID = <the declared object>``
#:   in place of the literal it used to re-spell. The identity each verifier
#:   REPORTS is byte-identical to before (``"subprocess-tests"`` and so on);
#:   what changed is that it is now the same object as the policy module's
#:   ``IMPL_*`` constant and as the registry's declaration, so the three copies
#:   that agreed by hand are one declaration and two references, and a policy
#:   naming a misspelling is refused at construction rather than on every
#:   assessment. No verdict, no tier, no evidence field, no sandbox call moved.
#:
#:   The reason it had to touch Hearth files at all: the derivation cannot run
#:   the other way. ``swarm/runtime.py`` imports the policy module, so the
#:   policy module cannot import the implementations; the implementations
#:   import their identity from a policy-package leaf instead, and that leaf
#:   imports nothing above ``policy/snapshot.py``.
#:
#: * **RE-OBSERVATION AT EXECUTION, PHASE 1 (G29)** — three files, and each
#:   change is an ADDITION at a named point rather than a rewrite of anything
#:   that was there. No existing branch was removed or re-ordered, and no
#:   existing refusal fires on different input than before.
#:
#:   - ``core/interfaces.py`` — the Ledger port gains ``mark_state_moved``, the
#:     ONE transition out of ``APPROVED``. It is a new abstract method rather
#:     than a parameter on an existing resolver because both existing resolvers
#:     guard on ``status = 'pending'`` deliberately, so that a decided hold is
#:     never re-opened; widening either would widen it for expiry and rotation
#:     too. Nothing else on the port moved.
#:   - ``execution/pending.py`` — the live state is CAPTURED at hold creation
#:     into the pinned record's ``target_state``, and ``approve`` gains the
#:     pre-approval comparison. The comparison sits after the TTL check and
#:     before the APPROVED write: before the write is the invariant (an approval
#:     on the record is one whose premise still held), and after the TTL is a
#:     sub-ruling recorded in the code — a live read spent on a hold that has
#:     already lapsed would produce an unavailability that MASKS a plain expiry.
#:     Also gains the pre-execution entry point the controller calls, and the
#:     chained observation record both comparisons write.
#:   - ``execution/controller.py`` — ``_execute`` gains the pre-execution
#:     re-read, placed after the at-most-once claim and immediately before
#:     ``executor.execute`` with nothing between them. That placement IS the
#:     bound it provides; the residual is recorded in the design's §7.1.
#:
#:   Deployments that wire no re-observation are unaffected in behaviour: the
#:   registry is optional and every existing suite passes with it absent. What
#:   they do NOT get is silence — ``policy/record.py``'s ``RECORD_VERSION`` moved
#:   1 -> 2 and a v2 record always carries a ``target_state`` block saying which
#:   of the three cases it is, because an absent block and a passing comparison
#:   would otherwise be the same bytes.
#:
#: RE-SANCTIONED AGAIN — re-observation WIRING, and the registry-mismatch
#: refusal it made reachable. One protected file moved:
#:
#:   - ``execution/pending.py`` — ``_compare_now`` gains a guard BEFORE it asks
#:     the registry to observe: a hold whose record says its live state was
#:     pinned, held by a service whose registry has that action class opted out,
#:     is refused (``StateUnobservable`` / ``target_state_registry_mismatch``)
#:     instead of compared or skipped. Also ``_from_row`` now reconstructs the
#:     human decision for ``STATE_MOVED`` holds, and the observation subject
#:     carries the pending-hold id so two holds sharing an ``attempt_id`` cannot
#:     collide on one receipt.
#:
#:   WHY THAT GUARD EXISTS AND WHY IT IS A REFUSAL. Until the previous sprint's
#:   mechanism was actually WIRED at the composition roots, no root held a
#:   registry, so two roots could never disagree. They can now, and the
#:   disagreement is reachable through the shipped CLI: ``prom approve`` builds
#:   its controller with the default ``sandbox://execution`` target, which opts
#:   ``branch.delete`` out, while the hold it approves may have been pinned by a
#:   root naming a ``git://`` principal. Measured: before the guard, that path
#:   raised a bare ``KeyError`` out of ``approve``. Skipping the comparison
#:   instead would execute an irreversible delete on evidence the hold's own
#:   record claims was re-checked — degrading a requested security property
#:   rather than refusing it. OPEN-GAPS G31.
#:
#: RE-SANCTIONED for the three review findings on the re-observation seam.
#: ``execution/controller.py`` moved for all three:
#:
#:   - **The supplied-service combination is refused, not degraded.**
#:     ``pending or PendingActionService(...)`` never constructs the service
#:     when one is supplied, so a ``reobservation=`` passed beside a ``pending=``
#:     was silently discarded and BOTH comparisons then ran on the supplied
#:     service's registry — possibly ``None``. A controller that looked enabled
#:     ran neither check. Now a ``ConfigError`` with the typed reason
#:     ``reobservation_registry_discarded``, compared by IDENTITY: equality on
#:     this dataclass delegates to the observers' ``__eq__``, which is a
#:     property of classes this check does not own, so an equality check could
#:     loosen without being edited.
#:   - **A pre-execution refusal writes a refused execution row** before it is
#:     re-raised. The hold was claimed and an execution was attempted; with no
#:     row, ``executions_for_pending`` cannot say why an approved action did not
#:     run, which is the audit contract this controller states.
#:   - **The claim is released for every refusal except a move.** Retaining it
#:     after a transient observer outage left the hold ``approved`` — so
#:     ``retry_decision`` accepted it — while ``claim_pending_execution`` failed
#:     forever: an approved action permanently unexecutable because a reader was
#:     down for a moment. The rule is keyed on TYPE (``CLAIM_RETAINED_BY``) and
#:     its key set is pinned by a test.
#:
#: RE-SANCTIONED for the pre-upgrade observation receipt (OPEN-GAPS G33).
#: ``execution/pending.py`` moved:
#:
#:   - ``pre_approval_entry`` now searches the PRE-UPGRADE subject spelling as
#:     well as the current one. A ledger outlives a deployment: a hold approved
#:     by the previous release wrote its receipt under ``observation:<attempt>#0``,
#:     before the pending-hold id was part of the key, and a lookup that found
#:     nothing made the execution receipt say ``prior: null`` — the spelling
#:     that means "this was the first reading". The record stated that state was
#:     never checked at approval for a hold where it was.
#:   - A receipt resolved that way is MARKED, never passed off as an exact
#:     match, and several receipts sharing one legacy subject are REFUSED rather
#:     than guessed between: taking the first is how the later hold's execution
#:     comes to restate the earlier hold's reading, which is the collision the
#:     new key was added to remove.
#:   - ``require_state_unmoved_for_execution`` refuses a pinned, observed hold
#:     whose receipt cannot be found under either spelling. The guard is
#:     CONDITIONED on the registry covering the class, and that condition is
#:     load-bearing: without it the guard reddens the kept gap reproduction,
#:     because a deployment that wires nothing pins nothing and would be refused
#:     at execution for a receipt it had no reason to write.
#:
#: RE-SANCTIONED for F16 — a setup timeout must not record as a successful
#: execution. ``execution/executor.py`` moved:
#:
#:   - ``_run`` decided the outcome from ``started_ok`` ALONE. The sandbox
#:     contract (``sandbox/base.py``) says ``started_ok`` answers only "did
#:     isolation start", and that ``started_ok=True`` with
#:     ``candidate_started=False`` — a wall-clock timeout during SETUP, before
#:     the candidate ran — "stays a harness fault". Reproduced: that triple
#:     returned ``executed=True`` with the detail "ran in sandbox".
#:     Could-not-verify written into the execution record as verified-clean, at
#:     the point downstream can no longer recover the difference.
#:   - It now refuses that triple, as it already refused ``started_ok=False``.
#:     No new outcome category: ``runner.py``'s three-way split has a verdict
#:     ABOUT the candidate in it, and the executor has no verdict to give —
#:     ``exit_status`` carries the candidate's own outcome — so the split
#:     collapses onto the two outcomes the executor already has.
#:   - KEYED ON ``candidate_started``, NOT on ``timed_out``: a candidate that
#:     started and was then wall-clock killed really did run and its side
#:     effects happened, and keying on the timeout would discard that
#:     execution's record. Pinned by its own test.
#:
#:   The verifier seam has classified this same triple as
#:   ``Unavailable(INFRA_FAULT)`` since the equivalent bug was found there
#:   (``test_sandbox_fault_classification.py``). The executor was reading fewer
#:   fields than the verifier for the same underlying fact; this is it catching
#:   up to its own contract.
#:
#: AMENDED IN THE SAME SPRINT, after review of the fix itself. The refusal
#: above first wrote ``started_ok=False`` for a case where isolation HAD
#: started. It refused correctly and recorded falsely — ``started_ok`` is
#: documented as whether ISOLATION started — and made the two harness faults
#: (no runtime; a setup that ran out of wall clock) indistinguishable in the
#: record. That is the collapse the refusal existed to prevent, committed one
#: field over. ``ExecutionResult`` now carries ``candidate_started`` beside
#: ``started_ok``, mirroring ``SandboxResult``, and each refusal states both
#: facts truthfully.
#:
#: * **REACHABILITY F1/F2/F3** — ``execution/pending.py`` now records an
#:   unavailable observation before refusing a persisted observation obligation
#:   that the current registry cannot satisfy, including a missing registry.
#:   ``core/interfaces.py`` supplies the raw receipt-source seam for diagnostics
#:   while guarded SQLite readers consult authoritative chained records.
#:   ``gate/authorization.py`` corrects its unavailable outcome documentation
#:   and emitted reason: the controller halts without an approvable human hold.
#:   These are deliberate content changes, not a permanent exemption for paths.
#:
#: * **G24 — AN AUTHORIZATION IS SPENT WHEN IT IS USED** — three files, one
#:   ruling. Measured at ``7cc2c4c``: the same correctly bound assessment,
#:   action and ``attempt_id`` submitted twice called the executor TWICE and
#:   wrote two execution rows, and a retained approved ``GateDecision`` handed
#:   straight to a concrete executor ran TWICE. A third path — ``swarm/
#:   runtime.py`` — reached an executor with no claim at all.
#:
#:   - ``execution/controller.py`` — ``_execute`` now spends the OCCURRENCE on
#:     every path, with NO ``pending_id is not None`` exception: that exception
#:     was the finding. The state is read early (so a replay refuses by name)
#:     and the claim is taken immediately before the executor (so it is
#:     at-most-once under concurrency). ``submit`` gains an optional
#:     ``idempotency_key``; a matching retry returns the PRIOR result, read
#:     through the chain, and calls no executor. The hold claim is untouched
#:     and remains the hold's retry-eligibility state.
#:   - ``execution/executor.py`` — ``SandboxExecutor.execute`` consumes the
#:     minted authorization BEFORE the sandbox check, because a caller holding
#:     a retained decision reaches that line without passing any gateway. A
#:     second presentation is refused for being a second presentation, whatever
#:     the sandbox would have said.
#:   - ``core/interfaces.py`` — the ``Ledger`` port gains the five spend
#:     methods and the single-row ``execution`` reader. A port that could not
#:     express the spend would have made the guarantee a property of one
#:     implementation.
#:
#:   The authority is the append-only chain, not the ``spent_authorizations``
#:   row, which decides the race and nothing else. See ``docs/OPEN-GAPS.md``
#:   G55 for the measurement, the residuals and what the mutation runner found.
#:
#:   RE-SANCTIONED IN THE SAME SPRINT, after review of #127 found that a
#:   returned prior result left ``stdout`` at its default. ``executions`` has
#:   no ``stdout`` column — measured — so a retry cannot be handed the
#:   program's output, and ``""`` is exactly what a program that printed
#:   nothing produces: "never recorded" and "printed nothing" became the same
#:   bytes at the point a caller reads them. The column is NOT added, because
#:   PROD-FIX-2 removed a raw model response from a persisted record for the
#:   same class of unbounded, attacker-influenced text; the limit is named in
#:   the field instead. ``policy/execution.py`` moved with it, putting the
#:   executor wall's check-and-set under a lock — see G55's residuals for what
#:   that does and does not prove.
#:
#: Those sprints are why these bytes are what they are. They do NOT license the
#: next edit to the same files: updating a digest below is a fresh decision, and
#: the reason for it belongs beside it.
DIGESTS: dict[str, str] = {
    # F-12: the two guard modules, sanctioned at the content that closes F-1,
    # F-4, F-5 and F-8. Unlike the rest of this ledger these are NOT frozen at
    # d0819bb -- they did not exist in the set then -- so their first sanctioned
    # state is this change.
    "src/prometheus_protocol/runtime/security_build.py":
        "9cf8f6db17317a0680c5df9f19755dcdd6e495e4b86212bfc77e157efc579c3a",
    "src/prometheus_protocol/ledger/readers.py":
        "3f3768d28ccf46ec6583796ed98f69eaed2ccbcb6f6a94abc0468ac4712c0cda",
    "src/prometheus_protocol/benchmarks/grounding_eval.py":
        "c60d17487aabd916fa79d57f5ddcdf301813186e704a937081d92db191143d01",
    "src/prometheus_protocol/benchmarks/judge_eval.py":
        "25430b5645aff6f655cfaccf33edd9e1cea3e5b4d0c62ef7f23183d9da9f3866",
    "src/prometheus_protocol/core/interfaces.py":
        "b7cbd57ea6b3ae889effac572e69fe111fd6f5e1701237019dcc560f8f1d4689",
    "src/prometheus_protocol/core/models.py":
        "96fe20410439abdb87fd9a34becdffab032fd106a5fa70f80271527a79df5910",
    "src/prometheus_protocol/execution/controller.py":
        "906c5d283dc7964fc20454d6da95ea0011ffc3afb3252278d8cca04c0063d701",
    "src/prometheus_protocol/execution/executor.py":
        "406e74033bc63d0c1739d109cab02ee31a553e5194d2e529526787dbe9dc944d",
    "src/prometheus_protocol/execution/pending.py":
        "eb4f2af5dd7999b4ed7504b8a52831af9522494fce3a5d88580bbd5224b4536a",
    "src/prometheus_protocol/forge/miner.py":
        "b0e2a53440df5b38a1031cc9648e19b3f9df20081ee34d4e035beda2b6973a29",
    "src/prometheus_protocol/gate/authorization.py":
        "cf1636871b21aa7c7669fa049f4818b2404bfb133465c128c2f75ebfb6d227e2",
    "src/prometheus_protocol/gate/promotion.py":
        "8b37e56a52706f66fe7c22fd51c8d10fa95a3ba2d07cae76068c5b85b7c628fa",
    "src/prometheus_protocol/orchestration/gateway.py":
        "2c5efd28491e5c2da60e45c56c6b4f56511c80363f8f400b89fc8c949db497d5",
    "src/prometheus_protocol/orchestration/messages.py":
        "bf2d1ff2e986c97aa4bc9c832f0cc18c1950740213dae6c4dc061e84e1073e1e",
    "src/prometheus_protocol/orchestration/runtime.py":
        "155f2e3ded19d9eada66999a82f3180f2887708230d871ea990d33b42724d2ce",
    "src/prometheus_protocol/orchestration/workflow.py":
        "5192847972a44f58d52f838db294c3cdc801d97e1b4bb7bc144fc808fef30e3b",
    "src/prometheus_protocol/verifier/aggregate.py":
        "5963bb6b4047c0ec2c900b10187e861ad95541dca87c0b98bdb5db34dcd1c37c",
    "src/prometheus_protocol/verifier/bank.py":
        "68464ca7ba79e03d8b77f9322af89a3df3f3f4b0ce547efcd0d9d9a6a18d70aa",
    "src/prometheus_protocol/verifier/grounding.py":
        "ce0b5efcac33802e2c3f5668589f401d2b7bce30062625fe51b4fc0c732de255",
    "src/prometheus_protocol/verifier/model_judge.py":
        "d4d2edcea250a4f5ea9825e11add33e3dea82500cb31d7dafde63c6068654d48",
    "src/prometheus_protocol/verifier/runner.py":
        "ce1618f8a550a2de1398bfd48734c3b36fec6df7c2c959f6bd2c99c752680281",
    "src/prometheus_protocol/verifier/sql.py":
        "c7ed91d3c1a3e25d70a52fb1708247768c103c58db7faad428bd532e54ba279e",
    "src/prometheus_protocol/verifier/trust.py":
        "e043b87e1b03613a18e7fa9ec037759f8049ca731b7cbe9d5bbac7622322792e",
}


def digest_of(relative_path: str, root: pathlib.Path | None = None) -> str:
    """SHA-256 of a protected file's bytes, read from ``root`` (default: repo)."""

    return hashlib.sha256(((root or REPO) / relative_path).read_bytes()).hexdigest()


def unsanctioned_changes(
    paths: tuple[str, ...], root: pathlib.Path | None = None
) -> list[str]:
    """Every protected file in ``paths`` whose content is not the sanctioned one.

    ``root`` exists so the guard can be pointed at a synthetic tree and PROVED to
    report a change — see ``test_the_ledger_actually_detects_a_changed_file``. A
    guard that cannot be shown to fire is a guard nobody has checked.
    """

    findings = []
    for relative_path in paths:
        sanctioned = DIGESTS.get(relative_path)
        if sanctioned is None:
            findings.append(
                f"{relative_path}: protected but absent from the ledger — add its "
                "sanctioned digest, do not drop it from the guard"
            )
            continue
        actual = digest_of(relative_path, root)
        if actual != sanctioned:
            findings.append(
                f"{relative_path}: content is {actual[:16]}…, sanctioned state is "
                f"{sanctioned[:16]}…"
            )
    return findings


UNSANCTIONED_MESSAGE = (
    "A frozen file's content is not the sanctioned content. This is not a "
    "diff against a branch — it is the bytes on disk against the bytes this "
    "repository agreed to. If the change is intended, update the digest in "
    "tests/conformance/hearth_ledger.py in THIS change, with the reason beside "
    "it, so the new content is reviewed rather than inherited. Adding the path "
    "to a permitted list is what this replaced: it sanctioned the file forever "
    "instead of sanctioning a state."
)
