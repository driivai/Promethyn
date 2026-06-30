# Promethyn — Invariants

These are formal claims a conforming implementation must uphold. Each is
checked by code; the relevant tests are noted.

## I1. Held-out firewall (load-bearing)

> Let `T` be the set of task ids the forge learns from (the `train` split) and
> `H` be the set of task ids the gate scores a candidate against (the
> `heldout` split). Then `T ∩ H = ∅`, always.

Rationale: if the two sets intersect, a skill could be promoted because it
fits the very tasks it was mined from, and the held-out pass rate would no
longer be evidence of generalisation.

Enforcement:
- The forge refuses any non-`train` attempt (`forge/miner.py`).
- The gate calls `assert_disjoint(train_ids, heldout_ids)` before scoring any
  candidate and raises `FirewallError` on intersection (`gate/promotion.py`).

Tests: `tests/conformance/test_firewall.py`.

## I2. Reversibility

> Every promotion can be undone, restoring the prior observable behaviour.

Skills are plain markdown files in the registry; removing a skill returns the
runtime to its pre-promotion pass rate. Promotions are recorded in the ledger
so they can be replayed or rolled back deterministically.

Tests: `tests/conformance/test_promotion.py::test_promotion_is_reversible`.

## I3. Auditability

> From the ledger alone, one can recover what was attempted, what passed, and
> what was promoted, in order.

Every attempt and every promotion is appended to the ledger with its cycle and
phase. No state change relevant to learning happens off-ledger.

Tests: `tests/conformance/test_promotion.py::test_run_is_auditable`.

## I4. Verifier authority

> A task passes only if the verifier returns a hard pass over all its hidden
> cases. The proposer never sees the hidden cases.

The provider contract accepts only the prompt, the entry point, and retrieved
skills. Hidden cases are supplied solely to the verifier.

Tests: `tests/unit/test_verifier.py`, `tests/unit/test_provider_mock.py`.

## I5. Determinism of the reference loop

> With the simulated provider and a fixed benchmark, the loop produces the
> same outcomes on every run.

Retrieval, mining, and gating are deterministic; the simulated provider uses
no randomness and no network. (A live model provider is not bound by this
claim.)

Tests: the conformance suite asserts exact rates rather than ranges.

## I6. Authoritative dominance

> A soft-tier verdict can never override a hard-tier verdict; it may only
> inform calibration.

When any authoritative verdict (hard or human) is present, the fused result is
decided by the authoritative reference. Advisory verifiers (soft, consistency)
contribute no weight to that result; their verdicts are recorded only as
calibration samples against the reference.

Enforcement: the verifier bank fuses the reference tier's verdicts for the
result and feeds advisory verdicts solely into trust updates
(`verifier/bank.py`).

Tests: `tests/conformance/test_verifier_trust.py::test_i6_soft_cannot_override_hard`.

## I7. Earned weight

> An un-audited verifier carries zero aggregation weight until calibrated
> against trusted references.

A verifier with a non-informative prior (soft or consistency tier) and no
calibration evidence has a Youden index of 0 and contributes a
log-likelihood ratio of exactly 0 to fusion — it cannot move a verdict.
Authoritative tiers are trusted by construction through their priors; advisory
tiers must earn weight by agreeing with authoritative references.

Enforcement: tier-dependent Beta priors and the log-likelihood-ratio fusion in
`verifier/trust.py` and `verifier/aggregate.py`.

Tests: `tests/conformance/test_verifier_trust.py::test_i7_unaudited_verifier_has_zero_weight`
and `::test_trust_is_earned_through_calibration`.

## Swarm invariants

These govern the swarm reasoning front-end (see `spec/swarm.md`). They are the
structural wall between proposing and asserting truth or authorizing action.

### INV-SWARM-1. The wall

> There is no code path from a `Proposal` or a `TestPlan` to
> `Executor.execute`. The executor accepts only an approved `GateDecision`.

Enforcement: `Executor.execute(decision: GateDecision)` has no overload taking a
proposal or test plan; it rejects a non-`GateDecision` argument and refuses an
unapproved decision (`swarm/executor.py`).

Tests: `tests/conformance/test_swarm_invariants.py::test_inv1_*`.

### INV-SWARM-2. Debate selects, never certifies

> `DebateLayer.select` returns a `TestPlan` with no verdict, confidence, or
> approval field. The only producer of a `Judgment` is the verifier bank, and
> of a `GateDecision`, the gate.

Enforcement: the `TestPlan` types carry no truth field, and no swarm module
constructs a `Judgment` or `GateDecision` (`swarm/debate.py`, `swarm/models.py`).

Tests: `tests/conformance/test_swarm_invariants.py::test_inv2_*`.

### INV-SWARM-3. Mandatory roles

> Every assembled swarm contains a non-removable `Skeptic` and
> `PolicyReviewer`. Configs that omit or forbid them still yield them; removal
> raises.

Enforcement: `RoleSynthesisEngine.assemble` injects them unconditionally and
`Swarm.remove` refuses a mandatory id (`swarm/synthesis.py`).

Tests: `tests/conformance/test_swarm_invariants.py::test_inv3_*`.

### INV-SWARM-4. Skeptic veto wired to verification

> A skeptic falsification check is included in the test plan for the criticized
> proposal, and a proposal whose check fails cannot become an approved
> `GateDecision` or reach the executor.

Enforcement: the debate layer maps skeptic checks onto their target's
verification requests; a failing check yields a `FAIL` judgment, which the
action gate denies (`swarm/debate.py`, `swarm/runtime.py`, `gate/authorization.py`).

Tests: `tests/conformance/test_swarm_invariants.py::test_inv4_*`.

### INV-SWARM-5. Reuse, no fork

> The swarm imports the verifier bank, gate, ledger, memory, and provider from
> their existing modules and defines no duplicate ledger, gate, or verifier
> type.

Enforcement: the swarm depends on the existing grounding modules and adds no
parallel grounding type (verified by import and AST checks).

Tests: `tests/conformance/test_swarm_invariants.py::test_inv5_*`.

### INV-SWARM-6. Firewall preserved

> Swarm role inputs exclude held-out task labels and verifier internals, and the
> held-out promotion firewall is unchanged.

Enforcement: a role receives only a `TaskPacket` and a proposer-side
`ProposerContext`; the promotion firewall in `gate/promotion.py` is untouched.

Tests: `tests/conformance/test_swarm_invariants.py::test_inv6_*` and the
unchanged `tests/conformance/test_firewall.py`.

## Sandbox invariants

Untrusted candidate code (model-generated solutions, and the Skeptic's
executable cases the verifier runs) executes only inside an isolating
`Sandbox`. The guarantee is a trusted-core safety property; the specific
isolation mechanism is a swappable adapter (`sandbox/`). Each invariant is
proven by an adversarial test that runs hostile code through a real isolating
adapter (`tests/conformance/test_sandbox.py`); those tests skip when the
isolation runtime is absent locally and FAIL rather than skip under
`PROM_REQUIRE_SANDBOX=1` (set in CI).

### INV-SANDBOX-1. Network denied

> Candidate code cannot reach the network. An outbound connection attempt fails
> inside the sandbox and the host is unaffected.

Enforcement: an isolating adapter runs the candidate with no network (a network
namespace with no interfaces, or `--network none`).

Tests: `tests/conformance/test_sandbox.py::test_inv_sandbox_1_network_is_denied`.

### INV-SANDBOX-2. Filesystem constrained

> Candidate code may read and write only its workspace. It cannot write outside
> the workspace, cannot modify read-only paths, and cannot read sensitive host
> paths.

Enforcement: a read-only root filesystem with a single writable workspace bind,
and sensitive host directories hidden (`sandbox/_bootstrap.py`, or the
container's read-only root + tmpfs workspace).

Tests: `tests/conformance/test_sandbox.py::test_inv_sandbox_2_filesystem_is_constrained`.

### INV-SANDBOX-3. Resources bounded

> A memory bomb, an infinite loop, and a process bomb each hit a limit and
> terminate without impacting the host.

Enforcement: POSIX rlimits (address space, CPU time, process count) and a
wall-clock bound; the sandbox reaps the whole process tree on exit. The
`SandboxResult` flags the breach.

Tests: `tests/conformance/test_sandbox.py::test_inv_sandbox_3_*`.

### INV-SANDBOX-4. Least privilege

> Candidate code runs unprivileged: no-new-privileges is set and capabilities
> are dropped, so a privilege-escalation attempt fails.

Enforcement: `PR_SET_NO_NEW_PRIVS`, a full capability drop after setup
(`sandbox/_bootstrap.py`), or `--cap-drop ALL --security-opt no-new-privileges`
with a non-root user (container adapter).

Tests: `tests/conformance/test_sandbox.py::test_inv_sandbox_4_least_privilege`.

### INV-SANDBOX-5. The sandbox is mandatory

> The default configuration executes candidate code only through an isolating
> adapter. The unsafe direct runner is reachable only with the explicit
> `PROM_ALLOW_UNSAFE_EXEC=1` opt-in; absent any isolating runtime, the default
> path refuses to run candidate code (it ABSTAINs) rather than running it in the
> clear.

Enforcement: `sandbox/factory.py` selection (`auto` never returns the unsafe
runner; a `NullSandbox` backstop yields `started_ok=False` → ABSTAIN).

Tests: `tests/conformance/test_sandbox.py::test_inv_sandbox_5_*`.
