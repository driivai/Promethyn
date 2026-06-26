# Prometheus Protocol — Swarm Reasoning Front-End

Status: draft (v0.1, structural skeleton). This document is the authoritative
design for the swarm. It builds the typed wall, the mandatory roles, the reuse
contract, and the conformance invariants, with simple deterministic roles and
**no real execution side-effects**. Sophisticated role reasoning and live tool
execution are explicitly out of scope (follow-up).

## 1. The wall (the load-bearing idea)

The proposer side may only *propose*; only the judge side may *assert truth* or
*authorize action*.

- A `Proposal` and a `TestPlan` cross from the proposer side to the judge side.
  By construction they carry **no** verdict, confidence-of-correctness, or
  approval.
- The first object that asserts truth is a `Judgment`, produced **only** by the
  verifier bank.
- The first object that authorizes action is a `GateDecision`, produced **only**
  by the gate.
- The `Executor` accepts **only** a `GateDecision`. It has no method that takes
  a `Proposal` or `TestPlan`. Passing a raw proposal is a type error.

Nothing reaches execution without being verified (bank) and gated. This is
enforced by types, not convention.

## 2. Objects (`swarm/models.py`)

- `TaskPacket(goal, context, constraints, budget, risk_class)` — the task given
  to the swarm. `budget` caps how many proposals are verified; `risk_class`
  (`low`/`medium`/`high`) tightens the authorization bar.
- `Provenance(content_hash, inputs)` — content hash plus the ids a proposal
  derives from (a critique's input is the proposal it criticizes).
- `FalsificationCheck(id, description, predicate)` — a concrete check that, if it
  fails, proves a proposal wrong. `predicate` names a deterministic predicate.
- `Proposal(id, role_id, kind, content, rationale, provenance, falsification_checks)`
  with `kind ∈ {hypothesis, option, forecast, critique, proposed_action}`. A
  `Proposal` has **no** verdict/confidence/approval field.
- `VerificationRequest(check, requested_by)` — a check to run for a proposal.
- `TestPlan` = ordered `TestPlanEntry(proposal, verification_requests)`. The
  `TestPlan` has **no** verdict/confidence/approval field.
- `VerifiedProposal(proposal, judgment)` — a proposal joined to the bank's
  judgment. Constructed **only** on the bank path (the runtime, immediately
  after `VerifierBank.judge`).
- `ExecutionResult(executed, subject_id, detail)` — the executor's record.

`Judgment`, `Verdict`, `Evidence`, and `GateDecision` are **reused** from the
existing modules; the swarm defines none of them.

## 3. Roles (`swarm/roles.py`)

`Role` is an ABC: `id`, `kind`, `mandatory: bool`, and
`propose(packet, context) -> list[Proposal]`. Roles receive only the
`TaskPacket` and a proposer-side `ProposerContext` (the packet plus proposals so
far and optional notes) — never held-out task labels or verifier internals.

Two roles are **mandatory and non-removable**:

- `Skeptic` — for each proposal, attaches `falsification_checks` (concrete checks
  that, if they fail, prove the proposal wrong).
- `PolicyReviewer` — for each `proposed_action`, attaches a policy check.

A few simple deterministic optional roles are provided for the skeleton.

## 4. Synthesis (`swarm/synthesis.py`)

`RoleSynthesisEngine.assemble(packet, config) -> Swarm`. Optional roles may be
selected per task; the `Skeptic` and `PolicyReviewer` are **injected by the
framework** and cannot be removed by config or by the swarm. `Swarm.remove` of a
mandatory role raises.

## 5. Debate (`swarm/debate.py`)

`DebateLayer.select(proposals, budget) -> TestPlan`. **Selection only**: it picks
which proposals to spend verification budget on and in what order, and gathers
each proposal's own checks plus the skeptic/policy checks targeting it into its
`verification_requests`. It does **not** construct a `Judgment` or a
`GateDecision`, and the `TestPlan` carries no truth/approval field.

## 6. Runtime (`swarm/runtime.py`)

`SwarmRuntime.run(packet)` wires:

```
packet -> RoleSynthesisEngine.assemble -> Swarm.propose
       -> DebateLayer.select -> (per proposal)
            verify checks -> Evidence
            -> VerifierBank.judge -> Judgment   (truth asserted here)
            -> VerifiedProposal
            -> (proposed_action only) Gate.decide -> GateDecision (action authorized here)
            -> (if approved) Executor.execute -> ExecutionResult
       -> Ledger records the chain
```

Verification of a proposal in this skeleton is deterministic: each check's named
predicate is evaluated against the proposal; the proposal's `Evidence` is `PASS`
when all checks hold, `FAIL` when any fails, and `ABSTAIN` when there is nothing
to verify (so an unverified proposal can never be authorized). The check
verifier is registered with the bank under the hard tier, so a clean proposal
yields an authoritative `PASS`. Live tool execution that produces real evidence
is follow-up; the deterministic check runner is its stand-in.

## 7. Executor (`swarm/executor.py`) — the wall's enforcement point

`Executor.execute(decision: GateDecision) -> ExecutionResult`. There is no
method that accepts a `Proposal` or `TestPlan`. The provided `RecordingExecutor`
is a no-op recorder — **no real tool side-effects** in this sprint. It rejects a
non-`GateDecision` argument (type error) and refuses an unapproved decision.

## 8. Reuse contract (no forking)

The swarm imports `VerifierBank`, the gate (`GateDecision` + `ActionGate`),
`Ledger`, `MemoryTier`, and `Provider` from their existing modules and defines
**no** duplicate ledger, gate, or verifier type. `ActionGate` extends the
existing `gate/` package (reusing `GateDecision`); it does not fork it.

## 9. Firewall preserved

Swarm roles receive only the `TaskPacket` and proposer-side context — never
held-out task labels or verifier internals. The held-out firewall in `gate/`
(skill promotion) is untouched and its conformance tests pass unchanged.

## 10. Invariants

See `spec/invariants.md`, INV-SWARM-1 … INV-SWARM-6, each covered in
`tests/conformance/`.
