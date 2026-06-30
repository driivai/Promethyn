# Provider-backed swarm roles and executable falsification checks

This document describes how the swarm's roles reason via the model provider and
how the Skeptic's falsification checks become real verification. It **implements**
the existing swarm invariants (INV-SWARM-1 … INV-SWARM-6 in `spec/invariants.md`)
— it does not change them. The trusted core is untouched: the verifier bank's
fusion, the gate, the held-out firewall, and the typed proposer/judge wall are
all unchanged, and the executor stays a no-op recorder. Making the proposer
smarter does not expand the trusted core; a smarter proposer answers to the same
unchanged judge.

## Roles reason via the provider

Each role builds a role-specific prompt from the `TaskPacket` and proposer-side
context **only** (never held-out labels or verifier internals — the firewall,
INV-SWARM-6) and calls the model provider:

| Role | Kind | Provider call | Output |
| --- | --- | --- | --- |
| `planner` | `proposed_action` | code domain: `propose_solution` (the actor's method); else `generate` | candidate code, or a textual next action |
| `analyst` | `hypothesis` | `generate` | a testable hypothesis |
| `skeptic` (mandatory) | `critique` | `generate` (code domain only) | executable falsification cases |
| `policy-reviewer` (mandatory) | `critique` | none (deterministic) | a policy check |

The provider is injected at construction, so `Role.propose(packet, context)` is
unchanged. Code generation **reuses the actor's `propose_solution`**; open-ended
reasoning uses an additive `Provider.generate(prompt, system)` that follows the
existing vendor-neutral boundary (the mock provider scripts it deterministically;
the remote provider speaks the same chat-completions contract).

**Validation is mandatory.** A reply is parsed strictly (`prompts.parse_reasoning`,
`prompts.parse_cases`); a malformed or unparseable reply — or any provider error,
or no provider — yields **no proposal** from that role. A role never lets an
unvalidated object cross the wall; it degrades gracefully. Every proposal carries
provenance (a content hash plus the inputs it derives from).

## Executable falsification checks (the load-bearing seam)

A `FalsificationCheck` is one of two kinds, and carries no verdict either way:

- **Structural** (`cases` empty): a deterministic predicate the runtime
  evaluates in-process (`non_empty_content`, `states_rationale`,
  `policy_compliant`). Cheap, always applied.
- **Executable** (`cases` non-empty): concrete input/output cases the Skeptic
  generated via the model. In the code domain the Skeptic attaches these to a
  proposed action; the runtime runs them through the **existing HARD subprocess
  verifier** against the proposal's code, calling its `entry_point`.

The DebateLayer maps each critique's checks onto the proposal it targets, so the
Skeptic's executable cases ride in that proposal's TestPlan entry (INV-SWARM-4).
At verification the runtime aggregates by **conjunction**: a proposal passes only
if every check that *could run* passed.

- A running executable case that **fails** → FAIL evidence → the action cannot be
  approved and never reaches the executor. The Skeptic's veto is wired to real
  verification, not to model opinion.
- A check that **cannot run** (no entry point, nothing parsed, or no code
  verifier wired) → **ABSTAIN**: it is excluded from the conjunction, so it
  neither blocks a proposal nor silently passes it, and it records no calibration
  sample.

Nothing here constructs a `Judgment` or a `GateDecision` (only the bank and the
gate do), and nothing new executes for real — the executor records an approved
decision as a no-op (INV-SWARM-1).

## Cost control

`Config.max_role_calls` (env `PROM_MAX_ROLE_CALLS`, default **16**) caps the
number of provider calls a single swarm task may make. The cap is enforced by a
per-task budget shared by the engine's roles and reset on each `assemble`; once
exhausted, generation returns empty and roles simply stop proposing. The
DebateLayer's separate verification budget is unchanged.

## Determinism

All role reasoning routes through the provider, so the mock provider yields
deterministic, scripted role outputs offline (see
`prometheus_protocol._examples.swarm_tasks`). With a real remote provider the
same roles reason for real. Identical scripted inputs produce an identical
TestPlan and identical judgments.

## Correlated-model caution

When one provider powers the actor, the reasoning roles, and the soft model-judge
at once, their errors correlate: a blind spot shared by proposer and judge will
not be caught by their agreement. The HARD subprocess verifier — which runs code,
not opinions — is the independent backstop, and the Skeptic's executable cases
route through it precisely so a proposal's veto does not reduce to "the model
agreed with itself." Configuring an independent judge/role model reduces the
correlation.
