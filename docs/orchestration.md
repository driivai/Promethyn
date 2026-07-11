# Governed multi-agent orchestration (skeleton)

Today one proposer proposes to one Hearth. This layer generalises the
**proposer** side into a DAG of agents while keeping the Hearth singular:
every agent's every action still routes through the existing
verify → gate → human-hold → execute → ledger pipeline, and every message
passed between agents is **tier-tagged** so an upstream error cannot be
laundered into a downstream fact.

This is the safe skeleton and the message contract. It deliberately does **not**
attempt principled confidence composition across dependent steps — an unsolved
problem, isolated below.

## The defining invariant

> The orchestrator can sequence agents and pass their outputs, but it has **no
> path to execute.** Every action any agent proposes is a proposal that flows
> through the same gate. The orchestrator has no execute method, no gate
> bypass, and cannot authorize anything.

Enforced by construction, in `orchestration/`:

- **`WorkflowRuntime`** holds a verifier bank (to grade), an `ActionGateway`
  (its only door to action), and a ledger port (to record). It has no
  executor, no gate, no controller, and no `execute`/`approve` method. Its
  authority to change the world is exactly the gateway's `route_action`.
- **`ActionGateway`** wraps a single bound `submit` callable
  (`ExecutionController.submit`) and exposes exactly one method,
  `route_action`. The runtime holds the gateway, not the controller — so its
  API offers no way to approve or execute; every action ends at the gate,
  which approves, routes to a human, or blocks.

## The tier-tagged message contract (no silent compounding)

When step A's output reaches step B, it is an **`AgentMessage`**, not a fact:
it carries A's step/agent id, the **tier** it was graded at (HARD/SOFT/…), the
**verdict**, a **per-step confidence**, and a content hash. B receives "A
claims X, tier=SOFT, confidence=0.6" — never "X is true".

This is structural, not disciplinary, on two sides:

- The **proposer** side cannot inject a grade: an agent returns an
  `AgentProposal` (content + at most one action). `AgentProposal` has **no tier
  and no confidence field** — an agent literally cannot hand its output a
  self-assigned grade.
- The **message** side cannot be untiered: `AgentMessage` requires a real
  `Tier` and `Verdict` (its `__post_init__` rejects anything else), and the
  runtime only ever builds one via `AgentMessage.graded(...)`, sourcing the
  tier/confidence from the **verifier bank's** judgment of the step's
  independently-graded evidence — never from the proposing agent.

So the only thing that travels agent-to-agent is a claim wearing its own
grading. An error upstream arrives downstream visibly discounted.

The proposer/judge wall lives *inside* each step: the `Agent` proposes; a
separate `StepGrader` (a verifier-shaped port, satisfied by the real domain
verifiers via the extension surface, or by a deterministic grader in the demo)
judges. The runtime fuses that evidence through the existing bank.

## The workflow ledger (per-step audit)

A multi-step run is attributable. The existing ledger is **extended
additively** — a new `workflow_steps` table (`CREATE TABLE IF NOT EXISTS`;
existing rows and queries untouched) and two concrete methods. Each step
records `workflow_id`, `step_id`, `agent_id`, the graded `tier`/`verdict`/
`confidence`, whether it proposed an action, what the gate decided
(`approve`/`route`/`block`/`none`), and the `subject_id`/`pending_id` linking
to any execution or human hold. "Show every step in this workflow, which
agent, at what tier, what the gate decided, where a human was asked" is one
query: `ledger.workflow_steps(workflow_id)`. The table **records**; it
authorizes nothing.

## The demo

`python -m prometheus_protocol.orchestration.demo` (needs the namespace
isolation runtime) runs three agents through the real chain:

```
[step] plan (planner): tier=soft confidence=0.50 -> NONE
[step] implement (implementer): tier=hard confidence=0.95 -> APPROVE
[step] export (exporter): tier=hard confidence=0.95 -> ROUTE (held #1 for a human)

[messages] what each downstream step actually received (never a bare fact):
  implement <- plan/planner claims [soft · pass · 0.50]: 'sum the first three primes: 2 + 3 + 5'
  export <- implement/implementer claims [hard · pass · 0.95]: 'computed 2 + 3 + 5 = 10'

[chain] conservative placeholder confidence (min of steps) = 0.50  — NOT a principled composition
...
[human] operator reviews held step export (pending #1) and approves it:
[human]   executed in sandbox 'namespace' (exit 0); output 'EXPORT: 10'
...
[audit] executions recorded: 2 (executed 2, held/blocked 0)
```

The soft `plan` output travels as an advisory claim; `implement`'s action
clears the gate and executes; the high-risk `export` action — authoritative
and passing — is still **routed to a human** (INV-EXEC-3 holds across the
workflow), and the operator approves it through the **controller**, not the
orchestrator.

## The open problem: confidence composition (isolated, not faked)

Combining per-step confidences into a joint chain confidence — A@0.8 feeding
B@0.7 into a sound "how much do we trust the chain's output" number — is an
**unsolved research problem**. Naive rules are all wrong in general: the
product assumes independence the steps do not have; the mean hides a weak link;
Bayesian composition needs a dependency model and per-verifier likelihoods this
skeleton does not have.

So this sprint does not invent a formula and call it sound. It **passes and
records** each step's own confidence in the tier-tagged messages, and reports a
chain-level number computed as the **minimum** of the confidences along the
realised path — labelled everywhere as a conservative *placeholder*, not a
solution. Minimum is the honest floor ("the chain is no stronger than its
weakest graded step") and it never over-states trust; it just cannot express
that two independent 0.9 steps might jointly warrant more or less than 0.9. A
principled solution needs a dependency model between steps and calibrated
per-step likelihoods — the next sprint, not this one.

## Honest findings

- **Did the proposer-graph generalisation plug into the Hearth cleanly?**
  Yes — the Hearth is byte-identical to `main` (a conformance test diffs the
  bank, both gates, executor, controller, pending, forge, and core
  models/interfaces and asserts no change). The single-proposer flow is
  untouched. The only reused primitive that needed anything was the ledger,
  and only additively. Nothing about "one proposer" was load-bearing in the
  Hearth; the gate already takes one action + one judgment at a time, which is
  exactly what a graph of agents submits, one action at a time.

- **Is "the orchestrator has no authority" by construction or by convention?**
  By construction at the **API/type** level: the runtime and gateway expose no
  execute/approve/gate/executor member, and a soft-only (non-authoritative)
  claim proposing an action is **blocked** by the gate (tested) — the gate is
  never bypassable. The honest caveat, documented in `gateway.py` and not
  papered over: this is capability safety *in Python*, airtight only up to
  introspection — because `submit` is a bound method, `gateway._submit.__self__`
  is the controller, so a deliberate object-model escape could reach its human
  verbs (as `git_tool._sandbox` is reachable in principle). That escape is
  never a capability the API offers, and even it cannot make the gate execute a
  **blocked** action — `approve` only runs an already-*routed* hold. A
  process/capability boundary is the follow-up that closes the introspection
  gap entirely; the gate-in-the-loop guarantee holds today regardless.

- **Where does the unsolved problem bite?** Exactly at chain confidence (above)
  and, relatedly, at the human-halt UX: this skeleton halts a *step* (the
  minimal, correct thing — a low-confidence or high-risk step routes via the
  existing hold) but does not yet model whole-workflow vs branch halting, or
  what context a human sees when step 7 of 12 halts. Both are follow-ups; the
  skeleton deliberately ships the safe minimum rather than a rich UX built on
  an unsound composition.

## Not in scope (follow-ups)

- Principled confidence composition across dependent steps.
- Workflow-halt UX (branch vs whole-workflow, halt context, resumption).
- A process/capability boundary to close the in-process introspection caveat.
- Real domain agents/graders wired in (the demo uses deterministic scripted
  ones; real steps plug the conformant domain verifiers into `StepGrader`).
