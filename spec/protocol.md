# Promethyn — Specification

Status: draft (v0.1). This document defines the open protocol. The reference
implementation lives in `src/prometheus_protocol/`; conformance tests live in
`tests/conformance/`.

## 1. Overview

Promethyn is a verifiable, reversible, self-improving learning
runtime. A frozen proposer suggests solutions to tasks; a sandboxed verifier
returns a hard pass/fail; failures are mined into reusable markdown *skills*;
and a promotion gate, guarded by a held-out firewall, decides which skills are
kept.

The protocol is defined by its components, the data that flows between them,
and a small set of invariants (see `invariants.md`). It is deliberately
neutral about which model sits behind the proposer.

## 2. Entities

| Entity   | Definition |
|----------|------------|
| Task     | A unit of work: an id, a prompt, an entry point, hidden cases, a split (`train` or `heldout`), and an optional failure cluster. |
| Case     | One hidden input/expected-output pair. Cases are never shown to the proposer. |
| Skill    | A reusable lesson stored as markdown, with triggers and tags for retrieval. |
| Attempt  | One proposed solution evaluated against one task, with its evidence. |
| Evidence | The verifier's hard verdict: counts of passed/total, failures, timing. |

## 3. Roles (service boundaries)

| Role      | Contract |
|-----------|----------|
| Provider  | `propose_solution(prompt, entry_point, skills) -> code`. Sees the prompt and retrieved skills only — never hidden cases. |
| Verifier  | `verify(code, task) -> Evidence`. Runs code against hidden cases under isolation, timeout, and resource limits. |
| Registry  | Stores skills; `retrieve(query)` returns the relevant ones; supports removal. |
| Forge     | `mine(train_failures) -> candidate skills`. Learns only from `train` failures. |
| Gate      | `evaluate(candidate, ...)` against the `heldout` split; enforces the firewall; promotes only genuine improvement. |
| Ledger    | Append-only record of attempts and promotions; makes runs auditable and reversible. |

## 4. The loop

### 4.1 Baseline run

For each task: retrieve relevant skills, ask the provider for code, verify it,
and record the attempt in the ledger. The baseline pass rate is the fraction
of attempts whose evidence passes.

### 4.2 One learning cycle

1. **Measure.** Record the held-out pass rate with the registry as it stands.
2. **Attempt train.** Propose and verify solutions for the `train` split;
   collect the failing attempts.
3. **Forge.** Mine candidate skills from the `train` failures only.
4. **Gate.** For each candidate, the gate checks the firewall, scores the
   candidate on the `heldout` split, and promotes it only if it strictly
   improves the held-out pass rate (beyond a configured threshold). Promotions
   are written to the registry and the ledger.
5. **Re-measure.** Record the held-out pass rate after promotions.

### 4.3 Ablation

A skill's contribution is the held-out pass rate with the skill present minus
the rate with it excluded. Ablation uses the ledger and registry only; it
mutates nothing.

## 5. Provider contract (remote)

The reference remote provider speaks the common chat-completions request
shape as JSON over HTTP and is configured entirely from the environment:

| Variable        | Meaning |
|-----------------|---------|
| `PROM_API_BASE` | Base URL of a compatible endpoint. |
| `PROM_MODEL`    | Model identifier passed through to the endpoint. |
| `PROM_API_KEY`  | Optional bearer credential. |

No brand strings or hosted defaults are baked in. Any endpoint accepting the
chat-completions request shape can be used.

## 6. Conformance

An implementation conforms if it upholds every claim in `invariants.md` and
reproduces the regression behaviour exercised in `tests/conformance/` on the
bundled benchmark: 40% held-out baseline, 100% after one cycle, +60% ablation
contribution for the mined skill, and no further learning on a second cycle.
