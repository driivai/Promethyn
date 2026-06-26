# Architecture

This document describes how the reference implementation is laid out and why.
For the protocol itself, see `spec/protocol.md`.

## Layering

```
            cli ──────────────┐
                              ▼
 examples ──►  runtime (orchestrator + factory)
                              │
        ┌──────────┬──────────┼──────────┬──────────┐
        ▼          ▼          ▼          ▼          ▼
     provider   verifier   registry    forge       gate
        └──────────┴────────┬─┴──────────┴──────────┘
                            ▼
                          core (models, interfaces, config)
                            ▲
                         ledger, memory
```

- **core** holds the data models, the abstract service interfaces, and
  configuration. Nothing in core depends on a concrete service.
- Each service package (**provider**, **verifier**, **registry**, **forge**,
  **gate**, **ledger**, **memory**) implements one interface from core and
  depends only on core.
- **runtime** wires the services together. The orchestrator sequences the
  loop; the factory is the single composition root.
- **cli** and **examples** are thin entry points over the runtime.

The public API surface is defined entirely by
`src/prometheus_protocol/__init__.py`. That file is the open-core line: it
lists exactly what is supported. Underscore-prefixed modules (for example
`_examples`) are shipped but not part of the stable API.

## Why these boundaries

- **The provider is blind to tests.** It receives a prompt, an entry point,
  and retrieved skills — never hidden cases. This makes "the model cheated by
  reading the test" structurally impossible.
- **The gate owns the firewall.** The single safety invariant lives in one
  guarded module, called on every promotion, rather than being spread across
  the loop.
- **The ledger is append-only.** Auditability and reversibility fall out of
  recording every attempt and promotion in order.

## Data flow in one cycle

1. `runtime.orchestrator` retrieves skills from `registry`, calls `provider`
   for code, and calls `verifier` for evidence; each attempt is written to
   `ledger`.
2. Training failures go to `forge`, which returns candidate skills.
3. Each candidate goes to `gate`, which enforces the firewall, scores it on
   the held-out split, and (on success) writes it to `registry` and `ledger`.

## Verifier-trust ranking

A single task can be checked by more than one verifier — a sandboxed test
runner (hard), a reviewer (human), a model-based critic (soft), a
self-consistency check (consistency). The verifier bank turns several such
verdicts into one judgment and ranks verifiers by how trustworthy they have
proven to be.

It is split along the same port/adapter lines as the rest of the system:

- `verifier/trust.py` — pure trust math. Each verifier has a confusion matrix
  against trusted references and a tier-dependent Beta prior. From these come
  sensitivity (TPR), specificity (TNR), a reliability scalar (Youden index),
  and a per-report log-likelihood ratio. No I/O.
- `verifier/aggregate.py` — pure fusion. Per-report log-LRs sum to a total
  log-odds, mapped through a stable sigmoid to a probability of PASS, then to a
  verdict and a confidence.
- `verifier/store.py` — the `TrustStore` port plus `InMemoryTrustStore` and
  `SqliteTrustStore` adapters. Counts and the tier prior persist, so earned
  trust survives restarts.
- `verifier/bank.py` — `VerifierBank`, depending only on the `TrustStore` port
  and the pure math. It registers verifiers per tier, fuses evidence into a
  `Judgment`, calibrates lower-trust verifiers against the authoritative
  reference, flags when an advisory-only judgment should be escalated, and
  ranks verifiers.

Two safety properties are load-bearing and enforced in code (see invariants I6
and I7): an advisory verdict can never override an authoritative one (it is
calibration signal only), and an un-audited verifier carries zero weight until
it has been calibrated against trusted references. Hard verifiers are
authoritative and also serve as the reference that calibrates soft ones; a
human reference, when present, outranks and calibrates the hard tier.

## Configuration

All knobs come from `PROM_*` environment variables resolved by
`core.config.Config`. Provider selection is by name (`mock` or `remote`), so
switching models is a configuration change, not a code change.
