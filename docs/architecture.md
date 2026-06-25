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

## Configuration

All knobs come from `PROM_*` environment variables resolved by
`core.config.Config`. Provider selection is by name (`mock` or `remote`), so
switching models is a configuration change, not a code change.
