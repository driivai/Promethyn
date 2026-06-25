# Prometheus Protocol

A verifiable, reversible, self-improving learning runtime.

A frozen proposer suggests solutions to tasks. A sandboxed verifier returns a
hard pass/fail. Failures are mined into reusable markdown **skills**. A
promotion gate — guarded by a **held-out firewall** — decides which skills are
kept. Every step is recorded in an append-only ledger, so a run is auditable
and any promotion is reversible.

The held-out firewall is the load-bearing safety invariant: the forge never
learns from held-out tasks, and the gate only ever scores against them. It is
enforced in code, not just documentation.

> **Status:** v0.1, open core. This repository is the open distribution
> (`prometheus-protocol`). It has no third-party runtime dependencies.

## Install

```bash
python -m pip install -e ".[dev]"
```

Requires Python 3.10+.

## Quickstart

Run the offline demo (simulated provider, ephemeral storage, no network, no
API key):

```bash
prometheus-protocol demo
```

Expected output:

```
Held-out baseline      : 40% (2/5)
Mined skills           : ['skill-empty-input']
Promoted skills        : ['skill-empty-input']
Held-out after cycle 1 : 100%
Ablation (skill-empty-input): +60%
Cycle 2 learned        : False (mined 0 skills)
```

That is the whole thesis in one run: the baseline fails an "empty-input"
cluster, a single mined skill repairs it, the held-out gate confirms the
improvement generalises, ablation attributes +60% to that skill, and a second
cycle finds nothing left to learn.

The same flow via the public API:

```python
from prometheus_protocol import Config, build_orchestrator
from prometheus_protocol._examples.python_functions import build_benchmark

orch = build_orchestrator(Config(ledger_path=":memory:"))
bench = build_benchmark()
print(orch.baseline(bench.heldout).pass_rate)          # 0.4
print(orch.run_cycle(bench.train, bench.heldout).post_heldout_rate)  # 1.0
```

## How it works

One learning cycle:

1. Measure the held-out pass rate as the registry stands.
2. Propose and verify solutions for the **train** split; collect failures.
3. Mine candidate skills from the train failures **only**.
4. For each candidate, the gate enforces the firewall, scores it on the
   **held-out** split, and promotes it only if it strictly improves the rate.
5. Re-measure the held-out pass rate.

See `spec/protocol.md` for the full specification and `spec/invariants.md` for
the formal invariants.

## Using a real model

The provider boundary is vendor-neutral and configured from the environment.
Point it at any endpoint that accepts the common chat-completions request
shape:

```bash
export PROM_PROVIDER=remote
export PROM_API_BASE=https://your-gateway.example/v1
export PROM_MODEL=your-model-id
export PROM_API_KEY=...        # optional
prometheus-protocol cycle
```

No brand strings or hosted defaults are baked into the source.

## Repository layout

```
spec/        protocol definition, invariants, spec changelog
src/prometheus_protocol/
  __init__.py   the public API surface (the open-core line)
  core/         models, interfaces, config
  provider/     vendor-neutral model boundary (remote + simulated)
  verifier/     sandboxed test runner (hard pass/fail)
  registry/     markdown skill store + retrieval
  forge/        lesson miner / skill proposer
  gate/         promotion gate + held-out firewall
  ledger/       SQLite experience ledger
  memory/       scoped memory tiers
  runtime/      orchestration + composition root
  cli/          console entry point
harness/     benchmarks, evaluation metrics, audit tooling
tests/       unit, integration, conformance
docs/        architecture, security model, ADRs
scripts/     repository hygiene guard
examples/    runnable examples
```

## Security

The verifier is **not** a real sandbox. Before running untrusted code you must
containerise it. See `docs/security-model.md` and `SECURITY.md`.

## Contributing & governance

See `CONTRIBUTING.md` (a Contributor License Agreement is required) and
`GOVERNANCE.md`.

## License

Apache-2.0. See `LICENSE`.
