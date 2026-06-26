# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/). A change to any invariant
in `spec/invariants.md` is a major version bump.

## [Unreleased]

### Added
- Initial open-core scaffold of the Prometheus Protocol runtime.
- Core models, service interfaces, and environment-driven configuration.
- Vendor-neutral provider boundary: a configuration-driven remote provider over
  the chat-completions request shape, and a deterministic offline simulated
  provider used as the default.
- Subprocess verifier with timeout and POSIX resource limits (documented as not
  a sandbox).
- SQLite experience ledger, markdown skill registry with retrieval, lesson
  forge, and promotion gate with the held-out firewall.
- Scoped memory tiers (interface plus in-memory implementation).
- Runtime orchestrator (baseline run and one learning cycle), composition-root
  factory, and a console entry point (`prometheus-protocol`).
- Example Python-function benchmark with train/held-out splits, plus an
  evaluation and audit harness.
- Unit, integration, and conformance test suites.
- Repository hygiene guard and CI (compile, hygiene, tests, build) across
  Python 3.10–3.12.
- Verifier-trust ranking: a calibrated trust model with tier-dependent priors
  (`verifier/trust.py`), trust-weighted log-odds evidence fusion
  (`verifier/aggregate.py`), a `TrustStore` port with in-memory and SQLite
  adapters (`verifier/store.py`), and a `VerifierBank` that fuses verdicts into
  a `Judgment`, calibrates lower-trust verifiers against authoritative
  references, and ranks verifiers by trustworthiness (`verifier/bank.py`).
- New public API: `VerifierBank`, `RankEntry`, `TrustStore`,
  `InMemoryTrustStore`, `SqliteTrustStore`, `TrustStats`, `Verdict`, `Tier`,
  `AUTHORITATIVE_TIERS`, and `Judgment`.
- Invariants I6 (authoritative dominance) and I7 (earned weight), with
  conformance coverage.
- The runtime now routes verification through the verifier bank: the subprocess
  runner emits tier-tagged `Evidence` (a stable `verifier_id`, `Tier.HARD`, a
  three-way verdict — PASS, FAIL, or ABSTAIN for infrastructure failures, plus
  cost/latency and a truncated detail log), and the orchestrator and promotion
  gate consult the bank's fused `Judgment` as the pass criterion. For the lone
  hard verifier this preserves every existing pass/fail outcome; the machinery
  is now load-bearing and ready for advisory verifiers.
- Each attempt's fused verdict and calibrated confidence are recorded for audit.
- Swarm reasoning front-end (`swarm/`): a typed proposal/test-plan contract that
  enforces the wall between proposing and asserting truth; mandatory,
  non-removable `Skeptic` and `PolicyReviewer` roles; role synthesis, debate
  selection, and a runtime that routes proposals through the existing verifier
  bank (judgment), gate (authorization), and ledger; and a no-op recording
  `Executor` that accepts only an approved `GateDecision` (no real side-effects
  this sprint). Documented in `spec/swarm.md`.
- Action-authorization gate (`gate/authorization.py`, `ActionGate`): turns a
  judgment into a `GateDecision`, reusing the existing gate package.
- Invariants INV-SWARM-1 … INV-SWARM-6, with conformance coverage.
- New public API: `TaskPacket`, `Proposal`, `Provenance`, `FalsificationCheck`,
  `TestPlan`, `VerifiedProposal`, `ExecutionResult`, `Role`,
  `RoleSynthesisEngine`, `Swarm`, `SwarmConfig`, `DebateLayer`, `SwarmRuntime`,
  `Executor`, `RecordingExecutor`, and `ActionGate`.

### Changed
- `Evidence` gained optional fields for verifier-trust fusion (`verifier_id`,
  `verdict`, `tier`, `cost`, `latency_ms`, `detail`). The change is additive and
  backward compatible: all new fields have defaults, and `verdict` is derived
  from `passed` when not supplied. Pre-1.0 additive change; no major bump.
- `Attempt` gained an optional `judgment` field (default `None`); the ledger
  records it inside the existing JSON evidence column, so there is no table
  schema change. Additive and backward compatible.
- `Config` gained `trust_store_path` (env `PROM_TRUST_STORE_PATH`, default
  `.prometheus/trust.db`) for the persisted trust store. Additive; existing
  configurations are unaffected. The orchestrator's constructor gained an
  optional `bank` argument with a behaviour-preserving default.
- `GateDecision` was generalised from a promotion-only result to a general gate
  decision: its fields are now `approved`, `subject_id`, `rate_before`,
  `rate_after`, `judgment`, and `reason`. The historical `promoted` and
  `skill_id` are retained as read-only properties, so the promotion path and its
  tests are unchanged. The constructor now takes `approved`/`subject_id` (the
  type was introduced earlier in this unreleased line and has no external
  consumers).
