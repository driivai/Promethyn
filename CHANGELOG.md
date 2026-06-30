# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/). A change to any invariant
in `spec/invariants.md` is a major version bump.

## [Unreleased]

### Added
- Sandbox isolation for untrusted candidate code (`sandbox/`). A `Sandbox` port
  (`Sandbox`, `SandboxResult`, `Limits`) plus adapters: a daemonless
  `NamespaceSandbox` (Linux user/mount/network/PID namespaces + read-only root
  with a writable workspace + dropped capabilities + no-new-privileges +
  rlimits), a production `ContainerSandbox` (Docker/Podman with `--network none`,
  read-only root, memory/CPU/pids limits, `--cap-drop ALL`, no-new-privileges,
  non-root, digest-pinnable image), and an explicitly-named `UnsafeLocalSandbox`
  (the prior no-isolation runner, opt-in only via `PROM_ALLOW_UNSAFE_EXEC=1`).
  The verifier now executes every candidate through the configured sandbox
  (`Config.sandbox` / `PROM_SANDBOX`, default `auto` = an isolating adapter);
  legitimate verdicts and the held-out rate are unchanged (parity), and a
  sandbox-start failure is ABSTAIN. New invariants INV-SANDBOX-1…5 in
  `spec/invariants.md` with adversarial conformance tests
  (`tests/conformance/test_sandbox.py`) that run hostile network/filesystem/
  resource/privilege code and assert containment; CI sets `PROM_REQUIRE_SANDBOX=1`
  so they run, not skip. Documented in `docs/sandbox.md` and `SECURITY.md`. New
  public API: `Sandbox`, `SandboxResult`, `Limits`, `NamespaceSandbox`,
  `ContainerSandbox`, `UnsafeLocalSandbox`, `NullSandbox`, `build_sandbox`, and
  `Config.sandbox` / `verifier_max_processes`. The swarm executor stays a no-op:
  this layer isolates the code the verifier already ran and grants no new
  execution capability.
- Operability hardening for findings F1–F5 from the end-to-end shakeout
  (`docs/shakeout-report.md`):
  - **(F1)** The CLI now reports known errors — a misconfigured provider, an
    unreadable state file — as a single `error: <message>` line on stderr with a
    non-zero exit, instead of a raw Python traceback. Unexpected exceptions still
    propagate; `-vv` surfaces the full traceback of a handled error.
  - **(F2)** New typed domain errors (`core/errors.py`): `PrometheusError`
    (base), `StateError`, and `ConfigError`. The SQLite ledger and trust-store
    adapters now wrap an open of a corrupt or locked file in a `StateError` that
    names the offending path and suggests recovery, rather than leaking a raw
    `sqlite3.DatabaseError`. `PrometheusError`, `StateError`, and `ConfigError`
    are part of the public API.
  - **(F4)** New read-only `status` CLI command: shows the configured storage,
    the promoted skills in the registry, and the verifier trust ranking
    (`bank.rank()`) with per-verifier reliability and calibration sample counts.
    It runs nothing, verifies nothing, and creates no state that is not already
    present.
  - **(F5)** Structured `logging` at the CLI, factory, orchestrator, and remote
    provider seams: lifecycle events (run start/finish, verifier registration,
    per-task judgment, gate decisions, promotions) at INFO/DEBUG. A `-v`/`-vv`
    flag (or `PROM_LOG_LEVEL`) selects verbosity; the default is WARNING. No
    control flow changed, and secrets (the API key) are never logged.
- Soft model-judge verifier (`verifier/model_judge.py`, `ModelJudgeVerifier`): an
  untrusted advisor that asks the model (via the provider) whether a candidate
  satisfies a task and returns `Tier.SOFT` evidence (PASS/FAIL/ABSTAIN). It runs
  no code, is blind to hidden cases, and abstains on any provider error.
  Registered alongside the hard verifier behind `Config.enable_model_judge`
  (default **off**); the bank calibrates it against the hard reference. With an
  optional independent judge model (`Config.judge_model` / `PROM_JUDGE_MODEL`) it
  can grade with a different model than the actor, reducing correlated error.
- `Provider.assess(prompt, system)`: optional, additive provider capability for
  advisory grading (default raises `NotImplementedError`; the remote provider
  overrides it with a judging request).
- Initial open-core scaffold of the Promethyn runtime.
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
- **(F3)** The subprocess verifier now returns `ABSTAIN` for a task with no test
  cases (nothing to verify) instead of `FAIL` (a confident failure). An ABSTAIN
  is not a pass and never feeds calibration. Verdicts for every non-empty case
  set are unchanged (parity is covered by tests), so pass rates on the example
  benchmark are identical.
- The verifier bank's fused **confidence** now reflects calibrated
  non-reference verifiers (e.g. a soft model-judge), so confidence becomes
  informative — agreement raises it, disagreement lowers it. The **verdict** is
  unchanged: it is still decided by the authoritative reference (I6), and an
  un-audited verifier contributes ~zero (I7). No verdict or pass-rate changes.
- `Config` gained `enable_model_judge` (env `PROM_ENABLE_MODEL_JUDGE`, default
  off) and `judge_model` (env `PROM_JUDGE_MODEL`); `Orchestrator` gained an
  optional `advisors` argument. All additive with behaviour-preserving defaults.
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
