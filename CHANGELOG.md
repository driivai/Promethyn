# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/). A change to any invariant
in `spec/invariants.md` is a major version bump.

## [Unreleased]

### Added
- **The verifier extension surface: a documented contract + a conformance
  suite.** The seam the three built-in domains (code, SQL, grounding) already
  share is now named, stabilised, and mechanically enforced, so a third party
  can add a domain verifier without touching the Hearth. New
  `prometheus_protocol.conformance` package: a `VerifierCase` descriptor and
  `check_verifier` that check the required guarantees — tier honesty (a SOFT
  process cannot emit HARD; authority follows the tier the platform assigns,
  not the verifier's say-so), fault distinction (candidate fault → FAIL,
  harness fault → ABSTAIN), fail-closed (no ground truth ⇒ ABSTAIN, never a
  guess), and a verifier-appropriate adversarial probe — plus a
  domain-general held-out-firewall check. Run it with `python -m
  prometheus_protocol.conformance`. The three shipped verifiers pass unchanged
  (proof the contract is real); deliberately non-conformant verifiers (a soft
  one stamping HARD, one guessing instead of abstaining) are REJECTED with the
  failing check named — the suite has teeth. `docs/extending-promethyn.md` is
  the guide (verifier contract, LearnableTask/held-out contract, registration
  surface, the can/cannot boundary, and an add-a-domain-in-N-steps walkthrough
  citing the real SQL and grounding examples). No Hearth change: the bank,
  gate, firewall, executor, and Evidence/verdict semantics are byte-identical
  (a conformance test asserts the diff against main is empty); the suite is a
  contract around the Hearth, and it reads it as a client, never modifies it.
- **grounding-v2: the harder, discriminating grounding item set.** The first
  live grounding run ceilinged (0/26 false-PASS on both arms — directional,
  not load-bearing, exactly the sql-v1 / live-v1 pattern), so
  `benchmarks/grounding_items_v2.py` adds 64 gold-labeled items over eight
  new sources: 45 not-supported claims engineered to be *nearly* right
  (quantifier-drift, scope-creep, unstated-inference, wrong-attribution,
  partial-support, near-miss-aggregation, temporal-near-miss,
  hedge-stripping, causation-from-correlation, plus a few easy anchors)
  against 19 supported controls including arithmetic-entailed
  `entailed-subtle` items that price in blanket strictness. Every item
  carries its gold rationale, and the whole set passed an adversarial
  label-review pass (each trap independently attacked with "could a careful
  reader legitimately argue the opposite?"); four items where reviewers
  registered genuine tension were rewritten before commit. The admissions
  harness gains data-only set selection (`--item-set grounding-v2`; default
  grounding-v1 unchanged; same verifier, same arithmetic), `judge_eval`
  forwards the new id, and the live workflow's `item_set` dropdown offers
  `grounding-v2`. Offline scripted reference on the new set: decided 62,
  abstained 2, false-PASS 3/44, false-FAIL 2/18 — all pinned by conformance.
- **The grounding domain: the first step past executable truth.**
  `GroundingVerifier` (`verifier/grounding.py`) judges whether a candidate
  claim is supported by a provided source — `Tier.SOFT` by construction (it
  executes nothing), strict verdict/confidence parsing with ABSTAIN on
  anything malformed, and tier-pinned so it cannot masquerade as HARD. A
  gold-labeled admissions set (`grounding-v1`, 44 items: 18 supported, 26
  plausible traps across ten families) makes the judge measurable where
  ground truth is a curated human label, not a program; the admissions
  harness (`benchmarks/grounding_eval.py`, read-only, reusing the
  fixture-tested eval arithmetic) reports false-PASS / false-FAIL / abstain /
  calibration / per-category leaks, offline against a scripted judge with
  designed deviations (verbatim: false-PASS 2/25 = 8.0%, false-FAIL 1/17,
  abstains 2 — all pinned by conformance) and live via the judge-eval-live
  workflow's new `item_set=grounding-v1` (operator-dispatched; both arms).
  The loop demo and conformance record the structural finding: with no HARD
  verifier, a soft-only judgment is non-authoritative and the gate blocks it
  at every risk class — no execution, not even a pending hold — so the human
  backstop is the only path to action; a human grounding review enters as
  `Tier.HUMAN` evidence, decides the fused verdict, and calibrates the judge
  exactly as the sandbox calibrates the code judge. No gate, bank, firewall,
  or HARD-domain behavior changed; soft-tier authority remains structurally
  unreachable and any future grant is flagged as a spec-owner invariant
  decision (`docs/domains-grounding.md`).

### Fixed
- **Multi-candidate promotion accounting credits marginal lift.** `run_cycle`
  used to score every candidate against the cycle-start held-out baseline, so
  a candidate evaluated after an earlier promotion in the same cycle
  inherited that promotion's lift — a free-riding skill could be promoted on
  improvement it did not cause (flagged, not fixed, when the SQL learn loop
  landed; single-candidate cycles never exposed it). The baseline now
  advances by re-measurement (`heldout-rebase` attempt rows) after each
  promotion that leaves candidates still to score, so each candidate's
  recorded lift — and its promotion ledger row — is its marginal
  contribution over the state its predecessors left. The gate, its
  promotion criterion, and the held-out firewall are untouched
  (`gate/promotion.py` zero-line diff); single-candidate and no-promotion
  cycles are bit-identical to the old accounting (code-domain pinned numbers
  unchanged). Conformance pins both directions with the shared pipeline over
  a stub verifier — a free-riding candidate is refused on zero marginal lift
  (the same test fails against the old accounting with the rider wrongly
  approved), a genuinely-marginal candidate still promotes on its own lift —
  plus promote/promote/rollback coherence (full unwind restores the
  cycle-start rate exactly). The SQL learn demo now demonstrates the fixed
  path instead of sidestepping it: the genuine lesson promotes first and the
  overfit one is refused at 60% → 60% against the re-based baseline.

### Added
- **The SQL learn loop, through the shared promotion pipeline.** Verified SQL
  competence is now promotable to a reusable skill exactly as code competence
  is: the same `Orchestrator` sequencing, `LessonForge`, `PromotionGate` (the
  gate module has a zero-line diff), held-out firewall, markdown skill
  registry, and ledger run both domains. `SqlTask` gains the same validated
  `train`/`heldout` split partition as the code `Task` (defaulting to `train`
  — the fail-safe direction; held-out membership is always explicit) plus an
  optional failure-concept `cluster`; sql-v1 is explicitly partitioned
  (18 train / 14 held-out) with two labelled clusters spanning both splits. A
  new `LearnableTask` port (`core/interfaces.py`) names what the learning
  loop requires of any domain's task; the orchestrator and the forge's
  provenance renderer now treat `entry_point` as optional code-domain
  metadata (code-domain behaviour is bit-identical; all pinned promotion
  numbers unchanged). `benchmarks/sql_learn_demo.py` runs one cycle through
  the real machinery — held-out baseline 20%, an overfit lesson REFUSED at
  20%→20%, a generalising lesson PROMOTED at 20%→60%, then a rollback
  restoring 20% exactly with a `rollback` ledger record. Conformance re-proves
  the firewall on SQL ids (unmodified gate and forge both refuse), audits
  no-held-out-leakage from the ledger alone, pins earned promotion and exact
  reversibility, and shows a promoted SQL skill leaves the code benchmark
  bit-identical (scoping by retrieval relevance, honestly documented as such).
- Operational hardening of execution and sandbox fault attribution (four
  tightenings; no verdict, gate, fusion, or INV-EXEC/INV-SANDBOX semantics
  loosened):
  - **Opportunistic pending-action expiry.** The execution controller sweeps
    lapsed holds at its natural touchpoints — construction, before listing,
    and before approving — and the `pending` CLI verb expires lapsed holds
    before listing, so the TTL is enforced in normal operation without a
    scheduler. The explicit `sweep` verb is unchanged (idempotent) and remains
    the recommended scheduled path for unattended deployments
    (`docs/operations.md` has cron/systemd recipes); the approval-time
    stale-guard stays authoritative.
  - **`retry-execution <id> --by <who>`** re-drives execution for a hold that
    is approved and has never successfully executed (its execution was refused
    fail-closed, or deferred with `approve --no-exec`), through the same
    gated, sandboxed, fail-closed controller path. It never re-opens the
    decision: pending/rejected/expired/already-executed holds are refused with
    a clear error, the human decision record is untouched, and every attempt —
    eligible or not — is recorded. The retry window reuses the TTL: a retry is
    accepted only within `PROM_PENDING_TTL` seconds of the recorded approval
    (`0` disables, as for pending expiry). Executions now carry a `pending_id`
    link column (additive, ensured on open) so "never executed" is provable
    from the ledger alone.
  - **Container-adapter candidate-start signal (parity).** The container
    adapter now carries the unforgeable candidate-start signal: a bootstrap
    mounted read-only into every container consumes a fresh per-run nonce from
    the first line of stdin (stored nowhere the candidate can read) and emits
    nonce-keyed started/exec-failed lines on stderr. A container-run candidate
    crash with a confirmed start classifies FAIL exactly as on the namespace
    adapter; container harness faults stay ABSTAIN. Transport and adapter
    wiring are proven without a daemon; real-container runs are gated
    (`PROM_REQUIRE_CONTAINER=1` to fail rather than skip).

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
- Provider-backed swarm roles: the swarm's roles now reason via the model
  provider instead of returning deterministic placeholders. Each role builds a
  role-specific prompt from the `TaskPacket` and proposer-side context only,
  calls the provider, and strictly validates the reply into typed proposals; a
  malformed reply (or a missing provider) yields no proposal (graceful
  degradation — nothing unvalidated crosses the wall). Code generation reuses the
  actor's `propose_solution`; open-ended reasoning uses a new additive
  `Provider.generate(prompt, system)`. Role prompt builders/parsers live in
  `swarm/prompts.py` (public: `build_reasoning_prompt`, `build_skeptic_prompt`,
  `parse_reasoning`, `parse_cases`). Documented in `docs/swarm-roles.md`.
- Executable Skeptic falsification checks: in the code domain the Skeptic asks
  the model for concrete input/output cases and attaches them as an executable
  check, which the runtime runs through the existing HARD subprocess verifier
  against the criticized proposal's code. A failing case is real FAIL evidence
  (the action cannot be approved and never reaches the executor, INV-SWARM-4); a
  check that cannot run ABSTAINs (no block, no calibration sample). The Skeptic's
  veto is wired to real verification rather than to model opinion.
- `Config.max_role_calls` (env `PROM_MAX_ROLE_CALLS`, default 16): a per-task cap
  on swarm provider calls so a run cannot make unbounded calls.
- `build_swarm_runtime(...)`: a composition root that wires model-backed roles,
  the reused bank/gate/firewall, a no-op recording executor, and a HARD code
  verifier for executable checks. Deterministic offline swarm fixtures in
  `prometheus_protocol._examples.swarm_tasks`.
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

### Fixed
- **`started_ok` is no longer forgeable.** The namespace adapter previously
  inferred "isolation never started" from a parseable stderr marker + exit
  127, which a hostile candidate could print to turn its own crash (FAIL) into
  a harness fault (ABSTAIN). Both `started_ok` and `candidate_started` now
  rest solely on status-pipe tokens the candidate can neither write nor unsay
  (setup-failed / started / exec-failed); the stderr marker remains for human
  diagnostics only. Genuine setup failures and exec failures still report
  not-started (ABSTAIN, fail-closed — an exec failure now also correctly
  revokes the candidate-start), and an unstarted run can no longer be recorded
  as a refusal when it in fact executed. This strengthens INV-SANDBOX /
  INV-EXEC *enforcement*; no invariant wording changes.

### Changed
- Swarm role/model surface, all additive and behaviour-preserving by default:
  roles take an optional injected `provider` (the `propose(packet, context)`
  signature is unchanged, so INV-SWARM-6 holds); `TaskPacket` gained
  `entry_point` (proposer-visible code-domain metadata, never a held-out label);
  `FalsificationCheck` gained `entry_point` and `cases` for executable checks;
  `SwarmRuntime` gained an optional `code_verifier`; `RoleSynthesisEngine` gained
  `provider`/`max_role_calls`; `Provider` gained `generate`; `MockProvider` gained
  a deterministic `responder`. The verifier bank's fusion, the gate, the held-out
  firewall, the proposer/judge wall, and the no-op executor are unchanged.
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
