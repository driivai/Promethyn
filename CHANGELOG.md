# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/). A change to any invariant
in `spec/invariants.md` is a major version bump.

## [Unreleased]

### Fixed
- **A mount table row is judged per resolution, not per table
  (SUBSTRATE-ROBUST).** One unrelated `nsfs` mount — a Docker service network
  namespace, whose mount root the kernel writes as a label
  (`net:[4026533001]`) rather than a pathname — appearing anywhere in
  `/proc/self/mountinfo` used to flip the store's classification from safe to
  unknown and refuse startup on a stock CI runner. The refusal direction was
  right; the coupling was not: an entry that has nothing to do with the path
  being resolved must not degrade that resolution. `parse_mount_table` now
  reads every row on its own terms and retains one it cannot read as an
  `UnparsedEntry` — with its mount id, parent id, mount point, raw line and
  reason — rather than failing the table or, worse, dropping the row. Each
  resolution then applies a deliberately conservative relevance rule
  (`could_affect_path`, and `could_affect_mount_id` for the descriptor join):
  a row is set aside only where it is *established* that it cannot matter —
  its location is readable and lies on a wholly unrelated subtree. A row that
  is an ancestor of the target, the target itself, at or below the target, or
  whose own location is unreadable, is relevant and still refuses. Topology
  anomalies (a parent that does not contain its child, a cycle, a self-parent
  away from `/`, a duplicated mount id) demote their own row the same way
  instead of poisoning coherent rows. What was set aside is carried on
  `SubstrateReport.set_aside`, named in every refusal and warning, logged at
  debug, and printed by the new `scripts/mountinfo_diagnostic.py`: setting a
  row aside silently would be the void-guard version of this fix. Verdicts are
  unchanged in kind — this reduces false refusals and relaxes nothing.

### Added
- **F3: the execution guard's substrate is checked, not assumed
  (PROM-FIX-A).** The cross-process execution guard is an OS file lock beside
  the consumed-approval store, which is mutual exclusion only on a local
  filesystem of one host; that used to be a deployment requirement stated in
  a document. `ConsumedApprovals` now probes the filesystem behind the store
  from the kernel's mount table before it creates anything there
  (`chokepoint/substrate.py`). A network or host-shared filesystem (NFS, CIFS,
  9p, virtiofs, Ceph, GFS2, sshfs and the like) is refused with `ConfigError`
  and has no opt-out; a filesystem the probe cannot identify (overlay, generic
  FUSE, an unknown driver, a platform without a mount table) is refused by
  default. Two settings on `SECURITY_FIELDS`, each the OR of the runner
  config, `Config` and the environment: `allow_unverified_substrate`
  (`PROM_ALLOW_UNVERIFIED_SUBSTRATE`) is the explicit opt-out for the
  unidentified case, logged as a warning at every construction;
  `require_verified_substrate` (`PROM_REQUIRE_VERIFIED_SUBSTRATE`) withdraws
  it. The pair set together is refused as incoherent.
- **F3: owner identity in every execution intent (PROM-FIX-A).** Each
  `execute_intent` records the owner's hostname, kernel boot id, machine id
  and pid (`chokepoint/ownership.py`). A recovering runner that cannot place
  the recorded owner on its own kernel or its own rebooted machine leaves the
  intent pending as `owner_unverifiable` — receipt not consulted, no outcome
  recorded, new approvals for the target refused unspent — instead of
  declaring it not committed. `reconcile_unfinished(assume_owner_dead=True)`
  is the operator's explicit assertion for that case; the outcome event
  records `owner_override`, `owner_basis` and `reconciled_by_host`. Multi-host
  execution is still unsupported; it now fails closed. Regression coverage in
  `tests/chokepoint/test_substrate.py` and `test_owner_identity.py`.

### Changed
- **PROM-FIX-B: executed revert evidence for every new guard, pinned and in
  CI.** `scripts/fix_b_revert_proofs.py` mutates each guard in memory — the
  strict boolean parser (unknown word read as false; programmatic value
  coerced), the link-count refusal, the identity-keyed lock (re-keyed to a
  pathname), the in-process mutex, the same-lock requirement, the legacy
  intent, the raw header-line and status-line checks, the unterminated
  header block, the parser-defect check and the `malformed` classification —
  and runs the tests that must go red: 12 reversions caught, 133 call-phase
  failures, pinned; a shortfall or an excess fails the build.
  `tests/conformance/test_fix_b_revert_pins.py` proves the pins and that
  every revert target still exists.
- **PROM-F11 close-out: the revert runners are pinned, and CI fails on a
  shortfall.** `scripts/f11_reconcile_revert_proofs.py` (43 reversions / 72
  call-phase failures) and `scripts/f11_source_revert_proofs.py` (15 / 21)
  now carry those counts as assertions: the mutation list is checked against
  its pin before anything runs, and the observed call-phase failures after.
  A runner that executed fewer proofs than it claims exits non-zero instead
  of printing a smaller number; `tests/chokepoint/test_f11_revert_pins.py`
  proves the pins, that every revert target still exists, and that the
  enforcement refuses a shortfall or an excess. The F11 CI gate prints the
  collected count per proof file. The threat model records the reconciler's
  no-wall-clock-deadline residual and the adapter requirement it implies;
  `docs/authorization-record.md` §7 names the implemented test behind each
  proposed proof label and states the digest-bound assumption of every
  "detected" row; the in-memory KMS model's docstring names the
  metadata-only limitation. F11 is closed as an open finding on the green
  exact-head Linux run recorded in `docs/reviews/PROM-F11-close-out.md`,
  subject to the maintainer's read; deployed-adapter acceptance is not
  implied.

### Fixed
- **Finding 3 (F5 fail-open): raw header syntax is validated before framing
  is trusted (PROM-FIX-B part 3).** A header line without a colon made
  `http.client`'s permissive parser drop every later header,
  `Content-Length` included; the strict framing check then saw no declared
  length, accepted EOF framing, and a 57-byte body declared as 10000 read
  clean — an empty anchor history verified `VALID`, a provider reply
  verified `PASS`. `core/transport.py` now validates every status line and
  header line against its grammar before the parser sees it, requires the
  header block to end with its blank line, caps lines and the block, and
  refuses any parser defect that remains as an independent second check.
  The refusal is a new `malformed` kind in the shared error bundle:
  `ProviderMalformedResponse` for the provider, `AnchorUnavailable` for the
  anchor, and an anchor history behind it is `NOT_VERIFIABLE`. Both clients
  share the fix; `tests/conformance/test_header_integrity.py` drives real
  sockets through both with the review's wire, every defect class the
  parser can record, every raw-syntax violation it accepts silently, and
  positive controls. Honest scope: this closes the demonstrated case, not
  every conceivable header anomaly.
- **Finding 2 (F3 fail-open): the execution guard is keyed to the store's
  identity, not its pathname (PROM-FIX-B part 2).** The independent review
  reproduced, with real subprocesses, hard links, SQLite and OS locks, that
  two hard links to one consumed-store inode gave two runners two different
  companion locks, both acquired, and recovery recorded `not_committed` for
  an owner that was still running. The guard is now an `flock` on a
  descriptor of the store's own inode, opened once and held for the store's
  lifetime, released with `LOCK_UN`: every alias of the store — hard link,
  file bind mount, symlink — opens the same inode and the kernel evaluates
  `flock` conflicts per inode across processes, so every alias resolves to
  one lock object; an in-process mutex makes two threads contend the way two
  processes do; a forked child contends with a descriptor of its own. A
  multiply linked store is refused at construction and re-validated before
  every acquisition. Every intent records the lock's identity
  (`owner_lock_id`), and "same boot id" establishes a dead owner only when
  the recorded lock is the lock this runner holds; otherwise, and for intents
  with no identity, the intent stays `owner_unverifiable` until the
  operator's recorded assertion. The guard is specified for Linux and
  refuses elsewhere. The authorization journal's store was already inode
  keyed by SQLite's own lock and singly-linked-checked before every use; a
  test now proves it. `tests/chokepoint/test_lock_identity.py` reproduces
  the review's scenario (a live subprocess owner, a real hard link, and
  under a mount namespace a real file bind mount) and the positive controls.
- **F9: one strict boolean parser at every entry point (PROM-FIX-B part 1).**
  The truth-set parser copied into seven modules and twenty-one test files
  had two fail-open shapes the independent review reproduced: a present but
  misspelled value (`PROM_REQUIRE_VERIFIED_SUBSTRATE=tru`) was silently
  `False`, and a programmatic string (`allow_unverified_substrate="false"`)
  was coerced with `bool()` and enabled the opt-out. `core/booleans.py` is now
  the single parser: unset takes the default; a set value must be one of
  `1/true/yes/on` or `0/false/no/off` and anything else is refused with
  `ConfigError`, never read as false; a programmatic boolean must be an
  actual `bool`. Applied to `Config` and `Config.from_env`,
  `MigrationRunnerConfig`, `resolve_substrate_policy`, the substrate, signer,
  ledger-anchor, unsafe-exec and digest-pin variables, and the CI gate flags
  (`PROM_REQUIRE_SANDBOX`, `PROM_REQUIRE_PG`, `PROM_REQUIRE_PRIVILEGED`,
  `PROM_REQUIRE_CONTAINER`), where a typo used to turn "fail, do not skip"
  into a silent skip. `tests/conformance/test_strict_booleans.py` covers
  every entry point and sweeps both trees for the old pattern.
- **Five claims corrected to what the code establishes today (PROM-FIX-B
  part 0).** The execution guard is keyed to the store's pathname, so
  recovery through an alias can declare a live owner not committed
  (finding 2); the substrate check classifies the filesystem type at the
  parent directory's pathname, not the opened store or lock objects, and
  uses no mount identity (findings 1A/1B); raw header syntax is not
  validated, so a colonless header line lets a truncated body read clean and
  an empty anchor history verify VALID (finding 3); "every Sign logged by the
  KMS" is a deployment obligation, not enforced by construction.
- **Two false documentation claims corrected (PROM-FIX-A).**
  `docs/threat-model.md` §2.4 said the chokepoint runner spawns no
  subprocesses; since #77 an `https://` ledger anchor resolves the log's
  hostname in a disposable interpreter for every request it makes. The
  section now enumerates that child (empty environment, no inherited
  descriptors, `-I`, `[host, port]` only, killed and reaped), cross-references
  §4, and records why the claim went stale. `docs/key-custody.md` said the
  ledger can recompute `approval_digest`; nothing persists the digest or the
  issuance and expiry fields it needs, and no production code calls it, so
  gate-versus-KMS reconciliation is now documented as not operational (open
  finding F11), with what would make it so.
- **F6: whole-request HTTP deadlines.** Provider and anchor requests now share
  one monotonic budget across DNS, all TCP address attempts, proxy CONNECT,
  TLS handshake, request writes, headers, chunk metadata and body reads. DNS
  runs in a disposable isolated interpreter with an empty environment and no
  inherited descriptors; timeout kills and reaps it instead of abandoning a
  thread. Reads enforce the remaining budget below buffering, including error
  responses. CONNECT responses are explicitly released even on Python 3.10,
  including when exception tracebacks remain live. Adds real-socket timing,
  cleanup and concurrency regressions plus
  resolver secret/descriptor isolation tests. Process startup/cleanup and OS
  scheduling remain overhead, not a hard real-time guarantee. F7 approval
  expiry is unchanged.
- **F4/F5: anchor acknowledgement and HTTP response integrity.** Append success
  now requires an expected HTTP status, a non-negative integer index, and
  read-back of the exact canonical submitted record at that index. Custom log
  ports are checked too; idempotent writes require history evidence, not a
  `/latest` claim. Both HTTP clients reject short Content-Length bodies,
  ambiguous framing, and incomplete or malformed chunk endings. Real-socket
  regressions cover valid responses, false acknowledgements, no-executor
  refusals and `NOT_VERIFIABLE` on incomplete history. Read-after-write
  consistency is required; dishonest witness operators remain outside this
  guarantee. Whole-exchange deadlines (F6) and expiry (F7) are not changed.
- **F2/F3: execution recovery uncertainty and ownership.** Database outcomes are
  now explicit: committed, definitely not committed, or unknown. Unknown outcomes
  remain pending and block later migrations until receipt reconciliation proves
  the result; historical ambiguous failure records are revisited. A required
  cross-process guard spans intent publication, execution and recovery in the
  supported shared-store, single-host deployment. Suspended owners cannot be
  declared rolled back. Adds real PostgreSQL commit-response-loss and process
  lifecycle regressions to the existing mandatory live-test job.
- **P0: candidate-forged verifier verdicts.** Expected answers, comparisons and
  pass counts now stay in the trusted parent. The sandbox returns bounded,
  type-preserving data only; candidate-written `result.json` is ignored.
  Malformed/incomplete responses, custom return objects, truncated output and
  abnormal exits cannot pass. Unsupported trusted task values refuse execution.
  Candidate prints now appear in evidence stderr. Regression coverage includes
  the original forged-file attack, protocol manipulation and real-sandbox CI
  tests for both namespace and container adapters.

### Changed
- **Relicensed to proprietary (PROM-IP).** The Apache-2.0 `LICENSE` is replaced
  by a placeholder proprietary notice naming DriivAIDev; `NOTICE`,
  `pyproject.toml` (`license = "LicenseRef-Proprietary"`, `authors`), the
  README and the site say the same. Commercial and OEM terms are separate
  written agreements. The boundary is recorded in `docs/LICENSE-HISTORY.md`:
  Apache-2.0 through commit `0c782e5`, proprietary from the relicense commit;
  copies obtained under Apache-2.0 remain under it. New for diligence:
  `docs/IP-READINESS.md` (the one-page summary), `docs/DEPENDENCY-LICENSES.md`
  (every dependency, its license and obligation, including the LGPL position
  on `psycopg`), `docs/sbom.cdx.json` (CycloneDX 1.6), `constraints.txt`
  (the closure pinned; CI installs under it) and
  `scripts/check_ip_consistency.py` (CI gate: one owner, one license, no
  stray former license). The commit-provenance rewrite is documented in
  `docs/repository-identity.md` and executed separately.

### Added
- **Durable, privilege-complete migration approvals.** The brokered migration
  runner now requires a filesystem-backed consumed-approval store; spent nonces
  survive restarts and claims serialize across threads and processes. Approval
  MACs bind a versioned canonical target object containing host, port, database,
  database user, and schema (excluding only the rotatable password), and the
  PostgreSQL executor establishes the bound schema as its transaction-local
  search path. The privileged executor now uses the PostgreSQL wire protocol,
  removing psql meta-commands from the artifact surface. Production composition
  requires a stable 256-bit signing key, durable store, and audit sink; direct
  runner construction also requires an audit sink. The runner commits a durable
  execution intent before database contact and links the outcome to it. Intent
  audit failures block execution; outcome audit failures return an explicit
  degraded result while leaving the intent for reconciliation. Store outages
  also fail closed. Approval JSON is strict and versioned, timestamps must be
  finite, and store files require safe ownership and permissions. Adversarial
  tests cover restart replay, thread/process/fork races, audit outages, corruption,
  user privilege changes, schema changes, and hostile psql command text. CI now
  provisions PostgreSQL and requires live driver, schema, rollback, and
  meta-command tests on every supported Python version.
- **Crash-reconcilable migration execution.** Every approved run now has a stable
  execution ID derived from its signed nonce, artifact, and canonical target.
  The PostgreSQL executor holds an execution-specific advisory lock and commits
  a receipt in `promethyn_internal.migration_receipts` in the same transaction as
  the migration. On restart, an intent without an audit outcome is reconciled
  against that receipt: a matching row proves commit, an absent row after the
  lock is acquired proves rollback, and an unavailable, active, or conflicting
  receipt blocks all further migrations. Explicit transaction-control statements
  are rejected before connection so artifact SQL cannot split the migration from
  its receipt. Unit tests force termination before execution, during the
  transaction, after commit, and before outcome recording; mandatory live
  PostgreSQL tests prove both committed and rolled-back restart recovery.
  Custom executor integrations now receive the execution ID and artifact digest
  and must supply a matching receipt lookup; construction rejects an unpaired
  custom executor rather than silently applying PostgreSQL recovery semantics.
- **Make the SOFT-lever experiment decidable (SC-2).** The lever machinery from
  the prior change was not *dispatchable* — it had no pre-committed adoption rule
  and could not produce a decision. This change fixes that, entirely offline (no
  live model call), adopting nothing and leaving default behaviour byte-identical.
  A **pre-registered adoption rule + power check**
  (`docs/soft-calibration-adoption-rule.md`, committed before any measurement
  code) shows the finding in bold: at the current 45/51 gold-negative
  denominators **no lever can clear the bar** (correcting 3 of 5 false-PASSes is
  McNemar p=0.125; a 5-pt drop is arithmetically impossible on live-v2's 3.9%).
  The driver is **instrumented** so the abstention trap is impossible to miss —
  every run prints coverage, false-PASS **and** false-FAIL as `n/d` (never a bare
  %), model-call count, and machine-readable JSON, with a rule-of-three ceiling on
  any thin denominator (a conformance test fails the build if a rate lacks its
  denominator). **`threshold` is now free** — a post-hoc θ-sweep frontier
  (`threshold_frontier`) recomputes verdicts from a persisted baseline with zero
  model calls and shows the coverage/false-PASS trade by construction (on scripted
  grounding-v2, θ=0.8 withholds 3 correct PASSes to catch 2 false ones); the
  hardcoded θ=0.8 default is deleted. The k-sample **vote fraction is renamed**
  (`vote_fraction`, not a confidence) and a test locks that it can never become
  `Judgment.confidence`. `ensemble` is relabelled the **independence positive
  control**, the four hedged predictions are replaced by **one falsifiable
  claim**, and the dispatch plan adds a **T=0.7/k=1 control** (isolating
  temperature from sampling), exact per-line call counts, dollar cost, and the
  honest verdict: **defer dispatch** until a larger gold set exists. That set's
  **protocol + a 20-item adversarial pilot + the required N** ship in
  `docs/gold-set-v3-protocol.md` / `benchmarks/gold_pilot_v3.py`. Finally a **skip
  sweep** (`docs/skip-sweep.md`) found two tests that never ran in CI — the
  container-backend real-`docker run` tests (flag set nowhere) and the
  Hearth-byte-identical guards (skipped under CI's shallow checkout) — and fixes
  both: a dedicated `container-sandbox.yml` job and `fetch-depth: 0` in `ci.yml`;
  the container backend is marked experimental until that job is green.
- **SOFT-judge calibration levers (opt-in, measured, none adopted by default).**
  The composition study showed composition cannot add signal the per-step judge
  lacks, so lowering the SOFT judge's **false-PASS** is the higher-leverage path.
  A new module (`verifier/soft_levers.py`) adds four configurable, `Tier.SOFT`
  wrappers around the existing judge — a confidence **threshold** (1×), an
  **ensemble** of independent judges requiring unanimity to PASS (N×), **k-sample**
  self-consistency (k×), and an **adversarial self-check** that elicits the
  strongest case against before deciding (2×) — plus a driver
  (`benchmarks/soft_calibration_eval.py`) that measures each against the recorded
  baselines by reusing the EXISTING item sets (live-v2, grounding-v2), the
  fixture-tested `compute_metrics` fold, and the report renderers. **A SOFT
  verdict stays SOFT** — a lever can only turn a shaky PASS into an ABSTAIN, never
  grant authority (tested: a lever's PASS still yields a non-authoritative
  judgment the gate blocks). Every lever's arithmetic is fixture-verified on
  scripted judge outputs before any live use, and each reports its model-call
  cost honestly. A single additive knob (`PROM_JUDGE_TEMPERATURE`, default 0) lets
  the k-sample lever draw varied samples; **default behaviour, the production
  judge path, and the Hearth are byte-identical to main** (conformance-tested) —
  no lever is adopted in this change; adoption is a separate, measurement-gated
  decision. The live measurement is an operator dispatch (spends credits); the
  exact per-lever commands, cost, and the honest bars (rule-of-three on 0/n; the
  silence trap) are in `docs/soft-calibration.md`.
- **Confidence composition, measured (not invented).** The open problem left by
  the orchestration skeleton — combining per-step confidences into a sound
  chain-level number — is now attacked *empirically*. A new benchmark
  (`benchmarks/chain_items.py`, `benchmarks/chain_eval.py`) builds 42 multi-step
  chains whose final output is HARD-verified by executing an assembled SQL query
  through the real `SqlVerifier` (ground truth is executed, never labelled;
  compounding and recovery are mechanical). Five candidate composition rules
  (`min`, `product`, `mean`, `tier_weighted`, `weakest_link_length`) ship as
  pure, tested **hypotheses** in `orchestration/composition.py`, and the harness
  measures each rule's calibration table, false-confidence rate (scored-high-but-
  actually-wrong) swept over thresholds, discrimination, and degradation with
  chain length. **Measured finding:** no rule is trustworthy enough to bear a
  halt decision — even with calibrated per-step inputs and strict compounding
  the safest rule (`product`) still mislabels ~1-in-13 "high-confidence" chains
  as safe when they are wrong, `mean` is dangerous at every threshold (it averages
  the weak link away), the rules that reach 0% false-confidence do so only by
  going nearly silent, and false-confidence rises with chain length — all on 8
  incorrect chains, so directional not settled. So the runtime's `min()`
  placeholder **stays unchanged** (it was not licensed for replacement; it is
  tied-best-calibrated and never over-states trust), the composed number is a
  human summary that may only make halting *more* conservative, and it is
  structurally unable to authorize — the composition module holds no gate/executor
  capability, and a high composed confidence provably cannot execute a
  non-authoritative action (the gate still decides — tested). The calibration
  arithmetic is fixture-verified before it is trusted. **No Hearth change** and
  **no orchestration-skeleton change** — both are byte-identical to main
  (conformance-tested); this sprint only ADDS. See `docs/composition-study.md`.
- **Governed multi-agent orchestration (skeleton).** A new `orchestration/`
  module generalises the *proposer* side into a DAG of agent steps while the
  Hearth stays singular: every agent's every action routes through the
  existing verify → gate → human-hold → execute → ledger pipeline, and
  inter-agent messages are tier-tagged so an upstream error cannot be
  laundered into a downstream fact. The orchestrator has **no authority to
  execute** — its whole vocabulary for touching the world is a submit-only
  `ActionGateway.route_action` that always ends at the gate; `WorkflowRuntime`
  holds no executor, gate, or `execute`/`approve` method (a soft-only claim
  proposing an action is blocked by the gate — tested). The message contract
  is structural both ways: an agent returns an `AgentProposal` with no tier or
  confidence field, and an `AgentMessage` cannot exist untiered — the runtime
  builds it from the verifier bank's judgment of an independent grader's
  evidence, never from the proposing agent. The ledger is **extended
  additively** (a `workflow_steps` table + two methods; existing rows and
  queries untouched) so a multi-step run is auditable per step
  (`workflow_id`/`agent_id`/tier/outcome) in one query. `python -m
  prometheus_protocol.orchestration.demo` runs three agents end to end (a soft
  plan, a hard implement that executes, a high-risk export routed to a human
  who approves it through the controller). **No Hearth change** — the bank,
  both gates, executor, controller, pending, forge, and core models/interfaces
  are byte-identical to main (conformance-tested). Deliberately out of scope
  and isolated as follow-ups: principled confidence composition across
  dependent steps (the runtime passes/records per-step confidence and reports
  a labelled *minimum* placeholder, not a solution), the workflow-halt UX, and
  a process boundary that would close the in-Python introspection caveat noted
  in `docs/orchestration.md`.
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
