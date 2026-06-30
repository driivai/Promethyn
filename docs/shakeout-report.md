# End-to-end shakeout — pain-point register

A diagnostic run of the full pipeline (mock provider, offline, deterministic)
against happy-path and adversarial inputs. Findings are recorded here; repros
live under `tests/shakeout/`. The diagnostic PR changed no substantive
behaviour — real bugs were left red (xfail) and tracked.

**Update — operability hardening:** findings **F1–F5 are now fixed**; their
repros have been turned green (see the CHANGELOG, Unreleased). F6–F9 remain open
and tracked below.

## Triage summary

| Severity | Count |
|----------|-------|
| blocker  | 0 |
| major    | 2 |
| minor    | 5 |
| nit      | 2 |

**Top 3 to fix next**

1. **F1 — CLI surfaces raw tracebacks.** Catch known errors at the CLI boundary
   (provider misconfig, corrupt state) and print a clean one-line message with a
   non-zero exit instead of a Python stack trace.
2. **F2 — Corrupt/locked state file crashes with a raw `sqlite3.DatabaseError`.**
   Wrap the ledger/trust-store open in a clear error that names the file.
3. **F3 — A task with no verifiable cases returns FAIL, not ABSTAIN.** "Cannot
   verify" should not be recorded as a confident failure (and then mined by the
   forge).

## Reproduced baseline → learn lift (mock provider)

```
$ prometheus-protocol baseline      # cold start
Baseline (all)   : 40% (4/10)   train: 40%   heldout: 40%
$ prometheus-protocol cycle
Held-out before : 40%   Mined: ['skill-empty-input']   Promoted: ['skill-empty-input']   Held-out after : 100%
$ prometheus-protocol audit
attempts: 45   promotions: 1   (cycle 1: promote skill-empty-input 40% -> 100%)
```

The documented 40% → 100% held-out lift reproduces from a clean state, and the
chain is recorded and re-readable.

## Full-loop timing (10-task example benchmark, mock provider)

| Command | Wall time |
|---------|-----------|
| `baseline` (10 tasks) | ~0.46 s |
| `cycle` (≈45 verifications) | ~0.76 s |

Fast at toy scale. Each task is one subprocess spawn; verification is **serial**
(see F7).

---

## Findings

### MAJOR

#### F1 — Unhandled errors surface as raw Python tracebacks at the CLI
- **Status:** ✅ fixed — `main()` catches known errors and prints a clean
  `error: <msg>` line (non-zero exit); `-vv` surfaces the traceback.
- **Category:** operability / DX
- **Repro:** `PROM_PROVIDER=remote prometheus-protocol baseline` with no
  `PROM_API_BASE`.
- **Observed:** a full traceback ending in
  `ValueError: api_base is required (set PROM_API_BASE)`, exit 1.
- **Expected:** a clean `error: api_base is required (set PROM_API_BASE)` on
  stderr, non-zero exit, no traceback.
- **Note:** the message text is good; the *presentation* is not. The same
  applies to corrupt-state and unreachable-endpoint errors.
- **Recommended action:** wrap the dispatch in `main()` in a `try/except` for
  known types (`ValueError`, `ProviderError`, `sqlite3.DatabaseError`,
  `FileNotFoundError`) → print `error: <msg>` and return 1; let truly unexpected
  exceptions still propagate. (Design choice on which to catch ⇒ a finding, not
  fixed here.)
- **Repro test:** `tests/shakeout/test_shakeout_cli.py` (xfail).

#### F2 — Corrupt or locked state file crashes with a raw `sqlite3.DatabaseError`
- **Status:** ✅ fixed — the ledger/trust-store adapters raise a typed
  `StateError` (in `core/errors.py`) naming the file, with recovery advice.
- **Category:** robustness / operability
- **Repro:** write non-database bytes to the trust-store / ledger path, then
  construct `SqliteTrustStore(path)` / `SqliteLedger(path)`.
- **Observed:** `sqlite3.DatabaseError('file is not a database')` propagates
  uncaught (and, via the factory/CLI, a traceback).
- **Expected:** a clear, typed error naming the offending file and suggesting
  recovery (e.g. "remove or repair `.prometheus/trust.db`").
- **Recommended action:** catch `sqlite3.DatabaseError`/`OperationalError` in the
  adapter `__init__` and re-raise a domain error with the path. (Defining the
  error type/behaviour is a design choice ⇒ finding.)
- **Repro test:** `tests/shakeout/test_shakeout_state.py` (xfail).

### MINOR

#### F3 — A task with no test cases returns FAIL instead of ABSTAIN
- **Status:** ✅ fixed — the runner returns ABSTAIN for `total == 0`; non-empty
  verdicts and benchmark rates are unchanged (parity tested).
- **Category:** correctness / robustness
- **Repro:** `SubprocessVerifier().verify(code=..., task=Task(..., cases=()))`.
- **Observed:** `verdict == FAIL` (`passed == False`).
- **Expected:** `ABSTAIN` — there is nothing to verify, so it is not a confident
  failure. As FAIL it counts against the pass rate and is eligible to be mined
  by the forge as a real failure.
- **Recommended action:** in the runner, treat `total == 0` (no cases) as
  ABSTAIN rather than FAIL. (Semantic judgement ⇒ finding.)
- **Repro test:** `tests/shakeout/test_shakeout_verifier.py` (xfail).

#### F4 — No `status` view; trust ranking and skills are never surfaced
- **Status:** ✅ fixed — added a read-only `status` command rendering the
  verifier ranking (with calibration counts) and the promoted skills.
- **Category:** DX / observability
- **Observed:** CLI commands are `demo / baseline / cycle / audit`. There is no
  `status` (the brief's mental model was `baseline / learn / ablate / status`);
  `audit` shows only attempt/promotion counts. `bank.rank()` (verifier trust
  ranking), the current skills, and soft-judge calibration state are computed but
  never shown to a user. Ablation is only reachable inside `demo`.
- **Expected:** a `status` command (or a richer `audit`) that surfaces the
  verifier ranking, calibration counts, and promoted skills.
- **Recommended action:** add a `status` command rendering `bank.rank()` +
  registry contents; consider `learn`/`ablate` aliases. (Feature ⇒ finding.)

#### F5 — No structured logging anywhere in the runtime
- **Status:** ✅ fixed — `logging` added at the CLI/factory/orchestrator/provider
  seams with a `-v`/`-vv` flag (and `PROM_LOG_LEVEL`); default WARNING.
- **Category:** operability
- **Observed:** `grep -rn "import logging" src/` → nothing. A failed or partial
  run yields only a traceback (or silence); there is no run log to debug from.
- **Recommended action:** add `logging` at the orchestrator/factory/provider
  seams (a `-v/--verbose` CLI flag). (Design ⇒ finding.)

#### F6 — Judgment confidence is not SQL-queryable (lives in a JSON column)
- **Category:** observability
- **Repro:** `SELECT id FROM attempts WHERE confidence > 0.9` →
  `sqlite3.OperationalError: no such column: confidence`.
- **Observed:** verdict/confidence are recoverable only by parsing the JSON
  `evidence` column (`row['evidence']['judgment']['confidence']`).
- **Expected (eventually):** first-class columns for analytics. Known limitation;
  it bites anyone wanting SQL-level confidence analytics.
- **Recommended action:** an additive `confidence REAL` / `verdict TEXT` column
  with a migration, when analytics are needed. (Schema change ⇒ finding.)
- **Repro test:** `tests/shakeout/test_shakeout_ledger.py` (characterisation,
  passing — a tripwire if a column is added).

#### F7 — Verification is serial; no batching/parallelism
- **Category:** performance
- **Observed:** each task is one subprocess spawn run sequentially (~40–75 ms
  each); with the soft judge enabled, each task also makes an in-band model call.
  At N tasks this is N spawns + N judge calls in series.
- **Expected:** acceptable at small scale; a scaling concern for large benchmarks
  / live judges.
- **Recommended action:** note as a scaling follow-up (parallel verification,
  async judge). No test (perf).

### NIT

#### F8 — `cycle` is stateful; the lift only reproduces from a clean state
- **Category:** DX
- **Observed:** `cycle` persists the promoted skill to `.prometheus/skills`, so a
  second `cycle` shows "Held-out before: 100%" and mines nothing. The documented
  40% → 100% lift only reproduces after clearing `.prometheus`. There is no
  `reset` command.
- **Recommended action:** document it, and/or add a `--fresh`/`reset` affordance.

#### F9 — `python -m prometheus_protocol.cli.main` emits a `RuntimeWarning`
- **Category:** DX (cosmetic)
- **Observed:** a runpy double-import `RuntimeWarning` when invoked via `-m`; the
  installed `prometheus-protocol` entry point is clean.
- **Recommended action:** prefer the entry point in docs; optionally add a
  `__main__.py`. Cosmetic.

---

## Verified healthy (no action)

- Cold-start boot smoke: every command runs; the 40% → 100% lift reproduces.
- Empty task set → graceful (pass rate 0.0, no crash).
- Forced timeout / harness error → **ABSTAIN** (not a pass, no calibration).
- The wall (INV-SWARM-1/4): the executor rejects a raw `Proposal` (`TypeError`)
  and an unapproved `GateDecision` (`ValueError`); a proposal whose skeptic check
  fails never reaches the executor; the executor is a no-op recorder (no side
  effects).
- Verifier bank: hard verdict decides; soft disagreement lowers confidence
  without flipping the verdict; parity holds; soft ABSTAIN creates no calibration
  sample.
- Trust calibration **persists** across a simulated restart of `trust.db`.
- Provider boundary: an unreachable endpoint raises an actionable `ProviderError`;
  the `api_key` is **not** echoed in error messages.
- Safety posture: `SECURITY.md` still states the subprocess verifier is **not a
  sandbox**; nothing in the stack performs real side-effecting execution (the
  executor is no-op; the verifier runs candidate code under rlimits, as
  documented).
