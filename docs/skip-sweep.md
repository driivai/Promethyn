# Skip sweep: which tests actually run in CI

A test gated on a flag or condition that is true (or absent) in every environment
we run is a test that does not exist. This is the sweep of every env-gated / `skipif`
/ `pytest.skip` in the suite, with the two columns that matter: **is the gate ever
satisfied anywhere we run**, and **has it ever run in CI**.

Command: `grep -rn "PROM_REQUIRE_\|skipif\|pytest.skip" tests/ | sort`.

| gate / condition | tests | set / true anywhere we run? | ever run in CI? | invariant guarded | load-bearing | status |
|---|---|---|---|---|---|---|
| `PROM_REQUIRE_SANDBOX` (skip if namespace runtime unavailable; **fail** under the flag) | test_sandbox, test_sandbox_fault_classification, test_execution(+_expiry,+_retry), test_git_demo, test_git_tool, test_grounding_domain, test_orchestration, test_composition, test_sql_learn_loop, test_sql_verifier, test_extension_surface, integration/test_live_execution | **YES** — `ci.yml` sets `PROM_REQUIRE_SANDBOX=1` and lifts AppArmor so the namespace runtime is available; the tests also run wherever the runtime is present, flag or not | **YES** | real-isolation execution, fail-closed sandbox, INV-EXEC, crash→FAIL fault attribution, grounding/SQL/orchestration behaviour | **yes** | **covered** — runs in CI, fails-not-skips under the flag |
| `PROM_REQUIRE_CONTAINER` (skip if unset) | test_sandbox_container_signal::test_real_container_run_confirms_candidate_start, ::test_real_container_candidate_crash_classifies_fail | **NO** — set in no workflow, script, or config (only referenced in the test, CHANGELOG, docs) | **NO — never, since inception (c92c2f3, PR #25)** | the unforgeable candidate-start signal survives a real `docker run`; container crash→FAIL (a HARD verifier for the container backend) | **yes** | **FIXED this sprint** — a dedicated `container-sandbox.yml` job now runs them nightly + on `sandbox/` PRs with the flag set (they could not run in the build env: docker daemon down — see §"why not here") |
| `skipif(git rev-parse origin/main fails)` (Hearth-byte-identical diff tests) | test_composition::test_hearth_is_unchanged_versus_main, test_orchestration::test_hearth_is_unchanged_versus_main, test_extension_surface::(hearth diff), test_soft_levers::test_hearth_and_default_judge_path_unchanged_versus_main | condition was **TRUE (skip) in CI**: `actions/checkout@v4` defaulted to a shallow checkout (fetch-depth 1), so `origin/main` was **not fetched** and these skipped | **was NO** in CI (silently skipped under shallow checkout) | Hearth (+ default-judge path, orchestration core, extension surface) **byte-identical to main** | **yes** | **FIXED this sprint** — `ci.yml` checkout now uses `fetch-depth: 0`, so `origin/main` resolves and these guards run |
| `PROM_REQUIRE_DIGEST_PIN` | test_execution_retry:472, test_sandbox_provenance:72,80 | n/a — **not a skip gate**: the tests `monkeypatch.setenv` this themselves to exercise digest-pinning | **YES** (always run) | supply-chain: a bare image tag is refused under the pin | yes | **covered** — test-controlled env, not a gate |

## The two findings, and what changed

1. **`PROM_REQUIRE_CONTAINER` — 2 tests, never run in CI.** They are the HARD
   verifier for the container backend: does the nonce-on-stdin / stderr
   start-signal survive a real `docker run`, and does a container-run crash
   classify FAIL (not ABSTAIN)? The 15 sibling tests that DO run test the adapter
   against a **stub** runtime written by the same author encoding the same
   assumptions — a stub cannot catch a mismatch between the assumed runtime and
   the real one, which is the only thing the real-container test exists to catch.
   The failure direction is the bad one: if a real runtime interleaves stderr
   differently than the stub assumes, `candidate_started` returns false and a
   crashing candidate classifies **ABSTAIN wearing a HARD tier tag** — the
   abstention trap one layer down, and authoritative. Now covered by a dedicated
   CI job (`.github/workflows/container-sandbox.yml`). The namespace backend
   already covers crash→FAIL under real isolation in CI (`PROM_REQUIRE_SANDBOX=1`)
   — a different transport, which is why this was not an emergency.

2. **`skipif origin/main` — 4 Hearth-byte-identical tests, silently skipped in
   CI.** The "Hearth unchanged" guard the project leans on to prove no PR mutates
   the trusted core was not actually running in CI, because the default shallow
   checkout does not fetch `origin/main`. Fixed by `fetch-depth: 0`.

## Why the container tests could not be proven in *this* build environment

The build sandbox has the `docker` CLI but **no reachable daemon**
(`docker info` fails; `ContainerSandbox.available()` is `False`). Run under the
flag, the tests correctly **fail rather than skip**:

```
$ PROM_REQUIRE_CONTAINER=1 python -m pytest tests/conformance/test_sandbox_container_signal.py -k real_container
E   Failed: PROM_REQUIRE_CONTAINER=1 but no functioning container runtime (docker/podman daemon) is available
FAILED ::test_real_container_run_confirms_candidate_start
FAILED ::test_real_container_candidate_crash_classifies_fail
2 failed, 15 deselected
```

That is the gate behaving correctly (fail-not-skip under the flag), and the
reason the end-to-end proof is deferred to the `ubuntu-latest` CI job, which ships
a running daemon.

## The `ubuntu-latest` job ran — and it is RED (a real bug, not a chore)

The `container-sandbox.yml` job ran on a real runner (Docker 28.0.4) and
**FAILED** on its first run
([run 29205643658](https://github.com/driivai/Promethyn/actions/runs/29205643658)),
which is the most valuable signal this job could produce. It confirms, on a real
`docker run`, the exact failure direction this test was built to catch:

```
test_real_container_run_confirms_candidate_start FAILED
  assert res.started_ok  →  False
  SandboxResult(stderr="python: can't open file '/workspace/.prom-start.py': [Errno 13] Permission denied",
                exit_status=2, started_ok=False, candidate_started=False,
                detail='container did not confirm candidate start')

test_real_container_candidate_crash_classifies_fail FAILED
  AssertionError: sandbox did not start: container did not confirm candidate start
  assert <Verdict.ABSTAIN> == <Verdict.FAIL>
2 failed, 15 deselected
```

**What it means.** Under a real container the in-container bootstrap file
`/workspace/.prom-start.py` is **not readable by the non-root container user**
(Errno 13). So the unforgeable candidate-start signal never fires,
`candidate_started` is False, and a crashing candidate **classifies ABSTAIN, not
FAIL** — a HARD verifier silently degrading into "could not verify" while wearing
a HARD tier tag. The stub-runtime tests that run in the default suite did not
catch it because a stub does not enforce the `--user`/bind-mount permission
interaction a real `docker run` does — which is precisely why the real-container
test exists.

**Resolution (EX-1).** This RED was the finding that opened EX-1, and it is now
**fixed and GREEN on record**
([run 29225713634](https://github.com/driivai/Promethyn/actions/runs/29225713634),
`2 passed`): the bootstrap is delivered via `python -c` and never staged into the
bind-mounted workspace, so it is both readable by the non-root user and
untamperable, and a container-run crash now **classifies FAIL**. The `sandbox/`
fix was in scope for EX-1 (the sprint this RED launched), not the earlier cleanup
branch. The `README`/`docs/sandbox.md` experimental caveats are dropped
accordingly. The daemonless **namespace** backend remains the proven default.

## Did the ABSTAIN bug contaminate any published number? (EX-1 §0 audit)

The container RED above is one instance of a wider bug: a HARD verifier that
**cannot execute** returns `Verdict.ABSTAIN` (`runner.py:188`, backend-agnostic),
and `benchmarks/judge_eval.py:192` **excludes every reference-ABSTAIN row from
`n_reference`** — so an infra-ABSTAIN silently shrinks the ground-truth
denominator under every published false-PASS / false-FAIL rate. Before fixing the
bug, EX-1 audited whether it had already corrupted a published figure. It
distinguishes two kinds of could-not-decide: **category B** (could-not-execute — an
infra/harness fault: sandbox did not start, candidate never confirmed) and
**category C** (`reported_total == 0`, task-unsound). Only B is the bug; C is a
legitimate abstain (the check ran, there was nothing to check).

**Method — measured, not asserted.** No per-item eval artifacts are committed to
the repo (the live-v1/live-v2 dispatch results live only in the Actions logs), so
the reference side was **re-derived by re-executing the deterministic HARD
reference** (`SubprocessVerifier(memory_mb=0)`, exactly as `judge_eval.py:504`
builds it) over every committed CODE item set, under the real namespace sandbox,
counting PASS / FAIL / ABSTAIN and classifying every abstain B vs C. The grounding
sets need no execution — their reference is the gold label, mapped straight to a
verdict (`grounding_eval.py:266` → `_GOLD_VERDICT`, `SUPPORTED→PASS`,
`NOT_SUPPORTED→FAIL`), so a reference-ABSTAIN is not representable there.

| published rate(s) | reference | re-executed result | category-B abstains |
|---|---|---|---|
| offline scripted (`judge-quality.md`) | HARD verifier ×10 | 5 PASS / 5 FAIL / **0 ABSTAIN** (`n_reference=10`) | **0** |
| live-v1 `0/32`, `0/16` (both arms) | HARD verifier ×48 | 16 PASS / 32 FAIL / **0 ABSTAIN** | **0** |
| live-v2 `2/51`=3.9%, `0/49`, `0/31` | HARD verifier ×82 | 31 PASS / 51 FAIL / **0 ABSTAIN** | **0** |
| grounding-v1 `0/26` (both arms) | gold label (no sandbox) | n/a — reference cannot ABSTAIN | **0 (structural)** |
| grounding-v2 `5/45`, `0/43` | gold label (no sandbox) | n/a — reference cannot ABSTAIN | **0 (structural)** |

The re-execution reproduces each documented PASS/FAIL split exactly (48/48 =
16 PASS / 32 FAIL; 82/82 = 31 PASS / 51 FAIL), and every published denominator is
full: where a code-domain denominator is short of the item count (e.g. live-v2
independent `0/49`, not `0/51`) it is short by the **judge's** documented abstains,
never the reference's.

**Finding: ZERO category-B reference-ABSTAINs behind any published number. No
published false-PASS or false-FAIL figure had its denominator shrunk by an
infra-fault; every rate in `docs/judge-quality.md` and
`docs/soft-calibration-adoption-rule.md` stands as published.** The bug was real,
latent, and authoritative — but it had not yet reached the numbers. It was caught
by the container job before it could.

## A near-miss: the type gate that would have passed vacuously (EX-1)

EX-1's fix rests on a type: `core.models.Unavailable` carries no `verdict`, so a
static checker refuses `x.verdict` on an `Evidence | Unavailable` until the
`Unavailable` branch is narrowed — the guarantee that a HARD verifier which could
not run can never be narrowed into a verdict. To make that guarantee load-bearing,
the sprint adds a mypy gate over the frozen Hearth files (`mypy.ini`, run in
`ci.yml`; the build fails if the core stops type-checking).

**The gate itself nearly shipped false-passing.** Invoked the obvious way —
`mypy --ignore-missing-imports <files>` from outside the package — mypy cannot
resolve `prometheus_protocol.*` and **degrades every prometheus type to `Any`**.
Under `Any`, `x.verdict` on an `Unavailable` is *accepted*: the gate reports
`Success` and verifies **nothing**. Caught by a deliberate teeth-probe (a bad
`x.verdict` that the gate MUST reject):

```
# toothless (types are Any): Success — the mistake is NOT caught
$ mypy --ignore-missing-imports _teeth_probe.py
Success: no issues found in 1 source file

# with types resolved (mypy_path=src, explicit_package_bases): the mistake IS caught
$ MYPYPATH=src mypy --explicit-package-bases --ignore-missing-imports _teeth_probe.py
_teeth_probe.py:3: error: Item "Unavailable" of "Evidence | Unavailable"
    has no attribute "verdict"  [union-attr]
```

`mypy.ini` therefore pins `mypy_path = src` + `explicit_package_bases = True`, and
the teeth-probe is kept as the standing check that the gate is not toothless.

**Why this belongs in the skip sweep: it is the same pattern, a third time.** A
check that reports success while verifying nothing is exactly the failure this
project keeps finding — and EX-1 is a nest of it:

1. a **false-passing verifier** — the sprint's subject: a HARD check that could
   not execute returned `ABSTAIN`, authoritative "no opinion" from a check that
   never ran;
2. a **false-passing sandbox check** — Bug 1: the container start-signal silently
   failed (unreadable bootstrap), so a crash classified ABSTAIN instead of FAIL;
3. a **false-passing type gate** — this: a mypy gate that would have reported
   `Success` while checking `Any`.

All three are "the check ran, a record said pass, nothing was actually verified."
The third was caught *before it shipped*, by treating the gate as a candidate that
must prove it catches the mistake — not by trusting its green.

### EX-1 deferred scope (follow-ups, deliberately out of scope)

EX-1 migrated only category **B** (could-not-execute) to `Unavailable`. Two
adjacent cases were left exactly as they were, on purpose, and are recorded here
so they are not forgotten:

- **Row 10 — a wall-clock timeout WITH a confirmed candidate start** stays
  `Verdict.ABSTAIN`. It is a real semantic question (arguably a `FAIL` — the
  candidate's own hang), but it is not *this* bug, and changing it would move
  PASS/FAIL semantics on already-published results. Follow-up: decide
  timeout-after-confirmed-start = FAIL vs ABSTAIN on its own evidence. (A timeout
  *without* a confirmed start IS category B and did migrate.)
- **Row 13 — `reported_total == 0` (an empty task)** stays `Verdict.ABSTAIN`. The
  check ran and there was nothing to check — a genuine "no opinion", correctly
  excluded from calibration. No change wanted; noted so the distinction between
  "task-unsound abstain" (keep) and "could-not-execute" (now `Unavailable`) stays
  explicit.
- **An authoritative could-not-execute *beside* a successful sibling — fixed, and the
  fifth instance of the pattern.** When one HARD/HUMAN verifier passes and another
  could not run, the verdict is (rightly) the one that executed — but the one that
  could not is an operational fault every time, and EX-1 originally *dropped* it at
  the bank (the exact "a fault that reports nothing looks like no fault" failure this
  sprint exists to kill). Fixed on both sides: the bank now carries it on
  `Judgment.unavailable`, and `_judgment_to_dict` (the approved tenth frozen file)
  persists it into the execution ledger's judgment blob — emitted **only when
  non-empty**, so a clean run's serialized judgment is byte-identical to before (no
  hash/chain over the blob; readers tolerate the extra key; no migration). Remaining
  follow-up (its own PR): promote it to a queryable ledger column.
- **A SOFT-only `Unavailable` with no graded evidence** falls through to
  `Judgment(ABSTAIN)` and is dropped — same shape as the bank case above, lower stakes
  (a SOFT verifier is advisory, so its non-execution is not a gate-relevant fault).
  Follow-up: carry it too, or decide explicitly that an advisory could-not-execute
  warrants no record.
- **The four pre-existing `[arg-type]` mypy findings in `verifier/bank.py` are the
  *fourth* instance of this sprint's recurring shape — a value that is present but
  void.** `Evidence.verdict` is typed `Verdict | None` though `__post_init__` always
  sets it: a **nullable verdict**, a verdict-shaped hole that can hold "nothing" and
  be mistaken for a value, which is exactly why the checker cannot see through the
  fusion calls. It sits with the test that never ran, the type gate that checked
  nothing, and the env var that was silently dropped — the same failure the whole
  sprint keeps finding. Ratcheted in EX-1 with targeted `# type: ignore[arg-type]`,
  not fixed (out of scope; the diff stays minimal). Follow-up: tighten
  `Evidence.verdict` to `Verdict` at construction and delete the four ignores
  (`warn_unused_ignores` will prove they are gone the moment the root is fixed).
- **Surface the reference partition in the *published* report.** `compute_metrics`
  now carries `n_reference_abstained` and asserts the reference denominator is total
  (`n_items == n_reference + n_reference_abstained + n_reference_unavailable`), but
  the published `docs/judge-quality.md` report is left byte-identical (adding the
  partition line changed the committed golden, which the `judge-eval` job correctly
  caught). Follow-up (its own PR, so the §0-certified numbers doc is reviewed as a
  diff): print the reference partition in the report.

## The scar: six present-but-void guards (EX-1)

The thing this sprint kept finding is one bug wearing six costumes: a guard or a
record that is **present, plausible, and void** — it looks like it enforces or
records something and enforces or records nothing. A summary is not a check; a field
is not a record. Named, in the order they surfaced:

1. **A test that never ran.** The four "Hearth is byte-identical to `origin/main`"
   guards `skipif` `origin/main` is unresolvable — TRUE under CI's default shallow
   checkout (`fetch-depth: 1`), so they **silently SKIPPED**. The whole "the frozen
   core did not change" guarantee was unenforced in CI. Cured with `fetch-depth: 0`
   plus a `-v -rs` step that shows them execute *by name* and shows the SKIPPED list
   (they must not be in it).
2. **A type gate that checked nothing.** The mypy Hearth gate would pass *vacuously*
   under `--ignore-missing-imports` alone — the package's own types degrade to `Any`,
   so it approves anything. Cured with `mypy_path=src` + `explicit_package_bases` so
   the real types resolve, and proven with a teeth-probe (a deliberate type error the
   gate must catch).
3. **An env var that was silently dropped.** `PYTHONDONTWRITEBYTECODE=1` was set to
   stop the container leaving a root-owned `__pycache__` the host can't reap — but the
   candidate harness runs under `python -I`, and isolated mode implies `-E`, which
   ignores every `PYTHON*` variable. The env var read like a guard and did nothing;
   only the real-container CI caught that the "fix" hadn't fixed anything. Cured with
   `-B`, a command-line flag `-I` does not suppress.
4. **A nullable verdict.** `Evidence.verdict` is typed `Verdict | None` though it is
   always set — a verdict-shaped hole that can hold "nothing" and be mistaken for a
   value, and the reason the checker cannot see through the fusion calls. Ratcheted
   with targeted ignores; tightening it is a named follow-up above.
5. **A field that records nothing.** `Judgment.unavailable` carried an authoritative
   could-not-execute, but the bank *dropped* it whenever a sibling produced a verdict,
   and nothing persisted it — a record that recorded nothing. Cured by carrying it at
   the bank and persisting it in the judgment blob (the tenth frozen file).
6. **A human gate routed around by momentum.** This one is about the sprint's own
   process, not its code — and it is the only instance in this list no test can
   catch. The review protocol held two items open at merge time (one of them flagged
   as a hard stop pending a ruling), and the PR merged anyway on the strength of a
   green build. Green is not the same as approved: CI asserts "the code passes its
   checks," never "the human said yes" — those are different predicates, and the
   second one was the whole point of the checkpoint ceremony. A human backstop is
   only a backstop if something actually *waits* on it; a gate that can be overtaken
   by momentum is present, plausible, and void — the same shape as the other five,
   wearing a process instead of a test. (Both open items were closed post-merge
   against what actually landed; nothing on main violated a ruling. That is luck,
   not enforcement.)

The common cure is the same every time: **make the check actually execute in the
environment it claims to guard.** Resolve `origin/main` and run the guard; give mypy
the real types; run the container on a real daemon; narrow the nullable and let the
type checker speak; persist the field and read it back. A check that never runs in its
real environment is indistinguishable from a check that passes — which is the entire
reason EX-1 exists: a HARD verifier that *could not execute* must not be allowed to
look exactly like one that ran and had no opinion.
