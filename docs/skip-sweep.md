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
a running daemon. Until that job has a green run on record, the container backend
is documented as **not verified end-to-end** (README "Not done yet";
`docs/sandbox.md` marks the adapter experimental).
