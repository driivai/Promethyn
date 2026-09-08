# PROM-F11 close-out — proven on Linux CI

Base: merged checkpoint 3, `047cb444e10781ee522ead9bf9f17ecde2165194`
(PR #81, head `ec888dab7635be06243b42a4792ad8aeba8bcc31`, squash-merged
2026-09-08 16:47:35 UTC after its exact-head Linux CI passed). Close-out
branch: `DriivAIDev/prom-f11-close-out`, PR #82. This record is written in the
commit that follows the first close-out commit's green run, and carries that
run's evidence; the commit that contains this file has its own run, recorded
in the PR. No live cloud/HSM adapter is claimed by anything below.

## 1. What the close-out changed

Everything the checkpoint-3 report described was already on `main` and had
run green on Linux at `ec888dab` and again on `047cb444`. Two things were not
true, and one was missing:

- **The mutation runners did not enforce their counts.** Both printed the
  number of reversions they ran and exited 0, so a runner that silently ran
  fewer proofs than it claims would have passed. `scripts/f11_reconcile_revert_proofs.py`
  is now pinned to 43 reversions / 72 call-phase failures and
  `scripts/f11_source_revert_proofs.py` to 15 / 21; the mutation list is
  checked against its pin before anything runs, the observed call-phase
  failures after, and either mismatch exits non-zero. Dropping one entry:
  `42 reversions listed, 43 pinned: ... nothing was run`.
  `tests/chokepoint/test_f11_revert_pins.py` proves the pins, that every
  revert target still exists in the function it rewrites, and that a
  shortfall or an excess on either count is refused.
- **The F11 JUnit gate printed one total.** It now prints the collected count
  per proof file and still requires each file to be non-empty.
- **The no-wall-clock-deadline residual was in the report and the operator
  doc, not the threat model.** `docs/threat-model.md` §2.6 now records it as
  an open residual and a requirement on any adapter, traced to its tests.
- Two traceability gaps: `docs/authorization-record.md` §7 now names the
  implemented test behind each proposed label (including the controls-both
  row) and states the digest-bound assumption of every "detected" row; the
  `unexplained_records` docstring in `chokepoint/kms_model.py` names the
  metadata-only limitation.

## 2. Linux CI at `c56e4911fea1cd06a2abb8f3107fe51ddc91ed23`

CI run 34267712049 (`.github/workflows/ci.yml`), every step of every job
`success`. Counts are copied from the job logs.

| Step | build (3.10) | build (3.11) | build (3.12) |
|---|---|---|---|
| Type gate (mypy) | no issues, 21 source files | same | same |
| Hygiene | 296 files, no banned tokens | same | same |
| F11 proofs, per file | 72 / 99 / 105 (2a persistence / 2b source / 3 reconciler) | same | same |
| F11 proofs, total | 276 executed; zero skips/failures/errors | same | same |
| 2b source guard reverts | 15 reverts caught; 21 call-phase failures; pinned 15 / 21 | same | same |
| 3 reconciliation guard reverts | 43 reverts caught; 72 call-phase failures; pinned 43 / 72 | same | same |
| IP consistency | pass | same | same |
| Live PostgreSQL + isolation (`PROM_REQUIRE_PG=1`) | 13 passed, no skips | same | same |
| Sandbox conformance (`PROM_REQUIRE_SANDBOX=1`) | 80 passed, 9 skipped (2 real-container opt-in, 1 uid drop, 6 verifier-boundary container variants) | same | same |
| Cross-user denial as root (`PROM_REQUIRE_PRIVILEGED=1`) | 1 passed | same | same |
| Hearth guards | 4 passed, none skipped | same | same |
| Full suite (`PROM_REQUIRE_SANDBOX=1`) | 1522 passed, 21 skipped | 1522 passed, 21 skipped | 1522 passed, 21 skipped, 2 warnings |
| Package build | ok | same | same |

The 21 full-suite skips are the same set on every job: 1 isolation and 11
migration-live (the `Test` step sets no PostgreSQL coordinates; those tests
run in the dedicated live step above), 2 real-container opt-in, 1 uid drop
(run under sudo in its own step), 6 verifier-boundary container variants
(nightly job). The 2 warnings on 3.12 are the existing multithreaded-`fork()`
deprecations, not suppressed.

Other checks on the same head: voidguard run 34267711963 — **0 VOID, 3 WARN,
2 UNKNOWN**, findings unchanged (VG-1-001 five runtime `skipif` probes,
VG-3-001..003 the PostgreSQL service-container env, VG-4-001 the
container-sandbox schedule); no suppression or baseline added. judge-eval run
34267711955 succeeded. `container-sandbox.yml` did not run: neither #81 nor
this PR touches a sandbox or verifier path, so for this code it is nightly-only;
its last scheduled run was on checkpoint 2a (`2ba1d468`).

## 3. Linux, locally (ext4, this checkout)

Full suite on the close-out branch: 1522 passed, 21 skipped, 0 failed; the
skip set matches CI except that the uid-drop test skips here for "no container
runtime available" instead of privilege. The 64 Darwin failures reported by
the checkpoint-3 report (substrate/ownership refusals on macOS, where the
mount table is unavailable) do not occur on Linux: that absence is the
evidence the substrate probe classifies the supported platform correctly.

## 4. Documentation checklist, verified against the tree

- Per-provider capability is explicit in `docs/key-custody.md` and
  `docs/threat-model.md`: GCP digest-bound evidence can support detection with
  an independently validated adapter; native AWS CloudTrail is metadata-only,
  INDETERMINATE, not detection; PKCS#11 is vendor-dependent; local HMAC has no
  independent witness.
- No sentence calls a result the forgery signal without the digest-bound
  qualification or the metadata-only limitation; the one that did was the
  in-memory model's docstring, corrected in this PR.
- The controls-both residual is stated in `key-custody.md`, `threat-model.md`
  and `audit-source-acceptance.md`, and traced to the passing
  `test_controls_both_residual_honestly_not_detected` (checkpoint 3) and
  `test_administrator_controls_both_residual_is_clean_looking` (2b), both
  executed under the no-skip gate above.
- The no-wall-clock-deadline residual is recorded in `docs/threat-model.md`
  §2.6 as open and as a requirement on any adapter.
- F11 is removed from the open findings in this commit, which follows the green
  run above and is itself run on CI before the maintainer's read.

## 5. Status

F11's missing control — a durable authorization record, an independent
read-only Sign source, and an operational reconciler that compares them — is
implemented, published, and proven on the required substrate. It is closed as
an open finding by this commit, subject to the maintainer's read of PR #82.
What remains is deployment work, not repository work: real-adapter acceptance
per `docs/audit-source-acceptance.md`, which no offline run can stand in for,
and the residuals named above, which stay named.
