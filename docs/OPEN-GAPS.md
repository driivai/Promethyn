# Open gaps — the tracker

A gap you NAMED is managed; a gap you HID is a vulnerability with better
marketing. This file is where named gaps live once they have a measured number,
so that the number survives the sprint that measured it. The threat model
(`docs/threat-model.md`) carries the *security* residuals per attacker class,
each stated where its defence is; this file carries the *engineering* gaps that
cut across sprints — the ones that were, until now, kept in a chat context and
had a countdown. Nothing here is a to-do list: an entry is closed by a change
that says so, and a number that changes is re-measured, not edited.

Each entry states: **what** the gap is · **measured** — the observed number and
the instrument · **why not closed** · **what closes it** · **test** — where the
limit is a PASSING test (doctrine #5), so it cannot erode quietly.

Read the rules in `docs/threat-model.md`, "Design principles", before adding an
entry. A number here is what was observed, on the date given, with the command
given. A predicted number is not a measurement.

---

## G1 — the type gate resolves first-party siblings only because missing imports are ignored

**What.** `mypy.ini` sets `ignore_missing_imports = True` for genuine
third-party packages. The same flag swallows two other things: a first-party
sibling import that mypy cannot resolve (scripts and tests importing each
other), and a standard-library module that does not exist at the pinned floor
— which is how `import tomllib` passed the gate on all three matrix jobs and
failed at import on 3.10.

**Measured** (2026-09-12, `python -m mypy --config-file <mypy.ini with the flag
off>`): `Found 25 errors in 24 files (checked 290 source files)`, every one
`import-not-found`, none third-party — `fix_b_revert_proofs` (9 sites),
`hearth_ledger` (5), `f11_support` (4), `type_gate` (2),
`test_authorization_record` (2), `_pg_fault_proxy` (2), `test_audit_source` (1).

**Why not closed — and the reason previously recorded was wrong.** The earlier
record said silencing those needs per-module `[mypy-...]` sections, which
`test_type_gate.py::test_mypy_ini_has_no_per_module_sections` forbids. Measured
on the same day: `mypy_path = src:scripts:tests/conformance:tests/chokepoint`
with the flag off reports `Success: no issues found in 290 source files`, with
no per-module section. So the blocker is not the rule; it is that the change
re-shapes the type gate's config — an allowlisted file whose `mypy_path = src`
is pinned by `_ALLOWED_CONFIG` — and makes the gate depend on every third-party
dependency shipping types, a trade to be made on its own evidence in its own
change. The stdlib-floor guard (`tests/conformance/test_stdlib_floor.py`) was
built beside the gate and does not depend on the flag either way.

**What closes it.** Widen `mypy_path` as measured, turn the flag off, update the
allowlist entry with the reason, and keep the floor guard. The withdrawn claim
is corrected in `test_stdlib_floor.py`'s docstring.

**Test.** None pins the 25 (running mypy twice per build is the cost); the
corrected claim lives in the docstring above.

---

## G2 — positional construction of wide dataclasses

**What.** A dataclass with six or more fields built positionally can mis-slot a
field without raising: `Evidence(True, 1, 1, (), "runner", Verdict.PASS, ...)`
put the implementation name into `stdout`, and the mistake was invisible on
every path that refused before the mis-set field was read. `Evidence` and
`Judgment` are now `kw_only` and cannot be built that way.

**Measured** (2026-09-12, `tests/support/positional_sweep.py`, the instrument
now committed): 49 dataclasses of six or more fields in the shipped package;
47 positional constructions across `src`, `tests`, `scripts`:

| class | fields | positional sites |
|---|---|---|
| `DbTarget` | 7 | 11 |
| `Coverage` | 9 | 7 |
| `GateRead` | 7 | 7 |
| `SubstrateReport` | 10 | 6 |
| `SignEvent` | 10 | 4 |
| `MigrationResult`, `ReconciliationResult`, `UnparsedEntry`, `PagedSignAuditSource` | 6–7 | 2 each |
| `MountEntry`, `KeyPin`, `JudgedRow`, `TrustStats` | 6–9 | 1 each |

Blast radius of converting to `kw_only`, measured in #100 before converting
any: `Judgment` 17 failures (converted there, 11 call sites), `DbTarget` 95,
`SignEvent` 104. The #100 record said "39 dataclasses / 59 constructions";
today's instrument reports 49 / 47. The 11 `Judgment` sites went away in #100,
and the earlier instrument was a scratch script whose module-import coverage
differed. The instrument is committed now so the next number is comparable to
this one.

**Why not closed.** A ~200-site mechanical sweep is its own change with its own
verification, not a rider on a load-bearing one.

**What closes it.** `kw_only` on `DbTarget` and `SignEvent` (the two on
security paths with the largest blast radius), call sites converted, then the
rest by field count.

**Test.** `tests/conformance/test_open_gaps.py::test_positional_construction_of_wide_dataclasses_does_not_grow`
ratchets the per-class site count (it may fall, never rise) and
`::test_evidence_and_judgment_cannot_be_built_positionally` keeps the closed
half closed.

---

## G3 — the stdlib-floor guard covers standard-library MODULE availability, and only that

**What.** `test_stdlib_floor.py::test_no_import_needs_a_newer_stdlib_than_the_floor`
reads typeshed's `VERSIONS` table and refuses an import of a stdlib module
newer than the declared floor. Two things it does not see, stated as limits
rather than implied:

- **third-party resolvability** — typeshed's table has no row for `psycopg`,
  `pytest` or `yaml`; whether a dependency exists, or is new enough, at the
  floor is decided by pip's `requires-python` on the dependency and by the
  3.10 matrix job importing it;
- **symbol-level additions** — `datetime.UTC` exists only from 3.11, the table
  says `datetime` is 3.0+, so `from datetime import UTC` passes the guard at a
  3.10 floor and fails at import on the 3.10 job.

**Measured** (2026-09-12): `_stdlib_minimums()` has no entry for any of the
three third-party names the tree imports; `datetime` is `(3, 0)`.

**What widens it.** The 3.10 job importing everything is the check that
actually catches both (it is what caught `tomllib` in the first place); a
symbol-level check would need typeshed's per-symbol `sys.version_info` guards
inside the stubs, which is a different instrument.

**Test.** `test_named_limit_the_guard_does_NOT_cover_third_party_resolvability`
and `test_named_limit_the_guard_does_NOT_see_symbol_level_additions`, both
passing.

---

## G4 — F10: the security-field and frozen-file guards do not prove enforcement (PARKED)

**What** (the independent review at `48190ea`, finding F10, Medium/assurance):
`tests/conformance/test_security_posture.py`'s attribute-read collector
(`_attribute_reads_outside_config`) counts any attribute name regardless of
object identity, Load/Store context or reachability — `if False:
unrelated.require_ledger_anchor = False` counts as a read — so "every security
field is consumed somewhere" is proven by name, not by enforcement. And the
frozen-file guard carried permanent path exemptions (`_EX1_CHANGED`,
`_HARDEN4_CHANGED`) that sanctioned a file forever once sanctioned once.

**Status: parked, pending a scoping pass** against the five guard-hardening
rounds that landed after the finding — TYPE-GATE (#87), TYPE-GATE-HARDEN (#88,
#89, #90) and the Hearth content ledger (#99), which replaced the path-exemption
set with per-file content digests and a recorded reason per sanction. That
likely closes the frozen-file half; the collector half is untouched
(`_attribute_reads_outside_config` is still at `test_security_posture.py:214`).
Nobody should assume the original finding holds in full, or that it is closed,
until the pass has been done and written down here.

**What closes it.** The scoping pass; then either a behavioural proof for the
dead-flag mechanism (drive each declared field and observe the enforcement it
names) or the residual re-stated in `docs/threat-model.md` §5.5, which already
names "the dead-flag mechanism sees attribute reads, not enforcement".

**Test.** None yet; that is what "parked" means.

---

## G5 — F11 detection is INDETERMINATE on AWS

**What.** F11's operational reconciliation needs digest-bound Sign evidence
from the signing service. GCP supplies the digest; native AWS CloudTrail is
metadata-only — no signed digest in the Sign event — so on AWS the reconciler
reports INDETERMINATE, never detection. Primes are AWS/GovCloud-heavy, so this
must not be overstated anywhere: "F11 detects unauthorized signing" is true on
GCP and false on AWS.

**Measured.** By construction, in the tests below; there is no AWS number
because there is nothing to measure — the digest is not in the event.

**What closes it.** An AWS-side digest witness the invoking side records and an
independent party retains — a design outside this repository's control, not
code here.

**Test.** `tests/chokepoint/test_audit_source.py::test_aws_mapping_is_metadata_only_even_for_digest_message_type`,
`::test_aws_shaped_event_cannot_become_digest_bearing`, `::test_aws_outcomes`.
Stated in `docs/threat-model.md` §2.6 and `docs/reconciliation.md`; this entry
is the index.

---

## G6 — banned tokens in commit history, and the control that now refuses them

**What.** The tree hygiene checker (`scripts/check_hygiene.py`) scans tracked
files. It never looked at commit messages, commit identities or pull-request
text, and all three carried banned tooling/vendor tokens onto `main`.

**Measured** (2026-09-12, `python scripts/check_message_hygiene.py --history
origin/main` and `--history=--all`):

| scope | commits reachable | carrying ≥ 1 term | co-authorship trailer | vendor name | vendor domain |
|---|---|---|---|---|---|
| `origin/main` | 85 | 74 | 74 sites | 8 sites (+1 "…code" variant) | 1 |
| all refs | 304 | 110 | 88 | 40 | 12 |

Two mechanisms, independent of each other:

1. The assistant-session trailer in the bodies of #87, #88, #89, #97, #98, #99
   and #100 (and #27 from an earlier session): the branch commits behind them
   carried it — I added it, contrary to the standing no-trailers rule — and the
   squash merge copied the body. The same harness set the vendor's no-reply
   address as the COMMITTER identity on every branch commit; two remote
   branches still carry it (`DriivAIDev/phase-1-2c-checkpoint-b-remediation`,
   2 commits, merged in #99 and never deleted; one older vendor-named branch,
   3 commits).
2. The co-authorship trailer on 74 of 85 `main` commits is written by GitHub's
   squash merge itself, for any commit author who is not the merging account —
   the merging account's commit identity differs from `DriivAIDev
   <will@driivai.com>`, so every squash adds it.

**The control now** (construction, not vigilance): `scripts/check_message_hygiene.py`
refuses a banned token in a commit message, an author or committer identity,
or a PR title/body. It runs as the `commit-msg` and `pre-push` hooks
(`python scripts/install_git_hooks.py`, per clone), in CI on every pull
request (the PR's commits, title and body), and on every push to `main`.

**Named limits.**
- The squash-merge commit is written by GitHub after CI has passed; no
  pre-merge check can refuse it. The push-to-`main` check DETECTS it and fails
  the `main` build. Stopping mechanism 2 at the source is the repository's
  squash-merge message setting and/or the merging account's commit email
  matching the author — repository settings outside this tree.
- Hooks are per clone and opt-in; CI is the check that does not depend on them.
- History is not rewritten by any of this. That is PROM-IP Part B (a
  destructive rewrite, pending the maintainer's go, `docs/IP-READINESS.md`);
  the sweep above is its measured scope.

**Test.** `tests/conformance/test_ci_single_source.py` does not cover this; the
checker's refusal is observed in the hooks and CI (recorded in the PR that
landed it). A test that plants a token in a message and asserts the refusal is
the next hardening of this entry.

---

## G7 — the sanctioned skip set is pinned from a local run; CI decides one entry

**What.** `2372 passed, 23 skipped` on 3.10, 3.11 and 3.12 said nothing about
COMPOSITION. It is now a manifest (`tests/conformance/skip_manifest.txt`),
checked by name on every matrix version (`scripts/check_skip_manifest.py`).

**Measured** (2026-09-12, locally, under the CI-equivalent environment,
`PROM_REQUIRE_SANDBOX=1 PROM_REQUIRE_LINUX=1`, interpreters from `/usr/bin`
in virtualenvs outside `/tmp`): 23 skipped on each of 3.10, 3.11, 3.12, the
SAME 23 by name on all three — 14 live-database proofs (they run in the
dedicated PostgreSQL step), 8 real-container opt-ins, 1 real-container test
skipping for want of a daemon.

**Named limit.** That last entry
(`test_sandbox_privilege.py::test_real_container_workspace_stays_owner_only_and_still_works`)
skips here because no container daemon is reachable; `ubuntu-latest` ships
one. The first CI run of the manifest decides whether it runs there — a
mismatch is the finding the manifest exists to surface, and the manifest is
corrected from the observed report, never predicted.

Also measured on the way: a virtualenv under `/tmp` cannot be used for this
measurement at all — the namespace sandbox hides `/tmp` under an empty tmpfs,
so an interpreter living there is unreachable inside the sandbox and every
`PROM_REQUIRE_SANDBOX=1` test fails for an environment reason (100 failures,
12 errors, on both 3.10 and 3.12, before the venvs were moved to `/opt`).

---

## G8 — the platform gate converts three channels; the returned channel watches two methods

**What.** Off Linux the chokepoint's fail-closed refusal reaches a test three
ways: RAISED (`UnsupportedPlatform` at construction, `_PlatformUnsupported`
wrapped in `_OwnershipUnavailable` from the execution guard), RETURNED as a
`MigrationResult`/`ReconciliationResult` with `reason=approval_store_unavailable`,
or RAISED IN A WORKER THREAD (the test then fails on an event never set, with
no marker in its own traceback). All three are converted to skips keyed on
TYPES — the exception's, or the result's typed `platform_unsupported` field,
which the runner derives from the cause's type — and fail under
`PROM_REQUIRE_LINUX=1`.

**Measured** (2026-09-12, `tests/chokepoint` under a plugin that flips
`sys.platform` to `darwin` after collection): 912 tests → 792 pass, 80
converted on the raised channel, 17 on the returned channel, 1 in a worker
thread, 8 skipped by the explicit `linux_only` gate, 14 skipped for want of a
database, **0 failures**. Before the returned and thread channels existed: 18
failures (17 whose assertion text quoted the result's repr — the population
the first, string-matching gate had been converting as if they were platform
refusals — and 1 thread test).

**Named limits.**
- The returned channel observes exactly `BrokeredMigrationRunner.execute` and
  `reconcile_unfinished`. A refusal returned from any other surface is a
  residual failure the next simulation run will show.
- The typed origin on the returned path is the guard's `_PlatformUnsupported`
  (its own `flock`-semantics check) or the opened-store probe's
  `UnsupportedPlatform` (the carrier of `SubstrateReport.platform_unsupported`);
  the result's field is derived from those types, not read off the report
  directly, because on that path the construction-time report was a stub.
- The simulation itself is a LOCAL instrument (G10).

**Test.** `tests/conformance/test_platform_contract.py`: one pytester
sub-session per channel, skipping without the flag and failing with it, plus
the control that a real misconfiguration is converted on neither.

---

## G9 — the authorization record's tamper evidence is bounded by the chain's anchor residual

**What.** A hold's pinned record is bound into the audit chain and checked at
approval (`docs/execution-authorization-record.md` §4). An adversary with write
access to `pending_actions` who also rewrites the chain entry AND every later
hash produces a self-consistent chain; without an external anchor approval
proceeds on the lying record. With an anchor it is `BROKEN` and refused. This
is `docs/ledger-integrity.md`'s residual, inherited; what the lying record buys
is a misled reviewer, not an execution the seam would not have authorized,
because approval still re-resolves the selected policy.

**Test.** `test_execution_authorization_record.py::test_the_named_limit_a_full_rewrite_is_NOT_detected_without_an_anchor_and_IS_with_one`,
passing, both halves asserted. Position: `docs/threat-model.md` §3.6.

---

## G10 — the non-Linux simulation is a local instrument, not a CI job

**What.** CI is Linux-only by contract. The platform gate's conversions are
proven in CI by pytester sub-sessions (`test_platform_contract.py`), but the
full simulation — 912 chokepoint tests under a flipped platform — runs only by
hand:

```
PYTHONPATH=<dir with darwin_plugin.py> python -m pytest -q tests/chokepoint \
  -p no:cacheprovider -p darwin_plugin --junitxml=darwin.xml
```

where `darwin_plugin.py` imports `ctypes` first (it picks a backend by platform
at import) and sets `sys.platform = "darwin"` in `pytest_collection_finish`.
Numbers in G8 come from it.

**What closes it.** A macOS runner, or a scheduled job running the simulation
on Linux — a cost decision, recorded here rather than assumed.

---

## G11 — remote branches that should not exist (housekeeping)

- `codex/conduct-defensive-code-review-of-latest-sprint` — merged as #98 (its
  four commits squashed into `4d2c065`). Deleting it from here is refused by
  the git proxy (`HTTP 403` on the delete push, observed 2026-09-12); it needs
  the UI.
- `DriivAIDev/phase-1-2c-checkpoint-b-remediation` — merged as #99, never
  deleted, 2 commits carrying the vendor committer identity (G6).
- Two branches prefixed with the vendor's name (`docs/pre-disclosure-audit.md`
  M3), 3 commits with the vendor identity.

The `pre-push` hook now refuses to RESURRECT a merged-and-deleted branch — a
push re-created one twice in one sprint, on a product whose three action
classes include `branch.delete` — keyed on "remote ref absent AND an upstream
configured", which is the one local fact that distinguishes a re-push from a
first push. Observed refusing `DriivAIDev/phase-1-2c-block1-r2-verdict`.
