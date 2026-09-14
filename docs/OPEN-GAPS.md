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

## G1 — the type gate resolved first-party siblings only because missing imports were ignored (CLOSED 2026-09-14)

**What.** `mypy.ini` sets `ignore_missing_imports = True` for genuine
third-party packages. The same flag swallows two other things: a first-party
sibling import that mypy cannot resolve (scripts and tests importing each
other), and a standard-library module that does not exist at the pinned floor
— which is how `import tomllib` passed the gate on all three matrix jobs and
failed at import on 3.10.

**Measured** (re-measured 2026-09-14 at the current file set, `python -m mypy
--config-file <mypy.ini with the flag off>`): `Found 28 errors in 27 files
(checked 304 source files)`, every one `import-not-found`, none third-party.
Counted by the module that could not be resolved, which is the axis that says
how much work closing it is:

| unresolved module | sites |
|---|---|
| `fix_b_revert_proofs` | 10 |
| `hearth_ledger` | 5 |
| `f11_support` | 4 |
| `type_gate`, `test_authorization_record`, `_pg_fault_proxy` | 2 each |
| `test_audit_source`, `mutation_worktree`, `check_hygiene` | 1 each |

The previous record here said 25 errors in 24 files at 290 checked, and was
measured before this sprint's 14 new files existed. It was a stale total inside
the tracker — doctrine #9 applied to our own record of doctrine #9 — and it is
corrected rather than re-dated. `mutation_worktree` and `check_hygiene` are new
rows; `fix_b_revert_proofs` gained one.

A note on reproducibility, because the first re-measurement disagreed with the
second. One run reported `30 errors in 28 files (checked 305 source files)`
while the full pytest suite was running concurrently in the same checkout;
two consecutive runs afterwards both reported 28/27/304. The 305 reading is
discarded as contaminated rather than averaged in, and the number above is the
one that reproduced.

**Why not closed — and the reason previously recorded was wrong.** The earlier
record said silencing those needs per-module `[mypy-...]` sections, which
`test_type_gate.py::test_mypy_ini_has_no_per_module_sections` forbids. Measured
again on 2026-09-14: `mypy_path = src:scripts:tests/conformance:tests/chokepoint`
with the flag off reports `Success: no issues found in 304 source files`, with
no per-module section. So the blocker is not the rule; it is that the change
re-shapes the type gate's config — an allowlisted file whose `mypy_path = src`
is pinned by `_ALLOWED_CONFIG` — and makes the gate depend on every third-party
dependency shipping types, a trade to be made on its own evidence in its own
change. The stdlib-floor guard (`tests/conformance/test_stdlib_floor.py`) was
built beside the gate and does not depend on the flag either way.

**What closed it, done.** `mypy_path` is now
`src:scripts:tests/conformance:tests/chokepoint`, `ignore_missing_imports` is
`False`, and `_ALLOWED_CONFIG` in `test_type_gate.py` carries both values with
the reason. No per-module `[mypy-...]` section was added — the rule that was
once thought to be the blocker never was.

**Observed after** (2026-09-14): `Success: no issues found in 308 source
files`. The 28 `import-not-found` errors are gone because the roots those
siblings live under are now on the path, not because anything was silenced.

**The gate caught a defect on the way through, in code written in the same
change.** With the flag off, `tests/support/platform_gate.py:194` reported
`"object" has no attribute "platform_unsupported"` — an `isinstance` narrowing
to a heterogeneous tuple of enumerated types. Resolved with `getattr`, not with
a `cast()` or an ignore directive, both of which this gate's own config
(`warn_unused_ignores`, `warn_redundant_casts`) exists to refuse. One finding
on the first run is a small sample, but it is the kind of finding the flag was
hiding.

**THE TRADE, stated here and not left to be discovered.** With the flag off the
gate depends on every third-party dependency shipping types or having stubs. A
new dependency without them now FAILS this gate rather than degrading silently
to `Any`. That is the intended direction, and it is a real cost at the next
dependency bump.

**Test.** `test_type_gate.py::test_the_config_carries_exactly_the_allowed_keys_and_values`
pins both values; the type gate itself is the standing check. The floor guard
(`test_stdlib_floor.py`) was re-probed under the new config rather than assumed:
`import tomllib` under the 3.10 floor still reddens
`test_no_import_needs_a_newer_stdlib_than_the_floor`. A config change is exactly
what could have disabled it silently.

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

## G4 — F10, scoped 2026-09-14: CLOSED as a finding, with its live remainder moved to G17

### The original text could not be recovered, and the citation here was wrong

**This entry's own source citation was false, and I wrote it.** It said "the
independent review at `48190ea`, finding F10". `48190ea` is
*"Relicense to proprietary and record the IP position for diligence (PROM-IP,
part A) (#73)"* and contains no finding of any kind. Withdrawn.

Searched, before working from memory:

| where | result |
|---|---|
| `grep -rn "F10"` over the tree | **only this entry** |
| `git log --all -S"F10"` | first appearance `30c22bf`/`c846272` — **my own #101, writing this entry** |
| every blob across all refs | F10 only in this file and in a fixture quoting my commit text |
| `docs/shakeout-report.md` | F1–F9, and about CLI tracebacks and corrupt state files — a different series |
| `docs/reviews/*.md` | F11 only |
| `docs/pre-disclosure-audit.md` | L1–L5, not F-numbered |
| GitHub PR search, `#60`–`#90` | one hit |

The one hit is **PR #78** (2026-09-07), in its "Not in scope" section:
*"F11's authorization record (only the false claim is removed). F7, F8, F9,
F10, F12 untouched."* That proves an F-series containing F10 and F12 existed
and that F10 was live on 2026-09-07. **It does not preserve a word of what F10
said.**

So the claims below are enumerated from THIS ENTRY'S PARAPHRASE, written by me
in #101, not from F10. Where the paraphrase is wrong, the dispositions below
are wrong with it, and nothing in this repository can currently tell us. The
review document should be attached to the repository if it still exists
anywhere; a finding that only survives as somebody's summary of it is a finding
that cannot be audited.

### The six claims, and what each one measures today

C1 identity · C2 Load/Store context · C3 reachability · C4 "proven by name, not
enforcement" · C5 the frozen-file guard's permanent path exemptions · C6 those
exemptions sanctioning a file forever.

**C1, C2, C3 — STILL OPEN.** `tests/conformance/test_security_posture.py:214-223`,
`_attribute_reads_outside_config`, unchanged since the finding. Probed by
driving the collector's exact body over planted source:

| probe | counted as a "read"? |
|---|---|
| `unrelated_thing.require_ledger_anchor` (C1, another object) | **yes** |
| `(1).require_ledger_anchor` (C1, a literal) | **yes** |
| `something.require_ledger_anchor = False` (C2, a WRITE) | **yes** |
| `if False:\n    unrelated.require_ledger_anchor = False` (C3) | **yes** |
| inside a function nobody calls (C3) | **yes** |
| `s = 'require_ledger_anchor'` (control — must NOT count) | no |

The control matters: the collector is not universally true, so these are real
blind spots rather than an instrument that says yes to everything.

**C4 — STILL OPEN, and it is the one that bites.** Probed end to end in a
mutation worktree: every genuine consumption of `require_ledger_anchor` removed
from `src/` (four sites in `runtime/factory.py`, `attestation/runtime.py`,
`chokepoint/runner.py`), with a single dead store left behind —

```python
if False:  # F10 probe
    _unrelated.require_ledger_anchor = False
```

**Observed: `26 passed`. `test_every_declared_security_field_is_consumed_somewhere`
stayed GREEN with the control wired to nothing.** That is F10's shape, alive:
the guard proves the NAME appears in an AST, and calls it consumption.

**C5 and C6 — CLOSED BY OTHER MEANS.** The exemption mechanism is gone, not
fixed: `_EX1_CHANGED` and `_HARDEN4_CHANGED` survive in the tree only as PROSE
describing their own removal (`hearth_ledger.py`'s docstring, this file, and
`threat-model.md`). What replaced them is a SHA-256 per protected file, which
is a different mechanism rather than a repair of the old one — so the original
remedy ("remove the permanent exemptions") is unnecessary rather than
unimplemented.

Probed rather than assumed, because "round N hardened this area" is not
evidence. Editing `gate/authorization.py` — **the exact file that `_EX1_CHANGED`
sanctioned forever** — reddens three tests:
`test_every_protected_file_exists_and_matches_its_digest`,
`test_the_ledger_actually_detects_a_changed_file`,
`test_the_guards_do_not_depend_on_a_branch_being_resolvable`. Same result for
`execution/pending.py`.

### Can each guard FAIL? (§3)

| guard | probe | reddened |
|---|---|---|
| `test_every_declared_security_field_is_consumed_somewhere` | strip all real reads, leave a dead store | **NO** |
| `test_the_mechanism_has_teeth` | drive it with `reads = ∅` | yes (fails closed) |
| `test_every_security_shaped_field_is_declared` | `SECURITY_FIELDS = ()` | yes |
| Hearth `..._matches_its_digest` | edit a protected file | yes |
| Hearth `..._actually_detects_a_changed_file` | edit a protected file | yes |
| Hearth `..._covers_exactly_the_protected_files` | empty the protected set AND lower its count pin | yes |

One guard cannot be made to fail by the defect it names. That is the finding,
and it is not fixed here.

### F10's disposition

**CLOSED as a finding.** Four of its six claims are resolved — two by removal
of the mechanism (C5, C6), and the remaining four are not "partly true": they
are true, reproduced, and moved to **G17** so they can be worked on their own
terms rather than keeping a 2026-09-07 finding open forever.

**Test.** The probes above are recorded, not committed as tests — this was a
scoping pass, and a test asserting that a guard is weak would have to be
rewritten by whoever strengthens it. G17 carries what to build.

---

## G5 — F11 detection has THREE substrate states, not two

**What.** F11's operational reconciliation needs digest-bound Sign evidence
from the signing service. What the substrate can supply decides what the
reconciler can ever say, and there are three answers, not the two this entry
used to name:

| substrate | Sign evidence | reconciler can report |
|---|---|---|
| GCP Cloud Audit | digest-bound | detection — MATCHED / UNWITNESSED / UNEXPLAINED |
| native AWS CloudTrail | metadata only | INDETERMINATE, never detection |
| air-gapped PKCS#11 | **none at all** | refuses; no reconciliation is possible |

Primes are AWS/GovCloud-heavy, so the middle row must not be overstated
anywhere: "F11 detects unauthorized signing" is true on GCP and false on AWS.
The bottom row must not be overstated either, in the opposite direction — it is
not a weaker detection, it is the absence of a substrate, and the code says so.

**Measured** (2026-09-14, driving the real `unavailable_pkcs11_read` through
the real `reconcile()`, both cases refusing):

```
AIR-GAPPED pkcs11, one authorization : clean=False exit=1
  problems  metadata_only, source_coverage_incomplete, source_incomplete
  records   [(INDETERMINATE, insufficient_evidence)]
AIR-GAPPED pkcs11, EMPTY ledger      : clean=False exit=1
  problems  metadata_only, source_coverage_incomplete, source_incomplete
```

The empty-ledger case is the one worth having: an instrument that cannot
represent what it is measuring must report UNAVAILABLE, not CLEAN, and a
reconciliation over a substrate that does not exist must not look like a
reconciliation that found nothing wrong. It does not. `normalize_pkcs11_event`
raises rather than returning a shape, and `unavailable_pkcs11_read` returns a
read carrying `no_portable_audit_source`, `capability="metadata_only"` and no
covered interval — three independent grounds for refusal.

**What was actually missing**, and it was the test rather than the code:
`test_audit_source.py::test_pkcs11_cannot_fabricate_an_audit_capability`
asserted the SHAPE of that read in isolation and never handed it to a
reconciler. Whether the reconciler refused it was unmeasured — a check that
stops before the thing it is about, which is the same pattern that let the
positional-`Evidence` defect survive (G2).

**Residual, named.** `native_locations` in `reconciliation.py` has rows for
`gcp-audit` and `model-gcp` only, so the `unsupported_digest_provenance` check
is inert for `pkcs11`. It does not matter today, because the three refusals
above fire first and a pkcs11 source cannot attest coverage at all — but it is
one allowlist that does not enumerate the provider it is asked about, and if a
vendor PKCS#11 audit read ever lands it will matter on that day.

**What closes it.** Row 2: an AWS-side digest witness the invoking side records
and an independent party retains — a design outside this repository's control.
Row 3: vendor evidence for a specific HSM, which is a per-deployment artifact,
not code here.

**Test.** Row 2:
`tests/chokepoint/test_audit_source.py::test_aws_mapping_is_metadata_only_even_for_digest_message_type`,
`::test_aws_shaped_event_cannot_become_digest_bearing`, `::test_aws_outcomes`.
Row 3, end to end:
`tests/chokepoint/test_reconciliation.py::test_air_gapped_pkcs11_never_reports_clean_with_an_authorization_to_explain`
and `::test_air_gapped_pkcs11_refuses_even_with_NOTHING_to_reconcile`, with
`::test_the_positive_control_the_same_empty_range_IS_clean_on_a_real_substrate`
as the doctrine #4 control — without it, both refusals would be consistent with
a reconciler that refuses every empty range and would prove nothing about
pkcs11. Stated in `docs/threat-model.md` §2.6 and `docs/reconciliation.md`;
this entry is the index.

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

**Re-measured after #101 merged** (2026-09-12, same commands, `main` at
`c846272`). This is the sizing PROM-IP Part B asked for, and it grew by exactly
the amount the mechanism below predicts — one commit, one trailer:

| scope | commits reachable | carrying ≥ 1 term | co-authorship trailer | vendor name | vendor domain |
|---|---|---|---|---|---|
| `origin/main` | 86 | 75 | 75 sites | 8 sites (+1 variant) | 1 |
| all refs | 310 | 111 | 89 | 40 | 12 |

The five branch commits of #101 are clean — `check_message_hygiene.py` over
`af93238..fbae17b` reports `5 commit(s) … no banned tokens in any message or
identity`. The squash commit is not: it carries one
one co-authorship trailer crediting `DriivAIDev <will@driivai.com>`, written
by GitHub. Compared
with #100's squash, which carried five sites (the vendor name four times plus a
co-authorship line), the branch-side control removed everything it can reach.
**No history rewrite has been executed**; Part B still waits on the final
entity name.

**Re-measured after #102 merged** (2026-09-14, same commands, `main` at
`4451aa1`). It grew by one commit and one trailer again, which is the mechanism
in G13 behaving exactly as recorded:

| scope | commits reachable | carrying ≥ 1 term | co-authorship trailer | vendor name | vendor domain |
|---|---|---|---|---|---|
| `origin/main` | 87 | 76 | 76 sites | 8 sites (+1 variant) | 1 |
| all refs | 312 | 112 | 90 | 40 | 12 |

**PART B IS SMALLER THAN 76, AND THIS IS THE NUMBER TO PLAN AGAINST.** The
"carrying ≥ 1 term" column counts the GitHub-written co-authorship trailer,
which names this repository's own author. Decomposed on 2026-09-14:

| scope | no term | ONLY the co-authorship trailer | carrying a VENDOR term |
|---|---|---|---|
| `origin/main` | 11 | 68 | **8** |
| all refs | 200 | 82 | **30** |

A provenance rewrite has to reach the last column. On `main` that is eight
commits — `af932383f8`, `475fd3cc75`, `4d2c065761`, `7bb471ea8b`, `d0819bbf8f`,
`edd14e45d1`, `98a0e7f66e`, `267a586104` — and across all refs thirty. The
other 68 carry a line crediting `DriivAIDev <will@driivai.com>`, which is not
what Part B is for.

Of the 90 co-authorship trailers across all refs, **89 name
`DriivAIDev <will@driivai.com>` and exactly one names a vendor** (`267a586104`,
which three other terms catch anyway). That ratio is why the refusing modes now
key on the identity rather than the string — see G13, closed.

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

**Observed firing in CI, on the PR that landed it** (#101, run 34701678262,
every matrix job, step "Message hygiene"): the harness that opens pull requests
appended a footer carrying the vendor's name to the PR body at creation — the
body I posted did not contain it — and the step refused it:

```
message hygiene passed: 2 commit(s) in af93238..2991f63, 17 terms, no banned tokens in any message or identity
message hygiene passed: pr-title.txt (130 chars), no banned tokens
message hygiene FAILED: pr-body.txt contains banned token(s) [...]
##[error]Process completed with exit code 1.
```

That is the control catching the exact thing that reached `main` through
#100. The body was stripped by editing the PR, and re-read to confirm.

**The `edited` window, now closed.** The limit recorded here was that ci.yml's
bare `pull_request:` trigger fires on `opened`, `synchronize` and `reopened`,
not on `edited`, so a body rewritten after the last check is unguarded. That is
real and was exercised: #101's body was edited twice after its last passing
check (both edits clean, so nothing was smuggled — the window was open, not
used). It could not be closed by adding `types` to ci.yml, because event types
are per-workflow and the trigger allowlist in `test_type_gate.py` requires that
trigger to stay bare, deliberately. So the check now also lives in
`.github/workflows/pr-text-hygiene.yml`, which fires on `opened`, `edited`,
`reopened` and `synchronize` and runs the checker alone in seconds rather than
re-running a three-interpreter matrix for a description edit. Its trigger list
is itself allowlisted
(`test_type_gate.py::test_the_pr_text_workflow_answers_to_exactly_the_permitted_events`),
because a filter that quietly loses `edited` would put the window straight back.

**What the `edited` window was NOT.** It is not how a banned token reached
`main`. Measured on `c846272`: the squash message is composed from the five
branch COMMIT messages (five `* ` entries, and the PR body's own opening
sentence appears nowhere in it), with a co-authorship trailer appended by
GitHub after
a `---------` separator. So the route is the squash composition, not the PR
text, and no pull-request-event check can refuse a commit that does not exist
until the merge button is pressed. That is G13.

**Test.** The refusal above is the observation; `tests/conformance/test_ci_single_source.py`
does not cover this. A test that plants a token in a message and asserts the
refusal is the next hardening of this entry.

---

## G7 — the skip set is a property of the tree ON A HOST (CLOSED by measurement, with a named limit)

**What.** `2372 passed, 23 skipped` on 3.10, 3.11 and 3.12 said nothing about
COMPOSITION. It is now a manifest (`tests/conformance/skip_manifest.txt`),
checked by name on every matrix version (`scripts/check_skip_manifest.py`).

**Measured** (2026-09-12, locally, under the CI-equivalent environment,
`PROM_REQUIRE_SANDBOX=1 PROM_REQUIRE_LINUX=1`, interpreters from `/usr/bin`
in virtualenvs outside `/tmp`): 23 skipped on each of 3.10, 3.11, 3.12, the
SAME 23 by name on all three — 14 live-database proofs (they run in the
dedicated PostgreSQL step), 8 real-container opt-ins, 1 real-container test
skipping for want of a daemon.

**What the first CI run decided** (run `34707644343`, `build (3.11)`, the step
that exists to surface exactly this). It refused, with **two** findings, and the
manifest was wrong in a more interesting way than predicted:

```
2424 passed, 23 skipped in 191.19s
skip manifest FAILED: 1 skip(s) not sanctioned:
  ...::test_another_local_user_cannot_read_or_write_the_workspace  (dropping to another uid requires privilege)
skip manifest FAILED: 1 sanctioned entry did not skip (ran, or no longer exists):
  ...::test_real_container_workspace_stays_owner_only_and_still_works
```

The predicted half happened: `ubuntu-latest` ships a container daemon, so the
container test RAN there. The unpredicted half is the finding: that runner is
also **unprivileged**, so the cross-user denial test skipped there — and this
host runs as root, so it runs here. Both hosts report 23 skips. A count could
never have separated them; the manifest by name did, on its first run.

**The correction.** The manifest has two sections. `[required]` keeps the
original rule (must skip everywhere; an entry that ran is stale and fails).
`[conditional]` is for a skip that depends on a named HOST fact, and each such
entry must carry `proof: <workflow> :: <step>` naming a step that runs the test
under a `PROM_REQUIRE_*` flag — the flag that turns a skip into a FAILURE there.
The checker resolves the workflow, the step, and the flag; a conditional entry
whose proof does not resolve fails the build, because a sanction with nothing
behind it is a hole. Exactly two entries are conditional: the two that swap.

**Named limit** (a passing test,
`test_skip_manifest_guard.py::test_the_named_limit_a_conditional_skip_is_excused_on_EVERY_host`).
A conditional entry is excused wherever it skips, including for a reason nobody
intended. What bounds that is the proof step — and for the container test that
step lives in `container-sandbox.yml`, which runs nightly and on sandbox-path
pull requests, not on every build. So a container runtime vanishing from
`ubuntu-latest` would be caught within a day, not within a build. The privilege
proof has no such gap: its step is in `ci.yml` and runs every time.

**Test.** `tests/conformance/test_skip_manifest_guard.py` drives the checker
over both recorded host compositions (both must pass), over an unsanctioned
skip and a stale required entry (both must fail), and over four broken proofs
with a fifth that resolves as the positive control.

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

### Re-measured 2026-09-14, per test, with the instrument committed

`scripts/darwin_plugin.py` is now in the tree, so this is re-derivable rather
than reconstructed from prose:

```
PYTHONPATH=scripts python -m pytest -q tests/chokepoint \
  -p no:cacheprovider -p darwin_plugin -p no:randomly --junitxml=darwin.xml
```

**915 tests → 795 pass, 120 skip, 0 fail.** Every skip, by disposition and
module — this is the per-test ledger, not a total:

| disposition | count | modules |
|---|---|---|
| converted: raised | 80 | `test_approval` 16, `test_approval_expiry_across_preparation` 13, `test_approval_durability` 12, `test_execution_recovery` 10, `test_lock_identity` 9, `test_owner_identity` 7, `test_ledger_chain` 6, `test_external_anchor` 5, `test_artifact_integrity` 1, `test_mount_relevance` 1 |
| converted: returned `MigrationResult` | 17 | `test_authorization_record` 10, `test_key_custody` 5, `test_approval_durability` 1, `test_reconciliation` 1 |
| converted: returned `ReconciliationResult` | 0 | — |
| converted: returned `SubstrateReport` | 0 | — |
| converted: worker thread | 1 | `test_execution_recovery` 1 |
| explicit `linux_only` gate | 8 | `test_substrate_linux` 7, `test_lock_identity` 1 |
| no database configured | 14 | `test_migration_live` 13, `test_isolation` 1 |

80 + 17 + 0 + 0 + 1 + 8 + 14 = 120, and 795 + 120 = 915. It reconciles because
every row was counted from the same JUnit file in one pass.

**THE THIRD RETURNED TYPE.** `SubstrateReport` carries `platform_unsupported`
exactly as the two runner results do and was NOT in the gate's enumerated list
— so a refusal returned as a report was invisible to both channels. Added.
Honestly: it converted **nothing** in the run above, because no test on this
tree currently refuses that way. This closed a latent enumeration gap, not an
observed failure, and the proof is a synthetic pytester sub-session rather than
a real conversion. `test_every_type_carrying_the_typed_field_is_in_the_gates_enumerated_list`
walks the shipped package for dataclasses declaring the field and fails if a
fourth appears without being enumerated, so the list cannot fall behind again.

**The older ledger does not reconcile, and the difference is not recoverable.**
An earlier sprint recorded "107 / 97 / 9 / 18" for this simulation. Those
totals were taken on a different tree with a different test population, and the
nine could not be recovered BY NAME from the record that survives — so the
accounting above is a fresh per-test ledger on today's tree rather than an
arithmetic reconciliation of the old one. Recorded here because it was
previously stated only in a pull-request body, which is not the tracker: a
number nobody can re-derive is a number that should stop being cited.

**STATUS OF THE NINE: UNRECOVERABLE. Not pending, not outstanding, not
awaiting a better search — unrecoverable, and it should stop appearing on owed
lists.** Asked again 2026-09-14 and the answer is the same, for a reason worth
stating plainly rather than softening. The nine
were never written down individually. What survives is the arithmetic
(`107 / 97 / 9 / 18`), and arithmetic does not name tests. Their tree is gone:
the population has moved from 912 to 915 through several sprints of additions
and renames, so even a name would not reliably resolve. Disposition per test is
available going forward — the table above is exactly that, and the instrument
that produced it is committed — but **retroactively it is unavailable, and a
plausible-looking mapping of the nine onto today's modules would be
manufactured, not measured.** The honest statement is that 9 tests were once
observed failing for genuine assertion reasons, nobody recorded which, and
today's tree has 0 failures in this simulation. Both facts are true; they do
not connect.

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

### The `pre-push` hook

The `pre-push` hook now refuses to RESURRECT a merged-and-deleted branch — a
push re-created one twice in one sprint, on a product whose three action
classes include `branch.delete` — keyed on "remote ref absent AND
`branch.<name>.remote` is this remote AND `branch.<name>.merge` is
`refs/heads/<name>`": an upstream that names the branch itself is the one
local fact that distinguishes a re-push from a first push. The first version
keyed on "any upstream configured" and refused this repository's own sprint
branch's first push (a branch created from `origin/main` tracks main); it was
narrowed in the same pull request. Observed refusing
`DriivAIDev/phase-1-2c-block1-r2-verdict` under both versions; observed
allowing `DriivAIDev/phase-1-2c-record-and-rotation` under the second.

---

## G12 — the workflow's collection pins were checkable only by pushing

**What.** Ten CI steps pin how many tests each module must contribute
(`expected = {"test_coverage_enforcement": 33, ...}`), so a proof that stops
being collected fails the build instead of passing quietly. The number lives in
`.github/workflows/ci.yml` and nowhere else, which made it a second copy of a
fact with nothing local comparing the two: the suite an author runs before
pushing cannot see a stale pin, because the pin is not part of the suite.

**Measured** (2026-09-12). A full local run reported `2419 passed, 23 skipped`
on 3.10, 3.11 and 3.12 from a detached worktree, and the next CI run
(`34701799636`, head `77669ad`) refused **all three** matrix jobs at the
PHASE-1.2a step:

```
AssertionError: ('test_policy_enforcement_regression', 20, 19)
```

Two tests had been added to pinned modules in the same change
(`test_every_matrix_row_is_mapped_and_the_mapping_is_nine_refusals_to_one_execution`
and `test_the_mint_sweep_sees_an_alias_assignment`) and the pins had not moved.
The step's loop stops at the first mismatch, so CI reported one of the two; the
second (`test_no_second_aggregator`, 12 against a pinned 11) was found in the
JUnit file behind it. Everything after that step — twenty-three steps, the full
suite, the skip manifest, the build — never ran on that commit: cost, one
complete CI cycle across three interpreters, for a defect with no runtime
consequence.

**What closes it — done here.** `tests/conformance/test_ci_collection_pins.py`
parses the pins out of the workflow (both shapes it uses: the per-module mapping
and a bare `assert len(cases) == N`), collects the files each step runs in one
`--collect-only` pass, and compares. It runs in the ordinary suite, so a stale
pin now fails where the author can see it, with the message CI would print.
Probed directly rather than assumed: against the tree at `77669ad` the guard
reports both mismatches; against the corrected pins it is silent.

**Named limits** (each a passing test in that module):

- It reads **collection**, not outcomes. Every pinned step also demands zero
  skips, failures and errors; that needs the run, and the run is CI's.
- It reads the two pin **shapes** the workflow uses today. The set of steps it
  can read is itself pinned in both directions, so a step whose pin the parser
  stops seeing fails here rather than becoming a number nothing checks.

**Also recorded.** The same class of number lives in
`scripts/type_gate.py` (`EXPECTED_CHECKED_FILES`) and in
`tests/conformance/hearth_ledger.py` (content digests). Those two are already
read by tests that run locally; this entry is closed for the workflow pins only.

That first parenthesis said "raised 302 → 303 here" and was **stale within the
same pull request** — two further commits took the gate to 304 and the sentence
was not re-read. Corrected, and the lesson kept rather than the number: a
tracker entry that states a moving figure in prose has no test behind it (nothing
parses these headings for numbers), so it drifts exactly like the workflow pin
this entry was written about. The figure now lives only in `type_gate.py`, which
the gate itself checks; over this sprint it went 290 → 304, and the 14 is the
count of Python files the sprint added under the three checked roots.

---

## G13 — every squash merge writes a banned token into `main`, and `main`'s CI goes red for it

**What.** GitHub composes a squash-merge commit at merge time, after every
pre-merge check has passed, and appends a co-authorship trailer for each
commit author who is not the merging account. That trailer's key is a banned
term
(`scripts/check_hygiene.py`'s term list), and `ci.yml`'s message-hygiene step
re-checks what landed on every push to `main`. So the push check refuses the
merge commit — correctly, by its own rule — and `main` goes red.

**Measured** (2026-09-12, `main` at `c846272`, the squash of #101):

```
message hygiene FAILED over af93238..c846272 (1 commit(s)):
  c846272a93 message: contains a banned token ('co-author…')
```

(The term is truncated in that quote, and only there: writing it in full would
make this file fail `scripts/check_hygiene.py`, which is the tree-side half of
the same control. A document describing a banned token cannot quote it — worth
knowing before the next entry tries.)

CI run `34720178244`, all three matrix jobs, failed at step 10 of 47; every
later step was skipped. The trailer is at line 274 of the message, after a
`---------` separator; the commit's author and committer identities are clean.
The five branch commits behind it pass the same checker.

**This is new behaviour, introduced by the control itself.** The main-push
check landed in #101, so #100's squash carried five banned-token sites and
nothing went red. It will now recur on **every** squash merge of a pull request
whose author is not the merging account, because the push check reads the range
from the previous head to the new one.

**Why it is not fixed here.** Each available option is either a repository
setting or a deliberate narrowing of a control, and both are the owner's call:

1. change the squash-message setting so GitHub does not copy commit bodies —
   unverified, and it may append co-author trailers regardless, so it needs
   testing on one merge before being relied on;
2. stop squashing pull requests authored by another account;
3. narrow the **push** path to tolerate the trailer GitHub generates while
   still refusing vendor tokens and identities — a weakening, to be sanctioned
   explicitly and recorded with its reason;
4. accept a red `main` after each merge and read it as a notice.

**Recommendation, recorded rather than taken:** (3), written as an allowlist of
GitHub-generated trailers on the push path only, with the pull-request path
unchanged — the refusal stays everywhere a human or an agent can still act on
it, and the one commit nobody can act on before it exists stops failing the
branch for a line the repository did not write.

---

### CLOSED, 2026-09-14 — by (3), and by refusing the composed message instead

Recurred exactly as predicted: `main` at `4451aa1`, the squash of #102, carries
the same trailer and the same red push check. Two things landed.

**First, the route is named rather than suspected.** `edited` was already
covered by `pr-text-hygiene.yml`, so the window it closes was not the route.
Measured by diffing the squash against the commit it squashed: `4451aa1`'s body
is `8f29b1d`'s body plus ONE appended line, the trailer, and nothing else —
64 lines to 65. The subject is the title with ` (#102)`. So the route is the
composition itself, at merge time, after every check.

**Second, the composed message turns out to be derivable, so the check moved
onto it.** `scripts/check_message_hygiene.py --composed` reconstructs what
GitHub will write from the branch's commits, the title and the number, and
refuses THAT. It reproduces both real squash commits in this repository byte
for byte — `4451aa1` (one commit) and `c846272` (five) — so it is a model of
the artifact rather than a guess about it. Wired into `pr-text-hygiene.yml`,
which needed `fetch-depth: 0` to see the commits at all.

**It shipped broken, and the way it broke is the point.** Run `34860607395`
refused all three jobs at step 34, identically:

```
SystemExit: git log --reverse c846272..8f29b1d --format=... failed:
  fatal: ambiguous argument 'c846272..8f29b1d': unknown revision or path
  not in the working tree
```

The guard read each squash's SOURCE commits out of history. **A squash merge
does not keep its source commits.** Once the branch is deleted they are
reachable from no ref, so no checkout fetches them however deep it goes —
`fetch-depth: 0` does not help, because depth is not the problem. Measured:
`8f29b1d` and `fbae17b` are reachable only from merged feature branches still
sitting on `origin`, and absent from a clone made the way the runner makes one.
It passed locally because that clone still carried those branches: a fixture
verified in the one checkout that happens to have it. The module's docstring
even anticipated the symptom and filed it under a future history rewrite; the
ordinary cause is a merged branch being deleted, and that was not considered.

Fixed by splitting composition from the git query and capturing the source rows
in `tests/conformance/composed_message_fixture.json`. The EXPECTED output is
deliberately NOT captured — it is still read live from the squash commit, which
is permanent — so GitHub's real bytes anchor the fixture and a tampered body
turns the byte comparison red. That is one of the mutations.

**And the fix's first version repeated the mistake.** The new anchor check
asked whether each anchor was an ancestor of `origin/main`. A pull-request
checkout has no `origin/main` remote-tracking ref at all — measured in the
CI-shaped clone: `fatal: ambiguous argument 'origin/main'` — so it would have
refused a second time for a reason unrelated to its subject. It asks
reachability from `HEAD` now, which is the property actually wanted: "on main"
was only ever a proxy for "will a checkout contain it". **The generalisable
lesson is narrower than "pin durable things": a guard must be exercised in a
checkout shaped like the one it will run in, because the local clone's extra
refs are invisible privilege.**

**The allowlist, and why (3) was the right option.** Measured across all refs:
**90 co-authorship trailers, 89 naming `DriivAIDev <will@driivai.com>` — the
repository's own author — and one naming a vendor.** That one is independently
caught by three vendor-name terms in the same list. So the string-keyed rule
scored 89 false positives against a single true positive it did not need to
catch, and the cost was a red `main` after every merge. The refusing modes now
ask WHO is named, against `PERMITTED_COAUTHORS`, a one-entry enumerated set.
Same allowlist doctrine as every other guard here: say what is permitted.

`--history` is deliberately NOT allowlisted. It is the instrument that sizes
PROM-IP Part B, and an instrument that quietly filters 89 sites would have the
rewrite planned against a number nobody chose.
`test_the_history_sweep_is_NOT_allowlisted` pins that.

**Observed after the change.** `--commits af93238..c846272` and
`--commits 8f29b1d..origin/main` — the two squashes that turned `main` red —
both pass. The vendor-trailer commit `267a586` is still refused, by the
identity rule AND by the vendor terms independently.

### KNOWN TRIGGER — PROM-IP Part B will turn `main` red, and the fix is one line

`PERMITTED_COAUTHORS` in `scripts/check_message_hygiene.py` is a one-entry set
naming `DriivAIDev <will@driivai.com>`. **That is the identity PROM-IP Part B
exists to replace.** When the entity forms and the canonical identity changes,
the trailer GitHub writes will name the new one, it will not be in the set, and
every commit will be refused — on the pull-request path, the push path, and
both git hooks, at once.

That is correct behaviour: fail closed and loud. It is recorded here because the
symptom — `main` suddenly red on a line nobody wrote, immediately after an
identity change — reads like a broken guard, and the instinct will be to revert
the guard. **A guard reverted in confusion is worse than a guard that fires.**

The change is one line:

```python
PERMITTED_COAUTHORS = frozenset({"<new canonical identity, case-folded>"})
```

Case-folded, whole `Name <email>` string, and the old entry comes OUT in the
same edit unless both identities are genuinely still in use —
`test_the_allowlist_is_a_small_enumerated_set_not_a_pattern` pins the set at one
entry, so adding without removing fails and makes that decision explicit rather
than incidental.

Two things NOT to do when it fires. Do not widen the entry to a pattern or a
domain suffix: the question is WHO, and a shape-matcher answers a different one.
Do not add the old identity back "temporarily" — the history rewrite is what
makes the old identity wrong, and a guard that still accepts it is a guard that
has not noticed the rewrite happened.

**Named limits that remain.** The merging account is not in a `pull_request`
payload, so `--composed` assumes the worst case; a human can still edit the
squash message in the merge dialog afterwards, and the push-to-`main` run is
unchanged as the backstop for both; the `---------` separator rule is derived
from the ONE multi-commit squash this repository has; and whether a red run
can block a merge is branch protection, not a workflow property.

**Test.** `tests/conformance/test_composed_message_guard.py`, 16 tests, and
`scripts/composed_message_revert_proofs.py`, 11 executed mutations in a
throwaway worktree — the nine-hyphen separator, the blank line before the
trailer, commit order, an anchor pointed at an unreachable commit, a tampered
fixture body, the allowlist widened to a vendor identity, the allowlist
disabled, the allowlist defanged, the merging-account exclusion, the sweep
quietly allowlisted, and the workflow's checkout back to shallow. All eleven
redden their named test; none stayed green.

One of them had to be rewritten to earn that. The anchor mutation first
relaxed the assertion itself (`== 0` → `in (0, 1)`) and stayed GREEN — it could
not have fired, because every anchor returns 0 and widening the accepted set
changes no outcome. Probed the field directly on unmutated code instead:
`git merge-base --is-ancestor` returns 0 for `4451aa1` and `c846272` and 1 for
the two commits that broke CI, so the assertion's subject is real and the
mutation was the empty part. It mutates the subject now. The fixture is keyed
by pull-request number rather than by squash sha for the same reason — keying
on a value under test makes any mutation of it an import-time `KeyError`
rather than a red test, and a mutation that only proves Python raises on a
missing key proves nothing.

---

## G14 — the CI database's coordinates have one source (CLOSED, filed 2026-09-14)

**What.** `PROM_CHOKEPOINT_PG_DB/_USER/_PASSWORD` for the live-database step and
`POSTGRES_DB/_USER/_PASSWORD` for the service container were once typed twice,
with nothing enforcing that the two copies matched
(`docs/pre-disclosure-audit.md` L2/L3). A producer and a consumer that must
agree, and no check that they do, is a silent-drift shape.

**Measured** (2026-09-14): `jobs.build.env` holds the three literals; the
service container and the live step both read them by expression
(`${{ env.PROM_CI_PG_* }}`); the health command reads the container's OWN
`$POSTGRES_USER`/`$POSTGRES_DB` rather than retyping anything; and each literal
occurs exactly once in the whole workflow.

**Why this entry exists at all.** It was closed in #101 and never given a
G-number, so by this tracker's own rule it was untracked — the fix was real and
the record was not. Filed now rather than left to be rediscovered.

**Test.** `tests/conformance/test_ci_single_source.py`, five tests:
`::test_the_job_env_is_the_one_source`,
`::test_the_service_container_reads_the_source_by_expression`,
`::test_the_live_step_reads_the_source_by_expression`,
`::test_each_literal_appears_exactly_once_in_the_workflow`,
`::test_the_health_check_reads_the_containers_own_environment`. The value is a
CI-only throwaway for a container that does not outlive the job, not a
credential.

---

## G15 — the swarm matrix's row mapping: which rows refuse, which executes, and what each drives (CLOSED, filed 2026-09-14)

**What.** `test_policy_enforcement_regression.py` runs a ten-row matrix. An
all-green matrix proves nothing unless the mapping says which rows assert a
REFUSAL and which assert a LEGITIMATE EXECUTION — a matrix where every row
refused would be a guard that passes by refusing everything.

**Measured at `68d80df`, the commit before enforcement: SIX of these ten
produced an approved action and an executor call.** The two rows that refused
without the sprint did so only because the verifier happened to return
`Unavailable`, which the old `_verify` propagated — an accident of one return
shape, not a rule.

**The mapping, both axes.** `_ROW_KIND` says what each row asserts; `_ROW_STATE`
(added 2026-09-14) says which coverage state each row drives. The second was
previously carried only in end-of-line comments, which is prose, which drifts.

| # | row | drives | asserts |
|---|---|---|---|
| 1 | missing verifier | `coverage.incomplete` | refused before the gate |
| 2 | raises | `coverage.incomplete` | refused before the gate |
| 3 | raises TimeoutError | `coverage.incomplete` | refused before the gate |
| 4 | returns Unavailable | `coverage.incomplete` | refused before the gate |
| 5 | returns ABSTAIN | `coverage.abstained` | refused before the gate |
| 6 | returns FAIL | `coverage.unsatisfactory` | **refused AT the gate** (blocked) |
| 7 | Subprocess timeout BEFORE candidate start | `coverage.incomplete` | refused before the gate |
| 8 | Subprocess timeout AFTER candidate start | `coverage.abstained` | refused before the gate |
| 9 | Subprocess refuses (no isolation) | `coverage.incomplete` | refused before the gate |
| 10 | Subprocess runs (positive control) | satisfied | **LEGITIMATE EXECUTION** |

**Nine refusals to one execution**, and the one refusal that reaches the gate is
distinguished from the eight that refuse before it: a FAILED required check is a
real answer, so coverage refuses as unsatisfactory, the bank reports an
authoritative FAIL and the gate blocks. The other eight never produce a verdict
for the gate to judge.

**"Eight-state" is historical and should stop being said.** The constant was
once `eight_state_matrix` and was renamed to `swarm_matrix`. Ten rows drive
FOUR distinct states, six of them `incomplete` by four different routes —
absence, exception, timeout, explicit could-not-run. That repetition is
deliberate (a matrix exercising `incomplete` once would leave three routes to it
untested), but it is not eight states.

**Test.** `::test_every_matrix_row_is_mapped_and_the_mapping_is_nine_refusals_to_one_execution`
and `::test_the_state_to_row_mapping_covers_the_matrix_and_names_real_states`,
which also asserts the two mappings agree about which row is the positive
control. Registered in `tests/conformance/positive_controls.json` (G16).

---

## G16 — the positive-control set is named (CLOSED, filed 2026-09-14)

**What.** Doctrine #4 says every negative has a positive control. Measured on
2026-09-14, **25 tests in this tree declare themselves one** — and until now
there was no record of WHICH refusal each stood beside. A positive control
whose negative nobody wrote down proves that something passes.

(The owed item was phrased as "four positive controls as a named set". Four was
the number in play when it was written; the tree has 25. Naming four of the 25
would have been exactly the arbitrariness the item was objecting to.)

**What it is.** `tests/conformance/positive_controls.json`: each entry pairs a
positive control with at least one negative and states the property the PAIR
establishes.

**Test.** `tests/conformance/test_positive_control_set.py` — every registered
test on both halves resolves to a collected test; every self-declared positive
control in the tree is registered (so the set cannot fall behind the code); and
no stale entry survives a test that stopped declaring itself one.

**Named limit.** It checks the pairs EXIST. It cannot check that a negative
genuinely exercises the refusal its `property` line claims — that is review's
job. A registry is not a semantic verifier, and reading it as coverage would be
the same error as reading an audit score as coverage. The count is deliberately
NOT pinned: a pin would move on every addition and train people to update a
number without reading the pairing.

---

## G17 — the dead-flag guard proves a NAME APPEARS, not that a control is enforced (F10's live remainder)

**What.** `tests/conformance/test_security_posture.py:214-223`:

```python
def _attribute_reads_outside_config() -> set[str]:
    names: set[str] = set()
    for path in SRC.rglob("*.py"):
        if path.name == "config.py" and path.parent.name == "core":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                names.add(node.attr)
    return names
```

`ast.Attribute` covers loads and stores, on any object, anywhere in the file,
reachable or not. `test_every_declared_security_field_is_consumed_somewhere`
then asserts each `SECURITY_FIELDS` name is in that set and reports "consumed".

**Measured** (2026-09-14, mutation worktree, primary tree untouched). Removing
every genuine consumption of `require_ledger_anchor` from `src/` and leaving one
dead store under `if False:` on an unrelated object: **`26 passed`** — the whole
file green, with a declared security control wired to nothing.

**Why it is not fixed here.** A remedy is a design question, not a one-line
change, and this was a scoping pass. At least three shapes are available and
they are not equivalent:

1. **Narrow the collector** — require `ctx=ast.Load`, exclude bodies under a
   constant-false test, resolve the object to a `Config`. Cheap, and still
   static: it would refuse the exact probe above and not the next one.
2. **Behavioural proof per field** — drive each declared field through the
   runtime and observe the enforcement it names. Strongest, and the largest:
   22 fields, each needing a scenario where flipping it changes an outcome.
3. **Accept it as a spelling check and rename it** — keep the guard for what it
   genuinely catches (a field nobody mentions at all, the original
   `require_digest_pin` defect) and stop the name claiming enforcement.

(3) is the smallest honest step and is NOT free: it is a decision to accept that
this control is unproven, which belongs to the owner, not to the scoping pass.

### Ruled 2026-09-14: do (3) then (2). Do NOT narrow the AST walk

Narrowing the walk would be another enumeration of forbidden shapes, and C1–C3
are the measured evidence that enumerations lose: `if False:` today, a decorator
or a dict lookup tomorrow.

**(3) LANDED.** The test is
`test_every_declared_security_field_is_SPELLED_somewhere_outside_config`, and it
says in its own docstring what it cannot catch, with the probe that showed it.
`test_the_mechanism_has_teeth` became
`test_the_spelling_check_is_not_universally_true`, which is what it actually
establishes. The collector keeps its misleading name deliberately — renaming it
would suggest its semantics changed, and they have not.

Docs corrected in the same change (doctrine #9). The sweep found one live false
claim: `docs/threat-model.md` §5.5 said the mechanism "proves a field is
*consumed* somewhere", with "read only to be logged" as its worst case. The
measured worst case is **never read at all**. Corrected in place with the
measurement. The §5 summary row now reads "dead-flag SPELLING check (G17)".
`docs/sandbox.md:103` was checked and is accurate — it describes the pre-fix
state historically.

**(2) PARTITIONED, NOT BUILT.** The 22 fields split by whether neutralizing the
field changes an authorization outcome — 14 yes, 2 no, 6 UNCLASSIFIED. The
partition is a CLASSIFICATION BY READING each consumer, not a measurement, and
it is stated that way on purpose: the behavioural proofs in 2b are what measure
it, and they await a ruling on the six. See the table below.

**What closes it.** The 14 outcome-affecting fields getting behavioural proofs
(neutralize the field, a named test reddens), the remainder recorded as
SPELLING-CHECKED ONLY, and a ruling on the six unclassified.

**Test.** The rename has landed and is covered by the suite. The behavioural
proofs are 2b and are not built.

### The partition (2a), for ruling

Classified by reading each consumption site outside the attestation snapshot
block (`attestation/runtime.py:195-250`, which records config into a posture
record and enforces nothing), and outside `cli/` and `benchmarks/`.

**OUTCOME-AFFECTING — 14.** Neutralizing changes whether something is
authorized, refused, or executed.

| field | the consumer that decides |
|---|---|
| `sandbox` | `runtime/factory.py:157` selects the adapter; a non-isolating one is refused for a remote provider |
| `require_digest_pin` | `sandbox/container.py:244` refuses an unpinned image |
| `allow_insecure_loopback` | `provider/remote.py:215` — plaintext remote refused at construction |
| `escalate_below` | `verifier/bank.py:441` `judgment.confidence < self.escalate_below` routes to a human |
| `gate_threshold` | `runtime/factory.py:336` is the `PromotionGate` threshold |
| `pending_ttl_seconds` | `runtime/factory.py:439` — an expired hold cannot be approved |
| `ledger_anchor` | `runtime/factory.py:192` `if not config.ledger_anchor:` refuses when one is required |
| `require_ledger_anchor` | `runtime/factory.py:191` raises that requirement |
| `require_external_signer` | `chokepoint/runner.py:499` refuses a non-external signer |
| `require_verified_substrate` | `chokepoint/runner.py:511`, `substrate.py:792` refuses an unverified substrate |
| `allow_unverified_substrate` | same pair — it LOWERS the bar, which is why it is here |
| `require_config_attestation` | `attestation/runtime.py:82` refuses at startup |
| `config_attestation_target` | `attestation/runtime.py:83` `if not …:` refuses when attestation is required |
| `verification_profile` | `runtime/factory.py:273` selects the profile, so it selects which requirements must be satisfied |

**NOT OUTCOME-AFFECTING — 2.** Neutralizing changes what is recorded or how much
work happens, never whether it was authorized.

| field | why |
|---|---|
| `ledger_anchor_retention_days` | retention of the anchor; no decision reads it |
| `max_role_calls` | bounds swarm iterations; exceeding it stops work, it authorizes nothing |

**2c — these two are SPELLING-CHECKED ONLY, and that is the whole claim made
about them.** They are covered by
`test_every_declared_security_field_is_SPELLED_somewhere_outside_config`, which
proves their name appears as an attribute outside `config.py` and nothing more.
No behavioural proof exists for either and none is planned: a proof would have
to assert that neutralizing them changes *nothing*, which is a claim about the
absence of an effect and is not provable by a test. If either later grows a
consumer that decides something, it moves into the outcome-affecting set and
gets a proof then. A named partial is the honest state; a uniform claim over 22
fields that holds for none of them was not.

**UNCLASSIFIED — 6, and the reason is a definition I should not pick alone.**
Each bounds a verifier or provider. Neutralizing one does not flip an
authorize/refuse directly — but a verifier that hangs or is killed produces
`Unavailable`, which makes coverage incomplete, which IS a refusal. So they
remove a refusal PATH without being a decision.

`verifier_timeout_s` · `verifier_memory_mb` · `verifier_cpu_seconds` ·
`verifier_max_processes` · `request_timeout_s` · `provider_max_response_bytes`

Whether "removes a refusal path that runs through coverage" counts as
outcome-affecting decides whether 2b is 14 proofs or 20. That is a scoping
call, and distributing these into either side to make the table tidy is exactly
what the UNCLASSIFIED category exists to prevent.

---

## G18 — the Hearth freezes 21 files, all under `src/`, and none of the guards themselves

**What.** `PROTECTED_FILES` is 21 paths, every one under
`src/prometheus_protocol/`. **No file under `scripts/` is content-pinned by
anything.** So the scripts that ENFORCE the doctrine — `check_hygiene.py`,
`check_message_hygiene.py`, `type_gate.py`, `check_skip_manifest.py`,
`check_ip_consistency.py`, the revert-proof runners — can be edited without any
digest noticing. Their behaviour is covered by conformance tests; their CONTENT
is covered by nothing.

**Measured** (2026-09-14): 21 paths referenced in `hearth_ledger.py`, all
`src/`; zero under `scripts/`. The one non-`src` string in that file is prose in
a comment, not a path entry.

**Status: DISCOVERED, NOT DECIDED.** This is a ruling, and stating it as a gap
without stating the trade would be filing half of it.

**The trade, both directions.**

* **Extend Hearth to `scripts/`** — a guard edit then requires a re-sanction: a
  new digest, in the ledger, with a written reason, in the same change. That is
  the property the Hearth exists for, applied to the files most worth
  protecting. The cost is real and recurring: this sprint alone edited five
  scripts, each of which would have needed a ledger entry, and a ceremony
  attached to every guard edit is a ceremony people learn to perform without
  reading.
* **Record the exclusion as CHOSEN** — say in the ledger that `scripts/` is
  deliberately out of scope, on the grounds that guard scripts are exercised by
  their own conformance tests and mutation proofs on every build, which a digest
  is not a substitute for. The cost is that an edit weakening a guard in a way
  its own tests do not cover has no second net.

**Right now it is neither.** It is an exclusion nobody chose, which is the
weakest of the three states and the only one that is definitely wrong.

**What closes it.** Either decision, written down. Not a third sprint of
noticing it.

**Test.** `test_hearth_ledger.py` pins `EXPECTED_PROTECTED_FILES = 21`, so the
set cannot shrink unnoticed — but nothing asserts what the set SHOULD contain,
which is exactly the decision above.

---

## G19 — eight refusals in the security-posture file are proven by their message alone

**What.** Discovered while scoping F10, and the same class as the 1a near-miss:
a refusal asserted with `pytest.raises(X, match="...")` proves the refusal
fired, and ties it to the named reason only through the string.

**Measured** (2026-09-14): all eight `match=` arguments stripped from
`tests/conformance/test_security_posture.py` — **`26 passed`, nothing reddened.**
Every one of those eight tests would pass on any `ConfigError` from any cause.

The affected assertions are at lines 93, 104, 145, 155, 164, 178, 183 and 196:
`"cannot be honoured"` (x3), `"no container runtime"`, `"no isolation"`,
`"PROM_ALLOW_UNSAFE_EXEC"`, `"without isolation"`, `"unknown sandbox"`.

**How bad, stated honestly.** Lower stakes than the 1a case. These tests assert
that a particular config COMBINATION is refused, and the raise carries most of
that property — a `ConfigError` from an unrelated cause is unlikely when the
only thing varied is the combination under test. The finding is that the
distinction between "refused for this reason" and "refused" is currently
carried by a string in every one of them, so a reworded diagnostic silently
converts eight reason-assertions into existence-assertions.

### CLOSED 2026-09-14 — converted to a typed reason

`ConfigError` now carries an optional `reason` from `CONFIG_REFUSAL_REASONS`, a
six-entry closed set in `core/errors.py`; an unknown reason is refused at
construction. Nine raise sites across `sandbox/factory.py`, `core/config.py`,
`runtime/factory.py` and `sandbox/base.py` set it. All eight `match=` arguments
are GONE rather than kept alongside — a message assertion that no longer carries
the property is a second thing to maintain that proves nothing.

`sandbox/base.py`'s `deny_network` refusal was a bare `ValueError`; it is now a
`ConfigError`, which IS a `ValueError` subclass, so every existing caller and
test that catches `ValueError` is unaffected.

**Second-order probes, all three run:**

| probe | observed |
|---|---|
| drop all 8 `match=`, keep the reasons | 26 passed — the reason carries it |
| swap every raise site's reason to one wrong-but-valid value | **9 tests red** |
| drop the reason assertions (pre-conversion state) | 26 passed |

The third needs its honest reading: dropping a reason assertion leaves
`pytest.raises(ConfigError)`, which still passes — not because the test is weak,
but because **the raise is genuinely half the property**. The reason assertion
is what distinguishes "refused for this reason" from "refused". The brief's
diagnostic ("if it stays green the refusal fires for more than one reason")
does not separate those two cases, and the second probe is what does: a wrong
reason reddens nine tests.

One test did not redden under the swap —
`test_config_rejects_an_unknown_sandbox_at_load` — because its expected reason
IS `unknown_sandbox`, which was the value I swapped everything TO. An artifact
of the probe's choice of target, not a weakness in that test.

**The conversion caught one of my own errors immediately.** I mapped
`match="no isolation"` to `digest_pin_unhonourable`; the refusal it exercises is
actually `unsafe_with_remote`. The message contains "no isolation" and so does a
different refusal. That is precisely the failure mode this closes.

---

## G20 — findings cited by NUMBER whose text this repository does not hold

**What.** F10's text exists nowhere in the tree, in any commit, or in any pull
request body (G4 records the search). The only evidence it existed is PR #78's
not-in-scope line: *"F7, F8, F9, F10, F12 untouched."* That line proves those
numbers were live on 2026-09-07 and preserves **not one word of any of them**.

So F10 is not a special case. Any of those numbers may be carrying a paraphrase
whose accuracy nothing here can check — including a paraphrase written by
whoever last touched it, from memory, which is how G4's citation came to point
at a relicensing commit.

**Swept 2026-09-14, every finding series cited in the tree:**

| series | where | is the finding's OWN TEXT held? |
|---|---|---|
| F1–F9 | `docs/shakeout-report.md` | **yes** — it is our own register and each finding is written out. Internal, not external |
| L1–L5 | `docs/pre-disclosure-audit.md` | **yes**, in full, with severity and location |
| M1–M3 | `docs/pre-disclosure-audit.md` | **yes** |
| E5-x | `docs/threat-model.md` §5 | **yes** |
| R1–R7 | `docs/execution-descriptor.md` | **no — but REPRODUCED.** Each is a table row of "what was done" and "what was observed". That is stronger than text for engineering purposes (a reproduction is re-runnable and does not rot with wording) and weaker for provenance: nobody can check our reproduction against what was actually reported |
| F11 | `docs/reviews/PROM-F11-*.md`, `docs/audit-source-acceptance.md` | **no.** Five documents describe our RESPONSE and what remains open. None quotes the finding. Cited "with detail", and the detail is ours |
| **F10** | nowhere | **no** |
| **F12** | nowhere | **no** |

**F10 and F12 hold nothing. F11 and R1–R7 hold our reading, not the source.**

**THE RULE THIS SETTLES.** *A finding arriving from outside gets its TEXT
committed on arrival, not its number.* A number without its text is an
unverifiable claim that reads as a tracked item — it survives sprints, gets
paraphrased, and the paraphrase becomes the thing people work from. Verbatim
text, in `docs/reviews/`, at the commit that first responds to it. Where the
source cannot be republished, commit the closest artifact and say which it is.

**Why the existing state is not equally fine.** A reproduction (R1–R7) answers
"is this real and does it still happen". It does not answer "is this what they
said", which is the question that matters when the finding is cited to a third
party — a diligence reader, an auditor, or the next engineer deciding whether a
closure is honest.

### What can and cannot be claimed about R1–R7, in a diligence setting

This is the practical consequence, and it should be written down before someone
has to answer it live.

**CAN be claimed, and is well supported:** *"An independent review found real
defects in five consecutive rounds, and each one is reproduced in this
repository with the reproduction and the observed outcome recorded."* Every part
of that is checkable here: the reproductions run, `docs/execution-descriptor.md`
carries what was done and what was seen, and the mutation proofs show the fixes
are load-bearing. A reader can re-run them.

**CANNOT be claimed:** *"Here is what the reviewers found, in their words."* We
do not hold their words. What we hold is our reproduction of what we understood
them to mean — written by the party with an interest in the finding being
closeable. That is a real limitation and stating it plainly is stronger than
having it discovered: a diligence reader who asks for the original reports and
is told they cannot be produced will reasonably discount the closures too.

**The difference matters most where a closure is contested.** If a reviewer's
finding was broader than our reproduction, the reproduction passes and the
finding is not closed — and nothing in this repository could detect that.
`G4` is the worked example: F10's paraphrase turned out to be the only record,
and its citation pointed at an unrelated commit for three sprints.

**What closes it.** Either the original documents attached to the repository,
or — if they are genuinely gone — an entry per orphaned number recording what
evidence survives and that the text does not, so nobody re-derives it from a
paraphrase a third time. F10 already has that treatment in G4; F12 does not.

**Test.** None. A test cannot know whether a document was ever received.

---

## G21 — three resource bounds accept "no bound", and removing one turns a FAIL into a PASS

**What.** `verifier_memory_mb`, `verifier_cpu_seconds` and
`verifier_max_processes` accept `0` at `Config` load, meaning "no bound".
Measured on the real `SubprocessVerifier` with byte-identical candidate code:

| bound | enforced | set to 0 |
|---|---|---|
| `verifier_memory_mb` (64) | `Verdict.FAIL` | **`Verdict.PASS`** |
| `verifier_cpu_seconds` (2) | `Verdict.FAIL` | **`Verdict.PASS`** |
| `verifier_max_processes` (4) | `Verdict.FAIL` | **`Verdict.PASS`** |

So these fields are outcome-affecting in the strongest sense: they do not merely
remove a refusal path, they change the verdict. An operator who zeroes one
silently widens what passes.

**The other three of the six are fail-closed and cannot be neutralized at all.**
`verifier_timeout_s`, `request_timeout_s` and `provider_max_response_bytes`
refuse both `0` and `-1` at load. The asymmetry is the finding as much as the
table is.

### What this is NOT, stated because the sprint that found it expected otherwise

The G17 ruling asked for proofs showing an Unavailable path — "neutralize the
bound, show the verifier fails to yield a verdict, show coverage reports
incomplete" — and named the risk as couldn't-verify collapsing into
verified-clean at the resource layer.

**That path does not exist here, and its absence is deliberate rather than a
defect.** A resource-limit kill is a FAIL, a verdict about the candidate.
`runner.py`'s docstring says so exactly, and all four measurements match it:

* FAIL — "the candidate crashing / being killed by a resource limit on its own
  code (a *confirmed* candidate start that produced no verdict)";
* ABSTAIN — "the candidate started and then ran past the wall clock";
* Unavailable — "a wall-clock timeout *before* the candidate started".

Measured: a confirmed start that runs past the wall clock returns
`Verdict.ABSTAIN`, not FAIL and not Unavailable. There is therefore no
couldn't-verify state on this path to collapse from, and the prescribed proof
shape cannot be built for these six without manufacturing it.

(An earlier reading of mine, withdrawn: I first reported the docstring as
claiming wall-clock timeouts are Unavailable and therefore false. It says
*before the candidate started*, which my probe did not exercise. The docstring
is accurate; the misreading was mine.)

### The control that exists

Every one of these values is captured in the startup posture record
(`attestation/runtime.py`), so the budget a verdict was produced under is
recorded rather than implicit. That is what those fields are doing in the
attestation snapshot — a point that reads as "recorded, not enforced" until you
need to know which budget produced a PASS.

**Why it is not fixed here.** Whether zero should remain accepted is a product
decision with a real cost either way: `Limits` documents that a disabled
address-space cap "can prevent some legitimate workloads" from being refused,
and this repository's own unit tests use `memory_mb=0` for exactly that reason
(a 256 MiB cap makes ordinary test candidates flaky). Refusing zero would make
those tests specify a real budget; permitting it keeps a foot-gun reachable from
`Config`. Three shapes are available — refuse zero outright, require an explicit
`allow_unbounded_verifier=True` beside it, or leave it and rely on the posture
record — and choosing is not a scoping pass's call.

**Test.** `tests/conformance/test_resource_bound_outcomes.py`, nine tests: the
FAIL→PASS flip per bound, that zero is reachable through `Config` per bound,
that the other three refuse zero, the ABSTAIN split, and a positive control that
an unbreached bound still returns real verdicts in both directions — without
which every assertion above is consistent with a verifier that fails everything
under a bound and passes everything without one.
