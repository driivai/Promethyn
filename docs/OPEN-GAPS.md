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
no per-module section. **That 304 is DATED AT OBSERVATION, 2026-09-14.** It is
the file set as it was that day, not a current figure and not a pin — the tree
has grown since (the live pin is `EXPECTED_CHECKED_FILES` in
`scripts/type_gate.py`, which is what moves). Read here, "at the current file
set" means *at the file set current on 2026-09-14*, and anyone comparing it to
today's count is comparing two different populations. So the blocker is not the rule; it is that the change
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
**Those four surfaces are the whole of its coverage. A REVIEW COMMENT is not
one of them and is checked by nothing** — measured, and filed as G28.

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

**And the number of entries is NEVER a coverage figure**, stated plainly because
a registry that grows looks like progress. "31 registered pairs" means 31
places where someone wrote down a pairing. It does not mean 31 properties are
covered, does not mean the covered ones are the important ones, and says
nothing at all about the refusals that have no pair because nobody noticed they
needed one. Quoting the count as a coverage figure, anywhere, is a misuse of
this instrument.

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

**(2) LANDED, AND MEASURED RATHER THAN CLASSIFIED.** The 22 fields split 14
outcome-affecting / 6 resource-bound / 2 spelling-only. That split began as a
CLASSIFICATION BY READING each consumer; it is now a measurement, because every
field in the first two classes has a behavioural proof and every proof has been
shown to redden under a mutation that neutralizes its field.

`tests/conformance/test_security_field_behaviour.py` holds the 14, and holds
the partition itself as executable structure — `OUTCOME_AFFECTING`,
`RESOURCE_BOUND`, `SPELLING_ONLY` and a `PROOFS` mapping, with guards that the
three classes partition `SECURITY_FIELDS` exactly and that every test `PROOFS`
names exists. A field added to `SECURITY_FIELDS` must be classified, and a
proof cannot be renamed away. The table below is now a description of that
structure rather than the structure itself.

### The measurement, 2026-09-15 (`scripts/mutation_worktree.py`, primary tree clean)

Per field: the consumption neutralized in `src/`, and what went red.

**14 of 14 reddened a NAMED test in the new module.** For **11 of the 14** the
spelling-check file stayed at `26 passed` — i.e. the new module caught exactly
what the old one cannot. For the other three (`sandbox`, `require_digest_pin`,
`verification_profile`) `test_security_posture.py` also reddened, but NOT
through the spelling check: through the ordinary assertions that already sat in
that file. Stated because "the spelling check went red too" would be a false
reading of the same output.

**C4, the reproduction that motivated all of this, is closed.** Its exact shape
— every genuine consumption of `require_ledger_anchor` removed from `src/`, one
dead store left under `if False:` — now reddens
`test_require_ledger_anchor_refuses_a_configuration_it_cannot_honour`, while
`test_security_posture.py` still reports `26 passed`, unchanged from the
original probe.

**Correction to that measurement (reachability F1/F2).** The coherence block in
`core/config.py` refuses a required witness whose target is absent or `file://`.
It does **not** establish successful publication or that the assembled ledger
has the configured anchor. A loadable Config with a valid WORM-shaped target
still reaches the runtime, so the earlier statement that the runtime check was
"unreachable from any loadable Config" was false. F1 built a runtime without
calling the attestation publisher; F2 built one with an unanchored injected
ledger. The original per-field proofs tested configuration shape and helper
behavior, not these assembly paths. The new build guard and permanent
reachability regressions are described in `docs/reachability-build.md`; they
are additional evidence, not a reinterpretation of the old green tests.

### Second-order probe on all 14

Strip the assertion that states the property, keep the neutralizing mutation:

* **11 of 14 go GREEN** (`23 passed`) — the assertion is load-bearing and
  nothing else in the module catches that mutation.
* **3 stay RED, and each for a different reason worth naming rather than
  recording as weak.** `sandbox`: a *different* field's test
  (`test_require_digest_pin_…`) also catches a hardcoded adapter, so the two
  proofs overlap. `escalate_below`: the same test's `assert routed != approved`
  carries "the field changes the outcome", and the stripped
  `assert routed == "route"` carried only "and in which direction".
  `pending_ttl_seconds`: the paired assertion at the other value fails too —
  both carry the same half, and the pair exists so a hardcode to *either* value
  is caught.

Strip the POSITIVE CONTROL instead: **14 of 14 stay RED**. That is the expected
result and it says what the control is for — not catching neutralization, which
the property statement does, but catching the opposite defect of code that
refuses or returns the same thing unconditionally.

**What closes it.** Closed for the 20 fields that have proofs. The 2 named
partials stay open by design and are described in 2c below.

**Test.** `tests/conformance/test_security_field_behaviour.py` (23 tests) and
`tests/conformance/test_resource_bound_outcomes.py` (18 tests), plus the rename
and the spelling check in `test_security_posture.py`.

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
| `require_config_attestation` | `attestation/runtime.py::attestation_target_for` refuses an absent/non-external target **when called**; `attest_at_startup` additionally signs/publishes. The old table's unconditional "refuses at startup" claim was false because production builders did not reach it (F1). The reachability guard now makes the covered assembly paths call it or refuse. |
| `config_attestation_target` | `core/config.py::Config.__post_init__` checks shape; `attestation/runtime.py::attestation_target_for` checks the target when reached. Shape validation is not publication. |
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

**RESOURCE-BOUND — 6. Ruled outcome-affecting, PROVEN UNDER A DIFFERENT SHAPE,
and the difference is the point of this entry.**

`verifier_timeout_s` · `verifier_memory_mb` · `verifier_cpu_seconds` ·
`verifier_max_processes` · `request_timeout_s` · `provider_max_response_bytes`

These were UNCLASSIFIED pending a ruling on whether "removes a refusal path that
runs through coverage" counts. It was ruled that it does — and then the
measurement showed the premise behind the question was wrong. Neutralizing one
of these does **not** produce an `Unavailable` that makes coverage incomplete.
It produces a **different VERDICT**: the same candidate bytes that return
`Verdict.FAIL` under a bound return `Verdict.PASS` without one (G21).

So the proof shape here is a **verdict flip, not a refusal**, and no refusal test
could catch it because nothing refuses. That is a STRONGER observation — the
control does not merely remove a path, it changes the answer — and a WEAKER
guarantee, because there is no refusal to assert on. Recording these as "proven"
alongside the 14 without recording the shape would let a reader carry the 14's
guarantee onto them, and they do not carry it.

| bound | proof |
|---|---|
| `verifier_memory_mb` | FAIL→PASS flip, bare `0` refused at load, named `UNBOUNDED` accepted |
| `verifier_cpu_seconds` | same three |
| `verifier_max_processes` | same three |
| `verifier_timeout_s` | a confirmed start that overruns is `ABSTAIN`; no unbounded spelling exists |
| `request_timeout_s` | refuses `0` and `-1` at load; no unbounded spelling exists |
| `provider_max_response_bytes` | refuses `0` and `-1` at load; no unbounded spelling exists |

**Test.** `tests/conformance/test_resource_bound_outcomes.py`, 18 tests. The
runner's three-way split (FAIL for a resource kill on a confirmed start, ABSTAIN
for a confirmed start that overruns, `Unavailable` only for a timeout *before*
the candidate started) was reviewed and RULED CORRECT: a candidate killed by a
limit on its own code produced a verdict about the candidate, and converting
that to `Unavailable` would discard real information. Doctrine #1 stops absence
being reported as a verdict; it does not turn verdicts into absences.

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

### RULED AND CLOSED 2026-09-15 — unbounded stays, but it must be NAMED

Not "refuse zero outright" and not "leave it". Unbounded is a supported posture
and removing it would be a different product: `Limits` documents that a disabled
address-space cap avoids refusing legitimate workloads, and this repository
relies on it — a 256 MiB cap makes ordinary test candidates flaky. What was
wrong was not that unbounded was reachable. It was that it was reachable by
saying *nothing in particular*.

* `Config` accepts `UNBOUNDED` (`"unbounded"`, exported from the package root)
  for `verifier_memory_mb`, `verifier_cpu_seconds`, `verifier_max_processes`.
* A bare `0` is **refused at load** with `reason="bound_zero_is_not_unbounded"`,
  as `verifier_timeout_s`, `request_timeout_s` and `provider_max_response_bytes`
  already refused it. Three fields in one struct failing closed while three did
  not was the inconsistency, and that is what is removed.
* The permitted spellings are an **allowlist over what varies**
  (`UNBOUNDED_SPELLINGS`), not an enumeration of bad values: a near-miss like
  `"unbouned"` and a stringified number like `"256"` are both refused with
  `reason="unknown_unbounded_spelling"` rather than falling back to either
  meaning.
* `SubprocessVerifier` and `Limits` keep their `0 = no limit` contract
  UNCHANGED for every caller that already used it, and both additionally ACCEPT
  the sentinel and carry it.

### AMENDED 2026-09-15 by the Codex review on PR #106 — the sentinel must travel

The first version of this fix resolved `UNBOUNDED` to `0` at the composition
root. That is one flattening point for three substrates that do not agree on
what a zero means, and the review found the consequence, correctly, as a P1:
`ContainerSandbox` coerces the memory limit with `max(bytes, 16 MiB)` and
emitted `--memory` unconditionally, so a posture an operator NAMED as "no cap"
arrived at the container runtime as **the tightest cap in the tree**, while the
namespace and unsafe adapters imposed nothing.

The remedy is not to special-case zero inside `ContainerSandbox.run` — that
fixes the instance and leaves the shape. `UNBOUNDED` now survives to the point
where **each adapter builds its own command** (`core/bounds.py`), and each
decides there: the container adapter omits the flags entirely, the namespace and
unsafe adapters resolve to `0` at their argv and rlimit lines, because on those
substrates `0` genuinely means "impose nothing". `--pids-limit` now emits the
documented `-1` rather than relying on `0` happening to mean unlimited.

The coercion predates the PR (`container.py`'s `max()` last changed in `d9a2bb7`,
2026-06-30) and was already live for `verifier_memory_mb=0`. What the PR changed
is that `0` went from an undocumented accident to a documented, supported
posture — which turned a latent inconsistency into a shipped promise the
container adapter did not keep. That is why it is a P1 on this PR and not a
pre-existing note.
* The posture record stores the operator's **spelling**, not a resolved `0`, so
  "no cap was asked for" and "a cap of zero" are distinguishable in the digest.
  `encode_value` tags `str` and `int` separately, so the two cannot collide.

**Migrated: 7 call sites** that passed a bare `0` through the `Config` surface —
six `verifier_memory_mb=0` keyword arguments (`tests/conftest.py`, two shakeout
modules, `test_sql_learn_loop.py`, `test_soft_judge.py`,
`test_swarm_provider_backed.py`) and one `PROM_VERIFIER_MEMORY_MB=0` environment
variable in `test_shakeout_cli.py`. The ~45 internal
`SubprocessVerifier(memory_mb=0)` calls are deliberately NOT migrated: that
constructor is not an operator surface and its contract did not change.

**Test.** `tests/conformance/test_resource_bound_outcomes.py`, 18 tests: the
FAIL→PASS flip per bound; the bare-zero refusal per bound with its typed reason;
the paired positive control that the named value loads AND still widens — without
which the refusal is equally consistent with unbounded having been removed
outright; the unrecognised-spelling refusal; a `replace()` round-trip, because
`__post_init__` re-validates what was stored and a normalisation that did not
round-trip would make a valid `Config` un-copyable; the ABSTAIN split; and a
positive control that an unbreached bound still returns real verdicts in both
directions, without which every assertion is consistent with a verifier that
fails everything under a bound and passes everything without one.

---

## G22 — `verifier_cpu_seconds` has NO expression on the container substrate

**Found while fixing the P1 on PR #106**, by asking the question the ruling
attached to that fix rather than by looking for this.

**What.** The three sandbox adapters do not agree on which bounds they enforce:

| bound | namespace | unsafe | container |
|---|---|---|---|
| `memory_bytes` | bootstrap argv + cgroup `memory.max` | `RLIMIT_AS` | `--memory` / `--memory-swap` |
| `max_processes` | bootstrap argv + cgroup `pids.max` | (process tree) | `--pids-limit` |
| `cpu_time_s` | bootstrap argv + cgroup `cpu.max` | `RLIMIT_CPU` | **nothing** |

Measured on the constructed command: `ContainerSandbox.run` builds its inner
argv as `["python", "-B", *argv[1:]]` and passes **no** limit arguments to the
bootstrap, unlike `NamespaceSandbox`, which passes memory, cpu, processes and
file size explicitly. So `cpu_time_s` reaches the container adapter and is
dropped.

**`--cpus "1"` is not it, and is hardcoded.** It is a scheduling RATE — at most
one core's worth of CPU per wall-clock second — not a quantity of CPU TIME. It
never terminates a candidate. A runaway loop under the namespace adapter is
killed by `RLIMIT_CPU` after `cpu_time_s` seconds; under the container adapter
it runs until the WALL-CLOCK timeout, which is a different bound with a
different meaning (`Verdict.ABSTAIN` rather than `Verdict.FAIL` — see G21).
So the same candidate can be FAILED on one substrate and ABSTAINED on another,
from the same configuration.

**This is not the reported defect, and is wider.** PR #106's finding was that an
unbounded memory posture became a 16 MiB cap on one substrate. This is that
`cpu_time_s` is *not honoured at all* on that substrate, bounded or unbounded.
Fixing the reported one does not touch it, and papering over it inside the
class-level guard — by treating `--cpus` as the container's expression of
`cpu_time_s` — would have recorded a bound as covered when it is absent.

**Why it is not fixed here.** The remedy is a design choice, not a one-line
change, and PR #106 is a review-response. At least three shapes exist and they
are not equivalent: pass the limits into the container's bootstrap the way the
namespace adapter does (most faithful, changes the image contract); use
`--ulimit cpu=N` (runtime-specific, and silently ignored by some); or declare
`cpu_time_s` unenforceable on this substrate and refuse the combination at load
(fail-closed, and would refuse a configuration that works today).

**What closes it.** Either an expression of `cpu_time_s` on the container
substrate with a command-level proof beside the others in
`test_sandbox_unbounded_reaches_the_command.py`, or a load-time refusal of the
combination with the same. Not a comment saying `--cpus` covers it.

**Test.** None yet — deliberately. The class-level guard in
`test_sandbox_unbounded_reaches_the_command.py` excludes `--cpus` from its
finite-number sweep and its docstring names this entry as the reason, so the
exclusion is recorded where someone reading that test will find it rather than
resolved by silence.

---

## G23 — branch protection was overridable by the party it constrains, and this tree cannot verify that it no longer is

**The observed instance.** Pull request **#106** merged at **2026-09-15
01:05:20Z**, merged by `driivai`, with review thread
**`PRRT_kwDOTFRnqM6iVMIm`** unresolved. That thread carried a **P1 finding**
(the container adapter turning a named unbounded memory posture into a 16 MiB
cap). The repository's branch protection required conversation resolution before
merge. The merge happened anyway, by administrator override.

Nothing was broken and nothing misfired. The rule did exactly what it was
configured to do: it asked, and the administrator answered.

**Closed at the host, 2026-09-15.** Branch protection has been reconfigured so
that conversation resolution cannot be bypassed by administrators.

### The general form, which is the part worth keeping

**A control that can be overridden by the party it constrains is a prompt, not a
gate, and must not be documented as a gate.** The distinction is not pedantry
about wording — it is the difference between a property a reader can rely on and
a habit they are trusting. A prompt is worth having; most of this repository's
process controls are prompts, and they catch real things. What is not acceptable
is describing one as though it were structural, because a reader who believes a
gate exists stops looking for the failure it was supposed to prevent.

This is the same error as G17, one layer out. There, a test named
`…_is_consumed_somewhere` proved only that a name was SPELLED, and the name
carried a guarantee the mechanism did not. Here, "CI gates `main`" carried a
guarantee the host configuration did not. Both were corrected by weakening the
claim to what is true rather than by strengthening the mechanism to match the
claim — and in both cases the weaker true statement is more useful, because it
says where to look next.

### Docs corrected under this entry (doctrine #9)

Two live claims, both overstating a workflow's reach:

| file | was | now |
|---|---|---|
| `docs/IP-READINESS.md` | "CI **gates** `main` on the canonical identity" | CI **detects** it; red-run-blocks-merge is branch protection, and on the `push: [main]` trigger the commit is already on `main` |
| `docs/repository-identity.md` §4 | "**Gate** it in CI." | "**Detect** it in CI." |

Checked and deliberately left unchanged:

* `docs/OPEN-GAPS.md` (G13's limits) already said *"whether a red run can block a
  merge is branch protection, not a workflow property"* — which is exactly the
  correct framing, written before this instance proved it mattered.
* `.github/workflows/pr-text-hygiene.yml` already said *"red is a
  branch-protection setting, not a workflow property"*.
* `docs/open-core-boundary.md` §15's "two public gates" describes a contribution
  POLICY for a future open-source repository, not a claim about this
  repository's host configuration. Left as policy language.

### THE LIMIT THAT REMAINS — UNVERIFIABLE FROM THE REPO

**Whether branch protection is now enforced cannot be asserted from inside this
tree, and this entry does not assert it.** Branch protection is host
configuration. It is not a file, it is not reachable from any ref, and the
GitHub MCP server available to this project exposes **no branch-protection or
ruleset endpoint** — checked, not assumed. A future session reading this entry
has no way to confirm the fix is still in place.

So this is recorded as **UNVERIFIABLE FROM THE REPO**, not as CLOSED. The
closure is real; the *evidence* for it lives somewhere this repository cannot
read.

**The manual check that confirms it** — the only thing that does:

> GitHub → repository **Settings** → **Rules** → **Rulesets** (or **Branches** →
> the `main` protection rule) → confirm **"Require conversation resolution
> before merging"** is on, and that **"Do not allow bypassing the above
> settings"** is checked / the bypass list is empty. A ruleset with an
> `Organization admin` or `Repository admin` bypass actor is the pre-2026-09-15
> state under a different name.

Whoever needs this asserted in a diligence setting should produce a screenshot
or the ruleset JSON, dated, from that page. That is the artifact; nothing in
this repository substitutes for it.

**Test.** **NONE, deliberately, and this is the load-bearing sentence.** A test
asserting branch-protection state would have to read a thing it cannot reach.
It would therefore assert a constant, pass forever, and report a host setting as
proven while measuring nothing — the exact shape of the defect this project
exists to name, added in the entry that names it. A named gap is a passing test
(doctrine #5); a green test over an unreadable subject is worse than no test.

**What closes it.** Nothing in this repository. It is closed at the host or it
is not closed; this entry exists so the claim is never made from here.

---

## G24 — one approved GateDecision permits repeated executor calls with the same attempt_id (FILED, NOT FIXED)

**Found by the Codex review of `6135652`, item 6.5.** Filed under an explicit
ruling that it is NOT to be fixed in that sprint.

**What.** `ExecutionController` claims a HELD action atomically before running
it, so a human-approved hold cannot be executed twice. **Auto-approved actions
are excluded from that claim.** One approving `GateDecision` can therefore be
handed to the executor repeatedly, with the same `attempt_id`, and each call
runs.

**Why it is a product decision and not a bug report.** It turns on what "one
attempt at one consequential action" means, and the two readings are both
defensible:

* **one action IDENTITY** — an `attempt_id` may be executed once, ever. Replay
  is refused. Clean, and it makes an idempotent retry after a timeout
  impossible: a caller who did not see the result cannot safely ask again.
* **one execution OCCURRENCE** — the gate authorizes an action, and the caller
  may run it as often as it is willing to pay for. Retry-safe, and it means the
  audit record of "authorized once" does not bound "executed once".

The cost is real in both directions, which is why this is a ruling and not a
fix. A migration runner that loses its connection mid-apply wants the second
reading; a payment wants the first.

**What is NOT in doubt:** nothing executes without an approving decision, and
the approval itself is recorded once. The question is only whether the RECORD
bounds the number of executions, and today, on the auto-approved path, it does
not.

**What closes it.** A ruling, then either an attempt-scoped claim covering the
auto-approved path with a test that a second call refuses, or an explicit
statement in `docs/execution-descriptor.md` that an approving decision is a
capability the caller may exercise repeatedly — with the audit consequence
spelled out.

**Test.** None yet. Deliberately: a test written before the ruling would pin
whichever reading the test author picked, which is the decision being deferred.

---

## G23 — addendum, 2026-09-15: #107 carried a Codex review with ZERO inline threads

**Measured, not assumed.** PR #107 (`fb7e376`, merged 01:58:55Z) carried a Codex
review submitted at 01:53:36Z in state `COMMENTED`, with the summary wrapper
*"Here are some automated review suggestions for this pull request."* — and
**zero inline review threads**. So #107 did not merge past an unresolved
conversation, and **G23 remains an incident on #106 alone**. No rewrite of that
entry is owed: it describes one occurrence, not a practice.

### The workflow rule that follows, because this nearly went the other way

**A Codex summary comment is NOT evidence of findings.** The wrapper comment and
the `COMMENTED` review state appear whether or not there are inline threads, and
its own About box — *"comments if it has suggestions, and reacts with 👍 once all
reviews finish with no findings"* — reads as though commenting implies findings.
It does not: the summary comment is posted separately from the review itself.

Reasoning from the summary alone would have produced a confident and wrong
conclusion here: that #107 probably carried a P1 like #106, that the rule had
been merged past twice, and that G23 needed rewriting from an incident into a
practice. **The signal is inline review threads, or the 👍 reaction documented as
the all-clear.** Nothing else.

This is the same class as G17 and G23 themselves: a surface that LOOKS like it
carries a guarantee, read as though it does. Three instances now, in three
different substrates — a test name, a branch-protection rule, a bot's summary
comment.

**Second observation of the rule in practice, 2026-09-15, #109.** All five
inline threads were already resolved before the first read of them; the
reply-before-resolve order was kept by resolving nothing, and a reply was posted
in each thread afterwards. Who resolved them was not observed and is not guessed
here.

---

## G25 — a NAME is not a membership: the composition pin's own thesis failed on itself

**Found by review (PR #108, P2), reproduced before fixing.**

**What.** `scripts/check_proof_composition.py` collected `{_base_name(c) for c in cases}`
— the set of names that ran — and discarded each testcase's MODULE. So a
required name could be satisfied by a **different collected module** while the
per-module counts stayed right.

**Reproduced, exactly.** Rename
`test_descriptor_refuses_each_cross_action_mismatch_before_execution` to a
filler in `test_execution_descriptor`, and hand its old name to
`test_mutation_plan_and_observed_failure_count_are_pinned` (unpinned) in
`test_phase_1_2c_checkpoint_b_revert_pins`. Counts unchanged: 18 + 4 = 22. The
name still appears in the report. `check(..., "checkpoint_b")` returned
**NO problems** — with the pinned proof gone.

That is this change's own argument failing on itself. It was written to say a
count does not cover what varies; it then pinned a name, and **what varies is
the `(module, name)` PAIR**.

### THE SPRINT'S PROOF WAS INSUFFICIENT, and this is the record of it

The five swap proofs run when the pins were converted probed **DELETION**:
remove a load-bearing refusal, append a benign passing test, watch the pin
redden. All five reddened, and that result stands — but it establishes less
than it appeared to.

**Deletion is the obvious attack; SUBSTITUTION is the shape a real patch takes.**
A name-only pin catches deletion and passes substitution, and nothing in that
first round distinguished the two. It is the same split as **Family A vs
Family B in the R2 mutations**, and I did not carry that distinction across to a
new instrument — which is the more useful half of this entry, because the
distinction was already written down in this repository.

**Fixed.** `required` is keyed BY MODULE in
`tests/conformance/proof_composition.json`, and the checker keys membership on
`(module, base name)`. A test that MOVES modules now breaks its pin exactly as
deletion does.

**Proof, per converted pin, on the real tree** — rename a pinned test to a
filler in its own module, give its old name to an unpinned test in a DIFFERENT
module of the same step, counts unchanged. **All five REDDEN**, each naming the
pair that moved:

| step | moved | from → to |
|---|---|---|
| `checkpoint_b` | `test_a_LEGITIMATELY_minted_assessment_does_not_cross_target_or_attempt` | descriptor → checkpoint-B revert pins |
| `authorization_record` | `test_a_FAILED_required_check_is_refused_at_the_gate_and_the_row_records_the_row` | record → hold pinning |
| `phase_1_2a` | `test_the_encoded_field_set_equals_the_dataclass_fields` | encoding → coverage enforcement |
| `phase_1_2b` | `test_a_covered_assessment_mints_a_migration_capability` | unbound-closed → 1.2b revert pins |
| `checkpoint_3` | `test_a_REGISTERED_verifier_cannot_lie_about_its_tier` | advisory → 1.2c revert pins |

**Test.** `test_the_checker_refuses_a_name_that_MOVED_to_another_module`,
parametrised over every step so no step is covered only by the easy case.

**The general form.** When an instrument pins an identifier, ask what the
identifier's SCOPE is. A bare name is scoped to nothing; the thing being
identified is scoped to a module. A pin over the narrower key passes every
substitution that stays inside the wider one.

---

## G26 — `PolicyRequirement` never checks that an implementation exists — CLOSED 2026-09-15

**Surfaced by the live-state design review (PR #109), and it is a defect in the
EXISTING policy model rather than in that feature.** Closed by the registry
described at the end of this entry; the filing is kept as written, because the
measurement it records is what the fix was built against. Filed separately for that
reason: folding it into a feature entry would hide a general defect inside a
specific one.

**What.** `PolicyRequirement.__post_init__` validates, measured:

* identity and permitted-set **normalisation**, via a `BoundRequirement` probe;
* that `applies_to` is a sequence and not a string;
* that it is **non-empty** — "applies to no action class" is refused;
* that every entry is a **known action class**;
* that there are no duplicates.

It does **not** validate that any name in `permitted` corresponds to an
implementation that exists. There is no registry to validate against: the
`IMPL_*` constants in `policy/profile.py` are bare strings —

```
IMPL_SUBPROCESS = "subprocess-tests"
IMPL_SWARM_STRUCTURAL = "swarm-checks"
IMPL_GIT_MERGE_CHECK = "git-merge-check"
```

— and their own comments say they were *"read off `SubprocessVerifier.VERIFIER_ID`"*
and *"read off `tools.git.MERGE_CHECK_VERIFIER_ID`, not invented here."* That is
correct because a person copied it correctly, not because anything checks.

**The consequence.** A typo in a `permitted` entry constructs cleanly. The
requirement then can never be satisfied — no result ever carries that
implementation identity — so every assessment refuses with
`coverage.incomplete`. **Which reads as a runtime outage, not a configuration
error.** An operator sees "a required check did not run" and looks at the
verifier, the sandbox, the network; the cause is a misspelled string in the
policy.

Fail-closed, so nothing is authorized that should not be. But a configuration
error that presents as an infrastructure fault costs the wrong debugging, and
the failure is *permanent and total* for that action class.

**Where it bites hardest: a customer-supplied policy.** The shipped profile has
constants beside the verifiers they name. A policy supplied as data has nothing
protecting it, and R1 already records that a customer-supplied, digest-pinned
policy is the intended later supplier of that value.

**This is also why the live-state design's covered set is FIXED rather than
per-policy** (`docs/live-state-pinning-design.md` §1.4). A per-policy aspect
list would hand the same unchecked surface to a second security parameter, where
a typo or a deliberate narrowing would be indistinguishable.

**What closes it.** An implementation registry resolved at policy construction:
every name in `permitted` must resolve to a registered implementation, and an
unknown one is refused **there**, with the policy in hand, rather than hours
later as coverage that never completes. The registry is the allowlist — over
what is PERMITTED to answer a check, keyed on implementation identity.

### CLOSED — 2026-09-15, the registry built (same change as design rev 3)

**What was built.** `src/prometheus_protocol/policy/implementations.py`: one
declaration per identity, `declare_implementation(identity, implemented_by=…)`,
which returns the identity so the declaration IS the constant everything else
references. The six shipped identities are declared there and consumed BY
REFERENCE at their sites — `verifier/runner.py` (`VERIFIER_ID = SUBPROCESS_TESTS`),
`verifier/sql.py`, `verifier/grounding.py`, `verifier/model_judge.py`,
`swarm/runtime.py` (`CHECK_VERIFIER_ID = SWARM_CHECKS`), `tools/git.py`
(`MERGE_CHECK_VERIFIER_ID = GIT_MERGE_CHECK`) — and by the policy module
(`IMPL_SUBPROCESS = SUBPROCESS_TESTS` and its two siblings,
`policy/profile.py:396-398`). One spelling, two references.

`PolicyRequirement.__post_init__` (`policy/profile.py:152-192`) refuses a
permitted name the registry has not declared with
`PolicyError(reason="implementation_not_registered")`, carrying `implementation`
and `check_id` (`:178-192`), and refuses an EMPTY registry first and distinctly
with `reason="implementation_registry_empty"` (`:169-177`).
`POLICY_REFUSAL_REASONS` (`:101-104`) is a closed set in the
`CONFIG_REFUSAL_REASONS` shape; an unknown reason is refused at construction.

**Observed registry population, 2026-09-15** — `declarations()` after
importing the package, seven entries:

| identity | declared site | what reports it |
|---|---|---|
| `subprocess-tests` | `verifier.runner.SubprocessVerifier` | HARD verifier |
| `sql-result-equivalence` | `verifier.sql.SqlVerifier` | HARD verifier |
| `grounding-judge` | `verifier.grounding.GroundingVerifier` | SOFT verifier |
| `model-judge` | `verifier.model_judge.ModelJudgeVerifier` | SOFT verifier |
| `swarm-checks` | `swarm.runtime.CHECK_VERIFIER_ID` | module constant |
| `git-merge-check` | `tools.git.MERGE_CHECK_VERIFIER_ID` | module constant |
| `human-grounding-review` | `benchmarks.grounding_loop_demo.HUMAN_REVIEWER_ID` | the demo's human reviewer; declared because the demo's own policy names it, and present only when that module is imported |

Two identities the package REPORTS but that answer no requirement are
deliberately not declared: `policy-coverage` (`verifier/bank.py:296`) and
`policy-resolver` (`swarm/runtime.py:218`) are the synthetic ids of the
`Unavailable` outcomes the bank and the resolver mint, and no policy may permit
them — one that tries is now refused. Identities composed at construction
(`verifier/soft_levers.py:159, 216, 316`) and the caller-chosen `verifier_id`
of the two judges are not declared; every wrapper emits `Tier.SOFT`, which
cannot satisfy a requirement regardless (`policy/coverage.py:360-365`).

**How it was derived, stated honestly.** The registry is not computed from the
package at runtime, and it cannot be derived in the direction "the policy reads
the implementations": `swarm/runtime.py:44` imports `policy/profile.py` — a
cycle — and `verifier/runner.py` imports the sandbox adapters, which every
policy load would then drag in. So the derivation runs the other way, each
implementation importing its identity FROM the leaf, and what is DERIVED is the
check. `tests/conformance/test_implementation_registry.py` walks the whole
package and requires, in both directions, that every identity a site reports is
declared naming that site, and that every declaration resolves to a site that
reports it BY REFERENCE — an AST check that the assignment is a `Name` or the
declaring call and never a string literal, because a value comparison cannot
tell a copy from a reference when the strings are equal. A package that cannot
be fully imported is refused as `SweepIncomplete`, not measured in part.

**What could vary outside the derivation:** order — a declaration must run
before a policy names it; the shipped ones are declared by the leaf the policy
module imports first, so a shipped profile cannot see an empty registry, while
a deployment's own implementation must import before its policy constructs, and
there is no un-declare; composed identities, above; and existence is not
correctness, below.

**Does any currently shipped requirement name an implementation that does not
exist?** Measured: **no.** Both committed profiles' permitted names —
`subprocess-tests`, `git-merge-check`, `swarm-checks` — resolve to declared
sites that report them live. Before this change the same fact held, kept true
by `test_the_shipped_profile_names_implementations_that_really_exist` comparing
three copies by hand; it is now true by construction and pinned by
`test_every_shipped_profile_names_only_implementations_the_package_reports_under`.

**Can `IMPL_*` be derived rather than hand-maintained?** Yes, and they are: each
is a reference to its declaration, not a spelling. What prevented the other
direction is the import graph above.

**Unregistered is not unavailable.** "No such implementation" is a
`PolicyError` at construction; "exists but could not answer" is doctrine #1's
`Unavailable` at assessment, refused by coverage as `coverage.incomplete`.
Different types, different moments, and the two reason vocabularies are
disjoint —
`test_no_such_implementation_and_implementation_unavailable_are_different_refusals`.

**Substitution, not only deletion.** A policy that swaps one registered
identity for another — `swarm-checks` where it meant `subprocess-tests` —
constructs. **Registration cannot catch that, and this entry does not claim it
does.** The first version of this paragraph then claimed the policy digest and
coverage catch it. Review (PR #111, P2) showed that holds only for a swap made
AFTER authoring, judged against evidence for the original policy, and that a
swap PRESENT at authoring is caught by nothing in this tree — see the review
round below, and **G27**. At a SITE, a swapped reference is caught by the
forward check (the site reports another declaration's identity) and by the
reverse sweep; two sites claiming one identity are refused by the registry
itself (`ImplementationConflict`).

**The empty set.** With the registry emptied, construction refuses under its
own reason rather than under "not registered" N times, and the positive control
constructs once the declarations are back:
`test_an_empty_registry_refuses_distinctly_rather_than_reading_as_permissive`.

**Named limits, as passing tests.** Requested checks from the untrusted side are
NOT validated against the registry — they may only add, and an unsatisfiable
addition refuses the whole action at coverage
(`test_requested_checks_are_not_validated_here_and_that_is_a_named_limit`); and
a policy constructed before its implementation declares is refused, not
deferred (`test_a_declaration_must_precede_the_policy_that_names_it`).

**Executed mutations** — through `scripts/mutation_worktree.py`, in a
disposable worktree carrying the exact working tree that became this commit,
primary tree untouched. Targets: nine conformance modules (the registry proofs,
coverage enforcement, policy enforcement regression, the execution descriptor,
unbound authorization, advisory-cannot-satisfy, hold pinning, the authorization
record, the git tool), 162 tests, all green unmutated. Run twice; the runs were
identical.

| mutation | class | observed | what it establishes |
|---|---|---|---|
| M1 the registry check removed (the `for name in self.permitted` loop iterates nothing) | deletion | **3 failed, 159 passed**: `test_a_misspelled_implementation_is_refused_at_construction_with_the_typed_reason`, `test_no_such_implementation_and_implementation_unavailable_are_different_refusals`, `test_a_declaration_must_precede_the_policy_that_names_it` | The check is load-bearing, and three proofs name it |
| M2 second-order: the refusal still raises, `reason=` dropped | second-order | **3 failed, 159 passed** — the SAME three as M1 | No proof relies on the raise alone: every proof that asserts the not-registered refusal asserts its reason. The raise carries the "it refuses" half and the reason the "which refusal" half; nothing survived that should have reddened |
| M3 the empty-registry refusal removed (`if not registry` → `if registry is None`) | deletion | **1 failed, 161 passed**: `test_an_empty_registry_refuses_distinctly_rather_than_reading_as_permissive` | With the distinct check gone an empty registry is still refused — by the per-name loop, under the WRONG reason — so what the proof catches is the loss of the distinct reason, not a fail-open |
| M8 M1 and M3 together: an empty registry would accept everything | deletion, the doctrine #8 shape | **4 failed, 158 passed**: M1's three plus the empty-registry proof | The fail-open the brief asked about is reachable only by removing both checks, and is then caught four times |
| M4 a site re-spells its identity as a literal (`VERIFIER_ID = "subprocess-tests"` in the runner) | deletion of the reference | **1 failed, 161 passed**: `test_every_declared_site_reports_its_identity_by_reference` | A value comparison passes this — the strings are equal — and only the AST check catches the copy |
| M5 a site's reference swapped for another declaration (`VERIFIER_ID = SWARM_CHECKS` in the runner) | cross-context substitution | **7 failed, 155 passed**: the by-reference sweep, the reverse sweep, the shipped-profiles proof, the pre-existing hand-agreement test in coverage enforcement, and three positive controls in policy enforcement regression whose real `SubprocessVerifier` evidence no longer satisfies `subprocess-tests` | Both directions of the sweep catch it, and so does the real verifier's evidence failing coverage |
| M6 the declaration deleted (`SUBPROCESS_TESTS = "subprocess-tests"` in the leaf, no `declare_implementation`) | deletion | **no summary line** — every target module failed at COLLECTION: importing `policy/profile.py` raises `PolicyError: requirement 'executable.cases' permits 'subprocess-tests', which is not the identity of any declared implementation` at the baseline profile's own construction (`profile.py:409` → `:180`) | The shipped profile refuses to exist without the declaration: correct, and the strongest possible red. See the note below |
| M7 the baseline policy swaps one registered identity for another (`permitted=(IMPL_SWARM_STRUCTURAL,)` on `executable.cases`) | substitution in the policy | **19 failed, 143 passed**, across coverage enforcement (11), policy enforcement regression (5), the execution descriptor (2), and the registry module's requested-checks limit proof (1). `test_a_swap_between_two_registered_implementations_is_NOT_the_registrys_property` stayed GREEN, as it states | Registration does not catch it and no proof claims it does; the policy digest and coverage do, nineteen times over |

**Round two — the site check, after the PR #111 review.** Same runner, same
disposable-worktree discipline, four target modules (the registry proofs,
coverage enforcement, advisory-cannot-satisfy, the execution descriptor), 91
tests, all green unmutated.

| mutation | class | observed | what it establishes |
|---|---|---|---|
| M9 site verification removed from the resolver | deletion | **2 failed, 89 passed**: the pointing-nowhere proof, the reports-another-identity proof | The resolver's check is load-bearing, and both path-declared refusals name it |
| M10 site verification removed from `load_profile` | deletion | **1 failed, 90 passed**: `test_the_committed_profiles_verify_every_declared_site_at_load` | The load-time check is separately load-bearing: the resolver's check does not stand in for it, because a committed profile is loaded before anything is resolved |
| M11 path declarations marked verified without checking (the cache poisoned) | cross-context substitution | **2 failed, 89 passed** — the same two as M9 | A verified mark that nothing earned is caught exactly where the missing check would be: the proofs test the property, not the code path |
| M12 a resolved site that reports a different identity accepted | substitution | **1 failed, 90 passed**: the reports-another-identity proof | The identity comparison, not merely the import, is what the proof pins |
| M13 the class-in-hand check removed at declaration | deletion | **1 failed, 90 passed**: `test_an_extension_class_reporting_another_identity_is_refused_at_declaration` | The on-the-spot form has its own proof; the path form's proofs do not cover it, and were not expected to |

**Round three — SECOND-ORDER probes on the site-check proofs.** Every
mutation keeps the raise and drops only the part that names the property: the
typed reason, the implementation or identity attribute, or the message the
proof reads. A proof that survived would be one resting on the raise alone.
Two target modules (the registry proofs, coverage enforcement), 51 tests, all
green unmutated.

| mutation | observed | what it establishes |
|---|---|---|
| S1 `reason=` dropped from the load-and-resolve refusal (the raise stays) | **3 failed, 48 passed**: the pointing-nowhere proof, the reports-another-identity proof, the committed-profiles-at-load proof | Every path-declared proof asserts the typed reason; none rests on the raise |
| S2 the resolver's re-raise drops only the reason it copies | **2 failed, 49 passed**: the two resolution proofs | The load proof survived, correctly — its path never enters the resolver — and the two that do enter it assert the reason survives the re-raise |
| S3 `implementation=` dropped from the load-and-resolve refusal | **3 failed, 48 passed**: the same three as S1 | The proofs assert WHICH implementation, not only which reason |
| S4 `identity=` dropped from the class-in-hand refusal | **1 failed, 50 passed**: the class-mismatch proof | The on-the-spot refusal's identity attribute is asserted |
| S5 the class-in-hand message stops naming what the class reported | **1 failed, 50 passed**: the class-mismatch proof | The proof reads the message for the reported identity, so a refusal that stops saying what it found reddens it |
| S6 the unresolved-site message stops naming the site | **1 failed, 50 passed**: the pointing-nowhere proof | The proof reads the message for the site, so a refusal that stops saying where it looked reddens it |

No second-round proof survived a probe aimed at its own property-naming half.
Three proofs have no second-order probe because they assert no refusal: the
extension positive control, the committed profiles' positive half, and the
G27 limit test — each states an acceptance, and an acceptance has no reason to
drop.

**A note on M6, because it is the doctrine #8 shape inside the tool.** The
mutation runner reported `(no summary)` and an EMPTY red list. Read carelessly,
that is GREEN. It was a collection failure, and the raw pytest output was
captured on a second run to say so. `MutationWorktree.pytest` returns
`(no summary)` when pytest prints no ` passed`/` failed` line, and a caller that
treats that as "nothing red" has the empty-set-reads-as-pass failure inside the
instrument built to find failures. Not changed here — outside this sprint's
scope — and recorded so the next mutation proof reads that value as "not
measured", never as green.

### Review round on PR #111 — two findings, both correct, both changed this entry

**Finding 1 (`policy/implementations.py`, P2): "Validate extension
implementation sites before registering them."** Quoted: *"this assignment
accepts any non-empty `implemented_by` string without resolving it or checking
that the target reports `identity`; `PolicyRequirement` subsequently checks
only the resulting key. For example,
`declare_implementation("custom", implemented_by="missing.module.Verifier")`
makes a policy permitting `custom` construct successfully and then fail forever
as incomplete coverage—the exact configuration-as-runtime-outage case this
registry is intended to prevent. The conformance sweep does not protect
installed extensions, so registration needs runtime validation or a production
validation/finalization step."* **Correct.** The sweep verified only sites
under `prometheus_protocol.`, and only in the suite. A deployment's declaration
was G26's unchecked string, one layer up.

**What changed.** A declaration is a CLAIM, and the claim is now tested. Two
forms. Declared **with the class in hand** — `implemented_by=MyVerifier` — the
registry verifies at the declaration that the class reports the identity at
class level; if it does not, the declaration is refused and nothing is
recorded. Declared **by dotted path** — recorded, and verified by
`verify_implementation()` when the policy is put to use: `load_profile()`
verifies the whole profile, and the trusted resolver verifies the applicable
requirements on every `resolve()` (`policy/resolver.py`), which is the one door
every policy passes on its way to an assessment, so a policy VALUE that never
went through `load_profile` — the customer-supplied shape R1 anticipates — is
checked there. The refusal is the new typed reason
`implementation_site_unresolved`, carrying the implementation, its requirement
and the site. Why a path is not verified at declaration: the shipped
declarations name sites inside the package that the registry module cannot
import (the cycle recorded above), and a deployment module declaring itself by
path while it is being imported has the same shape. A verified identity is
remembered for the process. **Named limit:** the identity must be reported at
CLASS level (own `VERIFIER_ID` or `verifier_id`) or by a module constant; an
instance-only identity cannot be verified without constructing the verifier,
which the registry will not do, and such a site is refused as reporting
nothing.

Tests: the review's example, verbatim
(`test_a_declaration_pointing_nowhere_is_refused_when_the_policy_is_resolved`);
a site that resolves but reports another identity
(`test_a_declaration_whose_site_reports_a_different_identity_is_refused_at_resolution`);
a class declared for an identity it does not report
(`test_an_extension_class_reporting_another_identity_is_refused_at_declaration`);
the committed profiles verified at load, with a shipped declaration re-pointed
at a missing site refused there
(`test_the_committed_profiles_verify_every_declared_site_at_load`); and the
positive control, an extension declared by class that resolves and satisfies
its requirement
(`test_an_extension_declared_with_its_class_is_verified_on_the_spot_and_works`).
The test doubles every existing suite declares now go through the class form,
so they are verified before any policy names them.

**Finding 2 (`docs/OPEN-GAPS.md`, this entry, P2): "Correct the claimed
protection against registered-ID swaps."** Quoted: *"When the wrong registered
identity is already present when a policy is authored, neither cited control
catches the substitution: the digest faithfully binds the swapped policy, and
coverage accepts a result whose `implementation` and `outcome.verifier_id` both
equal that newly permitted identity. In particular, an authoritative
`swarm-checks` result bound to `executable.cases` produces `CoverageSatisfied`;
the referenced test only supplies stale `subprocess-tests` evidence and
therefore proves mismatch rejection, not swap detection. This claim can lead
readers to rely on a nonexistent authorization control and should be removed or
backed by an implementation-to-check binding."* **Correct.** The claim is
withdrawn (the substitution paragraph above now says so). What it described
catches a swap made after authoring, against evidence for the original policy;
a swap present at authoring is self-consistent, and nothing in this tree
objects, because nothing binds an implementation to the checks it may answer.
Filed as **G27**, with the reason the binding is not built here. The test is
renamed to what it proves
(`test_a_swap_between_registered_implementations_present_at_authoring_is_caught_by_NOTHING`)
and now asserts the `CoverageSatisfied` the review described, with the
stale-evidence refusal kept and labelled as mismatch rejection.

**The residual, unchanged from when this was filed:** a registry proves the
name resolves to *something declared* — and now, when used, to something that
REPORTS the identity — not that the something does what the check means. A stub
registered under a real implementation's identity would satisfy the registry
and answer the requirement. That is a different control — implementation
identity is what coverage keys on (`policy/coverage.py:272-284`), and a
verifier's tier is fixed once known (`verifier/bank.py:138-165`) — and the
registry is not described as closing it. A policy that permits the wrong
registered implementation for a check is G27's, and is closed by nothing yet.

**Tests.** `tests/conformance/test_implementation_registry.py` (18), in CI's
full-suite job, none skipped. Four Hearth files re-sanctioned with the reason
beside the digests; the type gate re-pinned 314 → 316.

---

## G27 — no implementation-to-check binding: a policy may permit the wrong registered implementation for a check, and nothing objects

**Found by review (PR #111, P2), as a false claim in G26's closing text.**

**What.** `PolicyRequirement.permitted` says which implementations may satisfy
a check. The registry (G26) now guarantees each name is an implementation that
exists and, when used, reports that identity. Nothing guarantees it is an
implementation OF THAT CHECK. A policy authored with `permitted=("swarm-checks",)`
on `executable.cases` constructs, resolves, and is satisfied by an
authoritative `swarm-checks` result bound to that check: coverage compares the
result's `implementation` with the evidence's `verifier_id` and with the
permitted set (`policy/coverage.py:272-284`), and all three agree. The policy
digest binds the swapped policy faithfully. It is self-consistent, and wrong.

**Why it was misdescribed.** G26's first closing text said the digest and
coverage catch a registered-for-registered swap. They catch a swap made AFTER
authoring: evidence produced for the original policy's implementation is
refused under the swapped one as `coverage.invalid_evidence`, and a pinned
record's policy digest no longer matches the selected policy. That is mismatch
rejection. A swap present at authoring has no original to mismatch against. The
test that carried the claim supplied only the stale evidence and so proved the
narrower property; it is renamed, and now asserts the acceptance as well.

**Where the line is.** Which implementations may answer which check is the
policy author's assertion: R3 says the permitted set is the operator's
equivalence claim, and R1 says the policy is the deployment's risk decision. A
wrong permitted set is therefore an authoring error above every mechanism in
this tree. The control that would catch it is an **implementation-to-check
binding** — each implementation declares the check identities it answers, and
policy construction refuses a permitted implementation that does not answer
the requirement's check. That needs a ruling on who declares (the
implementation, beside its identity in `policy/implementations.py`, for the
shipped ones) and on how a customer implementation declares, and it is not
built here: a control nobody has ruled on would pin a shape, which is the same
reason G26 itself was filed without a test.

**Test.** The limit, as a passing test (doctrine #5):
`test_a_swap_between_registered_implementations_present_at_authoring_is_caught_by_NOTHING`
in `tests/conformance/test_implementation_registry.py` — the swapped policy's
own authoritative result is `CoverageSatisfied`.

**Docs corrected under this entry (doctrine #9):** G26's substitution
paragraph, and `docs/live-state-pinning-design.md` §7.5, whose
`CHECK_TARGET_STATE` row claimed the registry covers "a different
implementation answering it". It covers an UNDECLARED one, one whose declared
site does not report it, and a second site claiming the identity — not a wrong
registered one the policy itself permits.

---

## G28 — the assistant's GitHub channel appends a vendor footer to PR bodies and review replies after the text has passed the hygiene checker, and no guard sees a review reply

**Measured three times on 2026-09-15, each time on text that had passed
`scripts/check_message_hygiene.py --text-file` before it was sent.**

* **PR bodies.** #111 was opened with a checked body; the body GitHub stored
  ended with a two-line footer naming the vendor and its product, appended by
  the tool that created the PR. All three build jobs and pr-text refused at
  "Message hygiene (commit messages, identities, PR title and body)" with
  `message hygiene FAILED: pr-body.txt contains banned token(s)` naming the two
  tokens. The body was rewritten through the update tool, which appends nothing
  (read back to confirm), and a push re-triggered `ci.yml` with the clean
  payload. #112 reproduced it exactly at creation: pr-text refused the created
  body at 19:18:13Z and re-ran on `edited`; the three build jobs ran against the
  frozen created payload; this entry's own commit is the push that clears them.
* **Review replies.** The reply tool appends the same footer, without the link.
  Read back: the five #109 replies, the #108 reply and the #106 reply all carry
  it — seven observed. The two #111 replies went through the same tool and were
  not read back before the thread listing was rate-limited. No workflow checks
  a review comment: `ci.yml` checks commits, title and body, and
  `pr-text-hygiene.yml` checks title, body and the composed squash message. The
  tokens on those replies sit outside every guard, and were found only because
  a reply was read back for another reason.

**What the guards do and do not cover, stated.** A PR body is refused before
merge by two workflows and can be rewritten. A review reply is refused by
nothing, cannot be edited or deleted through this channel, and stays as posted.
The route is the channel, not the text: every body and reply had passed the
checker as written, and the checker cannot see what is appended after it runs.

**What closes it.** Not anything inside the repository: the footer is added by
the tooling that posts, after the text leaves the checker. Either the channel's
own attribution setting (a `DriivAIDev/disable-attribution` branch exists on
the remote and was not examined here), or a workflow that reads review comments
through the API and refuses on banned tokens, which would detect and not
prevent.

### Is there a posting path WITHOUT the footer? Measured 2026-09-15.

Four paths were tried. **No path that POSTS A COMMENT omits the footer.**

| path | appends? | observed |
|---|---|---|
| the inline review-reply tool | **yes** | nine replies, all read back (table below) |
| the issue/PR-comment tool — a different tool, probed deliberately | **yes** | comment `5687317374` on #112, posted 20:02:37Z and read back immediately: the footer is there. This is the load-bearing observation: the append is a property of the CHANNEL, not of one tool, so "use the other comment tool" is not a remedy |
| the PR-creation tool | **yes** | #111 and #112 both; their created bodies were refused by CI |
| the PR-UPDATE tool | **no** | the rewritten bodies of #111 and #112 came back clean and pr-text passed on both. This is why a body can be repaired and a comment cannot |

There is no raw-REST escape hatch in this environment: the only GitHub access
is through these tools (no `gh`, no direct API), so "call the endpoint
directly" was not available to try, and that is a limit of the environment
rather than a finding about GitHub. The probe comment is itself now a carrier,
deliberately: measuring cost one comment, and the alternative was to assert the
answer without testing it.

### PROM-IP PART B DOES NOT CLEAN THIS UP

Part B is a **history rewrite** — commit messages and identities (see this
file's G6 sizing, "the sizing PROM-IP Part B asked for"). A review comment is
not in git history at all: it lives in GitHub's API, attached to a pull
request. Rewriting every commit on every branch leaves all ten carriers exactly
where they are, on merged pull requests, and a force-push does not touch them.
Whether that matters for the provenance story is a judgement for whoever runs
Part B; what is recorded here is that it is **not** swept by it, so the
question is answered before diligence rather than during it.

### THE BOUNDED SET — twenty-nine carriers, ALL twenty-nine read back

(Three more have been observed since, outside this table: carriers 30, 31 and 32
are recorded in prose below, and the running total is stated there.)

| PR | kind | id |
|---|---|---|
| #106 | review reply | `4011093860` |
| #108 | review reply | `4011775351` |
| #109 | review reply | `4012114040` |
| #109 | review reply | `4012117730` |
| #109 | review reply | `4012118993` |
| #109 | review reply | `4012120458` |
| #109 | review reply | `4012154122` |
| #111 | review reply | `4012711563` |
| #111 | review reply | `4012712585` |
| #112 | PR comment | `5687317374` (the probe above) |
| #113 | review reply | `4020508859` |
| #113 | review reply | `4020509721` |
| #113 | review reply | `4020510841` |
| #113 | review reply | `4020511688` |
| #113 | review reply | `4020512632` |
| #113 | review reply | `4020513244` |
| #114 | review reply | `4021539074` |
| #114 | review reply | `4021539794` |
| #115 | review reply | `4021825848` |
| #117 | review reply | `4022309714` |
| #116 | review reply | `4022357029` — confirmed via REST |
| #118 | review reply | `4022525539` — confirmed via REST |
| #119 | PR body | `4544106496` — read back, confirmed, stripped |
| #119 | review reply | `4022679600` — confirmed via REST, same minute |
| #120 | PR body | `4547756338` — read back, confirmed, stripped |
| #120 | review reply | `4026263917` — confirmed via REST, same minute |
| #121 | PR body | `4552026493` — read back, confirmed, stripped, strip confirmed |
| #121 | review reply | `4030797503` — confirmed via REST, same minute |
| #121 | review reply | `4030798875` — confirmed via REST, same minute |

Twenty-five review replies, one PR comment and three PR bodies. Not approximate:
every row was fetched and its body inspected for the footer. The last two
unconfirmed rows were closed on 2026-09-16 through the REST channel described
below, and every row added since has been confirmed in the minute it was
created — which is what that channel buys. The six #113 replies are the answers to
that PR's six findings, posted after it merged; `4020508859` was read back and
the footer is present, so the route is unchanged and this entry is not stale. PR BODIES are not in this set — #111's and
#112's created bodies carried it, were refused by CI, and were rewritten
through the update tool, which appends nothing; the stored bodies are clean.

**THIRD OCCURRENCE OF THE BODY ROUTE, #113, 2026-09-15.** The pull request was
opened with a one-line PLACEHOLDER body and rewritten through the update path
immediately, rather than opened with the real body and repaired afterwards.
That is the remedy this entry's table implies, used deliberately for the first
time: the created body still carried the footer and still refused, but it
carried nothing else, so nothing of substance was ever in a refused payload and
the rewrite was one call rather than a reconstruction. `ci.yml` reads the
frozen payload, so the three build jobs still need a push to clear — which is
what the commit carrying this paragraph is.

**FOURTH OCCURRENCE ON #114 — AND IT IS A DIFFERENT ROUTE, which is why this
paragraph exists rather than a bump to the count above.** #114 was opened with
a placeholder body and rewritten through the update path, exactly as the
paragraph above prescribes. The update tool appended nothing, as recorded. The
body refused anyway, with `check_message_hygiene.py` reporting `pr-body.txt`
as carrying a banned token.

**That refusal message is deliberately NOT quoted verbatim here, and the reason
was measured on this paragraph.** The message names the token it found, and
`check_hygiene.py` scans tracked files — this file among the 415 it reports.
The first draft of this paragraph carried the quote and `check_hygiene.py`
refused it locally before it could be pushed. So the two controls compose in a
way neither one states: **a finding from `check_message_hygiene.py` cannot be
recorded verbatim in the tree `check_hygiene.py` scans.** Worth naming, because
the instinct when writing an entry like this is to paste the evidence, and here
the evidence is itself the contraband.

**The token was in the text the AUTHOR wrote.** A session-attribution URL was
appended to the body by hand. No tool added it; the remedy this entry
prescribes was followed correctly and could not have caught it, because the
remedy addresses a tool that appends and this was a human-authored line.

**What that corrects in this entry.** The table's "the PR-UPDATE tool —
appends? **no**" row is still true and is now insufficient on its own: it
licenses a reading in which a body written through the update path is safe,
and what it actually establishes is only that the TOOL adds nothing. The
author's own text is a separate route with no instrument in front of it —
`check_hygiene.py` scans the repository, `check_message_hygiene.py --commits`
scans commit messages and identities, and neither sees a PR body until CI
reads the frozen payload, at which point the refusal has already happened.

**The cost, measured on this PR.** The `build` job runs the PR-text step
BEFORE the suites, so one banned token in the body reddened all three Python
jobs and `pr-text` — four red jobs, no test failure, and every step after the
hygiene check unrun on all three versions. The type gate had already passed
(320 files, each version) and the repository hygiene check had already passed
(415 files). A body typo costs a full CI cycle.

**FIFTH OCCURRENCE, #115 — the ORIGINAL route, and now it has a fingerprint.**
#115 was opened with a placeholder body carrying no author-written link, and
the created body refused anyway: the creation tool appended the footer after
the checker had run, which is the route the table above records. The remedy
worked as designed — nothing of substance was in the refused payload, and the
rewrite through the update path made the re-triggered `pr-text` pass on the
`edited` event within forty seconds.

**The two routes are distinguishable from the refusal alone**, which is worth
recording because the body itself may be gone by the time anyone reads the log:

| route | tokens named in the refusal |
|---|---|
| author-written attribution link (#114) | one |
| the creation tool's appended footer (#115) | two — the vendor name appears both bare and as a two-word product name |

A future reader diagnosing a refused `pr-body.txt` can tell which happened from
the count, without recovering the payload.

**What it still costs, measured twice now.** `ci.yml` reads
`github.event.pull_request.body` frozen at trigger time, so rewriting the body
clears `pr-text` on the `edited` event but NOT the three build jobs: those
carry the stale payload and fail at the hygiene step in about thirty seconds,
before any suite runs. Only a push clears them. On #115 that cost a full build
cycle on three Pythons for a body that was already correct in storage.

**TWO CARRIERS WERE LISTED WITHOUT BEING READ BACK — AND THE WAIT WAS
UNNECESSARY.** `4022357029` and `4022525539` were each posted while the
review-thread listing was rate-limited, and were marked EXPECTED-not-OBSERVED
rather than omitted. Both are now **confirmed**: `GET /repos/{owner}/{repo}/
pulls/comments/{id}` returned HTTP 200 for each, footer present, while the
GraphQL listing was still refusing. See the fourth-channel note below — this
entry's own prescription was wrong, and the rows were markable as read for as
long as they sat marked as unread.

**A SECOND CHANNEL FOR THE SAME OBSERVATION, found while waiting on the
first.** `4022309714` was also posted under the rate limit and was first
recorded as not read back. It then came back through the PR-activity webhook,
whose payload carries the comment body AS STORED — footer included, and this
session did not write that footer. So the stored body was observed without the
GraphQL listing at all.

That matters beyond one row: the listing is hourly-limited and the webhook is
not, so "the footer cannot be confirmed right now" is a statement about ONE
channel rather than about the fact. Where a reply is answered by a later
webhook event, the confirmation is already in hand. Recorded because the
earlier paragraph implied waiting was the only option, and it was not.

**SIXTH OCCURRENCE, #116 — identical to the fifth, and that is the point.**
Same placeholder body, same appended footer, same two-token refusal, same three
build jobs dead at thirty seconds, same clearing push. Recorded as a single
line rather than a fifth paragraph, because the route is no longer being
discovered — it is being paid.

**THE STANDING COST, NAMED ONCE.** With the creation tool appending a footer
the checker never sees, every pull request opened this way spends one build
cycle on three Pythons before its first real run. The placeholder keeps
anything of substance out of the refused payload and the update path stores a
clean body within a minute, but neither clears the jobs that froze the created
one. That tax is unavoidable from inside this repository: it is a property of
the tool that opens the pull request, not of anything the tree can check or
configure. Stated here so it is a known price rather than a recurring surprise,
and so a future change to how pull requests are opened has a reason recorded.

**No new instrument.** The same limit as the rest of this entry: nothing in the
tree can read a PR body before it is posted. What changed is the claim, which
now says the update path protects against the tool and not against the author.

**The coverage claim was narrowed in six places** rather than left to be
read around, the same correction G23 took: `CONTRIBUTING.md`, `CHANGELOG.md`,
this file's G6 control paragraph, `scripts/check_message_hygiene.py`'s
docstring, and the step comments in both workflows now say that review comments
are outside the checked surface.

**Test.** None. Nothing in the tree can observe a review comment, and a test
that could would be reading GitHub, which the suite does not do. The narrowed
claims are prose, and prose is what this entry can offer.

**CARRIER 30, observed opening #123, and it cost a full red matrix.** The rate
holds: 10 of 10 pull requests opened through that channel have carried the
footer. What this occurrence adds is the SECOND-ORDER cost, which the entry had
not recorded. The footer is appended after the checker runs, so the body is
clean locally and dirty on GitHub; `update_pull_request` appends nothing and
removed it, and the `pr-text` workflow — which answers to `edited` — re-ran and
passed. But `ci.yml`'s own message-hygiene step reads
`PR_BODY: ${{ github.event.pull_request.body }}`, frozen at the triggering
event, and that event was the OPEN, whose payload still carries the footer. All
three matrix jobs therefore failed at step 10 with steps 11-51 skipped, on a
tree whose body was already correct, and re-running the jobs replays the same
stale payload. **Only a push re-triggers `ci.yml` with the corrected body.**
So the footer does not cost one refusal, it costs a matrix run and a commit
whose only purpose is to move the head — this one.

**CARRIER 31, observed opening #124. 11 of 11.** Identical shape and identical
cost, one pull request later, which is what a rate of 11 of 11 means in
practice: the footer is not an occasional slip to be watched for, it is the
channel's behaviour, and every pull request opened through it pays the same
matrix run. The only thing this occurrence changes is that the second commit it
forces was not empty — the proof counts below were held back for it — so the
cost this time was the matrix run alone.

**CARRIER 32 is a REVIEW REPLY, `4033141749` on #123, and it stands.** The
answer to the P2 that G45 records. It carries the footer for the same reason
the bodies do, and unlike them it cannot be cleaned: the channel offers no edit
for a review comment, only `add_reply_to_pull_request_comment`, so a correction
would be a second comment beside the first rather than a fix to it. That is the
asymmetry this entry has claimed since it was written, now observed once more on
the reply that answers a real finding.

**CARRIERS 33 to 35, all in the same working session**, which is the point
worth recording rather than the individual ids: a pull-request comment
(`5708938608`, reporting the matrix -- footer stripped afterwards, so it is a
carrier that existed rather than one that stands), and two review replies that
DO stand, `4036299792` on #123 withdrawing an over-wide claim and `4036455730`
on #124 answering a second reported defect. Three in one session, on three
different surfaces, none of them avoidable by care: the two that stand are the
two the channel offers no edit for.

Counting the bounded table's composition (25 review replies, 3 pull-request
bodies, 1 pull-request comment) plus carriers 30 to 35, the running total is
**35: 28 review replies, 5 bodies, 2 comments.** Stated with its composition
because a total alone is the shape G25 refuses, and recounted from the ids
rather than incremented: the previous total here was carried forward by
addition once and came out one short, which is what an unrecounted running
total does.

**CARRIER 36, opening #125. 12 of 12.** The rate has not moved and there is
nothing new to say about the mechanism; it is recorded because a rate claimed
without its next observation decays into a remembered number. Stripped via
`update_pull_request` as usual, which means `ci.yml`'s frozen `PR_BODY` still
carries it on the OPEN event and only this push clears it -- the cost carrier 30
first measured. **Running total 36: 28 review replies, 6 bodies, 2 comments**,
recounted rather than incremented.

**CARRIER 37, the three-version matrix comment on #125 (`5715808954`).** Posted
through the comment channel, read back with the footer present, stripped through
`update_issue_comment`, read back clean -- so it is a carrier that EXISTED
rather than one that stands, the same shape as carrier 33 and unlike every
review reply in the table above. Recorded for the reason the paragraph above
gives, not because the mechanism changed.

**What no check in this repository would have caught, stated because the
stripping was a choice and not an enforcement:** `ci.yml` reads
`github.event.pull_request.title` and `.body` and the branch's commit messages.
`pr-text-hygiene.yml` reads the title and body on `edited`. Neither reads a pull
request COMMENT, exactly as neither reads a review reply -- and none of the six
workflows in `.github/workflows/` triggers on a comment event at all, checked by
reading every `on:` block rather than the two that seemed likely. The footer on
`5715808954` was found by reading the comment back, which is a habit, not a
guard -- which is this entry's standing point and the reason the count is kept
by hand.

**Running total 37: 28 review replies, 6 bodies, 3 comments.** Recounted from
the bounded table's composition (25 review replies, 3 bodies, 1 comment) plus
carriers 30 to 37, not incremented.

**CARRIER 38, opening #126 (`4561120456`). 13 of 13.** Opened with a
one-line placeholder body, read back carrying the footer, rewritten through
`update_pull_request`. The matrix comment on #125 that carrier 37 records was
edited rather than followed by a new comment, so #125 closed at 37; this is the
next pull request's opening, recorded at the push that clears it — which is
this commit, for the reason carrier 30 first measured: `ci.yml` reads the
frozen `PR_BODY` on the OPEN event, and its message-hygiene step refuses the
placeholder's footer on `270238b` until a push re-triggers it with the clean
body. **Running total 38: 28 review replies, 7 bodies, 3 comments**, recounted
from the bounded table (25 review replies, 3 bodies, 1 comment) plus carriers
30 to 38, not incremented.

**CARRIER 39, opening #127 (`afa32de`'s pull request). 14 of 14.** Opened with
the FULL body — not a placeholder — read back carrying the footer, rewritten
through `update_pull_request`. Fourteen of fourteen openings, with no exception
in either direction: a one-line placeholder and a ten-thousand-character body
are appended to identically.

**A REFINEMENT MEASURED HERE, which narrows what "only a push clears it"
means.** This repository runs the body check in TWO places, and they behave
differently:

* the standalone `pr-text` workflow re-ran on the `edited` event and
  **PASSED** (`35293021482`, 7s) once the footer was stripped;
* the same check inside each `build` job read `PR_BODY` frozen at the OPEN
  trigger and **FAILED** on all three Pythons (`35292928221`), in 31–45s,
  after the type gate (343 files), the receipt check and the repository
  hygiene check had all passed — so the failure is genuinely the stale
  payload and nothing else.

So "only a push clears a stale text refusal" is true of the BUILD jobs and not
of `pr-text`, and a reader seeing one green and one red on the same body is
looking at that split rather than at a flake. The commit carrying this
paragraph is the push that clears the build jobs, for the reason carrier 30
first measured. **Running total 39: 28 review replies, 8 bodies, 3 comments**,
recounted from the bounded table (25 review replies, 3 bodies, 1 comment) plus
carriers 30 to 39, not incremented.

**CARRIER 40, opening #128 (`6b95f4e`'s pull request). 15 of 15.** Full body
again, appended to identically, rewritten through `update_pull_request`. The
two-check split recorded at carrier 39 reproduced exactly: `pr-text` red on the
frozen body then green on the edit, the three `build` jobs red on their own
frozen copy until this push. A second observation of a measured behaviour, so
the split is a property of the workflow rather than one run's accident.
**Running total 40: 28 review replies, 9 bodies, 3 comments**, recounted from
the bounded table (25 review replies, 3 bodies, 1 comment) plus carriers 30 to
40, not incremented. The three review replies posted on #127 while fixing its
findings are carriers 41 to 43 by the same rule, recorded at the next push.

**CARRIERS 41 TO 46**, enumerated rather than batched:

| carrier | channel | where |
|---|---|---|
| 41, 42, 43 | review replies | the three answers on #127's findings |
| 44, 45 | review replies | the two answers on #128's findings |
| 46 | body | the opening of #129 |

**16 of 16 openings** carry the footer, with no exception in either direction.
The five review replies cannot be edited — that is this entry's fourth-channel
note — so they stay as posted and are recorded rather than repaired; the body
was rewritten through `update_pull_request`. **Running total 46: 33 review
replies, 10 bodies, 3 comments**, recounted from the bounded table (25 review
replies, 3 bodies, 1 comment) plus carriers 30 to 46, not incremented.

**THE SPLIT HELD A THIRD TIME.** #128's opening reproduced carrier 39's
measurement again: `pr-text` red on the frozen body then green on the edit, the
three `build` jobs red on their own frozen copy until a push. Three
observations of the same behaviour across three pull requests, so it is a
property of the workflow and not an accident of one run.

**CARRIERS 47 AND 48.** The reply on #129's finding (47, a review reply, not
editable) and the opening of #130 (48, a body, rewritten). **17 of 17
openings.** **Running total 48: 34 review replies, 11 bodies, 3 comments**,
recounted from the bounded table (25 review replies, 3 bodies, 1 comment) plus
carriers 30 to 48, not incremented. The two-check split held a fourth time.

**CARRIER 49, opening #131, and the footer was REWRITTEN in flight — observed,
not inferred.** The body was posted with the footer's link pointing at the
product's bare documentation root; read back immediately through the
pull-request API, that link has a session-scoped path appended to it. The
channel substituted a longer URL into text that had already left the hygiene
checker — this entry's exact subject in a form it had not yet recorded: not an
APPENDED trailer but an EDITED one. The link is not quoted here, because
quoting it would put the banned token in this file and the checker refuses it,
which is the correct behaviour and was measured by trying. **18 of 18
openings** carry the footer.
**Running total 49: 34 review replies, 12 bodies, 3 comments**, recounted from
the bounded table (25 review replies, 3 bodies, 1 comment) plus carriers 30 to
49, not incremented.

A note on what that rewrite costs and does not cost. It does not defeat the
hygiene checker, which refuses the token whatever URL follows it; the footer
was always going to be a carrier and is recorded as one. What is new is that
the link is not the link that was sent, so a reader reconciling a carrier
against what the author wrote cannot do it from the text alone.

**RECORDED AND THEN REPAIRED, and the first version of this paragraph got the
second half wrong.** It said the body was "recorded rather than repaired,
because rewriting it would remove the evidence of the rewrite" — reasoning from
this entry's own habit rather than from what the repository does. Checked
against the artifact: **#130's `pr-text` check conclusion is `success`**, and so
are all eleven of its checks. A red `pr-text` is not this project's steady
state; the body is repaired and the carrier record is what preserves the
evidence, which is the arrangement that keeps both. Corrected, and #131's body
was rewritten to clear the check.

**AND THE COMMIT CHANNEL IS NOT THE PR-TEXT CHANNEL.** #131's first three
commits were authored and committed under a vendor identity and carried a
session trailer in the message, so `check_message_hygiene.py --history` refused
**15 findings across 3 commits** — five per commit: the message, and the author
and committer names and addresses. Every prior carrier in this entry is text a
CHANNEL appended after the fact; these were in the commit objects themselves,
which is a different seam and one G13 already names for `main`. Re-authored to
the project identity and the trailer removed; the sweep over the same range now
reports `no commit carries a banned token in its message or identities`. The
attribution it carried is not lost — it is in this entry, which is a more
durable record than a trailer the guard refuses.

**AND A REPAIRED BODY CANNOT BE CLEARED BY A RE-RUN. The two-check split has
been recorded four times in this entry as a behaviour; this is its MECHANISM,
and it was measured rather than inferred.** `.github/workflows/ci.yml:129` hands
the text to the job as `PR_BODY: ${{ github.event.pull_request.body }}`. Re-running
a failed job REPLAYS THE ORIGINAL EVENT PAYLOAD rather than re-reading the pull
request, so a body repaired after the event is not in the copy the re-run sees.

Observed on #131, run `35350855570` attempt 2, head `52f98fa`, started
13:35:17Z — after the body had been repaired and after `pr-text` had already
gone green against the live text at 13:33:43Z:

```
message hygiene passed: 3 commit(s) in 1506b61..52f98fa, 17 terms, no banned
  tokens in any message or identity
message hygiene passed: pr-title.txt (83 chars), no banned tokens
message hygiene FAILED: pr-body.txt contains banned token(s)
```

The commit-range check in the SAME step passed, so the re-authoring recorded
above had taken and the body was the only thing left red; the job's own
environment dump still held the pre-edit body verbatim, footer included. Two
checks over one artifact, two minutes apart, disagreeing because they are
reading two different versions of it.

The trigger half of this was already known and is written down at
`.github/workflows/pr-text-hygiene.yml:3-13`: `ci.yml`'s bare `pull_request:`
expands to opened, synchronize and reopened and NOT `edited`, which is why that
workflow exists. What is new here is that the OTHER escape — re-running the
failed job — does not work either, so the set of things that can clear a
repaired body in `ci.yml` has exactly one member: a push.

WHY THIS IS RECORDED AND NOT FIXED. The remedies a red-on-stale-text job
invites are the two this repository forbids — an empty commit, and a close and
reopen — and the reason they are forbidden does not weaken because the red is
spurious. The remedy that remains is a push carrying real content, which is
what this commit is. Adding `edited` to `ci.yml` would re-run the whole
three-interpreter matrix on every description edit, and
`pr-text-hygiene.yml:22-28` already weighs that trade and declines it; nothing
measured here changes the inputs to it. The checker is not at fault in either
direction: it refused the text it was handed, and the text it was handed was
stale.

**CARRIERS 50 TO 53, AND AN UNDERCOUNT CORRECTED BEFORE IT WAS RECORDED.**
Answering the first review round on #131 meant three replies on its review
threads and one comment invoking a review on the final head — four carriers,
not the one an earlier draft of this paragraph named. That draft said "the
comment invoking a review is carrier 50", counting the channel it had in mind
and not the ones it had already used; the three replies precede the comment, so
the comment is 53. Corrected here rather than quietly amended, because an
undercount by three in a count that enters this entry is the doctrine this
entry exists under.

| carrier | channel | where |
|---|---|---|
| 50, 51, 52 | review replies | the three answers on #131's first review round |
| 53 | comment | invoking a review on the final head |

**Running total 53: 37 review replies, 12 bodies, 4 comments**, recounted from
the bounded table (25 review replies, 3 bodies, 1 comment) plus carriers 30 to
53, not incremented. #131's body has been rewritten several times and a rewrite
of an existing body is not a new carrier.

**CARRIERS 54 TO 56**, the second review round answered the same way:

| carrier | channel | where |
|---|---|---|
| 54, 55 | review replies | the two answers on #131's second review round |
| 56 | comment | invoking a review on the head that answered it |

**Running total 56: 39 review replies, 12 bodies, 5 comments**, recounted from
the bounded table plus carriers 30 to 56, not incremented. The THIRD round's two
replies and its review invocation are carriers 57 to 59 by the same rule,
recorded at the next push.

**AND THE RATE IS NOW THE ENTRY'S OWN SUBJECT.** Three review rounds on one
pull request produced ten carriers in under two hours. Every one is a channel
appending a vendor footer to text that had already passed the hygiene checker,
which is what this entry has recorded since #111 — but the earlier carriers
arrived one pull request at a time. What is new is the MULTIPLIER: a project
whose merge rule requires a review on the final head, and which answers each
finding on its own thread, generates carriers in proportion to how carefully it
reviews. Recorded rather than argued with: the alternative is answering fewer
findings, and that trade is not one this entry gets to make.

**THE COUNT IS ACCURATE AS OF THIS COMMIT AND CANNOT BE ACCURATE AFTER IT, which
is a property of the count and not an oversight.** Reporting this commit's own
CI means posting a comment, and that comment will carry the footer -- so
recording carrier 37 creates carrier 38, and recording 38 would create 39. The
regress terminates by saying where the line is instead of chasing it: every
carrier observed up to the commit that carries this paragraph is counted here,
and any carrier created while reporting it is recorded at the next push. A
total in this entry therefore means "as of its commit", never "as of now".

---

## G29 — re-observation at execution: built for `branch.delete`, opted out by name for the other two

**The gap, measured.** A hold records evidence at assessment time and executes
later against that evidence REPLAYED from the persisted record:
`execution/pending.py` restores the coverage report with `restore_coverage` and
calls no verifier, and a search of `src/prometheus_protocol/execution/` for
`.verify(` returns nothing. Every action class has it. `branch.delete` is where
it is demonstrable, because its live-state check already exists — the merge
proof counts commits reachable from the branch and absent from the base
(`tools/git.py:141-158`) — so a branch reviewed as "zero commits absent" can
gain commits before the human approves and the delete executes on the replayed
sentence. That is irreversible loss of work that may exist nowhere else.

**THE REPRODUCTION IS KEPT, and it passes.**
`test_the_gap_without_reobservation_a_delete_executes_on_replayed_evidence`
wires the controller with no re-observation, lets the branch gain a commit
after review, approves, and shows the executor REACHED with an approved
decision whose record still says the delete is lossless. A named gap is a
passing test; this one is also the before-picture the fix is measured against.

**What was built** (`docs/live-state-pinning-design.md` revision 4 lists the
files): a derived covered set with its own digest domain, an observer that is
the same reader the merge proof uses, a registry that is total over
`ACTION_CLASSES`, capture at hold creation, a comparison before the approval is
recorded, a re-read immediately before the executor, a terminal transition out
of `APPROVED`, and an append-only chained observation record keyed on the
execution attempt.

**Executed mutations**, through `scripts/mutation_worktree.py`, four target
modules, 73 tests green unmutated. Five on the mechanism and eight second-order
probes on the proofs; every one reddened a named test and none survived.

| mutation | observed |
|---|---|
| the pre-approval comparison removed | 6 red |
| the pre-execution re-read removed — **also the red-first state**: on that path the tree is the pre-change tree, and the fixed half of the reproduction goes red | 5 red |
| the pre-execution comparison compares the observed digest against ITSELF (the §7.5 cell that passes every deletion probe) | 4 red |
| the observation record dropped from the chain | 6 red |
| the terminal state left as `approved`, so the hold stays retry-eligible | 4 red, including the derived literal-vs-enum check |
| S1 the pre-approval refusal keeps raising, its typed reason swapped | 1 red |
| S2 the pre-execution refusal keeps raising, its typed reason swapped | 1 red |
| S3 an unreadable target reported as a move instead | 3 red |
| S4 the observation record always says `matched` | 2 red |
| S5 the record forgets what it compared against | 1 red |
| S6 the execution entry stops restating the pre-approval one | 1 red |
| S7 the capture halt removed, pinning an unreadable target | 1 red |
| S8 the opt-out block stops naming the choice | 1 red |

**A mutation that was NOT measured, recorded rather than counted.** The first
attempt at "drop the observation record from the chain" replaced the call's
opening line only and left its keyword arguments stranded inside a tuple: a
`SyntaxError`, which the runner reported as `(no summary)` with an empty red
list. Read carelessly that is GREEN. It was re-run as a valid edit (the 6-red
row above) and the broken attempt is recorded here as not-measured, because
this is the second time the runner's `(no summary)` has had to be read as "not
measured" rather than "nothing red" (G26 carries the first).

**Named limits.**
- **Two of three action classes are opted out**, by name. That is machinery,
  not coverage: `sandbox.execute` and `database.migrate` are unobserved, and
  every hold's record says which reason was given.
- **The opt-out is not in the attested posture.** It is a composition-root
  argument, not a `Config` field on `SECURITY_FIELDS`, so it is not in the
  configuration-attestation digest. In the record, not in the attestation.
- **The state pin is not a `PolicyRequirement`.** §3.1 framed it as one so that
  unavailability would flow through coverage. The claim was VERIFIED and is
  true — an `Unavailable` in a `BoundResult` is recorded at
  `policy/coverage.py:331-334` and refused as `coverage.incomplete` at `:388` —
  but it is not the path used, because §2.1 ruled the capture point at hold
  creation, which is downstream of assessment and so downstream of coverage.
  Unavailability halts by its own path instead. Recorded because the brief said
  to verify the claim before relying on it, and verifying it is what showed it
  does not carry the capture.
- **The covered set is three aspects.** What can vary outside it, for this
  class: the reflog, other branches, the working tree, the remote. None is part
  of "is deleting this branch lossless", and a deployment whose loss model is
  wider is not covered.
- **The TOCTOU residual is bounded, not closed**, and the window is now
  read-to-execute. A third party committing to the branch between the re-read
  and the executor call is not detected.

**Re-verified at this head rather than assumed, because the design's two
previous claims about existing behaviour were both false when read.**
Unavailability still always halts and there is still no routing path:
`ActionGate.decide` tests `isinstance(judgment, Unavailable)` at
`gate/authorization.py:137` and returns a terminal `OUTCOME_UNAVAILABLE` at
`:149`, which is BEFORE `_outcome` (`:168`) and before `escalate_below` is
consulted (`:184-185`); `ExecutionController.submit` records it distinctly and
halts at `controller.py:174-178`, with the existing comment that it is
deliberately not parked as an approvable hold.

**THE TYPE GATE CAUGHT A DEFECT IN THIS SPRINT'S OWN CODE**, and it is recorded
because it is the shape this repository keeps finding. `pre_approval_entry`
narrowed a chain payload in EXPRESSION position — `payload if isinstance(payload,
dict) else None` — which `test_no_union_is_narrowed_in_expression_position`
refuses. It was right to: a payload of a third shape would have been taken by
the else-branch and become `None`, and this method's caller reads `None` as
"there was no pre-approval entry". A missing receipt would have been reported
as an absent one, inside the record whose whole purpose is to show that state
was checked twice. Fixed in statement form. The 30 module tests were green
while that was live; the guard that was not was a different instrument.

**Tests.** `tests/conformance/test_reobservation_branch_delete.py` (38) and
`tests/conformance/test_reobservation_wiring.py` (18), in CI's full-suite job,
none skipped. Five positive controls registered in `positive_controls.json`
with their negatives.

**CORRECTION, ENTERED AFTER THE MERGE. Every claim in this entry above this
line described a mechanism that no shipped code path reached.** `reobservation`
was an optional constructor argument defaulting to `None`, and all five
non-test constructions of `ExecutionController` omitted it. `None` is
byte-for-byte the unfixed path the reproduction measures, so on the merged tree
every deployment was on the before-picture while this entry said otherwise. The
30 proofs and 13 mutations were real and are unchanged; what none of them
covered was reach, because every one of them built its own controller.

**The shape, named: a proof that builds its own subject proves the subject,
never its reach.** This is the second time a security-critical parameter has
shipped here with no production caller wiring it (R4 was the first), and in both
the unwired default IS the behaviour.

---

## G30 — the re-observation opt-out is in every record and in no attestation

**Measured.** `build_reobservation` is a composition-root call, and its result
is a constructor argument. The opt-out reason for each action class therefore
appears in every hold's `target_state` block and in none of the configuration
attestation: it is not a `Config` field, so it is not in `SECURITY_FIELDS` and
not in the attestation digest. Two deployments with different re-observation
postures produce the same posture digest.

**What that costs.** The attestation is what a reader consults to learn what a
deployment enforces. Re-observation coverage is a security posture — it is the
difference between a delete checked against live state and one executed on
replayed evidence — and it is currently discoverable only by reading a hold
that already happened. There is no way to ask a deployment in advance what it
re-observes and get an attested answer.

**Not closed here, and why.** Moving it into `Config` is its own change: it
needs a `SECURITY_FIELDS` entry, an attestation re-pin, and a decision about how
a per-target choice (`git://` versus everything else) is expressed as a
configuration field when the target is itself a runtime argument. Filed rather
than done, so that the limit is a numbered gap rather than a paragraph inside
another entry's "named limits" list.

**Where it is stated today.** `docs/live-state-pinning-design.md` "WHAT PHASE 1
DOES NOT DO", and G29's named limits.

---

## G31 — two composition roots, two registries, and only one direction is reachable

**Found by probing, not by reading.** Wiring G29 created a case that could not
exist before it: two roots can now hold different registries. Driving the two
shipped roots against one ledger — a hold created by a root naming a `git://`
principal, then approved through a controller built the way `cli/main.py:341`
builds it — raised a bare `KeyError` out of `approve()`:

> `KeyError: "no state observer for action class 'branch.delete'; ReObservation is total over ACTION_CLASSES, so this means the class is opted out and the caller should not have asked"`

**Why it is reachable at all.** `build_execution_controller`'s
`target_canonical` defaults to `sandbox://execution`, and the CLI's `approve`
and `retry-execution` both call it without one (`cli/main.py:341`, `:386`). That
default opts `branch.delete` out. The hold being approved may have been pinned
by a root that named a git principal and does observe it.

**RULING AND FIX (doctrine #2).** A hold whose record says its live state was
pinned, presented to a service that does not observe its action class, is
REFUSED — not skipped. Skipping would execute an irreversible delete on evidence
the record claims was re-checked, which is degrading a requested security
property instead of refusing it. New type `StateUnobservable`, new typed reason
`target_state_registry_mismatch` in `EXECUTION_REFUSAL_REASONS`. It is a third
type beside `StateMoved` and `StateUnreadable` because it is a statement about
the DEPLOYMENT: the state did not move and was not unreadable; it was not read.

**The other direction is not reachable through the factory, and that is
checked.** A `sandbox://`-targeted root cannot CREATE a git-targeted hold: the
gate re-resolves requirements from its own `target_canonical` and refuses the
submission at authorization
(`test_a_sandbox_targeted_root_cannot_CREATE_a_git_targeted_hold_at_all`). The
registry disagreement therefore has exactly one reachable direction.

**The asymmetry, named.** A hold created with the class opted out and approved
under a registry that DOES observe proceeds, because there is no pin to compare
against. That is honest — its record says `observed: false` and no observation
is chained — but it is not symmetric with the refusal, and the difference is
which direction makes a false claim. Pinned as a measured property.

**Executed mutations** on the new guard, through `scripts/mutation_worktree.py`:

| mutation | observed |
|---|---|
| M7 deletion: the registry-mismatch guard removed | 2 red |
| M8 substitution: refuses, but as `StateMoved` / `state_moved_after_approval` — a real type and a real reason from the same closed sets, naming the wrong fact | 2 red |
| M9 degradation: returns `OUTCOME_MATCHED` instead of refusing — the silent-skip shape | 2 red |

**STILL OPEN after this fix.** The CLI's approve path re-observes NOTHING for a
git target — it refuses instead. That is the correct failure direction and it is
not the desired behaviour: a reviewer approving a branch delete through
`prom approve` is told the deployment cannot check it, rather than having it
checked. Closing that means the CLI naming its target, which is a change to how
a deployment declares its principal and is not in this sprint.

---

## G32 — three defects on the re-observation seam, found by review after merge

All three were correct, all three were on `execution/controller.py`, and all
three are fixed. Recorded together because they share one cause: the
pre-execution comparison was added to `_execute` as a single unguarded call, and
a call added between a claim and an executor inherits obligations to both.

**1. A supplied service silently discarded the registry (P1).**
`self._pending = pending or PendingActionService(..., reobservation=...)` never
constructs the service when `pending=` is given, so a `reobservation=` passed
beside it was dropped. Both comparisons then used the supplied service's
registry, which may be `None` — a controller whose every observable surface says
re-observation is enabled, running neither check.
**RULING (doctrine #2): refused, not degraded.** `ConfigError` with the typed
reason `reobservation_registry_discarded`, in `CONFIG_REFUSAL_REASONS`.

*Compared by IDENTITY, and that choice is pinned.* `ReObservation` is a
dataclass, so `==` delegates to the observers' `__eq__`.
`GitBranchStateObserver` defines none, so today equality behaves as identity —
which is the problem: the strictness of a security check would be a property of
classes the check does not own. An observer that later gained an `__eq__` on
`repo_path` would make two observers over *different* `GitTool`s compare equal.
A check that can loosen without being edited is not a check.
**This was found by mutation, not by reasoning:** substituting `!=` for
`is not` reddened NOTHING, because every "different registry" in the suite was
also unequal. A proof was added that builds two registries that ARE equal and
are not the same object; the mutation now reddens it.

**2. A pre-execution refusal left no execution row (P2).** `StateMoved` and
`StateUnreadable` both exited `_execute` before `record_execution`, although the
hold had been claimed and an execution attempted. `executions_for_pending()`
could not say why an approved action did not run — indistinguishable from one
nobody tried. Fixed: the refusal is persisted as a refused row naming its typed
reason, then re-raised. Proven for both refusal kinds.

**3. The claim leaked on non-terminal refusals (P1).** The claim is taken before
the comparison. A refusal raised without releasing it, and for a
non-terminal refusal the hold stayed `approved` — so `retry_decision` accepted
it — while `claim_pending_execution` failed forever with "already in progress or
has completed". **A transient observer outage permanently bricked an approved
action, with no verb to recover it.** That is the G21 road: an operator who
cannot recover removes the requirement.
**RULING: release for non-terminal refusals, retain for `StateMoved`.** Keyed on
TYPE in `CLAIM_RETAINED_BY`, whose key set is pinned by a test. The default for
an unnamed type is to RELEASE, which is safe because terminal-ness lives in the
STATUS — `StateMoved` transitions the hold out of `approved` and
`retry_decision` refuses it on that alone. The claim is belt; the status is
suspenders.

**Executed mutations**, through `scripts/mutation_worktree.py`, both attack
classes:

| mutation | observed |
|---|---|
| M14 deletion: the registry-discard check removed | 2 red |
| M15 substitution: equality for identity | **0 red on first run** — recorded as a gap in the proofs, not as a pass; 1 red after the distinguishing proof was added |
| M16 deletion: the refused execution row not written | 2 red |
| M17 substitution: the row is written but drops the typed reason | 2 red |
| M18 deletion: the claim is never released | 1 red |
| M19 substitution: the claim released for every refusal, moves included | 2 red |
| M20 substitution: the wrong type retains — unreadable treated as terminal | 3 red |

**M15 is the entry worth reading twice.** A green mutation is not evidence the
field is covered; it is evidence nothing has been measured yet. Probing the
field directly — constructing two equal, non-identical registries — showed the
suite could not distinguish the two checks at all.

---

## G33 — two defects the wiring introduced, found by review after #114 merged

Both were reported on #114 and both are correct. Both are consequences of the
same change — wiring re-observation into the shipped roots — and both were
**confirmed by direct probe before being accepted**, not taken on the
reviewer's word.

### 1. The synthesised observer guessed its base branch (P2)

`build_reobservation` built a `GitTool` with that class's own default
`base_branch="main"` whenever a root named a `git://` target and passed no
reader. `build_execution_controller` always took that path.

**Measured** on a repository based on `master`, driving the shipped factory:

| reader | `base_branch` | `rev('main')` | `classify(feature-work)` | hold |
|---|---|---|---|---|
| the caller's own `GitTool` | `master` | `None` | `unmerged_commits = 0` | — |
| the factory's synthesised one | `main` | `None` | `Unreadable('base_tip', 'unmerged_commits')` | **refused at creation** |

So the merge proof worked and the observer could not read the base at all, and
**every `branch.delete` hold was refused at creation** with
`target_state_unreadable`. Fail-closed in direction, and a total denial of the
feature for every deployment not based on `main`. The refusal also pointed at
the repository rather than at the wiring, which is where the defect was.

**The deeper reason it cannot be defaulted at all.** The base branch is not a
deployment-wide constant — it is *the base the merge proof was evaluated
against*. An observer reading a different base is precisely the second
definition of "unmerged" that `GitBranchStateObserver`'s own docstring exists to
forbid: the state a hold is pinned to would not be the state its evidence
describes. `build_reobservation` had created exactly the reader its sibling
class documents as forbidden.

**RULING: refuse, do not guess.** A `git://` principal with neither a `GitTool`
nor a `base_branch` raises `ConfigError` / `reobservation_base_branch_unknown`
at COMPOSITION time. A supplied tool whose base disagrees with a supplied
`base_branch` raises `reobservation_base_branch_conflict` — two definitions of
"unmerged" for one hold, and neither silently wins. `tools/stale_branch_demo.py`
is unaffected: it already passes its own reader, which is the preferred route
and is now pinned by a test.

**Not in `Config`.** There is no base-branch field and this change does not add
one, so the base a deployment observes against is still outside the attested
posture — the same limit G30 records for the opt-out.

### 2. A receipt written before the subject key changed was lost (P2)

#114 added the pending-hold id to the observation subject (G32 item 5). A hold
approved under the PREVIOUS release wrote its pre-approval receipt under
`observation:<attempt>#0`; the new lookup searched only
`observation:<attempt>@pending:<id>#0`, found nothing, and returned `None` —
which the caller reads as "there was no pre-approval reading".

**Measured** by approving under the old key and executing under the new one:
the pre-execution receipt came back with `prior: null`. That is the spelling
meaning *this was the first reading*, so **the record stated that state was
never checked at approval, for a hold where it was** — a false claim inside the
receipt whose entire purpose is to show the check happened twice.

**RULING: resolve an unambiguous legacy receipt, refuse an ambiguous one.**

| chain contains | behaviour |
|---|---|
| the current subject | used, unmarked |
| exactly one legacy subject | used, **marked** `resolved_from_pre_upgrade_subject` |
| several legacy subjects | refused — `pre_approval_receipt_ambiguous` |
| neither, on a pinned and observed hold | refused — `pre_approval_receipt_missing` |

The marking matters: a reader must be able to tell an attribution from an
identity. The ambiguous case is the exact collision the new key was added to
remove, met in a ledger written before it — taking the first is how the later
hold's execution comes to restate the earlier hold's reading, so it refuses.

The missing-receipt guard is **conditioned on coverage**, so the G31
registry-mismatch refusal still fires with its own reason: "this deployment
does not observe the class" explains "the receipt is missing" rather than being
masked by it. An unpinned hold needs no receipt and is not refused — pinned by
its own test, because a blanket guard here would refuse every hold in a
deployment that wires nothing.

**What this says about the earlier sprint.** The subject-key change was ruled
correct and still is; what it lacked was a reader for what the previous writer
left. A key change is a migration whether or not anything is migrated, and a
ledger outlives the deployment that wrote it.

### Executed mutations

Through `scripts/mutation_worktree.py`, both attack classes, 78 tests green
unmutated. Every one reddened a named test.

| mutation | observed |
|---|---|
| N1 deletion: the no-base refusal removed, so `GitTool`'s default returns | 1 red |
| N2 substitution: the named base is accepted and then not passed to the tool | 1 red |
| N3 deletion: the tool-vs-base conflict check removed | 1 red |
| N4 deletion: the legacy subject is never searched | 2 red |
| N5 substitution: an ambiguous legacy set takes the first instead of refusing | 1 red |
| N6 deletion: a resolved legacy receipt is not marked | 1 red |
| N7 deletion: a pinned hold with no receipt executes anyway | 1 red |
| N8 substitution: the missing-receipt guard drops its coverage condition | **4 red, including the gap reproduction itself** |

**N8 is the row that justifies the condition.** Widening the guard to every
hold with no receipt reddens `test_the_gap_without_reobservation_...` — the
kept measurement of the unfixed path — because a deployment that wires nothing
pins nothing and would then be refused at execution for a receipt it never had
any reason to write. The unconditioned guard does not tighten the control; it
breaks every deployment that has not adopted it.

---

## G34 — the base-branch refusal honoured its own rationale only for absence

Reported on #115 and correct. G33's fix replaced a *guessed* base branch with a
*required* one and moved the failure to composition time, and the PR body said
plainly why that mattered: the delayed failure surfaces as "the target could not
be read", which blames the repository for a wiring error. **An INVALID base
still did exactly that.**

**Measured** before the fix, through `build_reobservation`:

| `base_branch` | registry | `observe()` | hold |
|---|---|---|---|
| `""` | **built** | `Unreadable('base_tip',)` | refused, `target_state_unreadable` |
| `"   "` | **built** | `Unreadable('base_tip', 'unmerged_commits')` | same |
| `"--upload-pack=x"` | **built** | `Unreadable('base_tip', 'unmerged_commits')` | same |
| `"main"` | built | `BranchDeleteState` | created |

So the registry looked configured, and every `branch.delete` hold was refused at
creation — the same feature-wide denial G33 exists to remove, reached by a
different door. **A refusal that covers absence but not invalidity has closed
one case of the defect and left the other.**

**RULING: validate at composition, using the tool's OWN rule.**
`tools/git.py` gained `is_usable_branch_name`, exported so the composition root
asks the same question the reads ask. A root that re-spelled `_BRANCH_RE` would
be a second definition free to drift — accepting a name the tool then refuses,
which is this defect reintroduced at one remove. New typed reason
`reobservation_base_branch_unusable`.

> **CORRECTION, 2026-09-16 (doctrine #9).** "The composition root asks the same
> question the reads ask" was true when written and **stopped being true the
> moment G36 strengthened the predicate**: the root moved to the stronger rule
> and the reads stayed on `_BRANCH_RE`, so the two questions diverged. The
> window is `c8709cc..98e8587`, both on this branch and neither on `main`, so
> no released commit carried it — but it was carried in a commit whose own
> message said the opposite. That is **G37**, found by review on #118 and now
> closed: every read calls the predicate, pinned structurally. The sentence
> above is true again; it is left standing with this note because deleting it
> would hide that a claim of this exact shape had already gone stale once.

**Both routes, not one.** The supplied `GitTool` is validated as well as the
synthesised one: a reader handed in with an unusable base fails identically, and
checking one route while trusting the other is the asymmetry the guard exists to
close.

**What it does NOT add.** The dash-leading cases are the option-injection shape
the read boundary already refuses, so no new security property is gained there.
What is gained is that the diagnosis lands at the wiring rather than at the
repository. (Named as `_BRANCH_RE` when written; since G37 the reads go through
`is_usable_branch_name`, which still starts with that pattern, so the property
is unchanged and only the mechanism's name has moved.)

**Executed mutations**, through `scripts/mutation_worktree.py`, both attack
classes, 100 tests green unmutated:

| mutation | observed |
|---|---|
| P1 deletion: the usability check removed | 7 red |
| P2 substitution: only the synthesised route checked, a supplied reader trusted | 1 red |
| P3 substitution: the root re-spells the rule and drifts | 5 red, including the same-rule pin |
| P4 substitution: emptiness only, so option-injection shapes pass | 6 red |

**The pattern this is the third instance of.** #113 shipped a mechanism nothing
reached; #114 wired it and built the reader its own sibling class forbids;
#115 required the base but not a usable one. Each fix was correct about the case
it named and narrower than the sentence describing it. The instrument that keeps
catching it is review, not the suite — every one of these had green proofs.
## G35 — an outcome derived from a subset of the fields that determine it

**G34 is deliberately skipped here.** It is taken by the base-branch validation
change, open and unmerged at the time this was written. Reusing the number
would make two different findings share one label across two branches, and the
tracker is read by number.

**The reported defect, reproduced at `03010a9`.** `SandboxExecutor._run` decided
the outcome from `started_ok` alone. Fed `started_ok=True`,
`candidate_started=False`, `timed_out=True`:

    ExecutionResult(executed=True, refused=False, started_ok=True,
                    detail="ran in sandbox 'triple' (exit 0, network denied)")

A wall-clock timeout that fired during SETUP, before the candidate ran,
recorded as a clean execution. Could-not-verify written into the execution
record as verified-clean, at the point downstream can no longer recover the
difference.

**The contract already said so**, at `sandbox/base.py`: `started_ok` answers
only "did isolation start", `candidate_started` is the stronger definite
signal, and `started_ok=True` with `candidate_started=False` — "a wall-clock
timeout during setup, before the candidate ran" — "stays a harness fault". Not
a missing rule; a rule the executor did not read. The verifier seam has
classified the same triple as `Unavailable(INFRA_FAULT)` since the equivalent
bug was found there, so this was one seam catching up to the other.

**RULING: no fourth category.** `runner.py`'s three-way split contains a verdict
ABOUT the candidate; the executor has no verdict to give, because `exit_status`
carries the candidate's own outcome. The split collapses onto the two outcomes
the executor already has, and `candidate_started=False` becomes the refusal
`started_ok=False` already was. Keyed on `candidate_started`, never on
`timed_out`: a candidate that started and was then wall-clock killed really ran
and its side effects happened.

### CAN THE RECORD SAY IT? Half yes, and the half that is missing is named

The brief that produced this fix asked for this explicitly and **the answer was
not written down at the time — this section closes that shortfall.** The
question is whether the outcome vocabulary can express "the harness failed
before the candidate ran", because F14 chains it.

**STRUCTURALLY, YES — and that is what the fix added.** `ExecutionResult`
carries `started_ok` and `candidate_started` as two separate booleans, so the
pair `(True, False)` names this state exactly and distinguishes it from a
missing runtime `(False, False)`. Before the fix the executor wrote
`started_ok=False` for both, collapsing two harness faults with different
remedies into one value;
`test_the_two_harness_faults_are_DISTINGUISHABLE_in_the_record` pins the
separation. A consumer can branch on the pair today, and it is structured data,
not prose.

**AS A TYPED REASON, NO.** Measured:

    dataclasses.fields(ExecutionResult) ->
        executed, subject_id, detail, refused, started_ok,
        candidate_started, sandbox_name, exit_status, stdout

There is **no reason field drawn from a closed set**. `detail` is free text —
here, `"refused: sandbox started but the candidate never did, ..."`. The
closed vocabulary that does exist, `EXECUTION_REFUSAL_REASONS`
(`policy/execution.py:54`), has **seventeen** members and **every one names an
AUTHORIZATION condition** — chain integrity, descriptor binding, re-observation,
the pre-approval receipt. Not one names a harness fault or any execution-time
sandbox condition, because that set belongs to a different stage: it is the
vocabulary for *why a hold may not proceed*, not for *what happened when it
did*.

> **CORRECTION.** This paragraph first said **nineteen**. The set has
> seventeen; nineteen was arrived at by counting lines in the source, which
> includes comment lines, instead of the set. Withdrawn here rather than
> quietly edited, because a number nothing checks is exactly the failure this
> section is about — and the membership pin below now asserts the count so the
> same slip cannot recur silently.

**So the seam is half-typed**, and the asymmetry is the finding rather than an
oversight to paper over: the authorization stage refuses with a closed-set
reason a test can assert on, and the execution stage refuses with a sentence.
A consumer that wants "harness fault, candidate never started" as a *token*
must either read the two booleans — available, structured, and the recommended
route — or match on `detail`, which is fragile and which nothing pins.

**WHAT F14 WILL HAVE TO CHAIN, stated so the vocabulary is settled before it
starts.** F14 needs to know which of these it is building on:

1. The boolean pair is the contract, and F14 branches on `(started_ok,
   candidate_started)`. Nothing more is owed here. This is what the code
   supports **today**.
2. Or `ExecutionResult` gains a typed reason from a closed set — a new set for
   the execution stage, *not* a widening of `EXECUTION_REFUSAL_REASONS`, which
   would conflate two stages that refuse for unrelated causes. That is a design
   decision with a migration behind it (every construction site, every
   consumer, the receipt schema), and **it is deliberately NOT taken here**:
   this entry's fix was the smallest correct one, and inventing a vocabulary
   while fixing a mapping is how the mapping stops being reviewable.

**This entry does not decide between them.** It records that (1) is what
exists, that (2) is unbuilt, and that the choice is F14's to make with the cost
of (2) visible in advance — which is the whole reason the question was asked
before F14 rather than during it.

### The class, swept

| site | fields read before | total? |
|---|---|---|
| `verifier/runner.py` | 8, incl. `candidate_started` | yes |
| `verifier/sql.py` | branches on `candidate_started` inside `timed_out`, and again for a missing payload | yes |
| `execution/executor.py` | `started_ok` alone | **no — the reported defect** |
| `tools/git.py` reads | `started_ok` + `exit_status` | **no** |
| `tools/git.py` delete executor | `started_ok` alone | **no — the same defect** |
| `execution/controller.py`, `cli/main.py`, the three demos | `exit_status`, to RECORD rather than derive | n/a |

**The git reads were safe only by accident, and that is the entry's point.**
`branches`, `classify` and `rev` tested `started_ok or exit_status != 0`. With
the signal the adapters really produce (`exit_status=None` on a timeout) all
three fail closed. With the same harness fault and `exit_status=0`, `classify`
returned `0` — "zero commits absent from the base", the exact evidence that
authorizes an irreversible branch delete — from a run where git never executed.
**The safety of one module rested on a property of another, checked by
nothing.** A shared `_ran()` predicate now requires both flags, and a test pins
the cross-module invariant the old guards depended on.

**The branch-delete executor had the defect exactly**, in the tool that really
deletes: `executed=False` (fail-closed, so nothing was lost) with the detail
"delete of branch 'x' ran in sandbox but failed (exit None)" and
`started_ok=True` — a record saying the delete was attempted and rejected by
git, when git never started.

### Reachability, measured

Both isolating adapters hard-code `started_ok=True` on their TIMEOUT paths
while taking `candidate_started` from the start signal, and both tie
`started_ok = candidate_started` on their NORMAL paths. So for shipped
adapters the triple arises ONLY with `timed_out=True`, and
`started_ok=False` with `candidate_started=True` cannot arise at all. Pinned by
tests that read the adapters' source, so the fake sandbox in the proofs stands
in for a state the shipped code really produces.

### Executed mutations

| mutation | observed |
|---|---|
| Q1 deletion: the executor reverts to `started_ok` alone | 4 red |
| Q2 substitution: keys on `timed_out` instead of `candidate_started` | 3 red |
| Q3 substitution: refuses but still claims the run started | 1 red |
| Q4 deletion: git reads revert to the accidentally-safe guard | 1 red |
| Q5 substitution: `_ran` drops `started_ok` | **0 red first run**; 1 red after the probe below |
| Q6 deletion: the branch-delete executor drops its guard | 1 red |

**Q5 went green, and the probe is the record.** Reading `_ran` directly over all
four combinations showed `started_ok` decides only the CONTRADICTORY input —
isolation down, candidate confirmed running — which no adapter produces. It is
asserted anyway, for the reason the unreachable triple rows are asserted: a
predicate that reads the contract must not have a branch decided by nothing.

**Second-order probes, and which half each assertion carries.** Dropping any
single OUTCOME assertion still reddens, because the parametrised triple table
pins `executed`/`refused` for every combination independently — redundancy by
design, not weakness. The RECEIPT WORDING is different: a refusal whose detail
says nothing useful reddens exactly one test, and with that assertion dropped it
passes everything. That assertion is the sole carrier of "the record says what
happened".

### Two false doc claims, corrected

`docs/sandbox.md` said a setup failure, a setup-failed token or a revoked start
"all yield `started_ok=False`, which callers treat as a harness fault — never a
pass, a fail, or a claimed execution". Both halves were wrong: the timeout path
hard-codes `started_ok=True`, and "never a claimed execution" is precisely what
the executor was doing. The same file said `started_ok=False` makes the verifier
ABSTAIN; it returns `Unavailable`, and
`test_isolation_not_started_is_unavailable` has asserted so all along.

**F18 is a separate finding and is NOT fixed here.** Its claim — "never silently
weaker", about `SandboxResult.limiter`, in `docs/sandbox.md`,
`spec/invariants.md` and `sandbox/base.py` — does **not** share wording with
these. What it shares is the shape: a contract-completeness claim carried in
prose with no instrument behind it.

### Named limit

`tools/git.py` is **not** in the Hearth protected set, so the reader that
produces branch-delete evidence is not frozen. Noticed while re-sanctioning
`execution/executor.py`, which is. Recorded rather than changed: widening the
protected set is its own decision with its own re-pin.

---

## G36 — a branch-name predicate that was a charset, not git's rules

Reported on the base-branch validation change and correct. That change added
`is_usable_branch_name` so a base git will not read is refused at composition
instead of failing every hold later. The predicate was a charset pattern, and
git's reference-name rules are more than a charset — so names git rejects
passed it, and the delayed denial it existed to prevent came back for those.

**Measured against `git check-ref-format --branch`:**

| name | ours | git | why git refuses |
|---|---|---|---|
| `release/` | accepted | rejected | trailing slash |
| `a..b` | accepted | rejected | the range operator |
| `a.lock` | accepted | rejected | git's own lock suffix |
| `main\n` | accepted | rejected | Python's `$` matches before a trailing newline |
| `a//b` | accepted | rejected | empty path component |
| `a.` | accepted | rejected | trailing dot |

**Two more came from widening the corpus, not from the report**: `a.lock/b` and
`a/.b`. **Git's rules are PER COMPONENT**, and a whole-name check cannot
express them. `HEAD` was a third: it passed the charset and is a symbolic ref,
not a branch.

**The `$` case is worth naming on its own.** Python's `$` also matches
immediately before a trailing newline, so `"main\n"` matched a pattern that
looks exactly like it should not. The anchor is now `\Z`, and a test pins the
pattern itself — the behavioural proof alone would still pass if something
upstream happened to strip the newline, and the anchor could then regress
quietly.

**RULING: check against the authority, every run.** The rules belong to git.
Any spelling of them here is a second definition free to drift — which is this
defect. So `tests/conformance/test_git_ref_format.py` runs the predicate and
`git check-ref-format --branch` over the same corpus, hand-written plus 400
seeded random names, and asserts agreement in the direction that matters.

**THE INVARIANT IS ONE-DIRECTIONAL, and the other direction is asserted as a
NON-property.** Anything the predicate accepts, git must accept. The converse
deliberately does not hold: the predicate is a conservative SUBSET, refusing a
leading underscore, a bare `@`, a mid-path component ending in a dot. Refusing
a name git would have taken costs a caller an error message; accepting one git
will reject costs every hold on that deployment. Both directions are tested, so
a later reader who assumes exact agreement cannot "fix" the strictness and
widen the accepted set without a test saying so.

**Executed mutations**, through `scripts/mutation_worktree.py`, both attack
classes, 100 tests green unmutated:

| mutation | observed |
|---|---|
| R1 deletion: the anchor reverts to `$` | 3 red, incl. the pattern pin |
| R2 deletion: the per-component loop removed | 7 red |
| R3 substitution: components checked on the whole name instead | 5 red |
| R4 deletion: the range-operator and reserved-name check removed | 3 red |
| R5 substitution: `.lock` dropped from the forbidden suffixes | 3 red |

**The test requires git rather than skipping without it.** This module's whole
claim is that the predicate agrees with its authority; a run without git would
assert nothing while reporting success, which is the empty-instrument pass
doctrine #8 refuses.

**What this does not do.** It does not make the predicate equal to git's rules,
and does not claim to. It makes the accepted set a subset of git's, checked on
every run over a corpus that is itself pinned as non-trivial in both directions.

## G37 — the strengthened rule reached the composition root and not the reads

Reported by review on #118 and **confirmed by direct probe before being
accepted**. G36 strengthened `is_usable_branch_name` past the charset pattern
and exported it so the composition root could refuse an unusable base branch
where an operator can see it. The reads were not changed. `GitTool.classify`,
`GitTool.rev` and `GitBranchDeleteExecutor.execute` went on matching
`_BRANCH_RE` directly, so the stronger rule reached the root and stopped
there — and the exported predicate became **the second definition its own
docstring said it existed to prevent**, drifting in the direction that costs.

**Measured, on a real repository checked out on `main`:**

| probe | observed |
|---|---|
| `is_usable_branch_name("HEAD")` | `False` |
| `_BRANCH_RE.match("HEAD")` | matches |
| `git rev-parse --verify 'HEAD^{commit}'` | exit 0, resolves to a commit |
| `git rev-list --count main..HEAD` | `0`, exit 0 |
| `git check-ref-format --branch HEAD` | exit 128 |
| `git branch -D HEAD` | exit 1, `branch 'HEAD' not found` |

**Zero commits absent from the base is the merged verdict** — the exact
evidence an irreversible delete is authorised on. So a symbolic ref could be
observed as a branch, classified as provably merged, approved on that evidence,
and then fail at the one step that was supposed to be the formality. Not a lost
branch: a decision taken on a subject that was never a branch, recorded as
though it had been.

**THE BOUNDARY, stated rather than left absolute.** The merged verdict needs
`HEAD` at or behind base. Measured on a checkout one commit ahead,
`rev-list --count main..HEAD` returned `1` — not merged, so no approval. The
review's wording ("in a repository on `main`") is exactly right, and
`test_the_escalation_needs_HEAD_AT_OR_BEHIND_BASE_and_that_is_stated` pins it
so the finding is not later read as broader than it is, or narrower.

**THE OTHER REFUSED SHAPES WERE SAFE ONLY BY ACCIDENT.** Recorded because it
changes what the fix is worth. `release/`, `a..b`, `a.lock`, `a//b`, `a.`,
`a/.b` and `a.lock/b` all pass `_BRANCH_RE` and were handed to git, which
refused each at exit 128 — so the reads returned "not provably merged" for a
reason that had nothing to do with the predicate. **`HEAD` is the single member
of the refused set where that accident does not hold.** This is the same shape
`_ran` was found in one function away, where the reads were safe only because
the shipped adapters happen to leave `exit_status` at `None`.

**A TEST IN THE SUITE ASSERTED THE WRONG PROPERTY AND PASSED.**
`test_the_validator_is_the_tools_OWN_rule_not_a_second_spelling` pinned
`is_usable_branch_name` as EQUAL to `_BRANCH_RE`, over the corpus
`("main", "", "   ", "--x", "a/b.c-d", "..", "a b", "0")` on which the two
coincide. Once G36 landed the equality was false — and that test would have
FAILED on a corpus wide enough to hold one divergent name. It did not, because
the corpus was not. **It pinned the predicate TO the pattern: the drift it
names in its own docstring, asserted as the invariant.** It now checks what its
name claims, and the identity is asserted as a NON-property.

**RULING: one definition, enforced on the source.** The three reads call
`is_usable_branch_name`. An AST allowlist in
`tests/conformance/test_git_ref_format.py` permits exactly one function to
mention `_BRANCH_RE`, keyed on the enclosing function rather than on a count —
a count would be satisfied by moving the defect to a new read. The behavioural
proofs cover the reads that exist today; the allowlist covers the read added
next month.

**Executed mutations**, through `scripts/mutation_worktree.py`, both attack
classes, 118 tests green unmutated:

| mutation | class | observed |
|---|---|---|
| S1 `classify` reverts to the charset pattern (the defect, restored) | deletion | 5 red |
| S2 `rev` reverts to the charset pattern | deletion | 4 red |
| S3 the delete executor reverts to the charset pattern | deletion | 4 red |
| S4 `classify` checks the right function on the WRONG subject (`base_branch`) | substitution | 2 red |
| S5 the delete executor checks `base_branch`, not the action's branch | substitution | 1 red |
| S6 `rev` checks `base_branch`, not the ref it was handed | substitution | 1 red |
| S7 the reserved-name check removed from the predicate itself | deletion | 7 red |
| S8 the AST allowlist widened to permit all three reads | substitution | **GREEN** |
| S9 the outcome assertion weakened from `is None` to `in (None, 0)` | second-order | **GREEN** |

**THE TWO GREENS WERE PROBED DIRECTLY RATHER THAN EXPLAINED AWAY.** Both are
no-ops against fixed code: the widened allowlist permits three functions that
no longer mention `_BRANCH_RE` at all, and the weakened assertion still holds
because `classify("HEAD")` returns `None`, which satisfies both spellings.
Neither green says an instrument is untested; each says the mutation never
reached a state the instrument discriminates. **The real question is whether
each still catches the DEFECT**, so each was re-run with the defect restored
underneath it:

| paired probe | observed |
|---|---|
| T1 defect restored, both instruments intact (the control) | 5 red |
| T2 defect restored **and** the allowlist widened | 4 red |
| T3 defect restored **and** the outcome assertion weakened | 4 red |
| T4 defect restored, allowlist widened **and** assertion weakened | 3 red |
| T5 allowlist emptied on FIXED code — does the scan reach the source? | 1 red |

**Which half carries the property: neither, and that is the finding.** T2 shows
the behavioural test catches it with the structural pin disabled; T3 shows the
structural pin catches it with the behavioural assertion weakened; **T4 shows
three further instruments still catch it with both named halves removed** —
the allowlist's own positive control, the boundary test, and the corrected
one-definition test. T5 confirms the scan reaches real source rather than
passing on an empty set (doctrine #8). There is no single point of failure to
name.

**The pattern this is the fourth instance of.** #113 shipped a mechanism
nothing reached; #114 wired it and built the reader its own sibling class
forbids; #115 required a base but not a usable one; #116's predicate was a
charset, not git's rules — and this one strengthened that predicate everywhere
except the code that uses it. **Each fix was correct about the case it named
and narrower than the sentence describing it.** The instrument that keeps
catching it is review, not the suite: this one had green proofs, reddening
mutations in both attack classes, and a test asserting the inverse of the
property, all at once.

## G38 — the same `$` anchor defect, in the TLS diagnostic guard — RECORDED, NOT FIXED HERE

Found by sweeping the CLASS of G36/G37 rather than the instance, and **not by
any report**. The sweep asked a mechanical question across `src/`: which
module-private compiled regexes have more than one user, and of those, which
have a public wrapper that some other site bypasses? Two candidates came back.
One is not the shape; one is.

**Not the shape.** `chokepoint/audit_normalization.py`'s `_GCP_KEY` has three
users — `normalize_gcp_event`, `from_public_key_export`, `__post_init__` — and
every one calls `.fullmatch()` on the same object. The regex IS the rule there;
there is no stricter wrapper to diverge from. Recorded so the sweep's negative
result is a measurement rather than a silence.

**The shape.** `core/diagnostics.py:186`:

```python
_TLS_REASON = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
```

consulted at line 238 as `_TLS_REASON.match(str(value))`. **`$`, not `\Z`, and
`.match`, not `.fullmatch`** — G36's defect exactly, one module over.

**Measured, not inferred:**

| value | `.match` | `.fullmatch` |
|---|---|---|
| `CERT_EXPIRED` | True | True |
| `CERT_EXPIRED\n` | **True** | False |
| `CERT_EXPIRED\n\n` | False | False |
| `CERT_EXPIRED\nX` | False | False |
| `CERT_EXPIRED\r\n` | False | False |
| `CERT_EXPIRED\r` | False | False |
| `CERT_EXPIRED\nsecret` | False | False |

**THE EXPOSURE IS EXACTLY ONE TRAILING NEWLINE AND NOTHING ELSE**, and saying
so precisely is the point. `$` matches at end-of-string or immediately before a
single final newline, and `[A-Z0-9_]` cannot consume a newline, so no second
character can follow. **This is not a text-injection channel**: arbitrary prose
does not pass, and the table above is the evidence rather than the reasoning.

**Why it is still a defect.** The guard's own comment says the shape is
enforced here "so even a handler that put something else on the attribute could
not turn this key into a text channel" — defence in depth against a value that
is not the OpenSSL symbolic constant. A value that is supposed to be one
symbolic token can carry a line break, and a line break in a log record is the
one character that ends a record. **The guard is one character looser than the
sentence describing it** — the recurring shape this document keeps naming.

**In practice the field is filled by CPython from OpenSSL's table**, so nothing
reaching it today carries a newline. That is a statement about the current
caller, not about the guard, and the guard exists precisely for the case where
the caller is not what it was.

**RECORDED, NOT FIXED HERE, and that is deliberate.** This is a different
module, a different guard, and unrelated to the review finding that opened
#118. Fixing it in this PR would be scope this PR was not asked for, and the
precedent for splitting is the F16/F18 one: report the sibling finding with its
measurement, fix it in its own change. What is owed here is that it was swept
for, found, measured, and written down rather than left as an unexamined green.

**Neither file is in the Hearth ledger.** `core/diagnostics.py` is not
protected, nor is `tools/git.py` (G35). So the integrity ledger did not and
would not see either of these changes.

**THE PIN WRITTEN TO RECORD THIS GAP HAD G37'S DEFECT, and it is recorded
rather than quietly corrected.** The first version asserted on
`_TLS_REASON.match(...)` — the regex object. Two things determine whether the
guard admits a value: the anchor, and the method the call site uses. Measured
through `scripts/mutation_worktree.py` against a real baseline of 26:

| probe | first pin | corrected pin |
|---|---|---|
| U1 gap closed via the ANCHOR (`$` → `\Z`) | 1 red | 2 red |
| U2 gap closed via the CALL SITE (`.match` → `.fullmatch`) | **GREEN** | 2 red |
| U3 gap WIDENED (charset admits a newline) | 1 red | 1 red |
| U4 `_GCP_KEY` consulted with `.match` | 1 red | 1 red |

**U2 is the point.** Changing the call site genuinely closes this gap, and the
first pin stayed green through it: the pin's sentence was about the guard and
its reach was the pattern — a derivation over one of the two fields that
determine the outcome, which is G35's shape and G37's shape, in the instrument
written to record G37's sibling. The corrected pin goes through the real
`Diagnostic` constructor, so it is total over both.

**A SECOND ASSERTION WAS ADDED AT THE SINK**, because "the guard admits it"
and "it reaches the output" are different claims. Measured:
`Diagnostic(...).message()` renders `body_not_json tls_reason=CERT_EXPIRED\n`
— the newline is not dropped before rendering, so one diagnostic becomes two
lines in any line-oriented sink. That is the whole exposure, pinned where it
lands rather than where it is admitted.

**AN EARLIER RUN OF THIS PROBE REPORTED FOUR GREENS AND PROVED NOTHING.** Its
targets included a test module that does not exist, so pytest exited with no
summary, and the harness reported `(no summary)` with an empty failure list —
which a careless reader takes for "nothing reddened". The baseline assertion
(`"passed" in summary`) was added for that reason and is what caught it. The
empty-instrument pass, doctrine #8, in the tool used to check for it.

**SEVENTH OCCURRENCE, #119 — and the first one caught and corrected in the same
minute it was created.** The creation tool appended its footer to the PR body
after the hygiene checker ran, exactly as the fifth and sixth did. What is
different is only the response: the body was **read back immediately**, the
footer **observed** rather than assumed, and stripped via
`update_pull_request`, which appends nothing. The read-back after the strip
returned no vendor token, so this row is **confirmed in both directions** — the
append happened, and the correction took.

That makes `4544106496` the first carrier confirmed on the same channel that
created it, without waiting on the rate-limited review-thread listing. **A PR
BODY is readable through the plain REST pull endpoint**, which is not the
GraphQL listing and not the webhook — a THIRD independent channel, available
whenever the carrier is a body rather than a reply. Recorded because the entry
previously named only two.

**The standing cost was still paid.** `ci.yml` reads
`github.event.pull_request.body` frozen at trigger time, so the open-event text
check saw the stale payload regardless of how quickly the body was corrected.
Only a push clears it. Correcting the body faster does not avoid that; it only
shortens the window in which the repository's own record is wrong.

**A FOURTH CHANNEL, AND A CORRECTION TO THIS ENTRY'S OWN PRESCRIPTION.** This
entry has said, and a standing instruction repeated, that when the review-thread
listing is rate-limited the right response is to WAIT — an hour costs nothing.
**That was wrong, and it was wrong for the whole time it was written down.**

`get_review_comments` is GraphQL and shares the hourly limit. But review
comments are also served by plain REST, which does not:

| route | kind | observed |
|---|---|---|
| `get_review_comments` (MCP) | GraphQL | `API rate limit already exceeded` |
| `GET /repos/{o}/{r}/pulls/{n}/comments` | REST | **HTTP 200** |
| `GET /repos/{o}/{r}/pulls/comments/{id}` | REST | **HTTP 200** |

All three were exercised within the same minute on 2026-09-16: the GraphQL
listing refused, and both REST routes returned the bodies with the footer
present. So "the footer cannot be confirmed right now" was never a statement
about the FACT — it was a statement about one client, generalised to the fact.
**That is the same error this document names elsewhere as reading an
instrument's silence as a finding**, committed here in the entry that exists to
catch it.

**WHAT IT COST.** Two carrier rows sat marked unread across three pull requests
when a single REST call would have closed them. More seriously, a thread on
**#119** was posted by a reviewer at 04:59:42Z and reported in this session as
"no threads on it yet" — a claim resting on the GraphQL listing having refused,
when REST would have returned it. **An unreadable listing was read as an empty
one, which is precisely doctrine #8.** The finding in that thread was correct.

**THE RULE NOW:** a rate-limited GraphQL listing is a reason to try REST, not a
reason to wait. Waiting is the last resort, after every channel has refused, and
the channels are four: the GraphQL listing, the PR-activity webhook, the REST
pull endpoint for bodies, and the REST review-comment endpoints for replies.

**FIRST CARRIER CREATED AND CONFIRMED UNDER THE CORRECTED RULE.**
`4022679600`, the reply on #119, was read back through
`GET /repos/{o}/{r}/pulls/comments/{id}` immediately after posting: HTTP 200,
footer present, **observed**. No wait, no inference, no row marked pending.

That is the whole practical difference the fourth channel makes, and it is
worth stating as a number rather than a principle: under the old rule this row
would have read "not read back" for up to an hour, and two such rows stayed
that way across three pull requests. **A REPLY CARRIER CANNOT BE STRIPPED** the
way a PR body can — `update_pull_request` appends nothing, but there is no
equivalent for a review reply, so the footer stands on every one of the
twenty-two. Confirming them promptly does not remove them; it only keeps this
table honest about what is known versus assumed.

**EIGHTH OCCURRENCE, #120.** Same route, same read-back, same strip. Recorded
without further commentary: the mechanism has not changed since the fifth, and
repeating the analysis each time would pad this entry rather than extend it.
What the count is for is the rate — eight occurrences across eight pull
requests opened this way, which is every one of them. **The append is not
intermittent and no PR opened through that tool has escaped it.**

### The vocabulary pin was itself inferred from names, and review caught it

Reported on #120 and **confirmed by direct probe before being accepted.** The
first version of `test_the_authorization_vocabulary_names_no_harness_fault`
asked whether any member of `EXECUTION_REFUSAL_REASONS` contained one of seven
substrings — `sandbox`, `harness`, `candidate`, `started`, `timeout`,
`timed_out`, `isolation`. Measured, by adding one member at a time to the set:

| addition | caught? |
|---|---|
| `runtime_unavailable` | **missed** |
| `setup_failed` | **missed** |
| `infra_fault` | **missed** |
| `execution_did_not_run` | **missed** |
| `sandbox_candidate_never_started` | caught |

**Four of five missed**, and the one it caught was the one that happened to
contain the author's own tokens. So the test did not detect the change it
claimed to pin, and G35's statement could have gone stale under any plausibly
named addition.

**This is G25 restated: a name is not a membership.** A predicate over
spellings infers semantics from whatever fragments the author thought of, while
an addition is free to be called anything. The set is now pinned **as a set**:
any addition fails whatever it is named, and the failure message sends the
author back to this entry to decide whether the new reason belongs to the
authorization stage at all.

**The same review pass produced the count correction above** — `len(...) >= 15`
passed happily against a set of seventeen while the prose said nineteen. The
pin now asserts `== 17`, and the docstring states plainly that the count is not
the property; membership is. The count is asserted only because this entry
quotes a number.

**THE THREAD WATCHER HAS A FALSE-POSITIVE MODE, recorded before it misleads
someone.** The REST poll that caught #120's finding keys each comment on
`path:line` alongside its id. When a push makes a comment OUTDATED, GitHub
sets `line` to `null`, the formatted row changes, and the diff against the
previous poll emits the SAME comment a second time as though it were new.

Observed on #120: finding `4026187551` was emitted twice, once at
`test_execution_start_signal.py:635` and again at `:None` after a push. The
listing at that moment showed **one** finding and **one** reply, so the second
event was an artefact of the watcher, not a second report.

Recorded because the failure mode is the inverse of the one this entry was
correcting: over-reporting rather than under-reporting. It is the safer
direction — a duplicate is noticed, a miss is not — but a watcher that cries
twice teaches its reader to discount it, which eventually produces the miss
anyway. **Key on the comment id alone, not on id plus mutable coordinates.**

## G39 — the human decision and the execution outcome were outside the chain (F13 + F14)

Reproduced at HEAD before anything was written, with an append-only anchor in
place and `verify_chain().ok` True throughout:

**F13.** `resolve_pending_action` (`ledger/sqlite_ledger.py:505`) stored
approval status, reviewer identity and decision time in mutable columns, and
`_require_chain_binding` (`execution/pending.py:973`) bound the AUTHORIZATION
record, not those columns. Measured: create a genuine hold, `UPDATE` its row
to `approved` with a forged reviewer and time, invoke retry → **the executor
ran once**, chain VALID before and after, chain events `['pending.hold']`.

**F14.** `record_execution` (`ledger/sqlite_ledger.py:647`) inserted execution
rows and chained nothing. Measured: approve and execute, `UPDATE executions
SET executed=0, detail='forged'` → the forged outcome returned, chain VALID.

**F14, escalated.** The flipped row alone did NOT let retry run again: the
at-most-once claim (`execution_committed_at`) refused it — a *different*
mutable column. One more `UPDATE` (null the claim) and retry read the row,
believed the hold had never executed, and **ran the executor a second time**:
two execution rows, one approval, chain VALID. A database-write adversary gets
a second side effect, not just a lying row. Recorded because the audit's
probe said "changed outcome returned" and the real cost is one write further.

The chain was intact and truthful about what it covered. What it covered
excluded the two things a receipt exists to establish.

### Reproductions, permanent and red-first

`tests/conformance/test_chained_decision_and_outcome.py`. Observed against
the unfixed tree, in a clean worktree of `main` with only this module copied
in: **8 failed of 8**. F13, the F14 escalation, and both PART 4 tests fail on
`Failed: DID NOT RAISE ExecutionNotAuthorized` — retry and approval returned
normally, which is the defect: the executor ran, and there was nothing to
raise. The F14 detection test and both positives fail on
`ModuleNotFoundError: prometheus_protocol.ledger.receipts`; the CLI test on
`'receipts    : receipts valid' not in` an output that carried only the
chain line. (The first red run, before PART 3 and PART 4 existed, was 5 of 5.)

> A first draft of this paragraph said F13 failed on `spy.calls == []` and the
> escalation on `len(spy.calls) == 1`. That was written from reading the code
> path, not from the traceback, and it was wrong about WHICH line fires:
> `pytest.raises` fails first, because the call returns. The executor-call
> assertions never got to run. Corrected from the captured output, and the
> second-order table below confirms the same thing from the other side —
> `pytest.raises` is the assertion that carries each raise half.

After the fix: 8 passed.

| test | asserts |
|---|---|
| `test_F13_a_forged_approval_in_the_row_does_NOT_let_retry_execute` | executor never called; refused `decision_entry_missing`; chain VALID before and after |
| `test_F14_a_flipped_outcome_row_is_DETECTED_against_its_chained_counterpart` | chain VALID; `verify_receipts` names the execution and the fields `executed`, `detail` |
| `test_F14_a_flipped_outcome_plus_a_released_claim_does_NOT_execute_twice` | one executor call; refused `outcome_differs_from_chain_entry` |
| `test_F13_a_decision_altered_AFTER_a_genuine_approval_is_refused_at_retry` | an entry exists and the row differs: refused on the DIFFERENCE, field named |
| `test_F13_a_decided_hold_reset_to_pending_cannot_be_approved_again` | the re-approval attack: row reset to pending, chain says rejected, second approval refused, nothing written |
| `test_the_audit_cli_exits_2_when_a_row_disagrees_with_its_receipt` | the independent verifier's entry point reports both verdicts and exits 2 |

### Vocabulary ruling — chained the structural pair, introduced nothing

Per the brief and #120. The outcome receipt carries `(started_ok,
candidate_started)` as the executor measured them. **They had to be carried at
all first**: `_execute` (`execution/controller.py:454`) dropped both before
`record_execution`, and the `executions` table had no columns for them. Two
additive columns, nullable: `NULL` is "no executor was invoked for this row"
(blocked, unavailable, pre-execution-refused), a third state distinct from
`0`. The typed-reason question is filed as **G41** with #120's migration cost.

The four new refusal reasons — `decision_entry_missing`,
`decision_differs_from_chain_entry`, `outcome_entry_missing`,
`outcome_differs_from_chain_entry` — are AUTHORIZATION-stage integrity
conditions ("why may this hold not proceed"), alongside
`record_differs_from_chain_entry`. None describes what the sandbox did. The
membership pin moves 17 → 21, exact.

### Shape ruling — two new chained event types, not a grown record

**`DECISION_EVENT = "pending.decision"`**, subject `pending:<id>`;
**`OUTCOME_EVENT = "outcome.execution"`**, subject `execution:<id>`.

**The constraint that made the alternative unworkable** is the Block 1a one
(`docs/live-state-pinning-design.md`): `_require_chain_binding` compares
`stored != pending.record` over the WHOLE record (`execution/pending.py`). A
record written once at hold creation and required byte-equal to its entry
cannot carry a decision known at approval or an outcome known at execution —
writing either in would break the binding it is protected by. So each is its
own append-only entry and the row must equal the LATEST entry for its subject.

**No `RECORD_VERSION` bump.** The authorization record's shape is unchanged,
so pending holds are NOT staled. The chosen consequence instead: **a hold
already `approved` before this change, with no decision entry, is refused at
retry as `decision_entry_missing`** — fail-closed, and narrower than a version
bump, which stales every pending hold. Stated here so it is chosen rather than
discovered. An execution row written before this change has no outcome entry
and reads `outcome_entry_missing` to the verifier — correct: it is
unverifiable, and the verifier says so rather than passing it.

**Where the chain write lives: inside the ledger methods**, not the service.
`record_execution` has six call sites in the controller; chaining at each is
six chances to miss one, which is G37's shape. The three decision writers —
`resolve_pending_action`, `invalidate_pending_action`, `mark_state_moved` —
each call one helper after their `UPDATE` commits. The helper reads the row
back and projects it by name, so the receipt is the row AS STORED through the
SAME conversion a verifier uses, never the arguments the writer was handed.

**Why not `execution.outcome`.** `chokepoint/reconcile_gate.py:88` classifies
any chain event starting with `execute`/`execution` as its own and raises
`LookupError("missing legacy history")` on a payload without
`approval_binding`. Measured: the EXISTING `execution.observation` event
already trips it. That is G40, recorded and not widened.

### The derived check — the test that decides the sprint

`tests/conformance/test_receipt_derivation.py`. The rely-upon field sets are
`dataclasses.fields(DecisionRecord)` and `dataclasses.fields(OutcomeRecord)`
(`ledger/receipts.py`), and **field names are column names**, so the row is
projected by name with no hand mapping. The dataclasses are the SCHEMA; the
projection returns a dict, because a row whose `status` was overwritten with
a number is a mismatch to report, not a construction error to raise.

- **Two sources, checked against each other:** the columns the three writers'
  `SET` clauses touch are read off the ledger's source and must equal the
  derived decision set exactly. A writer that grows a column reddens it.
- **Per-field totality:** parametrised over the DERIVED lists — 6 decision
  fields, 11 outcome fields including the structural pair — each column
  overwritten alone after a genuine transition is reported as exactly that
  field.
- **What can vary outside the derivation, pinned EXACTLY** (no floor, per the
  brief's rule): `pending_actions` has 17 columns, 6 in the record, **11
  outside**; `executions` has 18, 11 in the record, **7 outside**. Each is
  named with its reason in the test, and the real table minus the record must
  equal that set — a column nobody decided about reddens it.

**What could vary outside the derivation, and why each is outside:**

| column | why outside |
|---|---|
| `pending_actions.execution_committed_at` | the at-most-once claim. Its role as the SOLE double-execution defence is closed — retry now reads `executed` off the chain, and the escalation test proves the claim is no longer load-bearing for that. Its role as a mutex between honest concurrent drivers is not a receipt property. **Residual.** |
| `pending_actions.action` | bound by the pinned record's `artifact_sha256`. **Measured**: a forged action column refuses at approval as `descriptor_snapshot_mismatch`, zero executor calls. |
| `pending_actions.authorization` | IS chained, under `pending.hold`, byte-equal |
| `pending_actions.{subject_id, risk_class, reason, verdict, confidence, judgment, created_at}` | hold-creation data, covered by the pinned record's descriptor and coverage blocks where it matters; not a decision |
| `executions.{verdict, confidence, authoritative, judgment}` | what AUTHORIZED, not what HAPPENED; the pinned record's coverage block is the chained account. And `_backfill_executions` legitimately `UPDATE`s `verdict/confidence/authoritative`, so chaining them would flag every backfilled row |
| `executions.unavailable` | derived from `source` at write time; `source` is in the record, so it cannot vary alone |
| `executions.authorization` | the pinned record, chained under `pending.hold` for a hold-linked row. **Residual for auto-approved rows**, which have no hold and whose record is chained nowhere |
| `id` on both | the subject, not a field |

### Executed mutations — both attack classes, the brief's list

Through `scripts/mutation_worktree.py`. First pass 67 green unmutated, second
pass 52 (a narrower module set).

| mutation | class | observed |
|---|---|---|
| D1 the decision event never chained | deletion | 36 red |
| D2 the outcome event never chained | deletion | 22 red |
| D3 decision binding removed from `_revalidate` (the F13 defect) | deletion | 3 red |
| R4 the whole retry loop reverted to the row read (the F14 defect) | deletion | 1 red |
| S1 the verifier compares the row's projection against ITSELF (§7.5) | self-comparison | 20 red |
| S2 the service's decision binding compares the row against itself (§7.5) | self-comparison | **GREEN, then 2 red** |
| D4 retry reads `executed` off the row, alone | deletion | **GREEN** |
| D4+M the row read AND the field-mismatch check removed | deletion pair | 1 red |

**S2 was green on the first pass and that green was a proof gap, not
evidence.** The F13 reproduction refuses on `decision_entry_missing` — the
"no entry" branch — before any comparison runs, so nothing exercised the
service comparing a row that DIFFERS from an existing entry. The two PART 4
tests were written for exactly that; S2 then reddens on both.

**D4 alone stays green, and the probe says why rather than an argument.** The
field-mismatch check immediately above it refuses any row that differs from
its receipt, so on every path that reaches the `executed` read, the row and
the chain agree on it — the two spellings are equivalent by construction.
D4+M removes the mismatch check as well: 1 red, the escalation test. **The
mismatch check carries the property**; the `chained["executed"]` read is
correct by intent and masked in practice. Recorded so a later reader does not
"fix" the redundancy by removing the wrong half.

**Substitution** (`tests/conformance/test_receipt_substitution.py`): one
hold's chained decision swapped for another's with the chain re-hashed to
self-consistency. Chain VALID; **detected without an anchor** by the receipt
check (the row disagrees with its entry) and refused at retry. **The named
limit**: entry AND row rewritten together is NOT detected without an anchor —
and what it buys is a downgrade, alice's approval reading as bob's rejection.
WITH an append-only anchor the same rewrite is `BROKEN` and retry refuses
`chain_did_not_verify`. The subject is hashed, so relabelling an entry between
holds is `BROKEN` on its own. Same limit as the authorization record's,
inherited exactly.

**Second-order**, each proof with its property assertion dropped and the TRUE
defect restored underneath: O1 (F13, minus `spy.calls == []`, + D3) 3 red; O2
(escalation, minus the call count, + R4) 1 red; O4 (altered-after-approval,
minus its reason assertions, + S2) 2 red. No proof survives. In each,
`pytest.raises` carries the raise half; the executor-call count is
belt-and-braces against an execute-then-refuse ordering.

### What the docs may claim afterwards — and the residual, plainly

An externally anchored chain protects only chained bytes. After this sprint
the chained bytes are: the pinned authorization record (`pending.hold`), the
observation receipts (`execution.observation`), **every decision transition**
(`pending.decision`) and **every execution outcome** (`outcome.execution`).
`audit --verify-chain` runs the hash walk AND the receipt check and exits 2
if either fails; the two are complementary — an intact chain under rewritten
rows fails the second, honest rows over a rewritten chain fail the first.

**What an adversary with database-write authority can still do:**

1. Rewrite a row AND its entry AND every later hash — detected only by an
   external anchor outside their authority. Unchanged from `docs/ledger-integrity.md`.
2. Null `execution_committed_at`. No longer buys a double execution (the
   chained outcome refuses it); still lets two HONEST drivers race, which the
   claim exists to prevent. Residual.
3. Rewrite `executions.authorization` on an **auto-approved** row, which has
   no hold and no `pending.hold` entry. Residual, named above.
4. Rewrite `executions.{verdict,confidence,authoritative,judgment}` to mislead
   a reader of `executions()` about what a run rested on. The coverage block
   in the chained pinned record is the authoritative account; the promoted
   columns are not. Residual, and the backfill path is why.
5. ~~Delete a whole execution row.~~ **Closed on this PR, by review.** Filed
   first as G42, an orphaned entry the verifier would not see. Review found
   it was a P1: delete the row (or re-attribute its `pending_id`) and null the
   claim, and retry — which discovered receipts by walking ROWS — saw nothing
   and ran the executor AGAIN. Measured. Retry now enumerates receipts from
   the chain; the verifier walks entries to rows for both tables. G42 records
   the correction of severity.

Not prevention. Nothing stops the write. The anchor is what turns a rewrite
from silent into witnessed, and this sprint widened what it witnesses.

### Instruments

- `tests/conformance/test_chained_decision_and_outcome.py` — 15 proofs (8 at first push; PART 5 added 7 for the two review findings)
- `tests/conformance/test_receipt_derivation.py` — 25, of which 17 parametrised over the derived fields
- `tests/conformance/test_receipt_substitution.py` — 4
- `tests/conformance/test_open_gaps.py` — 3 added (G40 ×2, the G39–G42 naming pin); the G42 limit pin removed when it closed
- **47 new proofs in total, counted by collection, not by hand** — the PR body first said 45 from a tally; corrected from the measurement
- Hearth: `execution/controller.py` and `execution/pending.py` re-sanctioned to measured digests; `ledger/sqlite_ledger.py` and `ledger/receipts.py` are **not** in the protected set (G35's limit, still open). **CORRECTED 2026-09-17 (F-12):** this enumeration was incomplete. `runtime/security_build.py` and `ledger/readers.py` -- the build guard and the reader-population derivation, the two modules that decide what every other guard's verdict MEANS -- were also outside the set, and not by a recorded decision: they were never added. Both are protected now and the pin moves 21 -> 23. The two ledger modules remain excluded, and that exclusion IS chosen, under G35.
- Type gate 322 → 326 (`ledger/receipts.py` and the three proof modules); wide dataclasses 50 → 52; additive-column pin +2; positive controls 54 → 58 (three paired positives for the receipts, one for G40's named limit); `EXECUTION_REFUSAL_REASONS` membership pin 17 → 21. Every one exact, none a floor.

## G40 — `chokepoint/reconcile_gate.py` misclassifies any `execution*` chain event as its own — RECORDED, NOT FIXED HERE

Found while naming G39's outcome event. `_decode_rows` (`chokepoint/reconcile_gate.py:88`)
routes every chain row whose `event` starts with `execute` or `execution` into
its execution-binding decoder and raises `LookupError("missing legacy
history")` when the payload has no `approval_binding`.

**Measured:** a ledger holding one `execution.observation` entry — the
re-observation receipt `execution/pending.py` has written since G29 — makes
`_decode_rows` raise. So a deployment that points the chokepoint's reconcile
gate at the same ledger file the execution controller writes cannot
reconcile. Whether any deployment shares the file is a deployment property
this repository does not fix; the collision is in the code regardless.

**Not fixed here**: chokepoint scope, NOT THIS SPRINT. G39's outcome event is
named `outcome.execution` — outside the prefix, measured to decode cleanly —
so this sprint does not widen it. The remedy is an exact event allowlist in
the reconcile gate rather than a prefix, and it belongs to the chokepoint's
own sprint with its own reproduction.

## G41 — an execution-stage typed reason, filed with its cost

#120 established the harness fault is expressible structurally through
`(started_ok, candidate_started)` and has no typed reason. G39 chained the
pair and, per the brief, introduced no vocabulary. The question stands, with
the cost #120 stated: a NEW execution-stage set (not a widening of
`EXECUTION_REFUSAL_REASONS`, which is the authorization vocabulary), a field
on `ExecutionResult`, every construction site, every consumer, the outcome
receipt's schema, and now the derived receipt check — which would pin the new
field by construction. Better added once the underlying bytes are committed
and verifiable, which they now are. Awaiting its own sprint.

## G42 — the receipt check walked rows, not entries — CLOSED 2026-09-16 by review of #121, and it was a P1

**As filed:** `verify_receipts` asked "does every row have an entry" and not
"does every entry have a row", so a DELETED execution row left its receipt
orphaned and unreported. Filed as a small gap to fold in later rather than
widen the sprint.

**THE SEVERITY WAS WRONG, and review of #121 said so.** Retry discovered which
receipts to check by walking the same ROWS. Measured, both variants, with an
anchor and the chain VALID:

| adversary write | + null the claim → retry |
|---|---|
| `DELETE FROM executions WHERE pending_id = ?` | **executor ran a second time** |
| `UPDATE executions SET pending_id = 999` | **executor ran a second time** |

Not an orphaned curiosity: the same double execution F14's escalation was
about, reached through deletion instead of a flipped flag. A deleted HOLD row
was the safe direction at retry (`KeyError`, nothing runs) but left its two
entries orphaned with `holds_checked=0` and nothing reported.

**Closed, both directions.** Retry enumerates the receipts for a hold from the
CHAIN (`outcome_entries_for`, whose payloads carry `pending_id` and cannot be
re-attributed without the mismatch showing), requires each to have its row
(`execution_row_missing`), compares it, and only then reads `executed` — and
still walks the rows, so an inserted row with no receipt is refused.
`verify_receipts` walks entries to rows for both tables (`execution_row_missing`,
`hold_row_missing`), subject-keyed and event-filtered so an entry this module
did not write is never mistaken for a receipt without a row. Membership pin
21 → 23. The G42 pin that held the gap open fired as written and is removed;
the proofs of the closed state are `test_chained_decision_and_outcome.py`
PART 5.

**The lesson recorded with it:** "the derived check is row-to-chain, and the
reverse direction is scope creep" was the wrong reason to defer. A check that
walks one direction is a check an adversary evades by deleting. The
derivation was right; its coverage was half.

**NINTH OCCURRENCE, #121 — and the CI cost observed, not predicted.** Same
route: the creation tool appended its footer after the hygiene checker ran;
read back, confirmed, stripped, and the strip read back. CI run
`35148672967`, triggered by the open event with the footer frozen in
`github.event.pull_request.body`, failed **all three build jobs at "Message
hygiene"** — the standing cost this entry names, now measured on the PR that
carries this sentence. Nine occurrences across nine pull requests opened
through that tool. **The rate is 9 of 9.**

### Found by review on #121 before merge — two P1s, both confirmed by probe

**P1 — retry derived its history from mutable rows.** See G42 above; the fix
and the measurement are there. What this entry adds is where it sat: in the
very loop this PR wrote to close F14's escalation. The loop read `executed`
off the CHAIN — correctly — but chose WHICH receipts to read by walking the
ROWS, so the chain-side truth was reachable only through a row-side index an
adversary could empty. The mismatch check (D4+M) carried the flipped-flag
case; nothing carried the deleted-row case, because there was no row to
mismatch.

**P1 — the documented programmatic verifier ran the hash walk alone.**
`docs/ledger-integrity.md` tells programmatic auditors to use
`verify_ledger_file(path, tip_anchor=…)`. Measured: over a ledger whose
outcome row was rewritten under an intact chain, it returned `ok=True,
status='valid'` while `verify_receipts` returned `ok=False` and the CLI
exited 2. Two entry points, two definitions of "verified". Closed with ONE
shared verifier, `verify_ledger`, used by both: `verify_ledger_file` now
returns a `LedgerVerification` carrying both verdicts, `ok` only when both
hold, with every field a `ChainVerification` consumer reads proxied
(`.status`, `.broken_index`, `.detail`, `.length`, `.render()` — 31 call sites
across the test suite, all in tests, none in `src/`) and `status` gaining one
value, `receipts_invalid`. A chain that could not be read reports receipts as
NOT CHECKED, never as clean.

**Red first, both.** PART 5 of `test_chained_decision_and_outcome.py` against
HEAD `4b48f82` in a clean worktree: **7 failed of 7** — the two double
executions on `DID NOT RAISE ExecutionNotAuthorized`, the two orphaned-entry
cases on `assert not True` (the verifier said ok), and the three programmatic
verifier tests on `AttributeError: 'ChainVerification' object has no attribute
'chain'`. After the fix: green.

**Executed mutations**, both attack classes, 202 green unmutated:

| mutation | class | observed |
|---|---|---|
| V1 the chain-side enumeration removed (only the row walk left) | deletion | 5 red |
| V2 receipts selected by the ROW's `pending_id`, not the payload's | substitution | 2 red |
| V3 the missing-row refusal dropped (a missing row skipped) | deletion | 1 red |
| V4 `verify_ledger` drops the receipt half | deletion | 2 red |
| V5 `verify_ledger_file` reverts to the hash walk alone | substitution | 1 red |
| V6 the inverse walk removed (G42 reopened) | deletion | 2 red |

**V2 is the cross-context substitution and it is the informative one**: the
enumeration is still chain-side and still "correct" in shape, but the
`pending_id` it filters on comes from the row the adversary controls, and it
reddens exactly the two tests the P1 was about — deletion and re-attribution.
Second-order, defect restored under each proof: deleted-row minus its
call-count assertion (+V1+V3) 3 red; re-attributed minus its (+V2) 2 red;
programmatic verifier minus `not forged.ok` (+V5) 1 red. No proof survives;
`pytest.raises` and the status assertion carry each half respectively.

## G43 — a component the build guard's traversal cannot reach is reported as `default_not_applicable`, not refused

**Filed by independent review of #122, fixed only in part here.** The Part 1
remediation states this limit at the mechanism and pins both halves of it; the
RULING that non-discovery must refuse is Part 2 work and is not done.

`runtime/security_build.py:_objects` descends `_WALKED_CONTAINERS`
(`tuple`, `list`, `dict`) and `__dict__`, and nothing else. A package-owned
component held in any other container is not reached, and
`validate_build` then reports its property `default_not_applicable` whenever
the Config value is its default — which reads downstream as fine. Every other
limit this guard states describes something it declines to cover. **This one
describes something it actively reports as applicable-and-absent when it is
neither**, which is couldn't-verify reported as verified-clean inside the guard
built to end that class (doctrine #1).

**Measured.** The same live defect — a `SubstratePolicy(allow_unverified=True)`
against a Config whose `allow_unverified_substrate` is `False` — attached to a
real `build_execution_controller`, in ten positions:

| position | observed |
|---|---|
| plain attribute | REFUSED `allow_unverified_substrate` |
| inside a `list` | REFUSED `allow_unverified_substrate` |
| inside a `set` | **PASSED → `default_not_applicable`** |
| inside a `frozenset` | **PASSED → `default_not_applicable`** |
| as a `dict` KEY | **PASSED → `default_not_applicable`** |
| behind a `SimpleNamespace` | **PASSED → `default_not_applicable`** |
| behind a lambda closure | **PASSED → `default_not_applicable`** |
| behind a generator | **PASSED → `default_not_applicable`** |
| external subclass, honest `__module__` | REFUSED `component` |
| duck-typed third-party replacement | **PASSED → `default_not_applicable`** |

The external-subclass refusal added in #122 covers MRO-based foreign subclasses
*that the traversal reaches*. It covers neither an unwalked container nor a
duck type with no first-party base.

**LATENT IN THE SHIPPED GRAPH, OPEN IN PRINCIPLE.** An exhaustive walk that
also descends sets, slots, closures and namespaces was run against all four
runtime roots: the only object `_objects` misses is `Config`, excluded
deliberately. So nothing hides there today. Nothing refuses if it ever does.

**Both halves are passing tests**, so this entry cannot go stale silently:
`test_security_build.py::test_the_shipped_graph_hides_nothing_from_the_traversal`
(latency) and
`::test_a_component_the_traversal_cannot_credit_refuses_the_build` (renamed from `test_an_unreachable_component_reads_as_not_applicable_not_as_a_refusal` when F-1's ruling replaced the limit it pinned)
(the behaviour, over five container shapes). The second asserts what the guard
DOES; closing this gap must flip it, which is the intended signal.

**The second half of the same finding, not fixed and not separately numbered:**
the *field* population is derived from `dataclasses.fields` and fails closed on
an unknown field, but the *consumer classes per property*
(`security_build.py:158-255`) are twelve hand-written names. Measured on
`build_orchestrator` with `gate_threshold=0.9`: the same disagreeing value
(`threshold=0.0`) is REFUSED when carried by `PromotionGate` and reported
`applied` when carried by a new first-party type. A new Config field refuses; a
new consumer of an existing field is silently uncovered. Draft hole #8's fix
was to add the second consumer to that list, which is the same shape as the
hole.

## G44 — a second guard over the same fact silently disarmed two older mutation proofs

**Found by CI on #122's own head, after the review, and it had already turned
the matrix red on all three Pythons.** Recorded here because the mechanism is
general and will recur every time this tree adds defence in depth.

**What CI observed.** Run 35169843547 on `4664dad` failed step 32,
"PHASE-1.2c Checkpoint B seam mutations (must be caught)", on Python 3.10,
3.11 and 3.12. Steps 33–50 never ran, so the PostgreSQL job, the sandbox
conformance job, the skip manifest and the full suite were never reached on
that head. The independent review of `4664dad` reported that it could
attribute no workflow run to that commit; a run existed and it was red. That
is a miss in the review, not a later regression.

**The proximate cause** was mechanical: `install_build_guards` replaces every
public factory function with a `@wraps`-decorated guard, and the shared
mutation harness took `inspect.getsource` (which follows `__wrapped__`) and
`__code__` (which does not) from the same name. Recompiling the inner source
and comparing its free variables to the wrapper's raised `AssertionError` at
`scripts/fix_b_revert_proofs.py`. `inspect.unwrap` fixes it, and the guard
still runs because the wrapper calls the function the harness patches.

**The real finding is what that assertion was hiding.** With the harness
repaired, two older proofs stopped isolating the mechanisms they name:

| proof | observed at `4664dad` | why |
|---|---|---|
| `chain-row-comparison-removed` | `1 passed` where a failure was required | the new authoritative reader compares the same record against the same receipt, so removing `_require_chain_binding`'s comparison left the tamper caught elsewhere |
| `selected-profile-injection-unwired` | 8 call failures against a pinned 9 | the new build guard resolves the profile itself and raised the same "no committed verification profile", so the unknown-profile half passed regardless |

Both were GREEN-for-the-wrong-reason: the proof would have passed whether or
not the mechanism it names still worked. That is the shape this tree keeps
finding, arriving this time through a genuinely good addition. Defence in
depth is not the defect; a single-target mutation left pointing at one of two
mechanisms is.

**The fix keeps each proof measuring its own mechanism** rather than relaxing
a pin. The harness now takes optional COMPANION edits, so a row can neuter
every mechanism carrying the property and isolate the one it names. With them
both runners return to their original pins — `8 / 9` and `7 / 18`, the same
numbers base `9141936` reports — so nothing was re-pinned to accommodate the
change.

**The limit, stated.** Companion edits are hand-written. Nothing derives the
set of mechanisms that carry a given property, so the next guard added over an
already-proved fact will disarm its proof the same way, and only a red pin or
a reviewer will say so. Deriving that set is not attempted here.

### THE STANDING RULE, earned when G44 recurred a second time

**A shared refusal label is a shared cause.** Three component-level refusals in
`security_build.py` all carried `property_name == "component"`. Adding the third
(non-discovery) made `external-subclass-refusal-deleted` SURVIVE: deleting that
refusal left components undiscovered, the new rule refused in its place, and the
proof went green while the mechanism it names was gone. Exactly G44's shape,
through a different door.

So: **adding a refusal to an existing label requires re-running every runner
that pins refusals on that label, at the moment the refusal is added** — not at
the end of the sprint, when the survivor is one red line in a long log and the
change that caused it is twenty edits back. The fix is to name the causes apart
(`component_not_discovered`, `component_unregistered_carrier`), which restored
the runner to 28 rows all red with no pin relaxed.

**BROADENED THE SAME DAY, by breaking it.** The rule as first written named
refusal labels. The next thing that went red in CI was not a label: a test was
RENAMED, and `receipt_classification_proofs.py` went on naming the old string.
The string still parsed, still read correctly in review, and selected nothing —
`RuntimeError: baseline invalid: ...: (no summary)`, on all three Pythons, with
every row before it caught. The runner refusing was right; a mutation that would
silently not apply is a proof of nothing presented as a proof of safety.

The general rule is therefore about REFERENCES, not labels: **a mutation runner
names its proof by a string that no compiler and no import checks, so changing
anything a runner names — a refusal label, a test name, a source line it
mutates — requires re-running that runner then.** Which runners name what is
now DERIVED rather than remembered:
`tests/conformance/test_proof_selectors_exist.py` reads every selector out of
every `scripts/*_proofs.py` and every test name out of the tree, and refuses a
selector that does not exist. Verified against the real defect in a
MutationWorktree: restoring the stale name reddens
`test_every_selector_a_runner_names_is_a_test_that_exists[receipt_classification_proofs.py]`.

There is no single doctrine file in this repository — the numbered doctrines are
referenced across this tracker and `docs/live-state-pinning-design.md` but never
enumerated in one place — so the rule lives here, with the entry it generalises.

## G45 — the three diagnostics an auditor reaches for on a corrupted ledger were the three that crashed on one — CLOSED 2026-09-17 by review of #123

**Reported by independent review of #123's opening head `2d23871`, against
`src/prometheus_protocol/ledger/sqlite_ledger.py`, and reproduced before any
fix.** It is a real defect and it was introduced by #122's own reader work.

`verify_chain` took its rows from `_receipt_source()`, the snapshot the receipt
check uses. That snapshot decodes the JSON columns of `pending_actions` and
`executions` — two tables the hash walk never looks at — because it has to
compare those rows against their receipts. A single malformed column in either
therefore raised `json.JSONDecodeError` out of `verify_chain`. The surrounding
handler catches `sqlite3.DatabaseError`, which a decoder error is not, so it
escaped `verify_chain`, `verify_ledger_file` and the CLI audit alike.

The snapshot was borrowed for a reason worth recording: `chained_events()`
became a guarded reader in #122, so calling it from the chain verifier would
recurse into a full authoritative read. Chain rows need no decoding, so the
verifier now reads `audit_chain` directly and nothing else.

Observed before, on a ledger with `pending_actions.action` overwritten with
`{not json`: `json.decoder.JSONDecodeError` from all three. Observed after:

```text
verify_chain           -> valid           (the chain itself is intact)
verify_receipts        -> checked=False, findings=(), ok=False, not_verifiable
verify_ledger_file     -> not_verifiable  ok=False
all 11 guarded readers -> ExecutionNotAuthorized reason='ledger_rows_unreadable'
```

Three separate verdicts because they are three separate facts, and the middle
one is doctrine #8: a couldn't-check that emitted no findings would have read
downstream as a clean ledger. `ledger_rows_unreadable` was minted rather than
reusing `chain_did_not_verify`, because the hash walk is not what failed and a
refusal naming the wrong cause is the shape this tree keeps finding.

**What the instruments missed, stated.** The reachability corpus had no
corrupted-storage fixture at all: every ledger it built was one this code had
written. No mutation could have caught this, because no proof supplied an input
the mutation would have changed the handling of. Six mutation rows now cover
the mechanism in both attack classes, and the per-reader parametrisation is
DERIVED from `reader_methods` rather than hand-listed — the first shape of it
named five readers, which is exactly the "a name is not a membership" failure
(G25) in a test written to fix a different one.

**Observed on the fix**, read off runs rather than predicted: reachability
proofs `156 passed`, zero skips, the classification module re-pinned `27 -> 53`
of which 11 are the derived per-reader parametrisation, 6 pin G47's boundary
and 5 pin G48's; receipt-classification
mutations `33 rows, 33 first-order red, zero survivors` (was 23), `10 of 33`
still red under second-order assertion deletion; record-revert mutations
unchanged at `7 / 18`, which matters because their companion edits anchor into
`_authoritative_read`; type gate `335 files`, unchanged; full suite
`3010 passed, 23 skipped` against base `81481c7` at `2982 passed, 23 skipped`,
the +28 being 26 classification cases and two in `test_positive_control_set`,
which collects one per registered control.

**Not claimed:** that corrupted-storage inputs are now covered generally, or
even that every JSON column is covered. One column shape, on the read path, and
only where the projector decodes STRICTLY -- `_execution_row` decodes
best-effort and swallows the same corruption into `None`. See G47 for that
boundary, measured and pinned, and G46 for the unreceipted-column family it
belongs to.

## G46 — an unreceipted column survives tampering with the ledger still `valid` — ON THE CRITICAL PATH FOR THE RECEIPT CONTRACT

> **THIS IS NOT A GENERAL GAP.** `confidence` is unreceipted and two threshold
> readers route on it (`executions_below_confidence`, `authoritative_pass_below`),
> so a receipt can claim an authorization path whose threshold decision rests on
> tamperable bytes. The receipt says the decision was made; it does not cover the
> value the decision turned on. That is the **fourth clause of the release gate**,
> not a backlog item, and it blocks the receipt contract rather than waiting on
> it.

Measured 2026-09-17 while scoping G45, on a ledger with one recorded hold:

| column overwritten | result |
|---|---|
| `pending_actions.confidence` = `'not a number'` | `pending_actions()` **returned the row**; `verify_ledger_file` -> `valid` |
| `pending_actions.id` = NULL | refused by SQLite: `IntegrityError: datatype mismatch` |
| `pending_actions.created_at` = NULL | refused by SQLite: `NOT NULL constraint failed` |
| `pending_actions.status` = NULL | refused by SQLite: `NOT NULL constraint failed` |

Three of the four are held by the schema. The fourth is not, and it is the one
that matters: `confidence` is what `executions_below_confidence` and
`authoritative_pass_below` threshold on, so editing it changes which rows a
routing query returns while every verdict stays `valid`.

This is inside the limit `docs/reachability-readers.md` already states — the
receipt covers the fields of `DecisionRecord` and `OutcomeRecord`, and
`confidence` is not among them — so it is a gap in the coverage, not a
contradiction of a claim. It is recorded rather than fixed because widening the
receipted field set is a change to what is chained, which belongs in its own
change with its own migration question, not in a review response.

**Not measured:** the other tables' unreceipted columns, and whether any other
unreceipted column feeds a routing or threshold decision.

## G47 — a malformed execution column is normalised to `None` and nothing says so — RECORDED, NOT FIXED HERE

**Found by probing the boundary of G45's own fix rather than by trusting it**,
which is the only reason it is here: the claim "a malformed JSON column
refuses" was about to be written without checking whether it was true of every
JSON column. It is not.

The two receipted tables do not decode alike. Derived from the projectors'
source by `test_the_two_decoders_are_split_exactly_as_the_limit_says`:

| projector | column | decoder |
|---|---|---|
| `_pending_row` | `action`, `judgment`, `authorization` | `json.loads` — strict |
| `_attempt_row` | `skills_used`, `evidence` | `json.loads` — strict |
| `_execution_row` | `judgment`, `authorization` | `_load_json` — best-effort |

`_load_json` says what it is in its own docstring: "returns ``None`` on empty
or malformed input". Measured end to end, on a ledger holding one hold and one
execution, each column overwritten with `{not json`:

```text
pending_actions.action         reader -> refused 'ledger_rows_unreadable'   file -> not_verifiable
pending_actions.judgment       reader -> refused 'ledger_rows_unreadable'   file -> not_verifiable
pending_actions.authorization  reader -> refused 'ledger_rows_unreadable'   file -> not_verifiable
audit_chain.payload            verify_chain -> not_verifiable               file -> not_verifiable
executions.judgment            reader -> RETURNED None                      file -> valid ok=True
executions.authorization       reader -> RETURNED None                      file -> valid ok=True
```

**Both channels miss it at once,** which is what makes it worth an entry rather
than a footnote. The read path turns the corruption into `None`, which every
caller reads as "this row had no judgment" — a rewrite presented as an absence,
doctrine #8 on a path G45 does not touch. And the receipt does not catch it
either: neither column is a field of `OutcomeRecord`, so the chained outcome
receipt never compares them. Same family as G46, one table over.

**Why it is not fixed here.** Making `_execution_row` strict would refuse every
read of any ledger that ever legitimately held a non-JSON string in those
columns. Every writer in the tree today serialises with `json.dumps`
(`sqlite_ledger.py` lines 711-712 and 939-942), so no current writer can
produce one — but whether a HISTORICAL writer did is unmeasured, and refusing a
pre-upgrade shape on an unmeasured assumption is exactly what made F-3 wrong
three weeks ago. The archaeology belongs in its own change, with the same
provenance discipline `test_the_fixture_is_the_pre_receipt_shape` applies.

**Pinned as behaviour, not prose.** Two parametrised tests hold the covered and
uncovered sides apart, and the decoder split is derived from source rather than
listed. The day someone makes the decode strict, the limit test reddens and has
to be withdrawn deliberately — with the history question answered — instead of
the surrounding claim quietly becoming true.

**Not measured:** whether any shipped ledger contains such a row; the same
question for `promotions` and `workflow_steps`, whose projectors decode nothing
and so are outside this table entirely.

## G48 — the fix for G45 caught the decoder's BASE class and relabelled unrelated faults — CLOSED 2026-09-17 by review of #124

**Reported by independent review of #124 against `9a0019b`, the commit that
closed G45, and reproduced before any change.** Recorded rather than quietly
fixed because the shape is the one this tree keeps finding, and this time it
arrived inside the fix written to stop it.

`_authoritative_read` wrapped the reader call and the snapshot in
`except ValueError`. `json.JSONDecodeError` IS a `ValueError`, so the guard did
catch every corruption it was written for — and also every unrelated
`ValueError` the reader itself raised. `executions_below_confidence` and
`authoritative_pass_below` both call `float(threshold)`. Observed on a
PERFECTLY CLEAN ledger, `verify_chain() == valid`, nothing corrupt anywhere:

```text
executions_below_confidence("not a number")  -> ExecutionNotAuthorized reason='ledger_rows_unreadable'
authoritative_pass_below("not a number")     -> ExecutionNotAuthorized reason='ledger_rows_unreadable'
```

A caller's bad argument, reported as storage corruption, sending the caller
down the corruption path. After narrowing both handlers to the decoder's own
exception:

```text
executions_below_confidence("not a number")  -> ValueError (its own)
authoritative_pass_below("not a number")     -> ValueError (its own)
executions_below_confidence(0.5)             -> []            (positive control)
pending_actions() on a malformed column      -> refused 'ledger_rows_unreadable'
verify_ledger_file on the same               -> not_verifiable
```

**Why the base class was chosen in the first place, stated.** The comment at
that handler argued `ValueError` was the NARROW choice — narrow against
`except Exception`, which would have turned a real defect in the projection
into a polite refusal. That reasoning was right about the direction and wrong
about the floor: the decoder raises an exception of its own, and nothing else
raises it, so there was a narrower option the comment did not consider.
"Narrower than the obviously wrong one" is not the same as narrow.

**The same widening was present in `verify_receipts`** and is narrowed with it.
There it would turn an undiagnosed fault into `checked=False` — the
couldn't-check verdict awarded for something nobody checked, doctrine #8
wearing the fix's clothes.

**Pinned in both directions.** Five cases: the two threshold readers refusing
to relabel a bad argument (asserting the raised error is NOT an
`ExecutionNotAuthorized`, since that class IS a `ValueError` and a bare
`pytest.raises(ValueError)` would pass on the defect itself), the two positive
controls that they still read a clean ledger, and one for `verify_receipts`.
Two mutation rows widen each handler back to `ValueError` and must redden.

**Not covered, measured rather than assumed:** a NULL JSON column would raise
`TypeError`, not `JSONDecodeError`, and is not caught. It is unreachable
through the schema — every JSON column on the hold is `NOT NULL`, and SQLite
refuses the UPDATE with `IntegrityError: NOT NULL constraint failed`.

## G49 — what neither component scope can see, named rather than left to be found

F-1's ruling made non-discovery a refusal (`security_build.py`, `_discovered`).
A total traversal of arbitrary Python objects is not achievable, so these are
the residuals — each a place a component could exist where the guard would not
know, and each a PASSING TEST rather than a paragraph
(`test_the_named_residuals_of_the_discovery_scope_are_real`, four cases):

| residual | why it is not closed |
|---|---|
| an object built lazily on first use | it does not exist when the guard runs |
| an object behind `__getattr__` or a property | the walk will not INVOKE it; running arbitrary code during a security check is a worse bargain than the gap |
| an object captured by a closure the CALLER wrote | only the package's own closures are followed. Measured: following every closure cell failed 4 chokepoint tests and errored 71 more on an in-memory audit medium behind a test-supplied executor |
| an object reachable only from module globals | not reachable from the root at all |

Two further shapes the collector itself cannot see: an object held only by a C
extension without `tp_traverse`, and one held only in a frame the walk never
reaches. Neither is reproducible as a test here and both are listed UNVERIFIED.

**Not claimed:** that the credited and discovered scopes agree on anything but
the objects carrying a compared attribute. The refusal is scoped to those
deliberately — see G50.

## G50 — the carrier discriminator is an attribute NAME, which is F-7's shape

`security_attribute_carriers` refuses a credited object that carries an
attribute a property is compared on and is not a registered consumer. The
discriminator is the NAME. That is the shape F-7 reports on
`type(obj).__module__`, inside the fix for F-4.

**Why it ships anyway, stated rather than glossed.** F-7's pin fails OPEN — a
foreign class sets `__module__` to a package-looking string, which need not name
a module that exists, and escapes the guard. This one fails CLOSED: an
unregistered carrier REFUSES THE BUILD. The cost is a false refusal a developer
resolves by registering the class, not a missed detection.

**Measured package-wide**, eight classes declare a compared attribute without
being registered consumers, pinned exactly by
`test_the_carrier_name_collisions_are_pinned_exactly`:

* three on `Config`, which both walks exclude, so they never reach the rule;
* `ResolvedPosture.escalate_below` — records a resolved escalation, does not
  implement the gate that honours it. NAME COINCIDENCE;
* four `signer` carriers — two request records, an in-memory audit model's
  signer factory, and the migration runner's config. METADATA CARRIERS.

Exactly one of the eight is REACHED by any graph the suite builds —
`AuthorizationContext`, whose `signer` is a dict of identity metadata — and it
is registered for that reason. `name` is excluded from the map entirely:
`core.models.Tier` carries it in the shipped swarm graph, so keying on it would
refuse a correct build.

**Not fixed because the population is not derivable.** Which class honours a
Config field is semantic and attribute names do not carry it: `timeout_s` is on
`SubprocessVerifier`, `RemoteModelProvider` and `HttpAppendOnlyLog` for three
different fields.

## G51 — the alternate-ledger and private-SQL limit lived only in two report sentences

Stated at `docs/reachability-build.md:32-33` and
`docs/reachability-readers.md:120` and nowhere in the tree. Doctrine #5: a named
gap is a passing test, and a limit that exists only in a report is a limit
nothing re-checks.

**What the limit is.** The reader guard is a boundary on the shipped
`SqliteLedger` public reader API. Trusted code can use the private `_conn`, the
`_receipt_source()` diagnostic, monkeypatch methods, mislabel a new reader as a
writer/diagnostic, or introduce a different `Ledger` implementation entirely —
none of which the derivation covers.

**Now a passing test**, `test_an_alternate_ledger_implementation_is_outside_this_derivation`.
Measured: `reader_methods` RECOGNISES `pending_actions` on an unrelated
implementation and the guard never WRAPS it, because `guard_readers` is applied
through `SqliteLedger.__init_subclass__` and an unrelated class never triggers
it. The read hands back rows nothing verified. If a future change starts
guarding alternate implementations, that test reddens and both documents must be
corrected rather than quietly becoming right.

**Not closed**, and the reason is the one the reports give: this is a
composition contract, not a sandbox against trusted Python. Closing it means
deciding what an alternate `Ledger` implementation must PROVE before its reads
count as authoritative, which is a design question and not a test.

## G52 — the guard-form audit: three name-keyed sweeps, one with a firing bypass

TYPE-GATE-HARDEN-2 applied the allowlist doctrine to the type gate's own guards
and flagged the rest as the next sprint. This is that audit.

**Population.** 91 conformance modules. The doctrine is about guards that SWEEP
the tree and judge what they find — an ordinary behavioural test constructs a
state and asserts the outcome, which is the second permitted form by
construction. Sweeping guards, measured by their use of `read_text`, `rglob`,
`walk_packages`, `ast.parse` or `getsource`: **62**.

**Shape 1 — a name pin on a writable attribute — found three times outside
`security_build.py`:**

| guard | discriminator |
|---|---|
| `tests/conformance/test_secret_canary_sweep.py:142` | `obj.__module__ == module.name` |
| `tests/conformance/test_implementation_registry.py:271` | `obj.__module__ == info.name` |
| `tests/conformance/test_sandbox_unbounded_reaches_the_command.py:174` | `cls.__module__.startswith("prometheus_protocol.")` |

**The bypass probe FIRES.** Against the secret-canary sweep, which exists to
find credential-bearing fields, with a dataclass planted in
`prometheus_protocol.core.config`:

```text
baseline credential fields discovered      : 9
with __module__ set honestly               : 10  (+1)
with __module__ set to a module that does
  not exist                                :  9  (+0)   <-- invisible
```

A credential-bearing dataclass escapes the sweep by lying about its module.
`__module__` is a writable string and the module it names need not exist.

**NOT FIXED HERE, and the reason is a design question.** The replacement for a
module-name discriminator is a derived one — the set of classes actually defined
in the file being swept, read from its AST rather than from an attribute the
class controls. That is constructible, but it changes what "belongs to this
module" means for every sweep at once, and re-pins three populations. It is one
change with one ruling, not three one-liners.

**Shape 2 — a search term that cannot match the value it looks for — not found
in this population.** The known instance (a bare `on:` key resolving to boolean
`True` under YAML 1.1, so a guard looking for the string `"on"` found nothing
and passed) is in workflow parsing, and the sweeps here read Python, not YAML.
Recorded as measured-absent rather than as clean.

### The per-guard inventory

Classified by static shape: does the guard state a PERMITTED set, prove the
property BEHAVIOURALLY (`pytest.raises` on a constructed defect), both, or
neither. Counts over the 62 sweeping guards:

| form | guards |
|---|---|
| both | 19 |
| PERMITTED set | 18 |
| PERMITTED set (exact equality) | 14 |
| BEHAVIOURAL | 6 |
| **NEITHER — name-keyed discriminator** | 5 |

**Two of the five flagged are FALSE POSITIVES of the classifier, checked by
hand rather than reported as findings:** `scripts/reachability_build_proofs.py`
carries `__module__` only inside the mutation STRING it applies, and
`tests/conformance/test_security_build.py` carries it inside
`test_the_carrier_name_collisions_are_pinned_exactly`, which is the pin for this
very shape. The three genuine instances are the ones tabled above.

The classifier is a static heuristic and its output is evidence, not a verdict —
which is why the three it found were each confirmed by reading the code and one
by a firing bypass probe. Full table:

| guard | form |
|---|---|
| `scripts/check_hygiene.py` | PERMITTED set (exact equality) |
| `scripts/check_ip_consistency.py` | PERMITTED set (exact equality) |
| `scripts/check_message_hygiene.py` | PERMITTED set |
| `scripts/check_proof_composition.py` | PERMITTED set (exact equality) |
| `scripts/check_skip_manifest.py` | PERMITTED set |
| `scripts/check_type_gate_manifest.py` | PERMITTED set (exact equality) |
| `scripts/check_type_gate_receipt.py` | PERMITTED set |
| `scripts/f11_reconcile_revert_proofs.py` | PERMITTED set |
| `scripts/f11_source_revert_proofs.py` | PERMITTED set |
| `scripts/fix_b_revert_proofs.py` | PERMITTED set |
| `scripts/mountinfo_diagnostic.py` | PERMITTED set (exact equality) |
| `scripts/mutation_worktree.py` | PERMITTED set (exact equality) |
| `scripts/phase_1_2c_checkpoint_b_revert_proofs.py` | PERMITTED set |
| `scripts/phase_1_2c_record_revert_proofs.py` | PERMITTED set |
| `scripts/pih4a_revert_proofs.py` | PERMITTED set |
| `scripts/reachability_build_proofs.py` | **NEITHER** — name-keyed discriminator |
| `scripts/reachability_reader_proofs.py` | PERMITTED set (exact equality) |
| `scripts/receipt_classification_proofs.py` | PERMITTED set |
| `scripts/type_gate_floor.py` | PERMITTED set (exact equality) |
| `scripts/type_gate_revert_proofs.py` | PERMITTED set |
| `tests/conformance/test_advisory_cannot_satisfy.py` | both |
| `tests/conformance/test_bank_decision_surface.py` | PERMITTED set |
| `tests/conformance/test_ci_collection_pins.py` | PERMITTED set (exact equality) |
| `tests/conformance/test_ci_single_source.py` | PERMITTED set (exact equality) |
| `tests/conformance/test_composed_message_guard.py` | both |
| `tests/conformance/test_config_attestation.py` | BEHAVIOURAL |
| `tests/conformance/test_dependency_closure.py` | PERMITTED set |
| `tests/conformance/test_execution_start_signal.py` | both |
| `tests/conformance/test_fix_b_revert_pins.py` | both |
| `tests/conformance/test_git_ref_format.py` | PERMITTED set |
| `tests/conformance/test_implementation_registry.py` | **NEITHER** — name-keyed discriminator |
| `tests/conformance/test_no_second_aggregator.py` | both |
| `tests/conformance/test_open_gaps.py` | both |
| `tests/conformance/test_phase_1_2a_revert_pins.py` | both |
| `tests/conformance/test_phase_1_2b_revert_pins.py` | both |
| `tests/conformance/test_phase_1_2c_checkpoint_b_revert_pins.py` | both |
| `tests/conformance/test_phase_1_2c_revert_pins.py` | both |
| `tests/conformance/test_pih4a_revert_pins.py` | both |
| `tests/conformance/test_platform_contract.py` | BEHAVIOURAL |
| `tests/conformance/test_policy_enforcement_regression.py` | BEHAVIOURAL |
| `tests/conformance/test_positive_control_set.py` | PERMITTED set (exact equality) |
| `tests/conformance/test_prod_fix_1_revert_pins.py` | both |
| `tests/conformance/test_prod_fix_2_revert_pins.py` | both |
| `tests/conformance/test_proof_composition.py` | PERMITTED set (exact equality) |
| `tests/conformance/test_receipt_classification.py` | both |
| `tests/conformance/test_receipt_derivation.py` | PERMITTED set (exact equality) |
| `tests/conformance/test_reobservation_branch_delete.py` | both |
| `tests/conformance/test_reobservation_wiring.py` | PERMITTED set |
| `tests/conformance/test_sandbox.py` | BEHAVIOURAL |
| `tests/conformance/test_sandbox_unbounded_reaches_the_command.py` | **NEITHER** — name-keyed discriminator |
| `tests/conformance/test_secret_canary_sweep.py` | **NEITHER** — name-keyed discriminator |
| `tests/conformance/test_security_build.py` | **NEITHER** — name-keyed discriminator |
| `tests/conformance/test_security_build_inventory.py` | PERMITTED set |
| `tests/conformance/test_security_field_behaviour.py` | BEHAVIOURAL |
| `tests/conformance/test_security_posture.py` | BEHAVIOURAL |
| `tests/conformance/test_skip_manifest_guard.py` | PERMITTED set |
| `tests/conformance/test_stdlib_floor.py` | PERMITTED set (exact equality) |
| `tests/conformance/test_strict_booleans.py` | both |
| `tests/conformance/test_substrate_revert_pins.py` | both |
| `tests/conformance/test_swarm_invariants.py` | both |
| `tests/conformance/test_type_gate.py` | PERMITTED set |
| `tests/conformance/test_type_gate_revert_pins.py` | both |

---

## G53 — counts from a filtered view: the eighth instance, the doctrine, and the sweep

**What happened.** The reader runner's row count entered PR #125's report as
**5** when the runner had **6** rows. The number came from the runner's log read
through a case-sensitive filter (`^[a-z0-9-]+:`), which dropped the one row whose
label begins with a capital — `F3-permissive-none` — and the report's own
"corrections to the brief" section repeated it. The same 5 sat in a `ci.yml`
step comment. An error-correcting section propagated the error, and the cause
was a filter that narrowed its own population before the count was taken.

**The doctrine, now written down** as `docs/DOCTRINE.md` #11 — the first
doctrine in this repository that exists as text rather than as citations:
*any count that enters a report, a pin, or a tracker comes from the artifact,
never from a filtered view of it; where a filter is unavoidable, the count and
the filter are reported together and the unfiltered total beside them.*
`tests/conformance/test_doctrine_index.py` keeps that file's index of cited
numbers equal to the numbers the tree cites, in both directions.

**The prior instances, checked against this tracker rather than accepted.** The
brief named eight. Traceable here by their wording: the positional sweep (G2),
the positive-control set (G16), the composition and membership pins (G25, one
entry for both), the `--history` sizing (G6's table, which already reports
"reachable" beside "carrying"). Not traceable to an entry by wording, and so
UNVERIFIED as tracker entries: the positive-control *collector* defect (six
docstrings that did not self-declare, fixed in flight in #125), the probe that
returned false GREENs, and the adapter collector. The eighth is this entry.
"Found by a person probing, never by a guard" holds for every one that is
traceable; for the three that are not, it is the brief's claim and not this
tracker's.

### The sweep — population first, then the subset

Every count-producing site in `scripts/`, `tests/support/`, `tests/conformance/`,
`tests/chokepoint/` and the Python heredocs of every workflow, enumerated from
the AST (a `len`, `sum`, `Counter` or `.count` call), classified by where the
number goes — into a PIN (compared with a constant, an ALL-CAPS name or a
manifest value), a REPORT (a print, an f-string, an assert message), STORED for
later, or OTHER (indexing, loop bounds) — and by whether a narrower feeds it (a
comprehension `if`, `startswith`/`endswith`/`lower`/`casefold`/`isidentifier`,
a regular-expression match, a `glob`, a slice, an `in` test, `filter()`), in
the counted expression or in the one-level definition of the name counted.

| | count |
|---|---|
| **population**: count-producing call sites | **477** |
| of which PIN / REPORT / STORED / OTHER | 320 / 73 / 43 / 41 |
| candidates: PIN, REPORT or STORED with a narrower in or feeding the count | **49** |
| a second shape the call walk cannot see: `x += 1` inside a loop that also filters | **5** |
| shell count pipelines (`grep -c`, `wc -l`) in workflows | 0 |

Of the 49 candidates, 43 are test-internal assertions where the filter IS the
property under test — `assert len(hits) == 1` over a comprehension that selects
the one receipt the test planted — and are not population counts; they are
listed here by count, with the rule that excluded them, rather than dropped
silently. The enumerator's own limits, stated: it sees calls and `+= 1`
counters; it does not see a count produced by an external tool and parsed
(mypy's "N source files" and pytest's "N collected" are the artifacts
themselves, and are what the fixes below tie to), nor a count kept in a
`Counter` updated by index, nor anything in `src/` (which produces no report
numbers by design and was out of scope by the brief).

### Sites, what each filters, and the measured delta today

| site | what is filtered before counting | filtered vs artifact today | action |
|---|---|---|---|
| `scripts/check_hygiene.py:83` | files `read_text` cannot decode are skipped silently, plus the terms file | **435 scanned of 437 candidates**: 1 excluded by design, 1 binary (`site/og.png`) — delta 2 | **FIXED**: reports scanned / candidates / excluded / unreadable and names the unreadable. Whether a binary should be scanned for tokens is a design question, **filed** here. |
| `tests/conformance/test_ci_collection_pins.py:204` (`_collected`) | lines of `--collect-only` output carrying `::` | 814 `::` lines = 814 summed = **814 pytest collected** — delta 0 | **FIXED**: the sum is tied to pytest's own `N tests collected` line; a line shape the filter cannot see now refuses. |
| `tests/conformance/test_ci_collection_pins.py:317` | `text.count(literal)` + a regex over the workflow, compared with `>= len(PINNED_STEPS) - 1` | 6 inline + 6 delegated = **12 = 12 pinned steps**; the `- 1` was slack of exactly one — delta 0 | **FIXED**: `==`. A tolerance on a population pin, removed with its measured value beside it. |
| `.github/workflows/ci.yml`, F11 proofs step | per-module `classname.endswith(module)`; no tie to `len(cases)` | 282 collected ids, **none class-held** — delta 0; the filter drops a test inside a class | **FIXED**: `assert counted == len(cases)`, the tie the other four inline steps already had. |
| `ci.yml` substrate, attestation, PROD-FIX-1, PROD-FIX-2 steps | same `endswith` filter | tied to the total on the next line; delta 0 | none needed; noted as the reason the F11 step stood out. |
| `scripts/type_gate_revert_proofs.py:497` | `failed` = `failure` elements only; an `error` or `skipped` element is neither counted nor refused (fix_b and f11 refuse them) | runner re-run with the refusal in place: **19 bypasses caught, 20 guard failures, pinned 19 / 20**, unchanged — delta 0 today | **FIXED**: refuses errors and skips, mirroring `fix_b_revert_proofs.py:279`. |
| `scripts/reachability_reader_proofs.py` | no row count in its own output; a reader counted labels through a filter | artifact **6** rows (12 runs); published **5** — **delta 1** | **FIXED**: rows hoisted to `mutations()`, `rows: N` printed first. The `ci.yml` comment that carried the 5 corrected. |
| `scripts/reachability_build_proofs.py`, `scripts/receipt_classification_proofs.py` | same: the count of `FIRST`/`SECOND` lines through a prefix filter | **34** and **33** from the tables; the build log's 184 lines account fully as 34 + 34 + 115 `RED` + 1 — delta 0 | **FIXED**: `rows: N` printed first. |
| `tests/conformance/test_proof_selectors_exist.py` | the runner population is the glob `scripts/*_proofs.py` | 17 on disk = **17 run by `ci.yml`** — delta 0 (F-9 had found 2 the workflow did not run) | **FIXED**: pinned both ways, disk against workflow, in the same module. |
| `tests/conformance/test_positive_control_set.py:103` | a test is a positive control if its docstring says the phrase or its name says `positive_control` | the delta between *is* and *says* has no mechanical measurement; six were found by hand in #125 | **filed**: the fix is a marker or decorator, a design choice, not a one-liner. |
| `tests/conformance/test_type_gate.py:110` | `> 100` over `rglob("*.py")` | **145** today | **filed** under Part 3's floor sweep, not this sprint. |
| `tests/conformance/test_git_ref_format.py:193-195` | `> 400`, `> 50`, `> 20` over a corpus split by the function under test | **449 / 377 / 72** today | **filed** under Part 3. |
| `docs/OPEN-GAPS.md` G28, the carrier table | this tracker's own count of 29 was re-derived on 2026-09-17 by a filter (`startswith("| #")` and a backtick) | the artifact — the rows of that table — gives **29**; the section's second table (2 rows) is a different population — delta 0 | none: the table is the artifact. Recorded because the derivation was the doctrine's shape. |
| `scripts/check_message_hygiene.py --history`, `scripts/mountinfo_diagnostic.py:88`, `tests/support/positional_sweep.py` | filter beside an unfiltered total, or a refusal on the unreadable | compliant | none. |

**Re-derived from the artifact, as the brief asked, old → new:** reader runner
rows **5 → 6**; build runner rows **34 → 34**; the OPEN-GAPS carrier table
**29 → 29**; the `ci.yml` reader-step comment **5 → 6**. Hygiene's reported
number moved from "435 files scanned" to "440 files scanned of 442 candidates"
on this branch — the difference from 435/437 being the five files this change
adds, which the old report would have folded into one number.

**What this does not close.** A filter that is the *definition* of a population
— "a selector is a `test_`-prefixed identifier" — cannot be replaced by the
artifact, because the artifact does not know what a selector is. The doctrine
asks that such a filter be stated beside its count, which
`test_proof_selectors_exist.py` does (63 selectors, 3 of 17 runners, the 14
others name files by path). The semantic filters above are filed, not fixed.

---

## G54 — the per-version pass counts were unreadable, and nothing compared them (CLOSED by the matrix-agreement guard)

**What was unreadable, measured.** On `67b05e8` the matrix was green — 57 of 57
steps on each Python, read job by job — and the per-version pass counts were
not: the job-log tail returned by the API is the wheel build (345 lines back
and still inside it), and the raw log URL is refused by the reporting
environment's egress proxy (`403`, connect rejected). The counts were read
locally instead, on one interpreter. Green said the suite ran on all three; it
did not say the three ran the same suite.

**The two cited precedents, checked.** `set_authorizer(None)` on 3.10 —
`src/prometheus_protocol/ledger/sqlite_ledger.py:353-360`: "It took the 3.10
matrix job to find that; 3.11 and 3.12 were green through all 51 steps." And
`import tomllib` — this tracker at lines 28 and 172: "passed the gate on all
three matrix jobs and failed at import on 3.10"; "the 3.10 job importing
everything is the check that actually catches both". Both were found by the
matrix, and **both were RED jobs**. Neither is an instance of three green jobs
with different counts, which is the class nothing was watching: a test that is
*absent* on one interpreter — defined under a `sys.version_info` guard,
parametrised from version-dependent data, or dropped by `collect_ignore` —
passes where it exists and is neither failed nor skipped where it does not.
The skip manifest pins each version's skip SET against the sanctioned one and
would not see it. The precedents motivate the matrix; they do not exemplify
this gap, and the brief's "the count is exactly what would have differed" is
true of the class and not of either example.

**CLOSED, by an instrument rather than a habit.**

* `scripts/check_matrix_agreement.py` reads one JUnit report per matrix
  version and compares them as SETS — collected ids and skipped ids, not counts
  (G25) — and refuses on: a version set that is not exactly the workflow's
  matrix, read from `ci.yml` (shortfall and excess both); an empty report
  (doctrine #8), refused before anything is compared; any failure or error; any
  id one version collected and another did not, naming the id and the version
  that lacks it; the same over skips. It prints the per-version table
  (collected / passed / skipped / failed / errors) and writes it to the step
  summary, so the counts are readable from a short job log without a raw log.
* `ci.yml`: each matrix job uploads `full-suite.xml` as
  `full-suite-<version>` with `if-no-files-found: error`; a `matrix-agreement`
  job with `needs: build` downloads every `full-suite-*` and runs the script.
  A red build job leaves it skipped, which is a red run either way.
* `tests/conformance/test_matrix_agreement.py`: 13 tests — one positive control,
  one refusal per disagreement, the command line both ways on the download
  layout, the workflow shape (upload name, `if-no-files-found`, the download
  pattern, the call), the matrix derived from the workflow it is given, and
  the named limit as a passing test. Membership pinned in
  `proof_composition.json` under `matrix_agreement`.
* `scripts/matrix_agreement_proofs.py`: **9 first-order rows in a
  MutationWorktree, both attack classes, all 9 caught, each by its named
  proof** — the collected comparison deleted (3 red), the skipped comparison
  deleted (1), composition substituted by a count (4), every version compared
  against itself (4), the empty-report refusal deleted (1), the failure and
  the error refusals deleted (1 each), the version set substituted by a count
  (1), the matrix hand-listed instead of read (1). Second-order
  assertion-deletion is deliberately not run here and the runner says why.

**Measured on this tree, with real interpreters.** The full suite was run from
a clean detached checkout of `03b28a9` on 3.10, 3.11 and 3.12 (all three are
installed here), one JUnit report each, and the guard was run on the three:

* the COLLECTED sets are identical on all three — **3075 ids each**; today's
  tree has no version-specific collection, which is now a measured fact and
  not an assumption;
* the first 3.10 and 3.12 runs, from virtual environments under `/tmp`, reported
  **115 failed, 2924 passed, 24 skipped, 12 errors** each against 3.11's
  **3052 passed, 23 skipped**. The guard refused, naming the 115, the 12 and
  the one skip 3.11 lacked. The cause is the environment and not the
  interpreter — identical counts on both versions, and every failure the
  namespace sandbox reporting itself unavailable, because the sandbox mounts a
  private `/tmp` and could not see an interpreter that lived there. That is the
  guard reporting a real difference in the shape it is built to report; the
  runs were repeated from environments outside `/tmp` and are recorded in the
  paragraph below.
* the runs repeated with the SYSTEM interpreters `/usr/bin/python3.10` and
  `3.12` (which the sandbox can see) and each version's packages on the
  parent's path: **3.10: 11 failed, 3041 passed, 23 skipped; 3.11: 3052
  passed, 23 skipped; 3.12: 11 failed, 3041 passed, 23 skipped**. The guard on
  the three: collected identical (3075), skipped identical (23), and two
  refusals — `failed: 3.10` and `failed: 3.12`, the same eleven ids on both:
  `test_config_attestation.py::test_the_digest_is_byte_identical_in_another_process`
  and ten parametrised cases of `test_platform_contract.py`, every one of
  which spawns a child with `sys.executable` and a clean environment, and the
  child reports `ModuleNotFoundError: No module named 'pytest'` — the system
  3.10 and 3.12 here have no packages installed; only the parent had them on
  `PYTHONPATH`. An installation difference, not an interpreter difference,
  measured from the failure text and from the two versions failing the same
  set. Nothing here produced three runs under identical conditions on all
  three interpreters; the matrix job on this branch is the first that can,
  and its table is reported on the pull request when it lands.
* what IS established about this tree from these runs, without qualification:
  the three interpreters COLLECT the same 3075 ids and SKIP the same 23; the
  class G54's guard exists for is absent today.

**The deliberate divergence, as the brief asked — real interpreters, not an
edited report.** In a throwaway worktree of `03b28a9`, one module was planted
with a test defined under `if sys.version_info >= (3, 12):` beside one defined
unconditionally, and run on `/usr/bin/python3.10`, `3.11` and `3.12`:

```text
3.10: 1 passed          3.11: 1 passed          3.12: 2 passed

| version | collected | passed | skipped | failed | errors |
| 3.10 | 1 | 1 | 0 | 0 | 0 |
| 3.11 | 1 | 1 | 0 | 0 | 0 |
| 3.12 | 2 | 2 | 0 | 0 | 0 |
matrix agreement FAILED: 2 disagreement(s) between the matrix versions:
  collected: 3.10 lacks 1 id(s) another version has: ['...test_version_gated_probe::test_exists_only_where_the_interpreter_is_new_enough']
  collected: 3.11 lacks 1 id(s) another version has: ['...test_version_gated_probe::test_exists_only_where_the_interpreter_is_new_enough']
exit=1
```

Three green runs; the guard reddens and names the test and the two versions
that never collected it. The positive control beside it: the gate replaced by
`if True:`, the same module on the same three interpreters — `2 passed` on
each, `matrix agreement passed: 3 versions (3.10, 3.11, 3.12); 2 collected, 0
skipped, identical sets on every version`, exit 0. The worktree was removed
afterwards; nothing of the probe is in the tree.

**Named limits.**

* The upload and download are proved only by a matrix run: the tests pin that
  the steps exist and are shaped correctly; the first run on this branch is
  what shows a report crossing the artifact store. Stated as a passing test.
* A `[conditional]` skip may legitimately differ by host. Within one matrix run
  the three jobs share an image, so a conditional entry differing across
  versions is refused as a version difference. A runner-pool change that gave
  the three jobs different hosts would refuse here and say which ids.
* The guard compares reports that reached it. A job that never uploaded is
  caught by `if-no-files-found: error` on its own side and by the version-set
  check on this side; a job that uploaded a report from a different run cannot
  happen within one workflow run's artifact namespace, and is not claimed
  against otherwise.

---

## G55 — an authorization was not spent when it was used: three paths to an executor, one claim (CLOSED by the occurrence spend)

**The finding, reproduced twice before anything was written.** At `7cc2c4c`,
submitting the same correctly bound assessment, action and `attempt_id` twice
through `ExecutionController.submit` called the executor **twice** and wrote
**two execution rows**, both carrying `attempt-1`. `controller.py:367` said so
in words: *"The auto-approved path carries no hold (pending_id is None) and
needs no claim."* Separately, an approved `GateDecision` retained and handed
straight to a concrete executor's public `execute()` ran **twice**, with no
gateway involved at all and therefore nothing ledger-side that could have seen
it.

**The enumeration was three, not two.** The brief asked whether the two found
were the whole enumeration. They were not. `swarm/runtime.py:290` — a shipped
path, built by `runtime/factory.py:406` — called `self.executor.execute(...)`
with no claim of any kind and no hold to claim; because a packet's
`attempt_id` is derived from the packet and proposal ids, re-running a packet
re-ran every approved proposal's side effect. The population is now DERIVED
rather than listed: `test_every_executor_call_site_in_the_tree_is_inside_a_spend_guarded_path`
sweeps `src/` by AST for `<x>.execute(<y>)`, excludes SQL receivers by name,
and allows exactly two modules — each of which must itself name
`claim_authorization`. A fourth path reddens it.

**The ruling: ONE OCCURRENCE, not one action identity.** The unit is the
descriptor's six fields plus the assessment's `snapshot_digest` — seven, pinned
against the descriptor's own dataclass rather than hand-listed. Two submissions
differing in any one are two occurrences and both may run; two agreeing in all
seven are one, and the second is refused by name. `risk_class` and `subject_id`
are outside the descriptor and so do not make a second occurrence, which is why
three tests that had been reusing one `attempt_id` across genuinely different
attempts had to say what they meant (`test_execution.py`,
`test_live_execution.py`, and the `GitBranchDeleteExecutor` start-signal test,
which was handing ONE decision object to two runs).

**Where the spend lives, and what that costs.** The authority is the
append-only chain: `spend_state` folds `authorization.spend` /
`authorization.release` / `authorization.outcome` entries for one subject. A
row exists — `spent_authorizations` — and decides the RACE only, via its
PRIMARY KEY; nothing asks it whether an authorization is spent. Reset or delete
the row and the fold still refuses (`test_deleting_the_spend_ROW_does_not_restore_the_authority`);
delete the chain entry and the anchor catches it
(`test_removing_the_chain_ENTRY_breaks_verification`). **The cost, stated:** an
O(entries) chain walk per execution, against a table that only grows.

**No `RECORD_VERSION` bump, and holds already pending are unaffected** —
measured, not assumed. Widening `receipts.OUTCOME_FIELDS` with the
authorization key would change the payload every existing outcome entry was
hashed over, so every pre-existing row would read as
`outcome_differs_from_chain_entry`. A new additive event changes nothing
already chained.

**Retry is DECLARED, not inferred.** The spend key is *derived* from the bound
fields; the idempotency key is *supplied and independent*, opted into on the
FIRST call. Matching key → the prior result is returned, read through the
chain's record of which execution row completed the spend, and **no executor is
called**. No key → `authorization_already_spent`. Wrong key →
`idempotency_key_mismatch`. Never declared → `authorization_not_retryable`.
Right key, past the window → `idempotency_key_expired`. Claimed and never
completed → `execution_outcome_unknown`, refused for every caller including a
matching key, because that is the one state where whether the side effect
happened is genuinely unknown.

**A retry cannot change a bound field, structurally.** The key IS the bound
fields, so a retry that alters one derives a different key, names no prior
spend, and is a new authorization that must pass the whole gate. There is no
retry path around the descriptor comparison because a matching retry reaches no
executor at all.

**What the mutation runner measured, including where it disagreed with the
brief's framing.** `scripts/spend_proofs.py`: 11 first-order rows, 22 runs with
the assertions-deleted variants, all 11 caught by their named proof; 8 of 11
still red with every assert deleted. Three findings worth keeping:

* Defence in depth changed which proof each row reaches. The spend has two
  independent barriers — the READ and the CLAIM — so deleting the read does
  NOT redden the reproduction (the claim still refuses a replay); it reddens
  the retry, the one behaviour only the read can give. Each row names the
  proof its mutation actually reaches, measured.
* **A one-field narrowing of the occurrence is not behaviourally visible.**
  `resolve` binds the artifact, target, action class and attempt into the
  snapshot, so `snapshot_digest` covaries with all six descriptor fields:
  remove `artifact_sha256` from `KEY_FIELDS` and two occurrences differing in
  it still derive different keys, and every behavioural proof stays green. Only
  the composition pin sees it — G25 again, a behaviour standing in for a
  composition. The covariance is itself pinned
  (`test_the_MEASURED_redundancy_snapshot_digest_already_covaries`) so that if
  it ever stops holding, the runner's selector is known to be wrong.
* **Nulling the hold claim does not reach the spend.** F14's write is caught
  first by `execution/pending.py`'s chain-derived outcome walk, as a plain
  `ValueError`. So the held path has THREE guards and that scenario isolates
  none of them; the single-target proof is two DISTINCT holds for one
  occurrence, where the hold claim and the outcome walk are both keyed on
  `pending_id` and cannot see across them. The order is pinned, because if it
  ever starts raising `authorization_already_spent` the outcome walk stopped
  running — a real regression wearing a green refusal.

**A reader that called another reader hid its own scope.** Found by the
instrument, not by review: `authorization_spend_state` first read the chain
through the public `chained_events`, and the nested read guard restores
`_ALLOW_ALL` on its way out, replacing the authorizer the scope instrument had
installed. The instrument reported the EMPTY SET for a read that really
touched `audit_chain` — doctrine #8 exactly. Fixed by reading through a private
`_chain_rows`, not by pinning the empty reading.

**Residual, named rather than implied away.**

* The retry window (24h, mirroring `Config.pending_ttl_seconds`) is a module
  constant and a controller argument. It is **not** a `Config` field: it cannot
  be set from the environment and does not appear in the attested posture.
  Pinned as a limit by `test_the_NAMED_LIMIT_the_retry_window_is_not_a_config_field`.
* The swarm path records ATTEMPT rows, not execution rows, so its completion
  names no `execution_id` and it has no prior result to return. No caller there
  can declare a retry key, so the branch is unreachable rather than broken.
* An auto-approved row's `authorization` column now HAS a chained counterpart —
  the spend's key is derived from it — so a rewrite no longer re-derives to the
  chained key. **Nothing in the tree performs that comparison today:**
  `verify_receipts` walks holds and outcomes, not spends. The rewrite is
  catchable by hand and still not caught by an instrument.
* At-most-once is a property of this system's record of the occurrence. It says
  nothing about two deployments with separate ledgers.

**Six new refusal reasons** (`EXECUTION_REFUSAL_REASONS`, 24 → 30), each with a
different remedy, and per the G44 rule every runner that pins refusals on those
labels was re-run at the moment they were added.

### What review of #127 found in this sprint's OWN code, and what each cost

Three findings on `afa32de`, all in code written for G24, and all the same
shape the entry above is about: a guarantee that holds against the attack it
was designed for and not against its mirror image.

**1. A RELEASE COULD UN-SPEND A COMPLETED OCCURRENCE (the serious one).**
Reproduced on an ordinary anchored ledger: call the public
`release_authorization` for an already `COMPLETED` key, and it deletes the
mutex row, appends a WELL-FORMED release, and the fold reads `released`;
`retry_verdict` then returns `may_execute` and **the executor runs a second
time, with `verify_chain().ok` True throughout**. G24 undone by an append that
looks legitimate.

The cause is an asymmetry in the fold I wrote: the outcome event carried an
ordering check (`if status != SPENT: raise`) from the start and the release
did not. The module docstring reasoned only about a release being **deleted**
— "can only make the fold read MORE spent, which is the fail-closed
direction" — which is true and was not the whole story. **A release ADDED
where none belongs moves the fold the other way, and the permissive direction
is the one an attacker picks.** Fixed symmetrically; the docstring's reasoning
is corrected in place rather than left to read as complete.

**2. THE EXECUTOR WALL'S CHECK-AND-SET WAS NOT ATOMIC.** `consume_authorization`
read the flag and then set it — two operations — so two threads handed the
same retained decision could both read it absent and both proceed. Now under a
module lock, the in-process counterpart of `claim_authorization`'s single
`INSERT` against a `PRIMARY KEY`.

**AND THE PROOF IS STRUCTURAL, NOT BEHAVIOURAL, WHICH THE MUTATION RUNNER
ESTABLISHED BEFORE I CLAIMED OTHERWISE.** Replacing the lock with a no-op
context manager left a thread test GREEN. Green means untested until a direct
probe says otherwise, so the field was probed on unmutated-but-unlocked code,
32 threads released from a barrier:

| switch interval | trials | raced |
|---|---|---|
| CPython default, 5ms | 400 | **0** |
| forced to 1e-7 | 400 | **9** (worst case 2 grants) |

Per-trial catch rate stayed near 1% at 8, 16, 32 and 64 threads. So the race is
**real** — that is what the second row measures — and a behavioural test for it
would miss its own guard's deletion about 99% of the time, which reads as a
proof and is not one. What is pinned instead is that the read and the write are
both inside the lock, derived from the AST. **The named limit: that proves the
code is shaped so the interpreter provides atomicity, not that it is atomic.**
The lock still matters beyond CPython — a free-threaded build has no GIL to
mask the window at all.

**3. A RETURNED PRIOR RESULT PRESENTED AN UNRECORDED `stdout` AS `""`.**
Measured: `executions` has no `stdout` column, so a retry cannot be handed the
program's output, and the first reconstruction left the field at its default.
`""` is exactly what a program that printed nothing produces, so "never
recorded" and "printed nothing" became the same bytes at the one point a caller
reads them — doctrine #1, in code written to serve a retry.

**The column was NOT added**, and that is a decision rather than an omission:
PROD-FIX-2 removed a raw model response from `Evidence.detail` because an
endpoint reflecting a header put a bearer token into the ledger, and candidate
stdout is the same class of unbounded, attacker-influenced text. The limit is
named in the field a caller reads, and a test derives the column set from the
table so that adding `stdout` later reddens rather than leaving a placeholder
where the output should be.

**Three more mutation rows** (14 first-order, 28 runs), each naming the proof
it reddens. Finding 1's row is the only one in this entry that mutates a guard
which did not previously exist — the others re-introduce something the sprint
had already closed.

**THE SEQUENCE, RECORDED BECAUSE IT DECIDED WHERE THE FIX LANDED.** #127 was
merged at `3e0adf8` while these three fixes were still local, so for the
interval between that merge and #128 landing, `main` carried finding 1 — a
reproducible way to undo G24 and execute a spent authorization a second time
with the chain still verifying. A merged pull request is finished, so the fixes
are a NEW pull request off `3e0adf8` rather than more commits on the merged
branch; the repository's own pre-push hook refused the resurrection when the
attempt was made, which is that guard (`docs/OPEN-GAPS.md` Block 1.2) doing
exactly its job on a real occasion rather than in a test.

**AND IT IS THE CASE FOR REVIEWING THE HEAD THAT MERGES.** The automated review
that found all three landed on `afa32de`, #127's FIRST head. The head actually
merged was `fd5cee2`. Nothing reviewed the merged head, and the three findings
were against code that was already in it.

### The SECOND review, which found the first fix incomplete — and the shape that ends it

Review of #128 found the release fix **guarded one branch and left its
sibling open**, so the identical bypass worked in two steps instead of one.
Reproduced:

1. execute; the occurrence is `completed`
2. **delete** the `spent_authorizations` row — explicitly inside this module's
   own stated threat model, which claims a reset row restores nothing
3. `claim_authorization` again: it wins, because the row is gone, and the
   **unconditional `COMPLETED -> SPENT`** made the fold agree
4. `release_authorization`: now legal, because step 3 forged the open spend
   the new guard requires
5. execute again — **executor calls 2, rows 2, `verify_chain().ok` True**

So the row-reset claim in the module docstring was true of the fold as a
*lookup* and false of the fold as a *state machine*. The same defect, twice,
in two different branches: an ordering rule applied to some events and not
their siblings, where the bypass is simply to reach the unguarded one.

**THE FIX IS THE SHAPE, NOT A THIRD GUARD.** Patching the branch that was
named would have invited a fourth finding, so the permitted transitions are
now DECLARED in one table (`_PERMITTED_FROM`) and the fold is a single lookup
against it: `spend` only from `unspent` or `released`, `outcome` and `release`
only from `spent`. Three `if` statements is three chances to forget the
fourth; one table cannot have a branch missing from it. Twelve sequences are
walked exhaustively, five of them permitted as the paired positives, and a
separate test pins that the table covers exactly the events the fold folds —
so a fourth event added to one and not the other raises a typed refusal rather
than a `KeyError` or an unchecked fold.

**The second P2: an in-band sentinel is not a signal.** The stdout limit was
first stated with a sentence inside `stdout` itself, and candidate code can
print that sentence verbatim — so a consumer reading the field as documented
captured output could not tell the diagnostic from the real thing, and a retry
reported non-empty text the program never emitted. The availability is now its
own field (`ExecutionResult.stdout_recorded`) with `stdout` left empty; the
prose stays in `detail`, where no consumer reads output. The same shape
`started_ok` and `candidate_started` already have, for the same reason: two
facts, not one.

**What the table did to the proofs, measured.** `scripts/spend_proofs.py` went
from 14 rows to **16**, and second-order survival from **9 of 14 to 16 of 16** —
every row still red with every assert deleted. A fold that refuses a history
raises, and a raise does not need an assertion to be observed. The structural
fix made the evidence stronger, which is not why it was chosen and is worth
recording.

### The THIRD review: the new flag defaulted fail-open, over a population I never looked at

`ExecutionResult.stdout_recorded` was added with a default of `True`, on the
reasoning that *"every executor that sets `stdout` sets it from a real run"*.
That is a true statement about the **five** construction sites which pass
`stdout=` — and the class is constructed at **eleven** sites. **NINE** of them
do not capture: three of the five passing `stdout=` pass the EMPTY LITERAL,
which is "nothing to report" rather than output, and six omit `stdout`
altogether. Every one of the nine inherited the default and told a consumer the
empty string was the program's own output. The flag added to remove an
ambiguity reintroduced it at nine sites.

**This paragraph first said six**, counting only the sites that omit `stdout`
and forgetting the three that pass the empty literal — the filtered-population
error again, inside the entry recording the filtered-population error. Caught
by review of #130; corrected here rather than rewritten away.

**The same error as the count-from-a-filtered-view class (doctrine #11), in a
different medium.** I reasoned about the population I had just edited instead
of the population the rule is over, and a claim true of the part read as a
claim about the whole.

Fixed in the fail-closed direction: the default is `False`, so a path that
forgets to opt in **under-claims** rather than asserting something untrue, and
the two sites that really capture a candidate's output — `execution/executor.py`
and `tools/git.py` — opt in explicitly.
`test_only_a_site_that_CAPTURES_output_may_claim_it_recorded_it` derives all
eleven from the AST and requires the claiming set and the capturing set to be
**identical**, with `stdout=""` counted as "nothing to report" rather than a
capture; a third capturing site has to be justified in that test. Two more
mutation rows, and the paired positive now drives the shipped `SandboxExecutor`
against a fake isolating sandbox that really returns output, because the
fixture spy captures nothing and honestly reports `False`.

### WITHDRAWN: every second-order figure this entry published was wrong

**The claim.** This entry reported, at four points, that N of N mutation rows
stayed red with every assert deleted — `8 of 11`, `9 of 14`, `16 of 16`,
`18 of 18`.

**None of them measured that.** Found by review of #130 and confirmed by direct
measurement: with every assert deleted and **no mutation applied at all**, the
proof module was already RED on one test.

```
UNSTRIPPED baseline: 63 passed in 2.22s
STRIPPED baseline  : 1 failed, 62 passed in 1.60s
   RED ...::test_resetting_the_row_and_RE_CLAIMING_does_not_reopen_the_release
```

**Two causes, both mine.** A test performed its effect INSIDE an assert —
`assert ledger.claim_authorization(...)` — so deleting the assert deleted the
claim, and the test failed for a reason unrelated to any mutation. And the
runner's second-order branch asked only *"are there any reds?"*, never *"did
the NAMED proof redden?"*, and never measured a stripped baseline at all. So
every row inherited that one invariant failure and was counted as surviving.

**The corrected figure, measured against a stripped baseline verified clean:
11 of 18.** Seven rows are caught only by an assert, and they are named in the
runner's output rather than folded into a total.

**What changed so this cannot recur.** The runner now measures the stripped
baseline BEFORE any mutation and REFUSES if it is red — an experiment with no
control produces no evidence, so it raises rather than reporting a number
(doctrine #8 applied to a runner). Refused rather than subtracted: excluding
the known-red test would make the count arithmetic over a number nobody
re-derives. And the stripped runs now require the named selector, exactly as
the first-order runs always did. Every side-effecting call in the module moved
out of its assert — they were also broken under `python -O`.

**Where the withdrawn numbers still appear.** The bodies of #128 and #129 are
merged and carry `16 of 16` and the figures before it. They are superseded by
this section rather than edited, so the record shows what was claimed and when
it was corrected.

**Three reviews, three findings in code written to fix the previous one.**
`spend_proofs.py` is now **18 rows, 36 runs**, and its second-order figure is
**11 of 18** — see the withdrawal below. The sequence is recorded here rather than smoothed over: each fix
was correct about what it fixed and wrong about a neighbour it did not look
at — the release branch, then its sibling the spend branch, then the flag's
default over the construction sites.

---

## G56 — the fix for the fail-open default named its two siblings and left them fail-open

**Found by asking the sprint's own question of the population rather than of
the flag.** #130 flipped `ExecutionResult.stdout_recorded` to the fail-closed
direction, and its entry above records why: a claim true of the FIVE sites that
pass `stdout=` had been made about all ELEVEN that construct the class. The
same dataclass docstring names `started_ok` and `candidate_started` as "two
facts, not one" — one paragraph above the field it fixed — and both were still
defaulting `True`.

**What.** `ExecutionResult.started_ok` and `ExecutionResult.candidate_started`
are claims about whether isolation came up and whether the candidate command
began. Both defaulted `True`, so any construction that did not state them
asserted that isolation started and the candidate ran. The executors' `_refuse`
helpers repeated the shape with their own `started_ok: bool = True,
candidate_started: bool = True` parameter defaults.

**Measured, from the AST, before the change** (`src/` only; the derivation is
the one `test_only_a_site_that_CAPTURES_output_may_claim_it_recorded_it` uses,
widened from one flag to three):

| | sites | explicit | INHERITED |
|---|---|---|---|
| `ExecutionResult` constructions | 11 | — | — |
| — `started_ok` | | 5 | **6** |
| — `candidate_started` | | 2 | **9** |
| — `stdout_recorded` (fixed by #130) | | 3 | 8 |
| `_refuse(...)` calls | 13 | 4 state both | **9 inherit at least one** |

Of the inheriting constructions, five are paths where nothing ran at all: three
swarm refusals (`swarm/runtime.py:536,552,565`), the ledger replay
(`execution/controller.py:526`) and a controller refusal (`:596`). Four of the
nine inheriting `_refuse` calls are refusals taken **before the sandbox is
constructed** — no action, a descriptor mismatch, an unsupported action kind, a
non-isolating adapter (`execution/executor.py:72,74,76,81`), and five more in
`tools/git.py:496,498,502,504,508`. One site asserted the claim outright rather
than inheriting it: the git dry-run at `tools/git.py:516` passed
`started_ok=True` while constructing no sandbox.

**Reproduced before fixing, and it reaches the audit ledger.** Driving the real
`SandboxExecutor` against a non-isolating adapter whose `run` raises — so the
probe cannot pass because the sandbox quietly ran — and then the real
`ExecutionController` against an in-memory `SqliteLedger`:

```
executions rows written: 1
  executed          : False
  refused           : True
  detail            : refused: sandbox 'non-isolating' does not isolate; ...
  started_ok        : True   <- the sandbox was never invoked
  candidate_started : True   <- nothing ran
```

The controller passes both through to `record_execution` on the one path that
calls an executor, so this is couldn't-verify persisted as verified-clean in
the audit record — doctrine #1 at the point `executor.py`'s own comment calls
"where it is most expensive".

**THE POPULATION IS THE FINDING, NOT THE FLAG.** #130 corrected a claim about
five sites into a claim about eleven, and in the same change left two fields
whose population it had just enumerated. The lesson the previous entry drew was
"reason about the population the rule is over"; the population it reasoned
about was one field's, and the rule is over the class.

**Fixed.** Both class defaults are `False`; both `_refuse` helpers default
`False`; the git dry-run states nothing; and the replay carries the stored
columns (`bool(row["started_ok"])`, three-valued in the ledger, so a `NULL`
from a row where no executor was invoked reads as `False`).

**And the rule is now a SHAPE, which needs no allowlist.** Every site that
observed isolation passes the value the adapter reported
(`started_ok=result.started_ok`), never a literal. So a literal `True` for
either flag is never correct: it is a claim written by hand where nothing was
measured. `test_no_site_may_claim_a_harness_fact_it_did_not_MEASURE` derives
every argument from the AST and requires the literal-`True` set to be EMPTY —
no hand-list, and no judgement about which sites "really ran", which is the
half a population rule alone could not decide. Measured after the fix: **0
literal-`True` arguments, 18 measured-or-`False` arguments.**

**WOULD THE BUILD GUARD HAVE CAUGHT IT? No, and the reason is its population.**
Measured:

* `started_ok` / `candidate_started` are not `Config` fields at all (37 fields,
  22 security-classified) — so `validate_build`'s row set never contains them;
* neither is in `SECURITY_FIELDS`;
* `ExecutionResult` carries none of the 24 attribute names
  `security_attribute_carriers()` keys on, so the unregistered-carrier refusal
  does not reach it either;
* and an `ExecutionResult` is a transient return value, not a component held in
  the returned runtime graph, so neither traversal scope sees one.

**That is a gap in the guard, not in the code.** The build guard ends this
class *for Config-derived properties applied to live components*. This defect
is a default on a RECORD the runtime produces, and the guard has no population
that includes records. Closing it would mean a second population — "fields that
are claims about what happened" — and deriving that set is semantic, which is
G50's wall. Not attempted here; named.

**The class sweep — three media, population first.**

| medium | population in `src/` | screened | live defect |
|---|---|---|---|
| boolean defaults a caller can omit (dataclass fields + keyword params) | **72** (44 fields, 28 params, 35 files) | 15 selected, 16 classified-not-permissive, **41 the screen could not classify** | this entry |
| three-argument absent-value reads (`getattr(o,k,d)`, `d.get(k,d)`) | **132** (65 `getattr`, 67 `.get`; 104 literal defaults, 28 computed) | 9 on control-shaped keys | none |
| claim-shaped flags defaulting `True`, by construction site | 3 classes | — | this entry only |

The screen is keyed on the NAME, which is G50's and G17's shape, and it is
reported as a screen rather than a verdict: every selected member was read, and
the 41 it could not classify are listed in the sweep's output rather than
dropped.

**The two near misses, latent rather than live, recorded so the next change
does not make them live:**

* `SandboxResult.started_ok` (`sandbox/base.py:176`) also defaults `True` —
  and **0 of its 13 constructions inherit it**. Every site states the value, so
  the permissive default is unreachable today. Nothing enforces that.
* `ReceiptVerification.checked` (`ledger/receipts.py:384`) defaults `True` with
  1 of 4 constructions inheriting, and `CoverageReport.recorded`
  (`policy/assessment.py:85`) defaults `True` with 2 of 4 inheriting. In all
  three the inheriting site is the success path where the claim is true
  (`receipts.py:559` after the walk ran; `assessment.py:96,99` inside
  `coverage_report`, which is only called with a real `validate_coverage`
  outcome). Correct today, one careless site from not being, and neither has a
  derived guard.

**Test.** `tests/conformance/test_execution_start_signal.py` — the reproduction
at the executor and again at the audit ledger, the paired positive control (a
real isolating run must still claim both, or "nothing claims anything" would
satisfy the reproduction), the fail-closed defaults, the shape rule with its
own non-vacuity control, and the replay.

**Executed mutations.** `scripts/spend_proofs.py` rows 17–21, each restoring one
half of the defect: the class defaults flipped back, the `_refuse` defaults
flipped back (measured twice — once at the executor's return value, once at the
ledger row), a literal claim put back where a measurement belongs, and the
replay's stored columns discarded again. All five are caught first-order by
their named proof.

**The runner grew a second proof module to carry them**, because a runner bound
to one test file can only pin proofs that happen to live there. Each distinct
module now gets its own clean baseline AND its own stripped baseline,
established before any mutation; a module whose stripped baseline is red has no
second-order control and the run refuses.

**Limit, stated.** The shape rule covers `ExecutionResult` and `_refuse` by
name. A third executor that constructs the record through a different helper is
outside it, and nothing derives the set of helpers that build this class.

---

## Superseded figures in merged pull-request bodies — #127, #128, #129, #130

Recorded here rather than by editing the merged bodies, so the record shows
what was claimed and when it was corrected. Extends the note in G55.

| PR | figure in its merged body | superseded by |
|---|---|---|
| #127 | `spend_proofs` at its first size, and the second-order figures before any stripped baseline existed | G55's withdrawal — every second-order figure this sprint published measured nothing, because the stripped baseline was red and nothing checked it |
| #128 | `16 of 16` second-order | the same withdrawal; the corrected figure was **11 of 18** |
| #129 | the figures before the withdrawal | the same withdrawal |
| #130 | `spend_proofs is now 18 rows, 36 runs`; `stdout_recorded` presented as the fail-open default corrected | **24 rows, 48 runs** after G56's five and #131's review round; and the correction was one field of three — G56 is the other two |
| #131, first head | `23 rows, 46 runs` | **24 rows, 48 runs**. The second review round added `pass-through-parameter-default-flipped-fail-open`: the pass-through form's premise — that the parameter it forwards defaults `False` — lives in a different statement from the claim resting on it, so flipping it left every call-site shape and the exact census unchanged. Superseded by my own change within the same pull request, and recorded here rather than edited in place |

**None of these bodies is wrong about what it measured at the time.** Each is a
figure that a later change moved, and the reason they are listed together is
that all four were merged before the review of their final head had landed —
which is the mechanism, not the arithmetic.
