# Assurance ledger — Sprint 1: the second axis

Sprint 0 found one method for the *population* question and showed it does not
answer the *per-member* one: neutralising the four verifier-bound comparisons
while leaving their populations intact left the proof green and every other test
green apart from the Hearth digest guard. A ledger built on the method alone
marks `verifier_timeout_s` ISOLATING when it is not.

That second half belongs to doctrine #4's positive control, and the two
disciplines had never been connected. This sprint connects them.

**Measured 2026-09-18 on `1506b61` plus this branch.** Python **3.11.15**,
Linux. Every count comes from the artifact that produced it (doctrine #11);
claims about existing behaviour carry a file and line or are marked UNVERIFIED
(doctrine #10); where an earlier figure of mine turned out wrong it is withdrawn
here in the text rather than quietly replaced.

## The three answers, up front

**2.1 — yes, there is an authority, and it settles 17 of 22.** The row's own
branch in `validate_build` names the comparison it performs, so the per-member
falsifier is derivable for every row whose branch contains the comparison. Three
rows DELEGATE to a call whose contract is semantic and two DEFER entirely; for
those five the falsifier is judgement. One question decides the branch: **is the
comparison expressed in the row's branch, or delegated to a call?**

**2.2 — the two axes give different verdicts on 7 of 22 rows.** Joint: 10
isolating on both, **7 isolating on population only**, 3 on neither, 2 not
measured. A single verdict would have reported all 17 of the population-CAUGHT
rows as proved, including seven that no proof checks per-member.

**2.3 — INERT is now a verdict the instrument emits, and the first oracle I
wrote for it was wrong in the flattering direction.** An artifact-comparison
oracle called four rows INERT that had in fact executed; two of those were real
SURVIVEDs. The oracle that means what the word means asks whether the mutated
statement EXECUTED during the proof run. Both are reported below, because the
disagreement is the finding.

---

# 2.1 Is there an authority for per-member isolation?

Sprint 0's population question was settled by one test: *can the varying
population be named by something other than the proof's author?* Ask the same of
per-member isolation: **can the comparison a row performs be named by something
other than the proof's author?**

The candidate authority is the row's own branch in `validate_build`
(`src/prometheus_protocol/runtime/security_build.py`). Derived from the AST —
15 branches in the `if`/`elif` chain, covering all 22 properties:

| class | rows | the per-member falsifier | derivable? |
|---|---|---|---|
| **COMPARISON** — the branch contains an `==` against the Config value, directly or through `matches(cls, attr, value)` | **12** | make the comparison compare a thing to itself | **YES** — the branch names the class, the attribute and the operand |
| **EXISTENCE/ATTRIBUTE** — no `== value`; the member's presence, or a boolean attribute read, *is* the check | **5** | credit the row without reading the attribute | **YES** — from the same branch, though it establishes less: "the attribute was read", not "the value agreed" |
| **DELEGATED** — the branch hands off to a call whose contract is semantic (`validate_ledger`, `validate_endpoint`) | **3** | whatever the callee establishes | **NO** — the branch says the call happened, not what it proves |
| **DEFERRED** — the branch writes a token and `continue`s unconditionally; there is no per-member check here at all | **2** | none exists in this branch | n/a — the check is the publication step, elsewhere |

Rows, as derived:

* COMPARISON (12): `verifier_timeout_s`, `verifier_memory_mb`,
  `verifier_cpu_seconds`, `verifier_max_processes`, `gate_threshold`,
  `escalate_below`, `pending_ttl_seconds`, `max_role_calls`,
  `request_timeout_s`, `provider_max_response_bytes`,
  `require_verified_substrate`, `allow_unverified_substrate`
* EXISTENCE/ATTRIBUTE (5): `sandbox`, `ledger_anchor_retention_days`,
  `require_external_signer`, `verification_profile`, `require_digest_pin`†
* DELEGATED (3): `allow_insecure_loopback`, `ledger_anchor`†,
  `require_ledger_anchor`†
* DEFERRED (2): `config_attestation_target`, `require_config_attestation`

† also defers when the property is unrequested — the branch `continue`s on
`if not value:` and does its work only when something was asked for.

## The answer, and the boundary

**There is an authority, and it is the same KIND as Sprint 0's class A: the
runtime's own declaration, read here as source rather than as a dataclass.** It
covers **17 of 22**. It runs out at exactly the place Sprint 0's did — where the
thing that varies is *semantic* rather than recorded. `validate_ledger` compares
an anchor's adapter type and its destination; nothing in `validate_build`'s
branch says so, and deriving it would mean following the call, which is the same
regress G50 names for the carrier map.

**This is a four-way split with boundaries, not a forced unification**, and it
is the honest result: a per-member falsifier is derivable when the comparison is
*written in the branch*, and is judgement when the branch's content is a call.

## The correction the derivation itself needed

The first version of this classifier tested for a `continue` anywhere in the
branch and called five rows DEFERRED. Three of those (`require_digest_pin`,
`ledger_anchor`, `require_ledger_anchor`) `continue` only when the property is
*unrequested* and do real work when it is. A filter applied before the
classification, narrowing the population it was classifying — the class this
whole programme is about, committed inside the instrument written to measure it.
Corrected by distinguishing an unconditional `continue` from a conditional one;
the corrected counts are the ones above.

---

# 2.2 Two verdicts per entry, not one

**Two uniform probes**, each inserted at one line in `validate_build` and applied
identically to all 22 rows, so no row is advantaged by a hand-picked edit:

| axis | probe | what it models |
|---|---|---|
| **population** | `applied = None` | the guard found nothing to compare against. `all(values) if values else None` is what an emptied population already produces, so this *is* the population-emptied state |
| **per-member** | `applied = True` | the comparison agreed no matter what the member said. The population is untouched |

Scope: eight modules, `349 passed` baseline. Both probes carry the reach marker
of §2.3, so INERT is separated from SURVIVED before any verdict is written.

## The per-row result

| property | population | per-member | joint |
|---|---|---|---|
| `verifier_timeout_s` | CAUGHT | SURVIVED | population only |
| `verifier_memory_mb` | SURVIVED | SURVIVED | **neither** |
| `verifier_cpu_seconds` | SURVIVED | SURVIVED | **neither** |
| `verifier_max_processes` | SURVIVED | SURVIVED | **neither** |
| `sandbox` | CAUGHT | SURVIVED | population only |
| `require_digest_pin` | CAUGHT | CAUGHT | isolating on both |
| `gate_threshold` | CAUGHT | SURVIVED | population only |
| `escalate_below` | CAUGHT | CAUGHT | isolating on both |
| `pending_ttl_seconds` | CAUGHT | CAUGHT | isolating on both |
| `max_role_calls` | CAUGHT | CAUGHT | isolating on both |
| `request_timeout_s` | CAUGHT | CAUGHT | isolating on both |
| `allow_insecure_loopback` | CAUGHT | SURVIVED | population only |
| `provider_max_response_bytes` | CAUGHT | CAUGHT | isolating on both |
| `ledger_anchor` | CAUGHT | SURVIVED | population only |
| `ledger_anchor_retention_days` | CAUGHT | CAUGHT | isolating on both |
| `require_ledger_anchor` | CAUGHT | SURVIVED | population only |
| `require_external_signer` | CAUGHT | CAUGHT | isolating on both |
| `require_verified_substrate` | CAUGHT | SURVIVED | population only |
| `allow_unverified_substrate` | CAUGHT | CAUGHT | isolating on both |
| `config_attestation_target` | INERT | INERT | not measured |
| `require_config_attestation` | INERT | INERT | not measured |
| `verification_profile` | CAUGHT | CAUGHT | isolating on both |

## The statement, on both axes

> **The build guard's per-property application matrix, 2026-09-18.**
>
> **N = 22** claimed properties, derived from `dataclasses.fields(Config)` where
> `metadata["security"] is True`.
>
> **Population axis** — *does the proof notice when the guard has nothing to
> compare against?*
> **M = 17** isolating · **K = 3** NON-ISOLATING (`verifier_memory_mb`,
> `verifier_cpu_seconds`, `verifier_max_processes`) · **J = 2** not measured,
> named (`config_attestation_target`, `require_config_attestation`).
> 17 + 3 + 2 = 22.
>
> **Per-member axis** — *does the proof notice when the comparison agrees no
> matter what the member says?*
> **M = 10** isolating · **K = 10** NON-ISOLATING (`allow_insecure_loopback`,
> `gate_threshold`, `ledger_anchor`, `require_ledger_anchor`,
> `require_verified_substrate`, `sandbox`, and the four verifier bounds) ·
> **J = 2** not measured, named. 10 + 10 + 2 = 22.
>
> **Joint** — 10 isolating on both axes · 7 on population only · 3 on neither ·
> 2 not measured. 10 + 7 + 3 + 2 = 22.

**The 7 "population only" rows are what a single verdict would have hidden.**
Each has a proof that notices when the guard has nothing to compare against, and
none has a proof that notices when the comparison stops comparing. Reporting one
verdict per entry — whichever axis you happened to probe — would have called all
17 population-CAUGHT rows proved.

**And the three "neither" rows are worse than Sprint 0 reported.**
`verifier_memory_mb`, `verifier_cpu_seconds` and `verifier_max_processes` fail
*both* axes: no proof in the eight-module scope notices either the population
being emptied or the comparison being neutralised. Only `verifier_timeout_s`,
the fourth of that quartet, is caught on the population axis — by
`test_a_disabled_requirement_is_not_reported_as_applied`, which asserts
`report["verifier_timeout_s"] == APPLIED` and names only that one field.

## What the two axes do NOT jointly establish

Stated plainly, because a two-axis verdict reads as more complete than it is.
Both probes act on `applied` after the branch has computed it. Neither asks
whether the branch compares *the right attribute on the right class* — that is
`security_attribute_carriers()`'s hand-list, and G50 says the population behind
it is not derivable. A row marked isolating on both axes has a proof that
notices the population emptying and a proof that notices the comparison
surrendering; it does not have a proof that the comparison is the correct one.
That is Sprint 0 §5's second limit, unchanged by this sprint.

---

# 2.3 INERT must not read as SURVIVED

Sprint 0's instrument printed `SURVIVED` for rows where its mutation had done
nothing, and the five inert rows were separated by hand, by reading branches.
A tool that cannot tell "the mutation did not reach" from "the proof did not
notice" reports the second when it means the first, and that is the direction
that flatters it.

## The first oracle, and why it was wrong

**Oracle A — the artifact comparison.** A mutation that does not change the
guard's report cannot be noticed by any proof, so: build the report matrix over
all five guarded roots under the mutation, compare with the unmutated matrix,
and call an identical matrix INERT. Mechanical, prior to the test run, no branch
reading.

It disagreed with the reach oracle on **four rows**, all on the per-member axis:

| row | Oracle A | reach | direction of the error |
|---|---|---|---|
| `require_digest_pin` | INERT | CAUGHT | understates the tree |
| `verification_profile` | INERT | CAUGHT | understates the tree |
| `ledger_anchor` | INERT | **SURVIVED** | **hides a real survivor** |
| `require_ledger_anchor` | INERT | **SURVIVED** | **hides a real survivor** |

**Why.** The artifact comparison is taken over *the configurations I chose to
build* — 18 cells. A proof may exercise a state no cell reproduces:
`test_a_container_sandbox_without_its_pin_cannot_earn_the_credit` builds a
runtime, hand-mutates the live sandbox to drop its pin, and calls
`validate_build` directly. No matrix cell does that. So "the artifact did not
change" was a claim about my population, not about the tree — **the
measurement-population class, inside the instrument built to stop it, on its
first run**, exactly as §2.3 predicted it would be.

Two of the four errors hide a real SURVIVED. That is the flattering direction.

## The oracle that means what the word means

**Reach.** Did the mutated statement EXECUTE during the proof run? The mutation
drops a marker when it fires:

```python
if name == "<property>":
    import pathlib as _p; _p.Path("<marker>").write_text("1")
    applied = <None|True>   # mutated
```

No marker ⇒ the mutation never reached ⇒ **INERT**, and no verdict is written.
Marker present and nothing red ⇒ the proof genuinely did not notice ⇒ SURVIVED.
It is measured over the population the *proofs* exercise, which is the only
population the verdict is about.

## The proof that the instrument reports INERT rather than SURVIVED

Required by this section, and both readings were observed on the same rows:

```
Sprint 0's instrument (no oracle):
    SURVIVED config_attestation_target: 349 passed in 22.39s
    SURVIVED require_config_attestation: 349 passed in 22.38s

this instrument (reach oracle):
    [per-member] INERT config_attestation_target: reached=False  349 passed
    [per-member] INERT require_config_attestation: reached=False  349 passed
```

Both rows write their token and `continue` before the mutated line
(`security_build.py`, the attestation branch), so the statement is unreachable
code. `reached=False` is the instrument saying so. Across all 44 runs the oracle
emits INERT on exactly the 2 rows per axis whose branch cannot reach the
mutation, and `reached=True` on the other 20.

## Withdrawn: Sprint 0's per-member figures

Sprint 0 reported, for the per-member axis, **M = 10, K = 7, J = 5**, with the
five inert rows separated by hand. Measured here by reach, the correct figures
are **M = 10, K = 10, J = 2**.

* `allow_insecure_loopback`, `ledger_anchor` and `require_ledger_anchor` were
  hand-classified as inert. All three **reach** the mutated line and all three
  **SURVIVE** it. They are non-isolating, not unmeasured.
* K was understated by three and J overstated by three.

The hand reading was wrong in the flattering direction too — it moved three real
survivors out of the K column. Sprint 0's document is corrected in place with a
pointer here; the figures are withdrawn in the text rather than edited away.

---

# 2.4 The claim identity primitive

119 claim-bearing rows across four registers in four vocabularies, none keying
on another. Not a counting problem: **there is no identity for a claim.** No
schema is designed here. What follows is what an identifier would have to be
stable across, and five hand tests of the obvious candidate.

## What it would have to be stable across

1. **Wording.** "`require_verified_substrate` raises the bar from the runtime
   config" and "the requirement is the OR of its sources" are the same claim in
   two sentences.
2. **Register.** The same property is a `Config` field, a G-number, a
   threat-model row, and a marketing bullet. Each register names things its own
   way and none carries the others' key.
3. **Scope.** The same property at different composition roots. The build
   guard's matrix reads `default_not_applicable` for the substrate rows at the
   four factory roots and `applied` at the migration root — one property, two
   scopes, two answers.
4. **Deployment mode.** `verifier_cpu_seconds` is enforced by `RLIMIT_CPU` under
   the namespace adapter and **not expressed at all** under the container
   adapter (G22). The claim's truth value depends on a mode, so an identifier
   that omits the mode identifies two different claims as one.
5. **Polarity.** A LIMIT and an enforcement about the same property are
   different claims with opposite proof obligations — closing a limit must
   *redden* its test (Sprint 0 §4 Entry D).

## The obvious candidate, and how it dies

**Candidate: the property NAME.** It is what every register happens to contain,
and Sprint 0 used it to tie the registers by substring. Measured, it fails in
both directions.

**Direction 1 — the name appears where there is no claim.** `ledger_anchor`
occurs on 13 lines of `docs/OPEN-GAPS.md`. The first three are:

```
docs/OPEN-GAPS.md:228  | `unrelated_thing.require_ledger_anchor` (C1, another object) | **yes** |
docs/OPEN-GAPS.md:229  | `(1).require_ledger_anchor` (C1, a literal) | **yes** |
docs/OPEN-GAPS.md:230  | `something.require_ledger_anchor = False` (C2, a WRITE) | **yes** |
```

Rows of a table of **AST shapes a guard must reject**. `(1).require_ledger_anchor`
is an integer literal with an attribute access; it is not a claim about the
ledger anchor in any sense. A name-keyed identifier ties the claim to three
lines that are about a collector's syntax.

**Direction 2 — the claim appears where the name does not.** `README.md:41`:

```
- **IS** a tamper-evident ledger — hash-chained, so an interior edit, deletion, or
```

That is the strongest anchoring claim the project makes to a reader, and it
contains neither `ledger_anchor` nor `require_ledger_anchor`. Measured across
the three prose registers: `require_digest_pin` → 4 / 8 / **0** lines
(OPEN-GAPS / threat-model / README); `require_verified_substrate` → 1 / 3 /
**0**; `ledger_anchor` → 13 / 7 / **0**. The README names none of them, and
makes claims about all three.

**So the name is neither necessary nor sufficient**, and the two directions fail
for different reasons — G17's "a name appears" on one side, and prose that
argues about a property without naming it on the other.

## Five claims, tied by hand

Each appears in more than one register. The column that matters is the last.

| # | claim | registers | what ties them | what defeats the tie |
|---|---|---|---|---|
| 1 | the ledger anchor is required and is honoured | build matrix (`ledger_anchor`, `require_ledger_anchor`) · `docs/threat-model.md:1403-1404` · `README.md:41` · G9 | the `Config` field name, in three of the four | the README states it without the name (above), and the matrix row splits one claim across two fields |
| 2 | `require_verified_substrate` raises the bar | build matrix · `test_security_field_behaviour.py:484` (`PROOFS`) · `docs/threat-model.md:1406` · `core/config.py:471` | the field name, in all four | **two different claims share it**: Sprint 0 Entry E measured that the behavioural claim and the build-matrix claim have different proofs in different modules. One name, two claims — the identifier is too coarse |
| 3 | `require_digest_pin` reaches the adapter that honours it | build matrix · `test_security_field_behaviour.py` (`PROOFS`) · `docs/threat-model.md:1319,1332` · `README.md:206` | the field name, in three | the README says it as "should be digest-pinned in production", a **deployment recommendation**, not a claim the tree can falsify. Same words, different kind of statement |
| 4 | `verifier_cpu_seconds` bounds candidate CPU | build matrix · G21 · **G22, which says it is NOT expressed on the container substrate** · `docs/threat-model.md` | the field name | **the polarity flips with the mode.** G22 is a LIMIT about the same name the matrix reports `applied` for. An identifier without the substrate identifies an enforcement and its own negation as one claim |
| 5 | the agent cannot reach the DB by any of six paths | `README.md:87,96-107` · `tests/chokepoint/test_isolation.py` · `tests/chokepoint/test_agent_zone_containment.py` · `docs/threat-model.md` §1 | nothing mechanical: the README links a test **file**, and that test delegates three of the six paths to a second file by **substring** | there is no property name at all. The claim is about a system behaviour, and the only tie is a link and a text search — which Sprint 0 §4 Entry F measured surviving the deletion of all three delegated proofs |

## What this says about the primitive

**An identifier has to be a tuple, and at least one member of it is not
mechanically available.** From the five tests, the members that were actually
needed are: the **property** (where one exists — claim 5 has none), the
**mechanism site** (claim 2 needed it to separate two claims sharing a name),
the **scope** (claim 4 needed the substrate; claim 3 needed "production" versus
"the tree"), and the **polarity** (claim 4 again — enforcement or limit).

Of those, only the property name is derivable from the registers as they stand.
The mechanism site exists in the code but no register records it; the scope and
the polarity exist only in prose. **So the primitive cannot be extracted from
the current registers — it has to be written down at the point a claim is
made**, and the only register here that does anything like that is
`test_security_field_behaviour.py`'s `PROOFS` map, which names a field and the
tests that prove it, and which was built by hand.

**And one thing this sprint can say that Sprint 0 could not:** an identifier
that carried only the property name would have merged claim 2's two claims and
claim 4's enforcement with its own limit. Both merges are the failure Sprint 0
§4 Entry E measured — a real proof attached to a claim that does not have one.
The identifier is not a naming convention; it is the thing that decides whether
`M` is counting proofs or counting coincidences.

---

# What this sprint does not establish

* Both probes act after the branch computes `applied`; neither establishes that
  the branch compares the right attribute on the right class (§2.2).
* The reach oracle proves the mutated statement executed. It does not prove the
  proof *depends* on it — a test could execute the line and be green for an
  unrelated reason, and SURVIVED then means "no proof in scope noticed", which
  is what it says and no more.
* The scope is eight modules, not the whole tree. Sprint 0's whole-tree runs
  showed the only additional red for a `security_build.py` edit is the Hearth
  digest guard, which fires on the file rather than on the behaviour — but that
  was measured for a different mutation, and is UNVERIFIED for these 44.
* §2.1's classifier reads `validate_build`'s branch chain. A row whose work
  moves out of that chain leaves the classification silently stale; nothing
  derives that it has moved.

---

# Addendum, 2026-09-18 — the review round, and three instruments that could not fail as documented

The automated review of this branch's first head raised three findings. All
three are correct, all three are the same shape, and the shape is this sprint's
own subject turned back on it: **a guard whose passing direction is wider than
the sentence written beside it.** They are recorded here rather than only fixed,
because the pattern is more useful than the three instances.

## The common shape: a comparand that is not independent of its subject

| # | the instrument | what it compared | why it could not go red |
|---|---|---|---|
| 1 | `_UNREAD_AT_SPRINT_0` | the unread set against a snapshot | the snapshot was RECOMPUTED from the same checkout by the same expression |
| 2 | the harness-flag sweep | each argument against the literal `True` | a DENYLIST OF ONE SHAPE over an open set of expressions |
| 3 | the register-coverage pin | the mapping against `{1: 5, 2: 16, 3: 1}` | an AGGREGATE stands in for the mapping, and compensating moves cancel |

One and three are the same error: the thing compared against was derived from
the thing being compared, so it agreed with it whatever it said. Two is the
mirror image — the comparand was independent, but the *rule* enumerated the
wrong side of an open set. **A denylist over expressions cannot be complete**,
and the three evasions are concrete: `started_ok=1` is a different constant with
the same truth value, `started_ok=decision.approved` is an unrelated boolean,
and `started_ok=result.candidate_started` is the OTHER harness fact read off the
right object. Each asserts something nothing measured; each passed.

Doctrine #11 is usually read as a rule about reports — a count comes from the
artifact, never a filtered view. Finding 3 is the same rule **inside an
instrument**: a histogram is a filtered view of a mapping, and asserting on it
pins the filter rather than the population.

## What changed

* The forty-one filenames are written out, and the assertion is set equality.
* The harness-flag rule is an **allowlist of the four forms this tree uses** —
  the fail-closed constant, the adapter result attribute, the same-named
  parameter pass-through, and the stored ledger column. Every one carries the
  flag's own name, so a cross-wired read is refused too. The census is pinned at
  4 / 8 / 4 / 2, because a shrinking population is how the rule goes quiet
  without going red.
* The `field -> registers` mapping is pinned per property, with the distribution
  kept beside it so the number §1.4 quotes is still pinned by name.
* The **class** gets its own derivation:
  `test_a_pinned_snapshot_is_never_recomputed_from_the_tree_it_checks` requires
  every `*_AT_SPRINT_0` binding to reference none of the live sources its
  subject is derived from. Fixing two instances is not closing the class.
* The compensating move is a **passing test** rather than a paragraph
  (doctrine #5): `test_the_histogram_cannot_stand_in_for_the_register_mapping`
  constructs the single-property trade and the two-property cancellation and
  shows the distribution does not move by one count in either.

## Executed proof: each finding reproduced, then caught

Three MutationWorktrees, one per finding, each measuring its own control. The
third leg restores the guard verbatim from the parent commit `52f98fa`, so the
"before" is the real pre-fix code and not a hand-written approximation.

```
FINDING 1 - unread set: pinned snapshot vs recomputed comparand
  CONTROL    expect GREEN observed GREEN  [ok]  1 passed
  CATCHES    expect RED   observed RED    [ok]  1 failed
  REPRODUCE  expect GREEN observed GREEN  [ok]  1 passed
FINDING 2 - harness flags: allowlist of forms vs denylist of `True`
  CONTROL    expect GREEN observed GREEN  [ok]  1 passed
  CATCHES    expect RED   observed RED    [ok]  1 failed
  REPRODUCE  expect GREEN observed GREEN  [ok]  1 passed
FINDING 3 - register coverage: per-property mapping vs histogram
  CONTROL    expect GREEN observed GREEN  [ok]  1 passed
  occurrences of the token in docs/OPEN-GAPS.md: 6
  CATCHES    expect RED   observed RED    [ok]  1 failed
  REPRODUCE  expect GREEN observed GREEN  [ok]  1 passed

9 of 9 legs matched their expectation
```

The mutations: finding 1 swaps one filename in `CONSULTED_NOT_INVENTORIED`, so
one document leaves the unread set and another enters it and **the count holds
at 41** while the membership changes; finding 2 plants `started_ok=1` at a real
construction site; finding 3 moves `verifier_cpu_seconds` out of OPEN-GAPS and
into the threat model, so it is a one-register property before and after and the
distribution does not move.

## Two errors inside the proof harness, both in the flattering direction

Reported because they are the same class as the findings, committed while
checking for the findings.

**The harness read an empty run as a pass.** The first version classified a leg
with no summary line as GREEN. The selector for finding 1 named a test that does
not exist, so nothing ran, and the script reported **three matching legs** for a
finding it had not tested at all. That is doctrine #8 — an empty instrument
reads as a pass — inside the harness written to check instruments for exactly
that. A missing summary is now a distinct `NO-RUN` verdict that matches no
expectation.

**A mutation that did not do what it said.** `MutationWorktree.apply` replaces
the FIRST occurrence; `verifier_cpu_seconds` is on **six** OPEN-GAPS lines. The
first draft called it once, so the property *gained* a register instead of
trading one, its tuple went from length 1 to 2, and the histogram moved — the
leg went red, and it went red for the wrong reason. It would have been reported
as proof that the mapping pin works, when what had actually been proved was that
the old histogram pin works. The row now counts the occurrences, applies once
per occurrence, and asserts the token is absent before running.

Both were caught by the controls rather than by reading, which is the argument
for the controls.

---

# Second review round — both fixes were the same defect, one level up

The review of the fixed head raised two more findings. Both are correct, and
the result is more useful than either: **the class I declared closed in the
addendum above was closed with an instrument of that class.**

## What the two findings say

| # | where | the evasion | verdict |
|---|---|---|---|
| A | `test_a_pinned_snapshot_is_never_recomputed_from_the_tree_it_checks` | `frozenset(_current_unread())` — the identical derivation behind a helper the rule had never heard of | GREEN |
| B | the harness-flag allowlist | flip `GitBranchDeleteExecutor._refuse`'s own `started_ok` default back to `True`; every call-site shape and the exact census are unchanged | GREEN |

Both measured before either was fixed, in a `MutationWorktree` — not argued.

**Finding A is the open-set error, committed inside the rule written to close
the open-set error.** The addendum above says, of the harness flags, that *a
denylist over an open set of expressions cannot be complete*. The snapshot rule
one section later asks whether the assignment mentions any of **eight
hard-coded names** — a denylist over an open set of *names*, which is the same
sentence with one word changed. A helper is one `def` away, and there is no
list of names that contains the names nobody has written yet.

**Finding B is the difference between a spelling and a premise.** The
pass-through `started_ok=started_ok` was called a measurement because the
identifier matched. It is a measurement only because the parameter it forwards
*defaults to the fail-closed answer* — and that premise lives in a different
statement from the claim resting on it, so the rule could go on holding while
the premise was removed. That is not a hypothetical: flipping the default
restores a live fail-open on every pre-sandbox refusal in the git executor,
which is the defect this whole pull request exists to fix, re-entering through
the guard built to prevent it.

## What changed

* `_non_literal_in` replaces the name list with an **allowlist of node types**:
  a snapshot is constants and the containers that hold them, all the way down.
  Every name, attribute, call, comprehension and operator is a way of asking
  the tree, and the tree is what a snapshot exists to disagree with. Only
  `frozenset` / `set` / `tuple` / `list` / `dict` may be called, with at most
  one argument that is itself literal.
* `_parameter_default_is_false` makes the pass-through's premise a **checked
  condition**: the name must resolve to a parameter of the enclosing function
  whose default is literally `False`. A parameter with no default is refused
  too — the value is then whatever a caller passes, which this function cannot
  see. The form is renamed from "same-named parameter pass-through" to
  **"fail-closed parameter pass-through"**, because the old name recorded the
  spelling and the new one records the reason.
* Both positive controls now plant the evasions that defeated the previous
  version alongside the ones it caught: the helper indirection, a set union, a
  comprehension and a dict splat for A; a fail-open default, a no-default
  parameter and no enclosing function at all for B.
* **Row 22** in `scripts/spend_proofs.py` — `pass-through-parameter-default-flipped-fail-open`.
  Finding B's evasion is a source mutation, so it belongs in the runner rather
  than in a one-off demonstration. The premise is now proved on every run.

## Executed proof

```
FINDING A - snapshot rule: literal construction vs eight hard-coded names
  CONTROL    expect GREEN observed GREEN  [ok]
  CATCHES    expect RED   observed RED    [ok]
  REPRODUCE  expect GREEN observed GREEN  [ok]
FINDING B - pass-through: the parameter's default vs its spelling
  CONTROL    expect GREEN observed GREEN  [ok]
  CATCHES    expect RED   observed RED    [ok]
  REPRODUCE  expect GREEN observed GREEN  [ok]

6 of 6 legs matched their expectation
```

`REPRODUCE` restores the guard from the reviewed head `a288260`, so the
"before" is the code the review was written about.

**And a third error in the harness, of the kind it keeps finding.** The first
run of this script used `MutationWorktree()` with its default
`include_dirty=False`, so the worktree was a checkout of `HEAD` — the reviewed
code, without the fixes. It reported both evasions GREEN and it was right to:
it had tested the old guards. A harness that silently substitutes a different
subject is the same failure as one that silently tests nothing, and it was
caught only because the expected verdict was written down before the run.

**And a fourth, found by the mutation runner rather than by the suite.**
Applying finding B's fix as a block rewrite of one region of
`test_execution_start_signal.py` **deleted a test** —
`test_the_replay_carries_the_STORED_harness_facts_not_a_default`, which sat
inside the replaced range. The module still reported `34 passed`, and a count
that goes down by one while staying green says nothing to a reader who does not
already know the number. What caught it was row 21 of `scripts/spend_proofs.py`:
its mutation stopped reddening **its named proof** and reddened only a
bystander, and the runner refuses that rather than counting the red. The test
was restored verbatim from `a288260`, and the module's test inventory is now
identical to the reviewed head's, checked by comparing the two.

That is the argument for naming the proof a row must redden instead of
accepting any red. "Something went red" would have passed this, and the proof
for the least visible of the three fail-open sites would have left the tree in
the same commit that claimed to strengthen it.

## What this round does not establish

* `_non_literal_in` bounds what a snapshot may be *built from*. It does not
  establish that the literal written down is the value that was measured — that
  is a human act, and the tie between them is the re-measurement discipline,
  not a test.
* `_parameter_default_is_false` checks the default of the enclosing function's
  parameter. It does not follow a pass-through through a second hop, and a
  parameter reassigned in the body before the call would still read as
  fail-closed. Neither shape occurs in this tree; both are UNVERIFIED for a
  tree where they do.
* The two fixes are allowlists, which is the direction that fails closed. An
  allowlist that is too narrow reddens a legitimate new form, which is a false
  red and a cost — paid deliberately, because the other direction is a false
  green and this entry is a record of what false greens cost.
