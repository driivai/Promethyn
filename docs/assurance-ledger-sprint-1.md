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

---

# Third review round — the population, twice, and a red CI I caused myself

Two more findings on `5d5f3f0`, both correct, both reproduced before either was
touched. Neither is a weakness in a *rule*: both are **members a collector could
not see**, which is the fourth and fifth time in this pull request that the
population rather than the logic was the hole.

| # | the collector | the member it could not see | verdict |
|---|---|---|---|
| C | the `*_AT_SPRINT_0` sweep | `_OTHER_AT_SPRINT_0: frozenset[str] = frozenset(_current_unread())` — an `AnnAssign`, not an `Assign` | GREEN |
| D | the harness-flag sweep | `ExecutionResult(False, subject, "", False, True, True)` — the flags claimed in the fifth and sixth POSITIONAL slots | GREEN |

Finding C is worse than it first reads. The skipped binding was not merely
unchecked: it never reached the population assertion either, which went on
naming the same two snapshots and passing. **A collector that cannot see a
member cannot refuse it, and it cannot report that it is missing one.** That is
doctrine #8 in the shape the sprint document names as taxonomy mode 5.

## What changed

* `_snapshot_binding` reads **both** binding forms and returns `("", None)` for
  a statement that binds no single name, so a bare annotation is not mistaken
  for a snapshot with an empty value.
* `ExecutionResult.started_ok` and `.candidate_started` are now
  **`field(default=False, kw_only=True)`**. Measured first: **0 of 22**
  constructions in the tree pass any positional argument, so nothing depended on
  the old signature. The class now refuses the shape outright — the fifth and
  sixth slots bind elsewhere and the flags keep their fail-closed default.
* The collector reads the positional slots **anyway**, with the binding order
  derived from `dataclasses.fields` on the live class, so the rule does not
  depend on the `kw_only` line staying and the two halves fail independently.
* **Row 23**, `record-class-harness-flags-no-longer-keyword-only`: removing the
  keyword-only guard must redden its pin.

## Executed proof

```
FINDING C   CONTROL            GREEN   CATCHES RED   REPRODUCE GREEN
FINDING D   CONTROL kw-only pin GREEN
            CONTROL shape rule  GREEN
            STRUCTURAL          RED     (kw_only removed -> its pin notices)
            DEFENCE             RED     (kw_only removed + positional claim
                                         planted -> the rule itself notices)
            REPRODUCE           GREEN   (the reviewed head sees neither)
```

**Finding D needed two legs, and the first version of its proof asserted the
wrong thing.** It expected the fixed guard to *catch* a planted positional
claim. It did not, and should not have: with the flags keyword-only there is no
claim left to catch — the argument binds to `sandbox_name` and the flags stay
`False`. A structural fix and a detection fix are different claims and they need
different legs, and writing the expectation down before the run is what exposed
the confusion.

## Finding D's premise, refused: the tree was not defenceless

The finding says a positional claim leaves "the population rule green despite a
new unmeasured harness claim". The first half is right and is measured above.
The second half overstates it, and the thing that settles it is a guard neither
the review nor I had consulted.

`tests/conformance/test_open_gaps.py::test_positional_construction_of_wide_dataclasses_does_not_grow`
is G2's ratchet over every dataclass of six fields or more, swept across `src`,
`tests`, `scripts` and `harness`. `ExecutionResult` is not in
`POSITIONAL_SITES_CEILING`, so its ceiling is **zero**. Planting the reviewer's
exact evasion in `src/` on the reviewed head `5d5f3f0`:

```
harness-flag rule         GREEN   1 passed
G2 positional ratchet     RED     1 failed
```

So the shape could not have reached `main` through this rule's blind spot; a
different guard, written for a different reason, refuses it. That does not make
the finding wrong — a rule whose sentence says "no site may claim a harness fact
it did not measure" must be able to see the claim, and it could not. It makes
the *consequence* wrong, and the difference matters: **two guards agreeing is
what defence in depth looks like, and reporting one of them as the only one is
how a tree gets described as weaker than it is.** Recorded in the direction that
does not flatter me either — I did not know G2 covered this until my own change
made it fail.

And it failed for a reason worth keeping: the behavioural assertion in the new
keyword-only pin was itself a positional construction of a wide dataclass, so
G2 counted it and refused. The repository already has the convention for that —
`test_evidence_and_judgment_cannot_be_built_positionally` calls through a local
name and says why — and the pin now follows it rather than inventing a way
around the sweep. A control that evades the guard it shares a tree with is not
a control.

## And the drift check earned its keep

Making the flags keyword-only changed the source text of the very lines that row
17 (`harness-facts-default-fail-open`) mutates. `MutationWorktree.apply` refused
it — *"the string has drifted, so this mutation would silently not apply"* — and
the run stopped rather than reporting twenty-four rows caught out of a set where
one had planted nothing.

That is the failure mode the drift check exists for, arriving on its own: a row
whose target moves does not go red, it goes **vacuous**, and a runner that
counted it would report a stronger result than it had. Re-stated against the new
source text, and the row is caught by its named proof again. **25 rows, 48 runs
plus the two new ones, all caught first-order by their named proof; second-order
11 of 25.**

Three of this pull request's own instruments have now refused work that would
have flattered it — the drift check here, the named-proof requirement when a
block rewrite deleted a test, and G2's ratchet when a control constructed
positionally. None of the three was consulted deliberately; all three fired.

## The CI failure on `a288260`, which was mine

The three `build` jobs went red on `a288260` — `1 failed, 3174 passed, 23
skipped`, the failure `test_doctrine_index`, the tree citing doctrine **#8**
fifty-six times against an index that said fifty-five.

The cause is not subtle. After running the full suite and before committing, I
edited the shape rule's positive control and the comment I added ends
`(doctrine #8)`. One more citation, never re-measured, pushed. **The figure that
commit's own message reports as observed — `2 failed, 3173 passed` — was
measured on a tree one edit short of the tree it describes**, which makes it a
claim about something that was never run. Withdrawn here rather than rewritten:
`a288260` was `1 failed, 3174 passed, 23 skipped` in CI, and the failing pin was
re-measured and corrected in the very next commit, so the head that carries it
is green on that test.

The rule broken is the one written down for pushing — *run the repo's own fast
checks, then push* — applied to a tree that was no longer the tree I had
checked. An edit after verification is a new tree, and this entry is now the
measured cost of treating it as the same one.

## What this round does not establish

* `_snapshot_binding` reads module-level statements. A snapshot bound inside a
  function, a class body, or a conditional is outside the sweep entirely, and
  nothing derives that one has moved there.
* The keyword-only guard covers `ExecutionResult` only. `SandboxResult`
  (`src/prometheus_protocol/sandbox/base.py:139-154`) carries the same two flag
  names and neither is keyword-only; measured from `dataclasses.fields`,
  `started_ok` defaults **`True`** there and `candidate_started` defaults
  `False`. So the positional shape is still available on that class, over a
  field whose default is already the permissive one. It is named here rather
  than fixed: it is the latent near-miss Part 1 already recorded (0 of 13
  constructions inherit that default), and widening this pull request to a
  second class is not what the review asked for.

---

# Where these three rounds actually landed

**#131 was merged at 14:56:28Z on head `5d5f3f0`, by its owner, while round 3's
fixes were still being written.** Recorded because the sections above would
otherwise read as if all three rounds landed together, and they did not.

| in `main` as of the squash `0944a0d` | not in it |
|---|---|
| Part 1, Part 2, and the fixes for review rounds **1 and 2** | review round **3** — findings C and D |

So the two gaps round 3 named were live in `main` for as long as it took to
carry this commit across: the snapshot collector reading `ast.Assign` only, and
the harness-flag collector reading `node.keywords` only. Neither is a defect in
shipped behaviour — both are guards that could not see a member — and the
positional one is covered in the meantime by G2's ratchet, measured above. The
snapshot one is covered by nothing else.

**The merge was a squash**, so `a288260`, `5d5f3f0` and the rest exist only on
the pull request, not in `main`'s history. Every SHA this document cites for a
reproduction is one of those: they remain fetchable through the pull request
and are named here so a reader who cannot find them in `git log main` knows
where to look rather than concluding the record is wrong. This is G13's seam
seen from the other side — a squash does not only compose a new message, it
makes the composed-from commits unreachable from the branch that keeps them.

And a smaller fact, recorded because the alternative is a silent gap: three
review replies, a review invocation and a body rewrite were posted to #131
between 15:02 and 15:04Z, after it had merged at 14:56. They are accurate and
they are answers to findings, but they answer them on a closed thread. A
session that watches a pull request learns it has merged from an event, and an
event that arrives late is indistinguishable from one that has not arrived.
