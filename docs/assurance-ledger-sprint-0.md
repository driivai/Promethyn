# Assurance ledger — Sprint 0: extract the method

This sprint asked whether one statement can be produced for this repository:

> *N claimed properties. M have isolating proofs. K have proofs that survive
> their own second-order probe and are marked NON-ISOLATING. J have no proof
> and are named.*

It does not design a file format and it does not build a tool. It answers three
questions: where the claims are and how many there are; whether the eight times
this repository derived "what would falsify this proof" share a method; and what
one ledger entry actually costs when it is produced by hand, end to end, with
every mutation run.

**Everything below is observed.** Every count comes from the artifact that
produced it, never from a filtered view (doctrine #11). Where a filter is
unavoidable the filter is stated beside the count. Claims about existing
behaviour carry a file and line or are marked UNVERIFIED (doctrine #10). Where
an expectation was wrong, the wrong expectation is recorded rather than edited
away.

## The three answers, up front

**§2 — one method, with a four-way branch.** The seven instruments (the brief
named eight; two of them are one instrument with two faces) share one method for
the *membership* question: name the varying population, find an authority for it
that is not the proof's author, compare as sets in both directions, fail closed
on an empty authority. They differ only in where the authority comes from, and
that choice is settled by a single question. **But the method does not cover the
*comparison* question** — what the proof does to each member — and that is a
separate discipline (doctrine #4's positive control) which this repository
solved separately and never connected. §2.4 measures the gap: a mutation that
neutralised a comparison while leaving its population intact survived its proof,
and survived all 3169 tests.

**§4 — the cost per entry, and how much is mechanical.** Running a mutation is
free; *choosing* it is not, and **the choice decided the verdict in two of the
five entries**. Entry A: deleting the population was CAUGHT, neutralising the
comparison over the same population SURVIVED — so the mutation that found the
gap was the one a naive generator would not write. Entry C: deleting one of two
mechanisms behind a shared label SURVIVED, deleting both was CAUGHT — so the
verdict depended on knowing how many mechanisms carry the property, which G44
says is not derivable. Per entry: **30–60 minutes of reading**, seconds of
machine time — *unless* the claim source has a uniform mechanism, in which case
one mutation template amortises across every row and the cost collapses to
machine time
(§4.7's 22-row sweep). So the ledger is a **tool** where the population is
derivable and a **specification** where it is not — and §1.3 measures what
happens to an unenforced specification here: the tracker states a five-field
entry schema and **1 entry in 56** carries all five.

**§1 — the claimed-property count, and the unit.** 119 claim-bearing rows across
four registers (22 + 56 + 29 + 12), and **N is not a number this repository can
currently produce** — not because counting is hard, but because there is no
identity for a claim. The same property is stated in four registers in four
vocabularies and none keys on another. §4 Entry E is the cost of guessing wrong.

**And the statement itself, produced for the one register where it can be.**
§4.7 closes with it: for the build guard's 22 matrix rows, **N = 22, M = 10
isolating, K = 7 NON-ISOLATING** (they survive their own probe and all 3169
tests), **J = 5 named as not measured by this probe**. 10 + 7 + 5 = 22, tied
back to the population. That is the target artifact, at the scale this sprint
could honestly reach.

> **WITHDRAWN 2026-09-18.** `K = 7, J = 5` was wrong: the inert rows were
> separated by hand, and three of the five had in fact executed the mutation
> and survived it. Measured mechanically in Sprint 1, this axis is **M = 10,
> K = 10, J = 2**. See §4.7's withdrawal and
> `docs/assurance-ledger-sprint-1.md` §2.3.

## The measurement environment, stated before any number

Measured 2026-09-18 at commit `bfe0a1b`, Python 3.11, Linux,
`pip install -e ".[dev]" -c constraints.txt`.

> **Corrected 2026-09-18 (Sprint 1).** This line said "Python 3.11.14", a
> version I had not run `python -V` to obtain — a claim about existing
> behaviour with no observation behind it, which is doctrine #10 broken in the
> document's own environment header. Observed: **3.11.15**. The suite numbers
> below reproduce on it.

```
$ python -m pytest -q
2 failed, 3144 passed, 23 skipped in 262.41s
$ python -m pytest --collect-only -q
3169 tests collected in 0.80s
```

Every measurement below is against that tree. **After this change** — which adds
`tests/conformance/test_assurance_ledger_limits.py` (§5) and four entries to the
positive-control registry — the same command reports `2 failed, 3158 passed, 23
skipped`, with the same two environment failures. Both numbers are stated so the
document's own effect on the number it opens with is visible rather than folded
in.

**The two failures are the environment, not the tree.** Both are in
`tests/conformance/test_composed_message_guard.py`, and both fail inside
`scripts/check_message_hygiene.py:146`, which runs `git log 267a586~1..267a586`.
This container holds a 50-commit clone (`git log --oneline | wc -l` → 50) and
`git cat-file -t 267a586` → `fatal: Not a valid object name`. Every mutation
run below that uses the whole tree deselects exactly those two, and says so.

This is itself the sprint's thesis in miniature. **3144 is the number a test
suite reports, and it answers no question anyone has.** It does not say which
properties are enforced. It does not distinguish a proof of a mechanism from a
proof that a mechanism's *name* appears. And two of its neighbours are red for a
reason that has nothing to do with the code at all.

---

# 1. Where the claims live — the population, and what counts as one

## 1.1 The unit decision, which is the first real output

A **claimed property** is counted here when all three hold:

1. it is attributable to a **named artifact at a file and line**;
2. it asserts something about **this system**, such that its negation would be a
   defect in the system rather than in a document;
3. it is **falsifiable in principle** — there is some state of the tree in which
   it would be false.

Three exclusions follow from that, and each is a judgement, not a derivation:

* **A doctrine is not a claimed property.** `docs/DOCTRINE.md` #11 says counts
  come from the artifact. That is a claim about how this repository *works*, not
  about what the runtime *does*. Its negation is a process failure, not a defect.
  Doctrines are counted in a separate register below.
* **A gap entry is the negation of a claim.** `docs/OPEN-GAPS.md` G22 says
  `verifier_cpu_seconds` has *no* expression on the container substrate. Under
  rule 2 that is a claim about the system and it is falsifiable — so it counts,
  but it belongs in its own column, because "is there a proof that would fail if
  this stopped holding" means the opposite thing for a LIMIT than for an
  enforcement. Closing a limit must *redden* its test. G43 states that intent at
  `docs/OPEN-GAPS.md:4149-4150`; §4 Entry D measures it.
* **A deployment mode is a scope, not a property.** `README.md:206` — "the
  container sandbox backend is proven end-to-end in CI, but is opt-in, not the
  default" — narrows where other claims apply. It is a qualifier on a population,
  and counting it as a property would double-count everything it qualifies.

## 1.2 The ambiguous cases, stated rather than resolved silently

**A claim that decomposes.** `sandbox` is one `Config` field and one row in the
build guard's matrix. `src/prometheus_protocol/runtime/security_build.py:495-500`
compares three separate things under that one row: that a sandbox exists at all,
that its `name` matches the configured adapter, and that it is `isolating`
whenever the provider is remote. `tests/conformance/test_security_field_behaviour.py:125-129`
splits the same field across two named proofs. One claim, one row, three
falsifiable statements, two proofs. Nothing in the tree decides which number is
right, and this sprint does not decide it either.

**A claim that duplicates another in different words.** `require_verified_substrate`
appears as (a) a row in the build guard's matrix, (b) an entry in the
`OUTCOME_AFFECTING` partition at `tests/conformance/test_security_field_behaviour.py:76-91`
with a named proof, (c) a refusal in the coherence block at
`src/prometheus_protocol/core/config.py:471-478`, and (d) an attacker-5 control in
`docs/threat-model.md` §5.3. §4 Entry E measured them and they are **not** the
same claim: they are proved in different modules, in different directions, by
tests that do not know about each other — and I guessed wrong about which of
them had a proof. A ledger that collapses them to one row has to pick one, and
picking wrong attaches a real proof to a claim that does not have it.

**A claim whose proof is delegated to a file's text.**
`tests/chokepoint/test_isolation.py:156-168` establishes that three socket attack
paths are covered "somewhere" by asserting that three *substrings* appear in a
companion file. §4 Entry F measures what that guard actually pins.

**A claim about the repository rather than the system.** Counted separately —
see the doctrine register.

**A limit whose content is "nothing enforces this".** G22. Its "**Test.**" field
reads *"None yet — deliberately."* (`docs/OPEN-GAPS.md:1677`). Under rule 2 it is
a claimed property with J=1.

## 1.3 The population, per source, each count from its artifact

### `docs/DOCTRINE.md` — the doctrine register (not claimed properties)

| | count | derivation |
|---|---|---|
| numbered doctrines indexed | **11** | rows matching `^\| \d+ \|` in the index table |
| with at least one citation in the tree | **8** | the `citations` column, which `tests/conformance/test_doctrine_index.py` pins in both directions |
| **never cited anywhere** | **3** (#3, #6, #7) | `docs/DOCTRINE.md:49,52,53` |
| written down in full, as text | **1** (#11) | `docs/DOCTRINE.md:63-97` |

Ten of the eleven exist only as citations. The file says so itself
(`docs/DOCTRINE.md:59-61`): the one-line usages "are not the doctrines' text,
which was never written down." So the register is 11 numbers, 1 doctrine, and 3
numbers that name nothing at all.

### `docs/OPEN-GAPS.md` — the tracker

| | count | derivation |
|---|---|---|
| `^## G…` headings | **56** | the artifact's own headings |
| distinct G-numbers | **55** | G23 carries two headings (`:1685` and `:1818`) |
| heading says CLOSED | **12** | substring `CLOSED` in the heading |
| body says CLOSED, heading does not | **5** | same substring, body only |
| carries a bolded **What closes it** field | **12** | |
| carries a bolded **Test** field (doctrine #5) | **23** | `**Test.**` exactly; a 24th spells it differently |
| heading says `NOT FIXED` / `FILED, NOT` | **4** | G24, G38, G40, G47 |

**LIMIT versus CLOSURE cannot be derived from this artifact.** The brief asks
which entries state a limit and which state a closure. There is no field that
says. 29 of the 56 headings carry neither a `CLOSED` marker anywhere nor a
"What closes it" field, and several entries are both at once — G7's heading reads
"CLOSED by measurement, **with a named limit**". The partition exists only in the
prose. **This is the single most important structural finding in §1** and it is
measured, not asserted:

> The tracker's preamble (`docs/OPEN-GAPS.md:12-14`) states that each entry
> carries five fields — *what · measured · why not closed · what closes it ·
> test*. Measured over all 56 headings:
>
> | field | entries carrying it |
> |---|---|
> | **What** | 38 / 56 |
> | **Measured** | 27 / 56 |
> | **Why not closed** | **2 / 56** |
> | **What closes it** | 12 / 56 |
> | **Test** | 23 / 56 |
> | **all five** | **1 / 56** |

A stated-but-unenforced entry schema decayed to one conforming entry in
fifty-six. That is the strongest single piece of evidence this sprint produced
about what the assurance ledger has to be, and §4.7 returns to it.

### The build guard's per-property application matrix

Derived from `dataclasses.fields(Config)` at
`src/prometheus_protocol/runtime/security_build.py:96-102`, which refuses any
field whose `metadata["security"]` is not a `bool`.

| | count |
|---|---|
| `Config` fields declared | **37** |
| classified `security=True` — **the matrix's rows** | **22** |

The matrix itself, read off the build report — the artifact, not a log — across
18 built cells spanning **all five** guarded composition roots:

```
cells built: 18 across FIVE guarded roots
properties in the matrix: 22
properties reaching 'applied' in >=1 of the 18 cells: 20
properties NEVER 'applied': 2 -> config_attestation_target, require_config_attestation
    both reach 'published', which is their own strongest token
token totals: applied 157, default_not_applicable 159, not_requested 78, published 2
tie-back OK: 18 cells x 22 properties == 396 == sum of all tokens
```

The tie-back is the doctrine-#11 discipline applied to my own instrument: the
per-token counts sum to the population, so a row the reader could not see would
be a red line and not a quiet shortfall. **Every one of the 22 rows reaches its
strongest token in at least one configuration.**

**This number is a correction, and the correction is worth more than the
number.** The first measurement covered four roots — the four in
`runtime/factory.py` — gave 15 cells, and reported that
`require_verified_substrate` and `allow_unverified_substrate` reached nothing but
`default_not_applicable` in every cell. That was a property of *my population*,
not of the guard. `install_build_guards` is also installed in
`src/prometheus_protocol/chokepoint/runner.py`, so `build_migration_runtime` is a
fifth guarded root, and it is the only one whose graph holds a `SubstratePolicy`.
Measured there, both rows read `applied`. **A four-root matrix is a filtered view
of a five-root population**, and I published a count from it while writing the
section about not doing that. It was caught by a mutation (§4 Entry E), not by
the instrument.

**And the fifth root turned up a finding of its own.** The report is attached to
the *returned object* on the four factory roots (`security_build.py:725`) and, on
the migration root, to the inner `BrokeredMigrationRunner` — so
`runtime._security_build_report`, the access every test in `test_security_build.py`
uses, raises `AttributeError` there. Measured: `MigrationRuntime` has the
attribute → `False`; one object in its graph carries it, with all 22 rows. The
guard runs on that root; its report is simply not where a reader would look.

**And "four roots" is a habit in this area, not only my mistake.** The build
guard's own traversal docstring measures itself on "the four shipped runtime
roots" (`security_build.py:193`); `test_no_shipped_root_hides_a_component_from_the_credited_walk`
and `test_every_reported_token_is_a_member_of_the_vocabulary` both parametrise
over the same four (`tests/conformance/test_security_build.py:500-501,694-697`).
The migration root is guarded by the same `install_build_guards` call and is
absent from all of them. Whether that is a gap or a deliberate scope is not for
this document to rule on — it is recorded here because a ledger derived from
those tests would inherit their population without noticing.

### Limits recorded as passing tests (doctrine #5)

23 of the 56 tracker entries carry a **Test** field. The tree also holds a
purpose-built register of this shape, which is the closest thing to an assurance
ledger that already exists here:

`tests/conformance/test_security_field_behaviour.py` partitions all 22 security
fields into `OUTCOME_AFFECTING` (14), `RESOURCE_BOUND` (6) and `SPELLING_ONLY`
(2) at lines 76-111, maps each of the 14 to its named proofs in `PROOFS` at
lines 119-152, and enforces three things mechanically:

* the partition equals `SECURITY_FIELDS` exactly, both directions (`:166-181`);
* every mapped proof name is a test that exists in that module (`:184-198`);
* the collector that checks it is not universally true (`:201-214`) — doctrine #8.

That is 22 claims, each with a named proof or an explicit reason for having
none, kept in agreement with the code by a ratchet. **It was built by hand.**
§4.9 uses it to price the ledger.

### `docs/threat-model.md`

| | count | derivation |
|---|---|---|
| attacker classes | **5** | `^## Attacker \d` |
| `###` sections | **29** | |
| distinct `test_*` tokens cited | **53** | regex over the document |
| resolve to a test **function** in the tree | **28** | compared against 1895 test function names parsed from `tests/**/*.py` |
| resolve to a test **file** stem | **22** | |
| resolve to neither | **3** | two are false positives of my regex (`attest_at_startup`, `attest_if_due` contain `test_at_startup`, `test_if_due`); the third is `test_a_planted_union_defect_still_fails_the_gate`, split across `docs/threat-model.md:68-69` by line wrapping and real at `tests/conformance/test_type_gate.py:288` |

So the threat model's citations all resolve — but **22 of the 53 resolve only to
a file**, which names a module and not a proof. "Which test proves this claim"
(`docs/threat-model.md:22`) is answered at file granularity for 22 of them.

### `README.md` and `site/`

| | count | derivation |
|---|---|---|
| `IS` / `IS NOT` / `HAS` bullets | **7** | `README.md:33-55` |
| "Proven and on `main`" bullets | **5** | `README.md:195-199` |
| "Not done yet" bullets | **6** | `README.md:203-208` |
| `test_*` tokens cited | **2** | `test_agent_cannot_reach_db_by_any_path`, and `test_isolation` (a file) |
| local link targets that do not resolve | **0** | 25 checked across `README.md`, `site/index.html`, `site/thanks.html` |

**No test in the tree reads `README.md` or `site/index.html` for anything but
ownership.** The only guard is `scripts/check_ip_consistency.py:128-135`, which
checks that the README's License section names the owner and that
`site/index.html` states the proprietary licence. Every other README claim — the
six-path bypass table, the 8/2/0 demo table, the 3.9% / 0% decorrelation figures,
the five "Proven" bullets — is bound to the tree by nothing.

**The false one, observed.** `README.md:226` reads:

```
python -m pytest -q              # run the suite (2431 passed, 23 skipped on 2026-09-12)
```

Observed here today: **3144 passed, 23 skipped, 2 failed**. The claim carries its
date, so it is a stale observation rather than a present-tense falsehood — but
nothing re-checks it, and a reader running the command today sees a number 713
larger and two reds. It is doctrine #9 (re-sweep documentation claims when the
code they describe changes) unapplied to the README's own headline command. This
is not the first time: `tests/conformance/composed_message_fixture.json:13`
preserves a PR body recording *"a README claiming 385 passed / 2 skipped against
2436 / 23"* being corrected. The class recurs because nothing mechanical catches
it.

**The scoped one.** `README.md:87` claims "6 of 6 direct-attack paths fail
inside", linking `tests/chokepoint/test_isolation.py::test_agent_cannot_reach_db_by_any_path`.
That test **skipped in this run** (`no configured DB coordinates for the
isolation proof`, `tests/chokepoint/test_isolation.py:46`), and even when it runs
it covers three paths — `_TCP_PATHS` at `:37` — unless
`PROM_CHOKEPOINT_PG_SOCKDIR` names a real socket directory. The other three are
delegated by `test_socket_paths_are_covered_somewhere` (`:156-168`), which
asserts that three substrings appear in a companion file. §4's sixth probe
measures that delegation.

## 1.4 The claimed-property count

| register | count | what one row is |
|---|---|---|
| build-guard matrix rows | **22** | one `security=True` `Config` field |
| `OUTCOME_AFFECTING` fields with a named proof | **14** | a subset of the 22, not additional |
| tracker entries | **56** | one `## G…` heading; 55 distinct numbers |
| — of which carry a **Test** field | 23 | |
| threat-model `###` sections | **29** | |
| README `IS`/`IS NOT`/`HAS` + Proven bullets | **12** | |
| doctrines *(separate register)* | **11** | 8 cited, 3 naming nothing, 1 written down |

**The honest headline is a range, and the range is the finding.** Counting
sources gives **119 claim-bearing rows** (22 + 56 + 29 + 12) across four
artefacts. Counting *distinct falsifiable statements about the system* gives a
different and smaller number, because the four registers overlap heavily and
nothing records the overlap: `require_verified_substrate` alone appears in all
four. Counting *decomposed* statements gives a larger one, because `sandbox` is
one row and three statements.

**N is not a number this repository can currently produce, and the reason is
structural: there is no identity for a claim.** Four registers name the same
properties in four vocabularies — a `Config` field name, a G-number, an attacker
class section, a marketing bullet — and none of them keys on the others. That,
and not the counting, is the work a ledger would have to do first.

## 1.5 What I could not reach

Named rather than left to be inferred. Completeness was not attempted.

* `CHANGELOG.md` (112 KB), `spec/` (4 files), and **41 of the 48** Markdown
  files under `docs/` — the exact set is pinned by
  `tests/conformance/test_assurance_ledger_limits.py`, so a new document joins
  the blind spot as a red line rather than as silence. Three more
  (`reachability-build.md`, `reachability-readers.md`,
  `live-state-pinning-design.md`) were read for a specific fact and **not**
  inventoried for claims; that is a different state from "read", and it is
  counted apart.
* Git history beyond the 50 commits this clone holds — so every claim about
  history (G6's token sweep, G13's squash finding) is UNVERIFIED here.
* CI logs and workflow run results; `.github/workflows/` was read as text only.
* Any claim carried in code comments rather than in a document. `src/` holds
  146 Python files and the build guard's docstrings alone carry several measured
  claims (for example `security_build.py:193-194`: "208 objects visited in 0.1 ms
  from `build_orchestrator`"). These are claims under rule 1-3 and they are not
  in any register above.

---

# 2. Is there a common method?

## 2.1 The eight solved instances, as they actually are

For each: what varied, what the permitted set was, and where the permitted set's
authority came from.

| # | instrument | what VARIES | the permitted set | its AUTHORITY |
|---|---|---|---|---|
| 1 | descriptor comparison — `tests/conformance/test_execution_descriptor.py:382,407-409` | the fields of `ExecutionDescriptor` | `SNAPSHOT_FIELDS`, what the digest commits to | **the dataclass**: `fields(ExecutionDescriptor)` |
| 2 | composition pins — `tests/conformance/proof_composition.json` | which proofs ran | `required`, keyed `(module, base name)` | **a hand-list, made fail-closed** by a per-module count tie-back |
| 3 | membership pin — `tests/conformance/test_execution_start_signal.py:652-712` | members of `EXECUTION_REFUSAL_REASONS` | `_AUTHORIZATION_REFUSAL_REASONS`, compared as a set both directions | **a hand-list, made fail-closed** by set equality |
| 4 | reader derivation — `src/prometheus_protocol/ledger/readers.py:31-64` | the public reader methods of a ledger class *and its subclasses* | whatever `dir(cls)` yields that is a plain annotated function | **the class's own API surface**, with unsupported shapes refusing |
| 5 | component traversal — `src/prometheus_protocol/runtime/security_build.py:178-260` | which objects the runtime is composed of | `_objects`, the credited walk | **the interpreter**: `gc.get_referents` as a second, independent scope |
| 6 | security field population — `src/prometheus_protocol/runtime/security_build.py:96-102` | `Config`'s security fields, including a subclass's | `fields(config)` on the **instance**, refusing any unclassified field | **the dataclass, at the object's real type** |
| 7 | matrix-agreement guard — `scripts/check_matrix_agreement.py` | which tests each interpreter collects | no list at all: the three versions' sets must be **equal to each other** | **three independent runs of the same producer** |
| 8 | proof-composition checker — `scripts/check_proof_composition.py:97-110` | which proofs ran, by module | `required` from the manifest | same instrument as #2 |

**#2 and #8 are one instrument with two faces** — the manifest and the checker
that reads it. The brief lists them separately; they are not two derivations.
So the population is **seven** distinct instruments, not eight, and that is the
first thing the sprint found by looking.

## 2.2 The answer: one method, four authorities, one decision

**There is a common method.** In all seven, "what would falsify this proof" was
answered by the same four moves:

1. **Name the varying population** — the set whose membership can change without
   anyone editing the proof. In every case the defect was that the proof was
   written over a *different* population from the one that varies.
2. **Find an authority for that population that is not the proof's author.**
3. **Compare the authority's population against the proof's, as SETS, in both
   directions.** Shortfall and excess both refuse.
4. **Fail closed when the authority is unreadable or empty** (doctrine #8).

The cases differ only at step 2, and they differ in exactly four ways:

| authority class | available when | instances |
|---|---|---|
| **A — the runtime's own declaration** (`dataclasses.fields`, `dir()` + `getattr_static`, type hints) | the varying population is something Python records | 1, 4, 6 |
| **B — the interpreter as a third party** (`gc.get_referents`) | the population is "what actually exists", and no declaration covers it | 5 |
| **C — a second independent run of the same producer** | there are N producers that should agree | 7 |
| **D — a hand-list, made fail-closed** | the population is **semantic** and nothing in the runtime records it | 2/8, 3 |

**The decision between them is one question:** *can the varying population be
named by something other than the proof's author?* If yes, use A, B or C in that
order of preference. If no, you are in class D, and class D carries three
disciplines that this repository earned by failing each of them:

* **(i) Compare as a set, both directions.** G25 (`docs/OPEN-GAPS.md:1854`): a
  name-only pin caught deletion and passed substitution; five pins reddened only
  after the key became a pair. And `docs/OPEN-GAPS.md:3683-3700`: a predicate over
  seven *spellings* missed **four of five** additions, and the one it caught
  contained the author's own tokens.
* **(ii) The key must be as wide as the identity of the thing named.** A bare
  test name is scoped to nothing; the test is scoped to a module. G25's closing
  line states it as a rule (`docs/OPEN-GAPS.md:1910-1914`).
* **(iii) An unrecognised member REFUSES, it is not ignored.**
  `readers.py:51-57` raises `TypeError` on a reader shape it cannot classify;
  `security_build.py:98-99` refuses a `Config` field with no security
  classification.

Class D is not a failure of the method — it is the method's honest terminus.
G50 (`docs/OPEN-GAPS.md:4507-4511`) says so directly about the carrier map:
*"Not fixed because the population is not derivable. Which class honours a
Config field is semantic and attribute names do not carry it."* The method's
value is that it tells you *when* you are in class D, and what to do there.

## 2.3 Tested out of sample

The method was extracted from seven instruments. Two more, not in the brief's
list, were checked against it afterwards:

* **`tests/conformance/test_doctrine_index.py`** — varying population: the
  doctrine numbers the tree cites. Authority: the tree itself (class A over text).
  Both directions, as sets, with an explicit one-way exemption for uncited
  numbers. Doctrine #8 guard at `:46-51`. **Fits.**
* **`scripts/check_skip_manifest.py`** — varying population: which tests skip.
  Authority: the JUnit report (class A over the artifact), against a hand-list
  (class D). Both directions. Class-D discipline (iii) present in an unusual and
  strong form: a `[conditional]` entry must carry a `proof:` reference that
  *resolves* to a workflow step carrying a `PROM_REQUIRE_*` flag, or the entry is
  "a hole, not a sanction". **Fits.**

## 2.4 What the method does NOT cover, measured

**The method answers "over what population?" It does not answer "what does the
proof do to each member?"** Those are two axes, and the repository solved them
separately and never connected them.

Measured, in this sprint, on a claim that looked clean:

```
[A] A1-comparison-neutralised-population-intact
    target:   test_security_build.py::test_a_disabled_requirement_is_not_reported_as_applied
    baseline: 1 passed
    mutated:  1 passed
    VERDICT: SURVIVED
```

The mutation replaced the two comparisons for the four verifier bounds
(`security_build.py:576,580`) with literal `True`, leaving the populations
intact. The row still reports `applied` — the token whose stated meaning is *"it
was compared against the live components that honour it"*
(`security_build.py:33-35`) — and the proof does not notice.

```
[A] A2-population-emptied
    baseline: 1 passed
    mutated:  1 failed
    VERDICT: CAUGHT
```

And the comparison-neutralised mutation was run again against **all 3169
collected tests**, not just its own proof:

```
[A] A1 / WHOLE TREE
    mutated: 3 failed, 3141 passed, 23 skipped, 2 deselected
    RED: test_hearth_ledger.py::test_every_protected_file_exists_and_matches_its_digest
    RED: test_hearth_ledger.py::test_the_guards_do_not_depend_on_a_branch_being_resolvable
    RED: test_hearth_ledger.py::test_the_ledger_actually_detects_a_changed_file
```

Three red, and all three are the **Hearth digest ledger** — a file-integrity
guard that fires because `security_build.py` is one of 23 frozen files, and
would fire identically for a correct edit. Excluding it, **nothing in 3169 tests
noticed.** (That confound is taxonomy mode 13, found here.)

The same proof catches the *population* being emptied and misses the
*comparison* being neutralised. The population half is method-covered; the
comparison half is covered by a different discipline entirely — **doctrine #4,
every negative has a positive control** — and that is exactly the work recorded
at `tests/conformance/test_security_build.py:823-830` and in
`scripts/reachability_build_proofs.py:113-141`, where six credit paths were
deleted before their controls existed and **all six survived, `70 passed`.**

The four verifier-bound rows are a seventh instance of that shape, found here.
They sit in `RESOURCE_BOUND`
(`tests/conformance/test_security_field_behaviour.py:95-102`), proved by verdict
flip in `test_resource_bound_outcomes.py` — which proves the *sandbox* enforces
the bound, and says nothing about whether the *build guard* compared it.

**So the Section 2 answer, in one line: one method with a four-way branch for
the membership question, plus a second and independent discipline for the
comparison question, and a ledger entry needs both.** A ledger built on the
method alone would have marked `verifier_timeout_s` ISOLATING.

---

# 3. The failure taxonomy — ways a ledger entry can be false

Thirteen modes — the brief named twelve; the thirteenth was found while running
§4. For each: the mechanism, the instance that proved it, and **the
check** — which is what makes this a method rather than a list. The last column
is whether that check can run without a human.

| # | mode | mechanism | instance | THE CHECK | mechanical? |
|---|---|---|---|---|---|
| 1 | **reason carried by a message string** | `pytest.raises(X, match="…")` ties the proof to the cause only through a diagnostic string; a reword converts a reason-assertion into an existence-assertion | G19 (`docs/OPEN-GAPS.md:1364`): all 8 `match=` stripped → `26 passed`, nothing reddened | strip every `match=` in the module and re-run; anything still green was carried by the string. Also: classify each `raises` site by whether the enclosing test asserts a **typed** discriminator | **YES** |
| 2 | **refusal sharing a label with another refusal** | two mechanisms raise the same `property_name`, so deleting one leaves the other answering for it | `security_build.py:75-90`: with all three component refusals labelled `"component"`, `external-subclass-refusal-deleted` **survived** | for each refusal label, count the distinct raise sites that use it. >1 ⇒ no single-target mutation can isolate any of them without companion edits | **YES** |
| 3 | **proof satisfied by an upstream refusal firing first** | the test asserts a refusal; a different, earlier refusal supplies it | `tests/conformance/test_security_build.py:41-52`: `resolve_attestation_signer` raised before `attest_at_startup` was reached, so `calls == []` and the F1 test never established F1 | assert the mechanism was **reached** (a spy, a call count), not only that something raised | **PARTLY** — detecting it is mechanical (did the named code run?); deciding what "reached" means is not |
| 4 | **count standing in for a composition** | two sets of equal size are indistinguishable by count; delete a load-bearing proof, add a benign one | G25: counts unchanged at 18 + 4 = 22, the pinned proof gone, checker returned **NO problems** | pin the SET, not `len`. Then ask whether the set's KEY is as wide as the identity of what it names | **YES** |
| 5 | **floor permitting members to vanish** | `>= N` passes for every population above N | `docs/OPEN-GAPS.md:3709-3711`: `len(...) >= 15` passed happily against a set of seventeen while the prose said nineteen. Now `== 30` at `test_execution_start_signal.py:741` | AST sweep for a comparison operator other than `==` against a population size | **YES** |
| 6 | **population narrowed by a filter before counting** | the filter drops members silently; downstream a narrowed population is indistinguishable from a smaller one | G53 (`docs/OPEN-GAPS.md:4680`): a case-sensitive filter published **5** rows for a runner with **6**. Doctrine #11 | take the count from the artifact; where a filter is unavoidable, tie the filtered count back to the total in the same step | **YES** |
| 7 | **instrument returning an empty set, read as clean** | zero findings and zero capability print identically | doctrine #8, the most-cited number in the tree (49 citations). Guarded at `test_security_field_behaviour.py:201-214` and `test_doctrine_index.py:46-51` | every derivation carries a positive control proving it can say no | **YES** |
| 8 | **traversal crediting components it never saw** | absence-from-the-walk is reported as absence-from-the-graph | G43 (`docs/OPEN-GAPS.md:4103`): one live defect in ten positions — **seven PASSED → `default_not_applicable`**, `applied` in the presence of a legitimate consumer | a second, independently-authored scope (class B) and refusal where they disagree | **YES** |
| 9 | **guard keyed on a name where it needed a type** | the discriminator is a writable string | G50 (`:4481`), G17 (`:1098`, the dead-flag guard proves a NAME APPEARS), G52 (`:4541`, three name-keyed sweeps, one with a firing bypass) | for each guard, ask what the key's type is. A `str` key over a semantic population fails open unless the refusal direction is closed | **PARTLY** — finding string keys is mechanical; deciding whether the key is load-bearing is not |
| 10 | **isolation destroyed by a later, unrelated guard** | defence in depth leaves a single-target mutation pointing at one of two mechanisms | G44 (`:4163`): `chain-row-comparison-removed` → `1 passed` where a failure was required; `selected-profile-injection-unwired` → 8 against a pinned 9 | **re-run every runner that pins a label the moment a refusal is added to it.** Derived, not remembered: `tests/conformance/test_proof_selectors_exist.py` | **PARTLY** — "which runners name this" is derived; "which mechanisms now carry this property" is **not derivable** and G44 says so (`:4206-4209`) |
| 11 | **assertion over a combination that cannot occur** | the test pins an upstream validator, not the guard it names | `tests/conformance/test_security_build.py:886-895`: `require_digest_pin=True` with `sandbox='namespace'` never reaches the build guard — `core/config.py:456` refuses it at load | assert the precondition: that the mutated code path is reached in the unmutated run | **PARTLY** |
| 12 | **claim about existing behaviour that was never read** | the claim is inferred from a name or remembered | doctrine #10 (`docs/live-state-pinning-design.md:187`); `docs/reachability-readers.md:52` ("that last sentence was not true"); `docs/threat-model.md:1465` (a paragraph that was "itself a false claim") | every claim carries a file and line, or is marked UNVERIFIED | **NO** — the *form* is checkable, the *truth* is not |
| 13 | **an integrity guard standing in for a proof** — *found in this sprint* | a file-digest guard reddens for any edit to a frozen file, so a whole-tree mutation run reports CAUGHT whether or not any proof of the property noticed | §4.8: A1 and C1 mutated `security_build.py`, one of 23 files frozen by the Hearth (`tests/conformance/hearth_ledger.py:142,157`). Whole tree, both: **exactly 3 red, all three in `test_hearth_ledger.py`**, and nothing else in 3169 tests | never read a red *count*; read the red *set*, and exclude the guards that fire on the file rather than on the behaviour. Mechanically: the frozen-file set is derivable (`PROTECTED_FILES`), so the exclusion is derivable too | **YES** |

## 3.1 The split, which is the finding

**Eight of thirteen have a fully mechanical check. Four are partly mechanical.
One is not mechanical at all.** (Twelve modes were given in the brief; the
thirteenth was found while running §4's whole-tree probes.)

The eight mechanical ones (1, 2, 4, 5, 6, 7, 8, 13) share a property worth naming:
each is a **defect in the shape of the proof**, visible without knowing what the
proof is about. You can find a floor, a bare name key, an untied filtered count
or a shared refusal label by reading the AST.

The four partial ones (3, 9, 10, 11) share a different property: the mechanical
half detects a **candidate**, and a human decides whether it is a defect. Mode 10
is the hardest, and the repository says why: *"Nothing derives the set of
mechanisms that carry a given property, so the next guard added over an
already-proved fact will disarm its proof the same way"* (`docs/OPEN-GAPS.md:4206-4209`).
**Mode 10 is the one that scales badly**: it gets worse with every guard added,
and the only remedy in the tree — hand-written companion edits — is class D with
no derivation available.

Mode 12 is not mechanical because it is about the world outside the tree.

**Mode 1's check, run as a measurement.** The sweep is cheap, so it was done over
the whole test tree rather than argued about. Population: every `pytest.raises`
call site in `tests/`, from the AST; classified by what the enclosing test
function also asserts.

```
population: pytest.raises call sites in tests/ = 558
  TYPED (asserts .reason / .property_name / .code / .kind):   113
  MATCH (only match=, or a substring on str(exc)):            176
  BARE  (neither: the exception TYPE is the whole claim):     269
  tie-back: 113 + 176 + 269 == 558
```

The BARE bucket needs splitting before it means anything, because
`pytest.raises(ClockUntrusted)` *is* a typed discriminator while
`pytest.raises(ValueError)` is not:

```
BARE  269 = 113 on a generic builtin + 156 on a project-specific class
MATCH 176 =  69 on a generic builtin + 107 on a project-specific class
weakest form (generic exception, no match=, no typed assertion): 113
```

**Stated limits of this instrument**, because it is exactly the kind of number
this document is about: it classifies per *function*, so a typed assertion
anywhere in a multi-assertion test marks every `raises` in it TYPED — which
over-counts TYPED. Its `GENERIC` list is hand-written, which is class D with
discipline (iii) absent. It does not know whether a project-specific exception
class is narrow enough to carry the cause. It is a screen, not a verdict.

**And it was confirmed behaviourally.** G19's probe, re-run on a file G19 did not
cover:

```
[B] B1-all-match=-arguments-stripped  (tests/chokepoint/test_substrate.py)
    baseline: 57 passed
    mutated:  57 passed      match= arguments removed: 13
    VERDICT: SURVIVED
```

Thirteen refusal causes in that file are carried entirely by their message
strings. G19 closed eight of this class in one file, in September 2026, by
converting to a typed `reason`. The class was not swept.

---

# 4. Five ledger entries, produced by hand

Chosen deliberately: one expected clean, one message-matched, one where several
guards share a cause, one that is a stated LIMIT, and one expected to have no
isolating proof. Every mutation below was run. **Two of my five expectations
were wrong**, and both wrong expectations are the entries worth reading.

Mutations run in `MutationWorktree` (`scripts/mutation_worktree.py`) — a detached
worktree of HEAD with its own `src` first on `PYTHONPATH`, so the primary tree is
never written to. Second-order probes replace every `assert` in the proof module
with `pass`, using the repository's own transform
(`scripts/reachability_build_proofs.py:without_asserts`).

## Entry A — `verifier_timeout_s` is `applied`

| field | content |
|---|---|
| **Claim** | The build guard reports `applied` for `verifier_timeout_s`, and `applied` means "this property was requested, and it was compared against the live components that honour it" (`src/prometheus_protocol/runtime/security_build.py:33-35`) |
| **Mechanism** | `src/prometheus_protocol/runtime/security_build.py:569-581` — the verifier-bound branch, comparing `SubprocessVerifier.timeout_s` and `Limits.wall_time_s` against the Config value |
| **Proof** | `tests/conformance/test_security_build.py:487` (`test_a_disabled_requirement_is_not_reported_as_applied`), which asserts `report["verifier_timeout_s"] == APPLIED` as the paired positive to the three `not_requested` rows |
| **Mutation 1 — comparison neutralised, population intact** | both comparison expressions → literal `True`. **`1 passed` → `1 passed`. SURVIVED.** |
| **Mutation 2 — population emptied** | both `instances(...)` → `()`. **`1 passed` → `1 failed`. CAUGHT.** |
| **Second-order** | on mutation 2, with all asserts in the proof module replaced by `pass`: see §4.8 — SURVIVED |
| **Verdict** | **NON-ISOLATING for the claim as stated.** The proof isolates the *population*; it does not isolate the *comparison*, which is the half the word `applied` names. |

**Where my expectation was wrong.** I picked this row expecting it to be clean:
it is the row the repository itself cites as the example of a property that "WAS
compared against live `SubprocessVerifier`/`Limits` objects"
(`tests/conformance/test_security_build.py:475-477`). That sentence is true of
the code and is not established by the test that carries it. This is F-5's shape
— six credit paths with negative controls and no positive ones, all six
surviving deletion (`tests/conformance/test_security_build.py:823-830`) —
recurring on a seventh path after F-5 closed the first six. The seventh is not a
regression of that fix; it is a place the fix did not look.

## Entry B — the incoherent substrate pair is refused at every layer

| field | content |
|---|---|
| **Claim** | `require_verified_substrate=True` alongside `allow_unverified_substrate=True` is refused at every layer that can see it |
| **Mechanism** | three raise sites, all with the same sentence: `src/prometheus_protocol/core/config.py:471-478`, `src/prometheus_protocol/chokepoint/runner.py:517`, `src/prometheus_protocol/chokepoint/substrate.py:818` |
| **Proof** | `tests/chokepoint/test_substrate.py:329-339` — four `pytest.raises(ConfigError, match="would never take effect")`, one per layer |
| **Mutation 1 — all `match=` stripped from the module** | 13 removed. **`57 passed` → `57 passed`. SURVIVED.** |
| **Mutation 2 — the `core/config.py` layer's refusal deleted** | `if self.require_verified_substrate and self.allow_unverified_substrate:` → `if False:`. **`1 passed` → `1 failed`. CAUGHT.** |
| **Mutation 3 — the same, over both substrate and field-behaviour modules** | **`80 passed` → `1 failed, 79 passed`. CAUGHT**, and *only* `test_the_incoherent_pair_is_refused_at_every_layer` reddened |
| **Verdict** | **ISOLATING for the refusal, NON-ISOLATING for the cause.** The proof establishes that each layer refuses. It does not establish *why*: the four assertions are tied to their causes by one shared sentence, and mutation 1 shows that sentence is carrying it alone. |

This is the useful shape of the distinction G19 drew and then had to defend
(`docs/OPEN-GAPS.md:1405-1414`): *the raise is genuinely half the property.*
Stripping `match=` does not show the test is weak; it shows which half of the
property is string-carried. Mutation 3's single red line — one test, not four —
is what an isolating refusal proof looks like.

## Entry C — an injected ledger anchor cannot substitute another witness

| field | content |
|---|---|
| **Claim** | A ledger injected at a composition root cannot pass off a different anchor as the configured witness |
| **Mechanism** | `src/prometheus_protocol/runtime/security_build.py:262-288` — `validate_ledger`, which raises `BuildRefused("ledger_anchor", …)` at **three** sites: `:271` no supported tip anchor, `:280` a different adapter type, `:288` a different destination |
| **Proof** | `tests/conformance/test_security_build.py:226` (`test_injected_anchor_cannot_substitute_another_witness`) |
| **Mutation 1 — adapter-type check deleted** | `if type(actual) is not type(expected):` → `if False:`. **`1 passed` → `1 passed`. SURVIVED.** Re-run against **all 3169 tests**: `3 failed, 3141 passed` — all three the Hearth digest guard, so **nothing in the whole suite noticed** |
| **Mutation 2 — destination check deleted** (the row `reachability_build_proofs.py:50-52` already pins) | **`1 passed` → `1 failed`. CAUGHT.** |
| **Mutation 3 — both deleted, as a companion edit (G44's fix)** | **`1 passed` → `1 failed`. CAUGHT.** |
| **Verdict** | **NON-ISOLATING for the adapter-type check.** The destination comparison answers in its place. |

**This is G44's shape, live, on a mechanism G44 did not name.** The existing
runner pins the destination check and nothing pins the adapter-type check;
deleting it is invisible. The remedy G44 prescribes — a companion edit that
neuters every mechanism carrying the property so the row isolates the one it
names — applies directly, and mutation 3 shows the pair is jointly load-bearing.
This entry is also the concrete instance of §5's third limit: **mutation 1
demonstrated one path around the guard; it says nothing about whether a third
exists.**

## Entry D — the discovery scope's four named residuals are real *(a stated LIMIT)*

| field | content |
|---|---|
| **Claim** | Four places exist where a security component can live and **neither** of the build guard's two scopes will see it: built lazily, reachable only via `__getattr__`, held in a foreign closure, or reachable only from module globals (`src/prometheus_protocol/runtime/security_build.py:198-216`; `docs/OPEN-GAPS.md` G49) |
| **Mechanism** | the *absence* of coverage — specifically `security_build.py:239-240`, which follows only `prometheus_protocol.`-owned closures |
| **Proof** | `tests/conformance/test_security_build.py:778-819` — `test_the_named_residuals_of_the_discovery_scope_are_real`, parametrised over all four, docstring: *"Doctrine #5: the stated limit is a PASSING TEST, not a paragraph"* |
| **Mutation — close one residual** | follow *every* closure, not only the package's: `if not obj.__module__.startswith("prometheus_protocol."): continue` → `if False: pass`. **`4 passed` → `1 failed, 3 passed`. CAUGHT**, and the red is exactly `[foreign_closure]` |
| **Same mutation, whole module** | **`87 passed` → `1 failed, 86 passed`.** The same single row. |
| **Same mutation, whole tree** | **`3144 passed` → `7 failed, 3066 passed, 71 errors`.** The red set: `[foreign_closure]`, the three Hearth digest tests, and three `test_reconciliation.py` tests — plus 71 errors |
| **Verdict** | **ISOLATING.** |

**A limit's mutation runs the other way, and that is the entry's methodological
point.** For an enforcement you remove the mechanism and require red. For a
limit you *close the gap* and require red — the limit test must fail when the
limit stops being true. G43 states the intent (`docs/OPEN-GAPS.md:4149-4150`:
"closing this gap must flip it, which is the intended signal"), and the corpus
already contains one gap-closing row of exactly this shape:
`receipt_classification_proofs.py:140-142` widens `_WALKED_CONTAINERS` to
`(tuple, list, dict, set, frozenset)` and requires
`test_a_component_the_traversal_cannot_credit_refuses_the_build` to redden. So
the direction is not novel — it is established, unnamed, and used for one of the
guard's two limit tests and not the other. **No runner names the residuals test
as a selector.** The precision of this run is worth noting: one of four
parametrisations reddened, and it was the right one.

This is also the cleanest entry in the five, and the reason is visible: the
limit's author wrote the four residuals as a parametrised behavioural test over a
planted defect, so the ledger entry had already been done.

**And the whole-tree run verified a claim in the mechanism's own docstring,
which is doctrine #10 turned on the tree rather than on a document.**
`security_build.py:208-212` states, as a measurement, that following every
closure cell *"failed 4 chokepoint tests and errored 71 more on an in-memory
audit medium held behind a test-supplied executor"*. That is a claim about
existing behaviour, made about a mutation nobody re-runs.

Re-run here, scoped to `tests/chokepoint` so the two halves are directly
comparable:

```
baseline (tests/chokepoint): 901 passed, 14 skipped in 31.52s
mutated  (tests/chokepoint): 3 failed, 827 passed, 14 skipped, 71 errors
FAILED: 3   (all in tests/chokepoint/test_reconciliation.py)
ERROR:  71  (all in tests/chokepoint/test_reconciliation.py)
```

**The error count reproduces exactly — 71. The failure count is 3, not 4.** The
whole-tree run agrees independently (7 red = 3 Hearth + `[foreign_closure]` + the
same 3 reconciliation tests). Whether the fourth failure went away with a later
change or was miscounted cannot be settled here: this clone holds 50 commits, so
the tree the docstring measured is not available. Recorded as a discrepancy,
UNVERIFIED in either direction, rather than resolved by assuming the docstring
was right or that it was wrong.

That is the only claim this sprint could check against a number someone else
wrote down first, and it is exactly the kind a ledger exists to keep honest: a
measurement, in a docstring, of a mutation that no runner re-runs — which drifted
by one and nothing said so.

## Entry E — `require_verified_substrate` reaches the live substrate policy

| field | content |
|---|---|
| **Claim (build-matrix form)** | the build guard compares `require_verified_substrate` against the live `SubstratePolicy` objects in the returned runtime — `security_build.py:544` |
| **Mechanism** | `applied = matches(SubstratePolicy, "require_verified", value)` |
| **Proof — what I found by searching** | *none.* No test asserts `report["require_verified_substrate"] == APPLIED`, and at four roots the row is never `applied` |
| **Mutation — the comparison deleted, whole tree** | `applied = matches(SubstratePolicy, …)` → `applied = None`. **`3144 passed` → `6 failed, 3138 passed`. CAUGHT.** Three of the six are the Hearth digest guard (taxonomy mode 13). The other three are real: `test_security_build.py::test_the_same_defect_in_a_credited_container_is_refused_on_its_merits`, and `test_substrate.py::test_the_builder_honours_the_requirement_from_config` and `::test_the_builder_refuses_an_unknown_substrate_unless_config_opts_out` |
| **Claim (behavioural form)** | `require_verified_substrate` raises the bar from the runtime config |
| **Proof** | `tests/conformance/test_security_field_behaviour.py:484-494` — named in the `PROOFS` map, so it cannot be renamed away |
| **Verdict** | **ISOLATING — and my expectation was wrong twice over.** |

**Where my expectation was wrong, and what the correction is worth.** I chose
this row expecting no proof at all, on two pieces of evidence: no test asserts
`== APPLIED` for it, and it read `default_not_applicable` in all 15 cells I had
measured. The mutation refuted both.

* It is proved in the **negative** direction, by a test I had not found because I
  searched for `APPLIED`: `test_the_same_defect_in_a_credited_container_is_refused_on_its_merits`
  (`tests/conformance/test_security_build.py:637-654`) plants a
  `SubstratePolicy(require_verified=False, allow_unverified=True)` against a
  Config that disagrees, and requires `BuildRefused("allow_unverified_substrate")`.
  It is itself labelled a positive control for seven other refusals.
* It is proved in the **positive** direction by the two `test_substrate.py`
  builder tests, which build a migration runtime that must *succeed* with
  `require_verified_substrate=True` — so neutralising the comparison turns their
  success into a refusal.
* And the 15-cell reading was **my own narrowed population**: those two tests
  build the fifth guarded root, which I had not built. Measured there, both rows
  read `applied` (§1.3).

So the honest verdict is the opposite of the one I set out to record, and the
remaining finding is sharper than the one I expected. Both the tests I found
establish the *refusal* — that a disagreeing component is caught — and the
builder tests establish that an agreeing graph builds. What no test asserts is
that the row then reads `applied`: the token itself, the thing a consumer of the
report reads, is never checked for these two properties. That is Entry A's
finding again, in a different place: **the mechanism is isolated; the report the
mechanism writes is not.**

**§1.2's "duplicates another in different words" case still stands, and now with
a measurement behind it.** `require_verified_substrate` carries at least two
distinct claims with distinct proofs, in distinct modules, in distinct
vocabularies. A ledger that treated it as one row would have to choose one of
them, and choosing wrong is mode 12 committed by the ledger itself. Choosing at
all requires a human.

## Entry F — the README's "6 of 6 paths" delegation *(sixth probe, not one of the five)*

Run because §1.3 turned it up and the brief asks for the false README claims.

| field | content |
|---|---|
| **Claim** | `README.md:87,96-107` — six direct-attack paths to a live PostgreSQL all fail inside the sandbox |
| **Cited proof** | `tests/chokepoint/test_isolation.py::test_agent_cannot_reach_db_by_any_path` — **skipped in this run** (`:46`), and scoped to three TCP paths unless a socket directory is configured (`:37-38,146-149`) |
| **Delegation** | `tests/chokepoint/test_isolation.py:156-168` asserts the three substrings `/run/postgresql`, `/tmp`, `abstract` appear in `test_agent_zone_containment.py` |
| **Mutation** | delete the three socket-path proofs from the companion module by AST: **SURVIVED** — see §4.8 |
| **Note** | the companion's nine tests do run here (`9 passed in 0.84s`), so the coverage is real in this environment — the question is only whether the delegation guard would notice if it stopped being |

## 4.7 The 22-property sweep: the prototype of the tool, and its blind spot

One mutation template, inserted at one line in `validate_build`, applied
identically to every one of the 22 rows so that no row is advantaged by a
hand-picked edit:

```python
if name == "<property>":
    applied = True   # mutated: credited without comparison
```

It models exactly what the `applied` token exists to rule out: the row reported
as compared when nothing was compared. Scope: eight modules (`349 passed`
baseline, ~22 s a run). Narrow ⊂ whole tree, so a row CAUGHT here is caught
there; the survivors are re-checked against all 3169 tests in §4.8.

| | count |
|---|---|
| rows swept | **22** |
| CAUGHT in the narrow scope | **10** |
| SURVIVED in the narrow scope | **12** |

The ten that reddened, each by the proof that caught it:

| property | the test that noticed |
|---|---|
| `require_digest_pin` | `test_a_container_sandbox_without_its_pin_cannot_earn_the_credit` |
| `escalate_below` | `test_default_escalation_cannot_be_relabelled_not_applicable` |
| `pending_ttl_seconds` | `test_default_value_is_not_permission_to_discard_a_bound` |
| `max_role_calls` | `test_a_role_budget_disagreeing_with_the_config_is_refused` |
| `request_timeout_s` | `test_a_remote_provider_disagreeing_with_the_bound_is_refused[request_timeout_s]` |
| `provider_max_response_bytes` | `test_a_remote_provider_disagreeing_with_the_bound_is_refused[provider_max_response_bytes]` |
| `ledger_anchor_retention_days` | `test_an_anchor_retaining_for_the_wrong_period_is_refused` |
| `require_external_signer` | `test_a_local_attestation_signer_cannot_earn_the_custody_credit` |
| `allow_unverified_substrate` | `test_the_same_defect_in_a_credited_container_is_refused_on_its_merits` |
| `verification_profile` | `test_build_checks_policy_at_both_bank_and_execution_authorizer` |

### The blind spot, found by reading the code and not by the tool

**The 12 survivors are not 12 unproved rows**, and saying so would be this
document's own subject matter committed one more time. The template only changes
behaviour where `applied` would otherwise have been `False` or `None`. Five rows
are outside that:

* `config_attestation_target` and `require_config_attestation` **never reach the
  line at all** — their branch writes `PUBLICATION_PENDING`/`NOT_REQUESTED` and
  `continue`s (`security_build.py:533-536`). The mutation is unreachable code.
* `ledger_anchor` and `require_ledger_anchor` `continue` when the value is falsy
  and set `applied = True` **literally** when it is not
  (`security_build.py:514-525`), so on both exercised paths the template is a
  **no-op**. Their real mechanism is `validate_ledger`, which the template does
  not touch — Entry C mutates it directly.
* `allow_insecure_loopback`'s comparison is the `validate_endpoint` call in the
  loop above it; `applied = True if endpoints else None`
  (`security_build.py:591-595`). Forcing `True` leaves the validation running,
  so the template is a no-op wherever an endpoint exists.

**So the honest reading of the sweep is:**

| | count |
|---|---|
| rows where the template is a real mutation | **17** |
| — CAUGHT | **10** |
| — **SURVIVED** | **7** |
| rows where the template is unreachable or a no-op, so the sweep says nothing | **5** |

The seven genuine survivors: `verifier_timeout_s`, `verifier_memory_mb`,
`verifier_cpu_seconds`, `verifier_max_processes`, `sandbox`, `gate_threshold`,
`require_verified_substrate`. Four of them are Entry A's row and its three
siblings.

**And `require_verified_substrate` surviving while `allow_unverified_substrate`
is CAUGHT is the sharpest single row in the sweep.** Both are compared by the
same line (`security_build.py:544`). The one test that catches either plants
`SubstratePolicy(require_verified=False, allow_unverified=True)` against a
Config where both are `False` — so only the `allow_unverified` side disagrees,
and the `require_verified` side is never contradicted by any planted defect in
the suite. One comparison, two directions, one proved.

**This is what a ledger tool's first version looks like.** The template is right
about the question and wrong about five of the twenty-two rows, and nothing in
the run said so — the sweep printed `SURVIVED` for rows where it had done
nothing. A tool that reported "12 of 22 have no isolating proof" would have been
wrong by five, in the direction that makes the codebase look worse, which is not
the safe direction either: a ledger that cries wolf gets discounted. Reading the
branch was the only way to tell, and reading the branch is judgement.

### The seven survivors, re-checked against all 3169 tests

The narrow scope is a subset, so only the survivors needed the whole-tree run.
The five inert rows were excluded and named rather than re-run to confirm that a
no-op is a no-op. Each of the seven, whole tree, two tests deselected:

```
SURVIVED verifier_timeout_s          3 failed, 3141 passed  | hearth-only reds: 3
SURVIVED verifier_memory_mb          3 failed, 3141 passed  | hearth-only reds: 3
SURVIVED verifier_cpu_seconds        3 failed, 3141 passed  | hearth-only reds: 3
SURVIVED verifier_max_processes      3 failed, 3141 passed  | hearth-only reds: 3
SURVIVED sandbox                     3 failed, 3141 passed  | hearth-only reds: 3
SURVIVED gate_threshold              3 failed, 3141 passed  | hearth-only reds: 3
SURVIVED require_verified_substrate  3 failed, 3141 passed  | hearth-only reds: 3

of 7 narrow survivors: 0 caught by the whole tree, 7 SURVIVE it
```

Every red in all seven runs is the Hearth digest guard firing on the edited
file (taxonomy mode 13), and nothing else. **For these seven rows, no test in
this repository notices when the build guard reports `applied` without having
compared anything.**

### The statement the sprint set out to produce, for one register

This is the target artifact — produced, with its bookkeeping visible, for the
**one** claim source where the population is derivable and the mechanism is
uniform. It is not the whole repository, and §5 says why it cannot be.

> **The build guard's per-property application matrix, 2026-09-18, commit `bfe0a1b`.**
>
> **N = 22** claimed properties, derived from `dataclasses.fields(Config)` where
> `metadata["security"] is True`, refusing any field without a classification.
>
> Against the claim *"`applied` means the property was compared against the live
> components that honour it"* (`security_build.py:33-35`), probed by crediting
> the row without comparing anything:
>
> * **M = 10** have an isolating proof. Each named, with the test that reddens.
> * **K = 7** survive their own probe — and survive all 3169 tests — and are
>   marked **NON-ISOLATING**: `verifier_timeout_s`, `verifier_memory_mb`,
>   `verifier_cpu_seconds`, `verifier_max_processes`, `sandbox`,
>   `gate_threshold`, `require_verified_substrate`.
> * **J = 5** are **not measured by this probe** and are named:
>   `config_attestation_target`, `require_config_attestation` (the branch
>   `continue`s before the probe), `ledger_anchor`, `require_ledger_anchor` (the
>   branch sets `applied = True` literally; their real mechanism is
>   `validate_ledger`, probed separately in Entry C), and
>   `allow_insecure_loopback` (its comparison is a call the probe leaves
>   running).
>
> 10 + 7 + 5 = 22. The bookkeeping ties back to the population, which is the
> only property of this statement that is mechanically guaranteed.

> ### WITHDRAWN 2026-09-18 — `K = 7, J = 5` above is wrong
>
> Sprint 1 replaced the hand reading with a mechanical oracle: does the mutated
> statement EXECUTE during the proof run? Measured that way, the correct
> figures for this axis are **M = 10, K = 10, J = 2**.
>
> `allow_insecure_loopback`, `ledger_anchor` and `require_ledger_anchor` were
> classified inert by reading their branches. All three REACH the mutated line
> and all three SURVIVE it — they are non-isolating, not unmeasured. **K was
> understated by three and J overstated by three**, and the error moved three
> real survivors out of the column that counts them, which is the flattering
> direction.
>
> The figures are left standing above and withdrawn here rather than edited,
> so the record shows what was claimed and what corrected it. See
> `docs/assurance-ledger-sprint-1.md` §2.3.

**Read the K row carefully, because it is the easiest sentence here to
over-read.** It does not say those seven mechanisms are broken; every one of
them works, verified on unmutated code by the 18-cell matrix in §1.3. It says
that if one of them stopped working, this repository would not find out from its
tests. Four of the seven have behavioural proofs elsewhere — the verifier bounds
are proved by verdict flip in `test_resource_bound_outcomes.py` — which prove
the *sandbox* enforces the bound and say nothing about whether the *build guard*
compared it. That distinction is the whole content of the K row.

## 4.8 Every run, in full

**The whole-tree probes.** All 3169 collected tests, with the two
environment-broken `test_composed_message_guard` tests deselected (stated, not
silent). Baseline in the worktree: `3144 passed, 23 skipped, 2 deselected`.

| probe | result | the red set, read rather than counted |
|---|---|---|
| **A1** verifier-bound comparison neutralised | `3 failed, 3141 passed` | 3 Hearth digest tests only — **no proof of the property noticed** |
| **C1** anchor adapter-type check deleted | `3 failed, 3141 passed` | 3 Hearth digest tests only — **no proof of the property noticed** |
| **E1** substrate row comparison deleted | `6 failed, 3138 passed` | 3 Hearth + `test_the_same_defect_in_a_credited_container_is_refused_on_its_merits` + two `test_substrate.py` builder tests — **CAUGHT** |
| **D1** foreign-closure residual closed | `7 failed, 3066 passed, 71 errors` | 3 Hearth + `[foreign_closure]` + three `test_reconciliation.py` tests, plus 71 errors — **CAUGHT**, and precisely |

**The second-order probes.** Every `assert` in the proof module replaced by
`pass`; `pytest.raises` survives. A row still CAUGHT was caught by a refusal
oracle; a row that SURVIVES was carried entirely by its assertions.

| entry | asserts deleted | result | reading |
|---|---|---|---|
| **A2** population emptied | 92, from `test_security_build.py` | `1 passed` — **SURVIVED** | the proof is assert-only; nothing raises, so with the asserts gone it proves nothing |
| **C2** destination check deleted | 92, same module | `1 failed` — **CAUGHT** | `pytest.raises(BuildRefused)` carried it |
| **B2** coherence refusal deleted | 49, from `test_substrate.py` | `1 failed` — **CAUGHT** | the refusal oracle carried it |
| **D1** residual closed | 92, same module | `4 passed` — **SURVIVED** | the limit proof is assert-only, which is correct for a limit: there is no refusal to catch |

That split is worth stating plainly because it is easy to read backwards. A
second-order SURVIVOR is not a weaker proof than a second-order CATCH — it says
the proof's claim is a **value** claim, not a refusal claim, and a value claim
has nowhere else to live but an assertion. What the second-order probe actually
separates is *which oracle is load-bearing*, and both entries that survived it
(A2, D1) are entries whose claim is about a reported value or an observed set.

**Entry F — the README's delegated socket-path coverage.**

```
baseline: 10 passed, 1 skipped
socket proofs removed: ['test_abstract_namespace_sockets_are_unreachable',
                        'test_stock_postgres_socket_locations_are_unreachable',
                        'test_the_socket_files_are_not_even_visible']
mutated:  7 passed, 1 skipped
VERDICT for test_socket_paths_are_covered_somewhere: SURVIVED
```

The three socket-path proofs were deleted from the companion module by AST and
the delegation guard stayed green, because the three substrings it checks for
(`/run/postgresql`, `/tmp`, `abstract`) still appear elsewhere in that file. So
`README.md:87`'s "6 of 6 direct-attack paths" rests, for three of the six, on a
guard that **pins text and not coverage** — taxonomy mode 9, in the guard whose
docstring says it exists "so deleting it cannot silently drop the coverage this
test delegates" (`tests/chokepoint/test_isolation.py:158-161`). Deleting the
coverage does not drop the guard.

To be exact about what this does and does not show: the coverage is real in this
environment — those nine tests passed (`9 passed in 0.84s`) before the mutation.
The finding is that nothing would notice if it stopped being real, and that the
one test the README links skips by default here.

## 4.9 The cost of one entry, and what that makes this product

**What is mechanical, measured:**

| step | cost |
|---|---|
| establish the baseline | one pytest run: **0.15 s** scoped to one test, **0.8 s** to one module, **260 s** to the whole tree |
| apply the mutation and re-run | the same again |
| diff the red set | free — `MutationWorktree.pytest` returns it |
| second-order (delete every assert) | free — the transform is 8 lines and already in the tree |
| separating a proof's reds from an integrity guard's | free — the Hearth's frozen-file set is derivable (`PROTECTED_FILES`) |
| **decide CAUGHT or SURVIVED** | free |

**What is judgement, and is not close to free:**

| step | why a human is required |
|---|---|
| **naming the mechanism for a claim** | Entry E took reading four files to establish that one property carries two different claims with different proof status. Nothing in the tree links `require_verified_substrate` the README-adjacent claim, the `Config` field, the G-number and the threat-model section |
| **choosing deletion versus substitution** | Entry A: deleting the population was CAUGHT, substituting `True` for the comparison over that same population SURVIVED. G25 names the split: *"Deletion is the obvious attack; SUBSTITUTION is the shape a real patch takes"* (`docs/OPEN-GAPS.md:1882`). A generator that only deletes would have marked Entry A ISOLATING |
| **knowing how many mechanisms carry the property** | Entry C: deleting one of `validate_ledger`'s three `ledger_anchor` refusals SURVIVED; deleting two CAUGHT. G44's companion edits are the remedy and G44 states that the set is not derivable (`docs/OPEN-GAPS.md:4206-4209`) |
| **choosing the direction for a LIMIT** | Entry D's mutation *closes* the gap. A tool that removes mechanisms would report a limit as unprovable |
| **reading a survivor** | mutation 1 of Entry C survived because a sibling guard answered. Mutation 1 of Entry A survived because the proof was over the wrong half. Same observation, two different findings, two different fixes |
| **establishing that the mutation was a mutation at all** | the strongest number in this sprint. Of the 22 rows swept with one uniform template, **5 were inert** — the branch `continue`d before the mutated line, or already set `applied = True`, or its real comparison was a call the template left running. The runner printed `SURVIVED` for all five. Only reading the branch tells them apart, and `MutationWorktree.apply` cannot: it refuses a string that is *absent*, not one that is *ineffective* |

**Honest per-entry cost from this sprint:** roughly **30–60 minutes of reading
and judgement**, plus **seconds to minutes of machine time** (22 s scoped, 260 s
whole-tree, per run, and each entry needs several), for an entry whose mechanism
is already localised in a file built for the purpose. Entry E, where
the claim had to be disentangled from three other statements of the same
property, took longer than the other four together. None of the five would have
been produced correctly by a tool that generates mutations automatically.

**But that is not the whole answer, and the other half changes the product.**

Where a claim source has **one uniform mechanism**, the judgement amortises. The
22 build-matrix rows all reduce to the same question — *is the row credited
without comparing anything?* — and therefore to the same mutation, inserted at
one line:

```python
if name == "<property>":
    applied = True   # credited without comparison
```

One template, written once, applied identically to all 22 so no row is
advantaged by a hand-picked edit. §4.7 reports the result, **including the five
rows on which it turned out to be inert** — which is the honest version of
"the tool works". That is the prototype, and it is the same instrument shape §2
describes: a
population derived from the runtime's own declaration
(`fields(Config)` → 22 rows), compared in both directions, failing closed.

**So this is both, and the split is not arbitrary:**

* For a claim source with a **derivable population and a uniform mechanism**, the
  ledger is a **tool you run**, and the per-entry cost collapses to machine time.
  Registers of this kind here: the build-guard matrix (22), the security-field
  partition (22), the skip manifest, the doctrine index.
* For a claim source that is **prose** — the tracker, the threat model, the
  README — the ledger is a **specification others follow**, and its per-entry
  cost is a human's.

**And §1.3 already measured what happens to a specification others follow.** The
tracker states a five-field entry schema in its preamble and **1 entry in 56
carries all five fields.** Not because the authors were careless: the entries are
unusually rigorous, several run to a hundred lines with measured tables. They
simply did not converge on a form, because nothing made them. The one register
that *is* enforced — `test_security_field_behaviour.py`'s partition-plus-`PROOFS`
ratchet — is complete today: 22 of 22 fields classified, 14 of 14
outcome-affecting fields mapped to proofs that exist. How long it has been
complete is UNVERIFIED here; this clone holds 50 commits.

**The recommendation this sprint supports:** the ledger should be a tool
wherever the population is derivable, and where it is not, the *specification*
must ship with a ratchet like `test_the_partition_covers_every_declared_security_field_exactly_once`
(`tests/conformance/test_security_field_behaviour.py:166`), or it will be 1-in-56
within a year. An entry format with no enforcing test is the thing this
repository already tried.

**Observed while writing this document, which is the argument in miniature.**
Producing it reddened three existing ratchets, each of which was right to fire:
`scripts/type_gate.py`'s exact file-count pin refused at 344 against 343;
`tests/conformance/test_positive_control_set.py` refused a self-declared
positive control that was not registered; and
`tests/conformance/test_doctrine_index.py` refused the un-re-measured citation
table **twice** — once for the document, once again after a later revision added
more citations. Each was re-measured and re-pinned with the reason recorded, and
none could have been skipped. The tracker's five-field schema, which has no
ratchet, was followed by this document and by nothing else that arrived in the
last year.

---

# 5. What this cannot establish

Stated before anyone else states it.

1. **A ledger over the claims you can find says nothing about claims nobody
   wrote down.** §1.5 names what was not reached. Worse than the unread
   documents: `src/` holds 146 files whose docstrings carry measured claims in
   the same voice as the documents (`security_build.py:193-194` publishes a
   measured object count and a timing), and no register contains them. One of
   those was checked in this sprint (§4 Entry D) and had **drifted by one**
   without anything noticing. The only mechanical form this limit can take is:
   *pin the set of sources the ledger reads, and count and name the ones it does
   not.* Expressed as a test in
   `tests/conformance/test_assurance_ledger_limits.py`.

2. **An isolating proof establishes that the proof notices the mechanism's
   removal — not that the mechanism is correct.** Entry A's mutation 2 is
   CAUGHT; that establishes the proof watches the population. It does not
   establish that comparing `SubprocessVerifier.timeout_s` to
   `config.verifier_timeout_s` is the right comparison. The repository already
   says this about its own strongest token: `applied` means compared, and
   `docs/DOCTRINE.md:93-95` says a count from the artifact "can still be a
   count of the wrong thing; the doctrine is about the reading, not the choice of
   what to read." The same sentence applies to every row of a ledger.

3. **A mutation demonstrates one path around a guard, never the absence of a
   second.** Entry C is the instance: the adapter-type check could be deleted
   because the destination check answered. Deleting both reddens — which proves
   the pair is jointly load-bearing and proves nothing about a third path. The
   *presence* of a second mechanism on a shared label is mechanically detectable
   (taxonomy mode 2's check), and that is the strongest available form. Expressed
   as a test.

4. **Judgment-dependent modes cannot be audited mechanically.** §3.1 measured the
   split: 8 mechanical, 4 partial, 1 not. Mode 10 is the load-bearing one and it
   degrades as the tree hardens — every new guard over an already-proved fact can
   silently disarm an older proof, and G44 states that the set of mechanisms
   carrying a property is not derivable (`docs/OPEN-GAPS.md:4206-4209`). A ledger
   that reported "M have isolating proofs" without re-running the affected
   runners on every added refusal would be reporting a number that decays.

**A fifth, which the brief did not name and this sprint found.** §1.4: **there is
no identity for a claim in this repository.** Four registers name overlapping
properties in four vocabularies and none keys on another, so N cannot be
produced without first deciding — by hand, per property — whether two sentences
are the same claim. Entry E shows the cost of getting that decision wrong: it
attaches a real proof to a claim that has none.

Four of these five are expressed as passing tests in
`tests/conformance/test_assurance_ledger_limits.py`. The second cannot be: it is
a statement about what proof means, not about the tree.

---

# Appendix — reproducing every number here

```
pip install -e ".[dev]" -c constraints.txt --ignore-installed PyYAML
python -m pytest -q                         # 2 failed (environment), 3144 passed, 23 skipped
python -m pytest --collect-only -q          # 3169 tests collected
```

Scripts used, all read-only against the primary tree (mutations run in a
detached worktree via `scripts/mutation_worktree.py`):

| what | where |
|---|---|
| the per-property matrix, from the artifact | §1.3, 18 built cells across five roots, with a tie-back assertion |
| the claim-source inventory | §1.3, derived from each file |
| the `pytest.raises` classification | §3.1, AST over `tests/**/*.py` |
| the mutation corpus size | 19 runners, **306** rows, 0 unreadable |
| the five entries and the 22-row sweep | §4 |

## This document's own instrument narrowed its population twice

Recorded rather than quietly fixed, because it is the document's subject matter
and because two instances in one sprint is the rate, not an accident.

**First: the mutation-corpus counter.** Its first version matched `ast.Assign`
only and reported **279 rows with 2 runners "unreadable"**. The two it could not
read (`composed_message_revert_proofs.py`, `spend_proofs.py`) declare `MUTATIONS`
with a type annotation, which is `ast.AnnAssign`. A filter narrowed the
population and the shortfall was reported as a property of *the runners* rather
than of *the instrument*. Widening the matcher gives **306 rows, 0 unreadable**.
Caught by the instrument printing its own "unreadable" count beside its total —
which is what doctrine #11 asks for, and the only reason it was visible.

**Second: the per-property matrix.** Its first version built the four roots in
`runtime/factory.py`, reported 15 cells, and concluded that two of the 22
properties were never `applied`. There are **five** guarded roots;
`build_migration_runtime` is the fifth and the only one holding a
`SubstratePolicy`. Corrected: 18 cells, and both of those rows read `applied`
there. **Not** caught by the instrument — its tie-back assertion held perfectly,
because a tie-back checks that the population sums, not that the population is
the right one. It was caught by a mutation, four hours later (§4 Entry E).

That pair is the sharpest evidence in this document for §5's second limit. The
tie-back is doctrine #11 correctly applied and it did not help, because *the
doctrine is about the reading, not the choice of what to read*
(`docs/DOCTRINE.md:93-95`). An assurance ledger will make this same mistake, and
its own tie-backs will not catch it either.
