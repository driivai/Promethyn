# Doctrine

The numbered doctrines this repository's guards and tracker cite. **Until this
file, they were cited and never enumerated** — `docs/OPEN-GAPS.md` recorded
that on 2026-09-17 under G44 ("there is no doctrine file in this repository"),
and the sprint that recorded it declined to reconstruct one from scattered
references. This file does not reconstruct them either. It does two things:

1. **Indexes every doctrine number the tree cites**, with where each is first
   cited, so a reader who meets "doctrine #8" can find the usage that defines
   it. The index is derived from the tree by
   `tests/conformance/test_doctrine_index.py`, which refuses a cited number this
   file does not index and an indexed number the tree never cites. Numbers with
   no citation are listed as such rather than invented.
2. **Records, in full, each doctrine written down from now on.** The first is
   #11, below. A doctrine added here is stated here; a doctrine that exists only
   as citations stays a citation until someone writes it down deliberately.

## Index of cited numbers

Re-measured 2026-09-18 (was 2026-09-17) over `docs/`, `src/`, `tests/`,
`scripts/` and `.github/`, by the derivation the test runs, which also PINS the
citation count per number exactly: a new citation anywhere reddens
`test_doctrine_index.py` until this table is re-measured, so the numbers here
are never a remembered snapshot (doctrine #11). "First cited" is the earliest
line in path order, not the origin.

**What moved on 2026-09-18 and why.** `docs/assurance-ledger-sprint-0.md` and
`tests/conformance/test_assurance_ledger_limits.py` arrived, citing #4, #5, #8,
#9, #10 and #11; the gate refused the un-re-measured table first, which is the
behaviour this pin is for. Two rows changed their "first cited" cell as a
consequence of path order alone — `assurance-ledger-sprint-0.md` sorts before
`live-state-pinning-design.md`, so #10 and #11 now point at the new document
rather than at their origins. That is what "earliest line in path order, not the
origin" means, and the earlier cells were `docs/live-state-pinning-design.md:187`
and this file.

**Re-measured again on 2026-09-18 (G56 and Sprint 1).** Counts moved for #1,
#4, #8, #10 and #11; #11's "first cited" moved to `docs/OPEN-GAPS.md:5191`
because that file sorts before the sprint documents and now carries a citation
of its own. The location column moved without the count column moving for #2
(`:2852` → `:2858`) — the same unchecked column corrected below, drifting again
with the lines above it.

**And a correction the pin could not make.** Row #2's "first cited" read
`docs/OPEN-GAPS.md:2782`; the derivation puts it at `docs/OPEN-GAPS.md:2852`. The
count column is pinned and was right; the *location* column is checked by
nothing, so it drifted seventy lines and no test could say so. Corrected here.
That is doctrine #10's own shape inside doctrine #11's own table — a claim about
existing behaviour, carrying a file and line, that was never re-read.

| # | citations | first cited | the usage, in one line |
|---|---|---|---|
| 1 | 20 | `docs/OPEN-GAPS.md:1315` | `Unavailable` is first-class: absence of an answer is a value, never a default |
| 2 | 10 | `docs/OPEN-GAPS.md:3020` | refused, not degraded: a state the guard cannot establish is written as a refusal, not a clean one |
| 3 | 0 | — | never cited in the tree |
| 4 | 38 | `docs/OPEN-GAPS.md:358` | every negative has a positive control |
| 5 | 23 | `docs/OPEN-GAPS.md:14` | a named gap is a passing test, so it cannot erode quietly |
| 6 | 0 | — | never cited in the tree |
| 7 | 0 | — | never cited in the tree |
| 8 | 59 | `docs/OPEN-GAPS.md:2096` | an empty instrument reads downstream as a pass, so emptiness refuses |
| 9 | 10 | `docs/OPEN-GAPS.md:47` | re-sweep documentation claims when the code they describe changes |
| 10 | 9 | `docs/assurance-ledger-sprint-0.md:18` | a claim about existing behaviour carries a file and line, or is marked UNVERIFIED |
| 11 | 23 | `docs/OPEN-GAPS.md:5353` | counts come from the artifact, never from a filtered view of it (below) |

The one-line usages for #1–#10 are paraphrases of how the citations use each
number; they are not the doctrines' text, which was never written down. Where
a citation and this paraphrase disagree, the citation is the record.

## Doctrine #11 — counts come from the artifact

> Any count that enters a report, a pin, or a tracker comes from the ARTIFACT,
> never from a filtered view of it. A filter applied before counting narrows
> the population silently, and a narrowed population is indistinguishable
> downstream from a smaller one. Where a filter is unavoidable, the count and
> the filter are reported together and the unfiltered total is reported beside
> it.

**Why it was written down.** A reader-runner row count was published as 5 when
the runner had 6 rows. The number came from the runner's log read through a
case-sensitive filter, which dropped the one row whose label began with a
capital letter, and the report's own corrections section repeated it. That was
the eighth appearance of the class in this repository — a count derived from a
narrowed view of the thing counted, found each time by a person probing and
never by a guard. The sweep that followed, its sites and their measured deltas,
are OPEN-GAPS G53; the per-version count gap it exposed is G54.

**What it demands, concretely.**

* A report says how many rows a runner has because the runner printed
  `rows: N` from its own table, not because someone counted matching lines.
* A per-module count that is derived by matching a module name is tied back to
  the total in the same step (`assert sum(per_module) == len(cases)`), so a
  member the matcher cannot see is a red line and not a quiet shortfall.
* A tool that skips what it cannot read says so beside its count: "435 files
  scanned of 437 candidates; 1 excluded by design; 1 unreadable" is a count;
  "435 files scanned" is a narrowed one.
* A floor (`> 100`) over a filtered population is not a pin. The exact count is.

**What it does not claim.** A count from the artifact can still be a count of
the wrong thing; the doctrine is about the reading, not the choice of what to
read. And "the artifact" is the thing that produced the number, not a second
filtered view with a different filter — two filters that agree prove that they
agree.
