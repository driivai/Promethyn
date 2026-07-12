# gold-set-v3: construction protocol + pilot

The load-bearing claim of the judge work — *an independent-family judge leaks 0%
false-PASS* — currently rests on **0/45** (grounding-v2) and **0/49** (live-v2).
Rule of three hands a hostile reviewer "≤ 6.7%" and "≤ 6.1%" for free, and the
pre-registered power check (`docs/soft-calibration-adoption-rule.md`) shows no
lever can be adopted at these denominators. No lever fixes that. A **larger,
harder gold set** does. This document is the protocol for building it, plus a
20-item pilot that proves the protocol (`benchmarks/gold_pilot_v3.py`).

This sprint does **not** build the whole set. It builds the method and shows it
runs.

## Construction protocol

1. **Item selection.** Each item is `(source, claim, gold_label, category, note)`.
   Sources are short, self-contained, and unambiguous to a careful reader.
   Claims are authored to sit *near* the source's meaning — the paraphrase or
   inference a fluent summarizer produces — not obviously off. Easy controls
   (clearly-supported and clearly-unsupported) anchor the scale so a judge that
   rejects everything pays a measurable false-FAIL price.
2. **Gold-label assignment.** The gold label is a **curated human reference**,
   not an executed program (grounding has no executable truth). It is assigned by
   entailment-by-the-source ONLY: a claim is `supported` iff the source alone
   entails it; outside knowledge, plausibility, and partial support are
   `not-supported`. Every item records its gold **rationale** in `note`.
3. **Who assigns, and disagreement resolution.** Two independent labelers assign
   gold to each item without seeing the other's label. A third adjudicates any
   disagreement; an item that cannot reach a confident, defensible label after
   adjudication is **discarded, not shipped with a coin-flip label** — a
   contested gold label poisons the false-PASS numerator it is supposed to
   define. (The pilot here was authored and self-adjudicated by one author; the
   full set requires the two-labeler + adjudicator process above, and the
   labeling-cost estimate below prices that.)
4. **Firewall.** Grounding eval items are **reference-side only**: they are never
   shown to a proposer and never enter a promotion/training path. So the held-out
   firewall (`assert_disjoint` over train/heldout ids) applies trivially — the
   whole gold set is evaluation, never training. A gold item can never leak into
   the thing it measures.

## Adversarial selection criterion (the load-bearing part)

Items are chosen to be **trap shapes that plausibly slip past an _independent_
judge** — not merely hard for the actor's own family. That distinction is the
whole point: the independent baseline is already at the floor, so the only items
that can move it are ones a *different-family* grader would also wave through.
The trap taxonomy (each named, each with a distinct failure mode):

| category | the trap |
|---|---|
| `unstated-inference` | the conclusion a reasonable reader draws that the source never states (the flagship) |
| `wrong-attribution` (correct-claim-wrong-citation) | a real fact/recommendation attached to the wrong actor or the wrong thing |
| `partial-support` | ~80% grounded, one unstated qualifier or a false half riding along |
| `hedge-stripping` (confident hedging) | a genuinely hedged source stated a shade too confidently |
| `quantifier-drift` | "some/usually" strengthened to "most/always" |
| `near-miss-aggregation` | a derived quantity slightly wrong — catching it needs the arithmetic |
| `scope-creep` | true of a stated subset, asserted of the whole |
| `causation-from-correlation` | adjacency or credit stated as cause |
| `temporal-near-miss` | a time claim wrong only against the source's own frame |
| `negation-flip` | the source's polarity inverted |

Supported items include `entailed-subtle` cases (entailments that require
arithmetic or composition, e.g. "4.2/3.5 = 20%"), so a lazy grader that protects
itself by rejecting everything is caught by the false-FAIL it pays.

## The pilot (20 items, `benchmarks/gold_pilot_v3.py`)

Three sources (a clinic notice, a quarterly note, a survey summary), **14
gold-negative traps + 6 gold-positive** (matching grounding-v2's ~70% negative
ratio so the false-PASS denominator is the majority). Every item carries its gold
rationale. The pilot is **not powered to adopt anything** (see below); it proves
the construction protocol and wires into the existing grounding harness. A real
independent-arm run is an operator dispatch and is **deferred** — no cached
provider is available offline, so per the sprint the labeled items ship and the
run defers.

> **If a live independent-arm run on this pilot surfaces even one false-PASS, that
> is a significant result on its own:** it puts a nonzero numerator under the 0%
> claim and makes the honesty in `docs/judge-quality.md` load-bearing rather than
> decorative. Report it prominently either way.

## Power target — the N this pilot is a down-payment on

From the pre-registered rule's α = 0.05 / power = 0.80 targets
(`docs/soft-calibration-adoption-rule.md`), with grounding's ~70% gold-negative
fraction:

| goal | gold-negative items / arm | ≈ total items |
|---|---|---|
| detect a 5-point correlated effect (11% → 6%) | ≈ 488 | ≈ **700** |
| bound the independent false-PASS floor **< 2%** (0/n, 3/n < 0.02) | > 150 | ≈ **215** |
| bound the floor **< 1%** | > 300 | ≈ **429** |

The **total** column is the gold-negative count divided by the ~0.70 gold-negative
fraction (e.g. `150 / 0.70 = 214 ≈ 215`, `488 / 0.70 = 697 ≈ 700`); the 150 is
rule-of-three (`3/150 = 2%`) and the 488 is the two-proportion power formula. Both
derivations are shown step-by-step in `docs/soft-calibration-adoption-rule.md`
§"Required N".

So the minimum useful build is **≈ 215 items** (to retire the rule-of-three
objection by bounding the floor under 2%); a build that could **adopt** a lever
on a 5-point effect is **≈ 700 items**. The 20-item pilot is ~9% of the smaller
target.

### Labeling cost (stated honestly)

An adversarial grounding item is slow to make: author a self-contained source,
craft a *near-miss* claim that a careful reader can still call, assign gold by
strict entailment, write the rationale, then run it past a second labeler with
adjudication. Estimate **~20–40 minutes per shipped item** end-to-end (the
near-miss crafting and the dual-label/adjudication dominate; easy controls are
faster, flagship `unstated-inference` traps slower).

| build | items | est. labeling effort |
|---|---|---|
| pilot | 20 | ~7–13 h (done) |
| floor < 2% | ~215 | **~72–143 h** |
| adopt 5-pt effect | ~700 | **~230–470 h** |

These are person-hours of expert labeling, not compute. That is the real price of
making the experiment decidable — and it is why the honest recommendation is to
pay it deliberately rather than spend credits on sets that cannot decide
(`docs/soft-calibration.md`, dispatch verdict).
