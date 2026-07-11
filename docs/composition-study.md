# Confidence composition: a measured answer (not a formula)

The orchestration runtime records each step's confidence and reports a
chain-level number as the **minimum** along the path — a labelled conservative
*placeholder*, never claimed to be sound (`docs/orchestration.md`). This study
asks the composition question **empirically**:

> Can any rule for combining per-step confidences produce a chain-level number
> trustworthy enough to bear a halt decision — and if so, which, and how wrong
> is it?

The discipline is the one that produced the decorrelation result: **do not
derive the rule, measure it.** Build chains whose final output is
HARD-verifiable, run them, and ask which candidate rule's output best predicts
whether the chain was *actually* correct. A finding of *"no rule is good
enough"* is a valid, valuable result — and it is the result.

Reproduce: `python -m prometheus_protocol.benchmarks.chain_eval` (needs the
isolation runtime). The run is deterministic.

## The instrument

Each chain assembles ONE SQL query from per-step fragments; the assembled query
is executed by the **real HARD `SqlVerifier`** against the reference, and the
chain is CORRECT / INCORRECT by **execution, never a label**. Compounding is
mechanical (a wrong fragment that survives to the assembly makes the executed
query wrong); recovery is mechanical (a later step overwriting the same slot
with the correct fragment repairs the chain). An instrument self-check executes
every reference (must self-verify PASS) and every designed-wrong candidate (must
execute FAIL — no wrong fragment coincidentally equivalent) before any number is
reported.

**Honest disclosure — authored vs. measured.** Every per-step confidence is a
real `VerifierBank` output; every chain verdict is real execution. What is
*authored* (disclosed) is the instrument: the **mix** of chains and the
**fallibility of SOFT steps**. A SOFT step models a fallible model-judge — its
grader ACCEPTS (PASS) the step at its profile confidence whether or not the
fragment is correct, and wrong-but-accepted fragments are injected so each
profile's wrong-rate matches `1 − confidence`. The harness **re-measures** that
calibration and prints it (below), so the per-step signal composition had to
work with is visible, not assumed. Because the dependence structure and base
rate are design choices, these numbers characterise the rules **on this
instrument** — directional (small N), not a natural-workload calibration. That
conditionality is the point: it is *why* no rule can be certified sound.

### The chain set (42 chains, executed ground truth)

```
chains: 42   step-length distribution: N=2:14, N=3:16, N=4:1, N=5:11
ground truth (EXECUTED): correct 34, incorrect 8, abstained/excluded 0
by scenario: all_correct 32/0, compound 0/5, confident_wrong 0/3, recover 2/0
```

Only **8 incorrect chains** — every headline below rests on that denominator, so
every rate is directional. (Failures are rare precisely because well-calibrated
steps rarely fail; buying more failures means either more chains or worse-
calibrated steps. We kept the steps calibrated and the set honest about N.)

### Instrument self-calibration — the per-step signal composition saw

```
profile          steps  wrong  empirical-reliability  profile-confidence
hard_pass          79      0           100.0%              0.950
hard_strong         4      0           100.0%              0.995
hard_weak           1      0           100.0%              0.633
soft_uncal          7      4            42.9%              0.500
soft_075           12      3            75.0%              0.750
soft_0875          16      2            87.5%              0.875
soft_095           16      1            93.8%              0.955
```

Two things to read here. First, the **SOFT** profiles are calibrated by
construction (75.0%↔0.750, 87.5%↔0.875, 93.8%↔0.955) — and the high ones sit
right in the live SOFT false-PASS band (grounding-v2 correlated 11.1%, code
3.9%; `docs/judge-quality.md`). Second — and less obvious — a **HARD** step is
100% reliable at *every* confidence the advisors move it to (0.633, 0.950,
0.995). HARD confidence is not a correctness probability; it is calibration
signal around a verdict that is authoritative anyway. That single fact bends the
whole result, as we will see.

## The candidate rules (hypotheses, in `orchestration/composition.py`)

`min` (the current floor) · `product` (independence) · `mean` · `tier_weighted`
(cap each SOFT step at the measured SOFT reliability ceiling ≈0.889, then
product) · `weakest_link_length` (`min − 0.02·(N−1)`). None is asserted sound;
the measurement decides.

## The measurement

### Calibration (ECE = expected calibration error; lower is better)

| rule | ECE | discrimination (sep) | reads as |
|---|---|---|---|
| `weakest_link_length` | **0.054** | **0.115** | best-calibrated, best-separating |
| `min` | 0.055 | 0.107 | ~tied best |
| `mean` | 0.083 | 0.028 | **cannot separate** correct from wrong |
| `product` | 0.103 | 0.097 | systematically **under-confident** |
| `tier_weighted` | 0.123 | 0.082 | over-discounts |

Discrimination `sep` is the gap between the mean composed value on correct vs.
incorrect chains. **Every rule's separation is small** (≤0.12): the composed
number barely tells correct and incorrect chains apart. `mean` is the extreme —
`sep=0.028`, essentially blind — because it averages a weak link away. `product`
is under-confident because it multiplies HARD confidences (~0.95) as if they were
correctness probabilities, when HARD steps are really ~100% reliable; its
`[0.8,1.0]` bucket is 92.3% correct at a mean composed of only 0.877.

### The dangerous direction — false-confidence, swept over thresholds

The number that decides whether a rule can bear a halt decision: of the chains a
rule scored **≥ θ**, what fraction were **actually incorrect** (`n` = how many
chains cleared θ).

```
rule                θ=0.80 (n)   θ=0.90 (n)   θ=0.95 (n)
min                 12.5% (24)    8.3% (12)    0.0% ( 1)
product              7.7% (13)    0.0% ( 5)    0.0% ( 1)
mean                17.1% (35)   16.0% (25)   14.3% ( 7)
tier_weighted        8.3% (12)    0.0% ( 2)    0.0% ( 1)
weakest_link_length 10.5% (19)   10.0% (10)    0.0% ( 1)
```

Read this carefully, because it is the whole finding:

- At **θ=0.80**, every rule is dangerous. The *best* (`product`, 7.7%) still
  calls ~1 in 13 "high-confidence" chains safe when it is wrong. `mean` is worst
  at 17.1%.
- At **θ=0.90**, `product` and `tier_weighted` reach 0% — but only by clearing
  **5 and 2 chains**. They buy safety with *silence*: they abstain on almost
  everything, which is not "bearing a halt decision," it is declining to.
- Every **0.0%** cell rests on **1–5 chains**. It is the absence of an event in a
  tiny sample, not evidence of safety.
- **`mean` cannot be made safe by raising the threshold** — 14.3% still wrong at
  θ=0.95 — because the failure it hides (one confident-but-wrong step averaged
  against confident-and-right ones) lives *above* any threshold.

### Degradation with chain length (false-confidence rate by N)

```
rule                N=2    N=3    N=4    N=5
min                  0.0%  20.0%    n/a  14.3%
product              0.0%  16.7%    n/a    n/a
mean                10.0%  15.4%   0.0%  27.3%
weakest_link_length  0.0%  20.0%    n/a   0.0%
```

For every rule, false-confidence is ~0 at N=2 and rises with N (cells are sparse
— 1 chain at N=4, few high-confidence failures at N=5 — so this is a trend, not a
curve). Longer chains are exactly where composition is most needed and least
trustworthy.

## The honest conclusion

**Can a composed confidence bear a halt decision? No — not on this evidence.**

1. **No single rule wins.** The best-*calibrated* rule (`weakest_link_length`)
   is not the *safest* (`product`), which is not the most *discriminating*, and
   the differences between them rest on 1–3 chains. The sample cannot rank them.
2. **Even the favourable case fails the bar.** These are calibrated per-step
   inputs and strict mechanical compounding — an *optimistic* setting. Even so,
   the safest rule's false-confidence at a useful threshold is 7.7%, and the rules
   that reach 0% do it by going nearly silent. Autonomously trusting a composed
   number would mean auto-approving a wrong chain on the order of 1-in-13.
3. **Reality is worse than the instrument.** Live per-step confidence is only
   *imperfectly* calibrated (SOFT false-PASS 4–11%, and the correlated arm is
   higher), inter-step errors are correlated in ways this instrument does not
   model, and the base rate here is authored. The real false-confidence would be
   higher than measured, not lower.
4. **The root cause is structural, not a missing formula.** Composition cannot
   manufacture signal the per-step confidences do not carry. When a wrong step
   reports high confidence (the SOFT false-PASS that live measurement already
   found), *every* function of those confidences inherits the miscalibration —
   `mean` hides it, `product` drowns it in HARD under-confidence, `min` only
   catches it when the weak step also *reports* low. A sound composition needs a
   per-step *dependency model* and calibrated per-step *likelihoods* this system
   does not have.

**What we ship.** The `min()` placeholder **stays**, unchanged, in the runtime —
the measurement did not license replacing it, and `min` is (tied) best-calibrated
here while never over-stating trust. The candidate rules ship as **measured
hypotheses** in `orchestration/composition.py`, not as a decision function. No
composed number is wired into the gate.

**What a composed number is allowed to do.** It is a **summary for a human**. It
may only ever make halting **more** conservative — a low composed number is one
more reason to route a step to a person sooner. It can **never** lift a block,
raise a tier, or authorize execution: authority comes only from the gate + HARD
verification + human approval. This is enforced by construction — the
composition module holds no gate/executor capability, and a high composed
confidence provably cannot execute a non-authoritative action (the gate decides
on each action's own judgment; tested in
`tests/conformance/test_composition.py::test_high_composed_confidence_cannot_execute_a_soft_action`).

## Limits and follow-ups

- **Small N (8 incorrect chains).** Directional, not settled — stated everywhere
  above. A larger executed chain set would tighten the error bars, but cannot
  change conclusion (1): a rule that needs a bigger sample to look safe is not
  safe enough to gate on.
- **Authored dependence + base rate.** The instrument is a controlled study, not
  a sampled workload. A natural-workload calibration is the honest next
  instrument — and needs real multi-agent traces with executed outcomes.
- **The unsolved core remains open:** a principled composition needs a
  dependency model between steps and calibrated per-step likelihoods. This study
  bounds *how badly the naive rules fail* and *why*; it does not solve it.
- **Per-step calibration is the higher-leverage fix.** Because composition cannot
  add signal, improving per-step SOFT calibration (lowering false-PASS) would do
  more for chain trust than any composition rule measured here.
