# Lowering SOFT false-PASS: candidate levers and how to measure them

The composition study (`docs/composition-study.md`) proved that composing
per-step confidences **cannot manufacture signal the steps lack** — so lowering
the SOFT judge's own **false-PASS** (the dangerous direction: judge PASSes what
ground truth FAILs) is the highest-leverage path to chain trust. The
independent-family judge is already adopted and proven (`docs/judge-quality.md`).
This document adds *candidate levers* that try to lower false-PASS **further**,
and — critically — the protocol to **measure** each one before adopting it.

**Adopt nothing on faith.** Each lever is an opt-in wrapper that changes nothing
by default. A lever is adopted only if an operator-dispatched live run on the
hardest sets shows it lowers false-PASS without collapsing coverage — and a
finding of *"lever X does not help"* is a valid, expected outcome (see the
honest note at the end, a prediction on record **before** the data).

## The levers (`verifier/soft_levers.py`)

Each is a `Tier.SOFT` wrapper around the existing judge. **A SOFT verdict stays
SOFT** — a lever can only turn a shaky PASS into an ABSTAIN; it never makes a
soft judgment authoritative (tested). Each lever moves ABSTAIN/FAIL to buy a
lower false-PASS; none turns a FAIL into a PASS. Each exposes its model-call
cost.

| lever | rule | cost | knobs |
|---|---|---|---|
| `baseline` | the plain independent judge (comparison point) | 1× | — |
| `threshold` | accept a PASS only at stated confidence ≥ θ, else ABSTAIN | 1× | `--min-confidence` |
| `ensemble` | N independent judges; **unanimity** to PASS, else ABSTAIN/FAIL | N× | `PROM_JUDGE_MODELS`, `--on-disagreement` |
| `k-sample` | same judge k times; majority/unanimity to PASS | k× | `--k`, `--require`, `PROM_JUDGE_TEMPERATURE` |
| `adversarial` | elicit the strongest case AGAINST, then re-decide | 2× | — |

Cost is not free: a lever that halves false-PASS at 3× the model calls is a
tradeoff, not a win. The driver prints the exact call count per run.

## How it is measured (the existing harness, unchanged)

The driver `benchmarks/soft_calibration_eval.py` **reuses**, byte-for-byte: the
item sets (`live_items_v2`, `grounding_items_v2`), the fixture-tested metric fold
`judge_eval.compute_metrics`, and the report renderers. Only the *judge* is
wrapped with the selected lever, so every number is directly comparable to the
recorded baselines. It reports, per lever: **false-PASS** (the number that
matters), false-FAIL, ABSTAIN rate, agreement, the **surviving denominator**,
the per-trap-category breakdown (grounding), and the model-call cost.

Use the **hardest** sets — grounding-v2 (64 items; 45 gold NOT-SUPPORTED = the
false-PASS denominator) and live-v2 (82 items) — because easy sets ceiling out
and cannot discriminate (the v1 lesson).

### Fixture-verified before live

Every lever's aggregation arithmetic is proven offline on scripted judge outputs
with hand-computed expected verdicts/confidences
(`tests/conformance/test_soft_levers.py`), so the measurement is trustworthy
before a single credit is spent. The offline driver mode is a deterministic
**plumbing smoke** (a scripted judge), not a judge measurement.

## The exact operator dispatch (spends credits — run outside the build env)

Set the provider once (neutral placeholders — the model-id mapping stays out of
the repo; `<judge-model-A>` and `<judge-model-B>` must be **independent
families** from `<actor-model>` and from each other):

```
export PROM_PROVIDER=remote
export PROM_API_BASE=<endpoint>
export PROM_API_KEY=<key>
export PROM_MODEL=<actor-model>          # candidates' author (actor family)
export PROM_JUDGE_MODEL=<judge-model-A>  # independent judge (already-proven baseline)
```

Run each lever on **both** hardest sets (swap `--item-set grounding-v2` ↔
`--item-set live-v2`):

```
# 0. baseline (the comparison point)               cost 1×  (64 / 82 calls)
python -m prometheus_protocol.benchmarks.soft_calibration_eval --live \
    --item-set grounding-v2 --lever baseline

# 1. confidence threshold                          cost 1×  (64 / 82 calls)
python -m prometheus_protocol.benchmarks.soft_calibration_eval --live \
    --item-set grounding-v2 --lever threshold --min-confidence 0.8
#   (repeat at --min-confidence 0.7 and 0.9 to trace the false-PASS/coverage curve)

# 2. ensemble of two independent judges            cost 2×  (128 / 164 calls)
PROM_JUDGE_MODELS=<judge-model-A>,<judge-model-B> \
python -m prometheus_protocol.benchmarks.soft_calibration_eval --live \
    --item-set grounding-v2 --lever ensemble --on-disagreement abstain

# 3. self-consistency / k-sampling  (REQUIRES temp>0) cost 3×  (192 / 246 calls)
PROM_JUDGE_TEMPERATURE=0.7 \
python -m prometheus_protocol.benchmarks.soft_calibration_eval --live \
    --item-set grounding-v2 --lever k-sample --k 3 --require majority

# 4. adversarial self-check                        cost 2×  (128 / 164 calls)
python -m prometheus_protocol.benchmarks.soft_calibration_eval --live \
    --item-set grounding-v2 --lever adversarial
```

Both arms of the correlated-grader comparison still apply: to measure a lever
against the *correlated* baseline, set `PROM_JUDGE_MODEL=<actor-model>` (judge =
actor family); against the *independent* baseline, keep them distinct. The
already-recorded independent baseline is grounding-v2 false-PASS **0/45** and
live-v2 near-**0** — that is the bar a lever must beat, and it is already at the
floor.

## Honest bars (read before believing any number)

- **Tiny denominators.** grounding-v2's false-PASS denominator is 45; live-v2's
  is smaller still. Report **direction, not precise effect size**.
- **Rule of three.** An observed **0/n** false-PASS bounds the true rate only at
  **≤ 3/n** (95%): 0/45 means "≤ ~6.7%", *not* "0%". No lever "eliminates"
  false-PASS — that claim is unprovable at this N.
- **The silence trap** (from the composition study): a lever that reaches a low
  false-PASS by ABSTAINing on most items has not improved the judge — it has
  gone quiet. Always read the **surviving PASS denominator and the ABSTAIN
  rate** next to the false-PASS number. A threshold that cuts false-PASS to 0 by
  refusing to decide 60% of items is abstention, not calibration.
- **Single run, small set.** Directional, exactly as the recorded baselines are.

## The honest note — a prediction on record, before the data

I expect most of these levers to help little **on the independent baseline**,
for a structural reason: the independent judge is already at ~0% false-PASS on
these sets (a floor), and the false-PASSes that remain are **systematic**
(the model genuinely misreads a subtle trap), not variance-driven. Composition
could not fix that; neither can most of these levers. Specifically:

- **`k-sample` — expect no meaningful help (often a literal no-op).** At
  temperature 0 the k samples are *identical*, so majority-of-k is the single
  reply (the driver warns). Even at temperature > 0, a judge that systematically
  misreads a trap draws *correlated* wrong samples — repeated sampling averages
  noise, not bias. It pays k× for variance reduction where the error is bias.
  Predicted to be the weakest lever.
- **`threshold` — expect a small cut of the LOW-confidence false-PASSes only,
  at a coverage cost.** It cannot touch a *confident* false-PASS (the dangerous
  ones — the judge is sure and wrong), and it withholds correct low-confidence
  PASSes too. Net: false-PASS down a little, ABSTAIN up, denominator shrinks —
  watch the silence trap. Useful mainly as a routing knob, not a fix.
- **`ensemble` of independent families — the most likely to help *where there
  is headroom*, but plausibly net-negative on the already-at-floor independent
  baseline.** Two *independent* judges' systematic errors are less correlated
  than one judge's repeated samples, so unanimity removes the false-PASSes where
  the families disagree — a real gain on the *correlated* arm or a harder future
  set. But it pays 2×+ and raises false-FAIL/ABSTAIN (any dissent blocks a PASS),
  and the independent baseline is already ~0% false-PASS: there is no false-PASS
  left to remove, so on *that* arm the lever is likely pure cost and lost
  coverage. (An independent forecaster in this sprint's adversarial review
  predicted ensemble **net-negative** outright on the floor set; I rate it
  best-of-the-four only conditional on headroom. Either way, bounded by
  rule-of-three — measure both arms before believing it.)
- **`adversarial` self-check — plausibly helps on the exact trap shapes,**
  because it forces the judge to articulate the failure mode a careless pass
  skips; but it risks *raising false-FAIL* (talking itself out of correct
  PASSes) and costs 2×. Direction genuinely uncertain — precisely why it must be
  measured, not assumed.

If the live runs bear this out, the adopted set stays **independent judging
only**, with `ensemble` and `adversarial` as measured-optional tighteners for
high-stakes routing — and `k-sample`/`threshold` recorded as *measured and not
worth their cost*. Whatever the data says, **default behaviour does not change in
this PR**: adoption is a separate, measurement-gated decision.

## Invariants (tested)

- **SOFT stays SOFT.** Every lever emits `Tier.SOFT`; a lever's PASS, however
  confident, yields a non-authoritative bank judgment that the gate **blocks**
  (`test_soft_levers.py::test_soft_stays_soft_no_lever_grants_authority`).
- **Default unchanged.** The production judge path (`model_judge.py`,
  `grounding.py`), the read-only harness (`judge_eval.py`, `grounding_eval.py`),
  and the Hearth are byte-identical to main; the new `judge_temperature` knob
  defaults to 0 (byte-identical request payload).
- **Fixture-verified arithmetic.** Every lever's aggregation is proven on
  scripted inputs before any live use.
