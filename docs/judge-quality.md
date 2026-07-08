# Judge quality: measured, not asserted

The soft `ModelJudgeVerifier` is an advisor: the bank calibrates it against the
authoritative HARD reference and it never decides a verdict. But its *real*
quality — how often it agrees with ground truth, how often it passes what the
reference fails, whether its stated confidence means anything — had never been
measured. This document records the methodology and the reference results of
the judge-quality evaluation harness, and how to regenerate both.

Two design facts make the measurement trustworthy:

* **Read-only by construction.** The harness
  (`prometheus_protocol/benchmarks/judge_eval.py`) never imports the verifier
  bank, any trust store, or the ledger. Verifiers are invoked directly and
  their evidence is folded into metrics in memory. Running an evaluation
  creates no calibration samples, no trust rows, and no ledger rows —
  evaluation is not experience. (Tested: a run against a pre-existing trust
  store leaves the file byte-identical.)
* **Production judge semantics untouched.** Confidence is elicited with an
  evaluation-only judge prompt that keeps the same one-word verdict contract;
  the strict first-word verdict parser is unchanged, and the confidence is read
  from the raw reply the judge already carries in `Evidence.detail`.

## Metrics and their denominators

Ground truth is the HARD subprocess verifier executing each candidate against
hidden cases inside the mandatory isolating sandbox. Items whose reference
verdict is ABSTAIN carry no ground truth and are excluded from every rate. The
judge's own ABSTAINs are counted and reported, but excluded from the agreement
and error denominators — an abstain is "no opinion", not a wrong opinion.

| metric | definition |
|---|---|
| agreement | judge verdict == reference verdict, over items the judge decided |
| false-PASS rate | judge PASS over items the reference FAILed (and the judge decided) |
| false-FAIL rate | judge FAIL over items the reference PASSed (and the judge decided) |
| calibration | stated confidence, bucketed at 0.2 intervals, vs actual correctness |
| actor-identity split | all of the above, split by whether the candidate is attributed to the judge's own model |

**False-PASS is the dangerous direction.** In the code domain the HARD verifier
outranks the judge, so a judge false-PASS costs nothing today. In Milestone C
domains without a hard backstop, the false-PASS rate is exactly the rate at
which a bad candidate would get through an advisory-only panel — it is the
number to watch, and the reason judge independence is foundational.

A false-FAIL costs useful work but is the safe direction. Rates whose
denominator is empty are reported as `-`, never as a fake 0%.

## Reference run (offline, scripted)

The default mode uses a deterministic scripted judge with deliberate,
hand-placed disagreements: two false-PASSes (one overconfident), one
low-confidence false-FAIL, one abstain, and one verdict without a stated
confidence. Every number below is hand-checkable and bit-for-bit reproducible;
this run validates the **harness**, not any real judge. Regenerate with:

```
python -m prometheus_protocol.benchmarks.judge_eval
```

Output (verbatim):

```
# Judge-quality evaluation (offline scripted reference)

judge model : scripted-judge
items       : 10
with authoritative reference : 10
judge decided : 9  |  judge abstained : 1

| metric | value |
|---|---|
| agreement (of decided) | 6/9 = 66.7% |
| false-PASS (judge PASS where reference FAIL) | 2/4 = 50.0% |
| false-FAIL (judge FAIL where reference PASS) | 1/5 = 20.0% |

## Calibration (stated confidence vs correctness)

| confidence | n | correct | accuracy |
|---|---|---|---|
| [0.00, 0.20) | 0 | 0 | - |
| [0.20, 0.40) | 1 | 0 | 0.0% |
| [0.40, 0.60) | 2 | 1 | 50.0% |
| [0.60, 0.80) | 1 | 1 | 100.0% |
| [0.80, 1.00] | 4 | 3 | 75.0% |
| unstated | 1 | 1 | 100.0% |

## Actor-identity split (correlated-grader signal)

| slice | decided | agreement | false-PASS | false-FAIL |
|---|---|---|---|---|
| same model as judge | 5 | 3/5 = 60.0% | 2/3 = 66.7% | 0/2 = 0.0% |
| different model | 4 | 3/4 = 75.0% | 0/1 = 0.0% | 1/3 = 33.3% |
```

The scripted split deliberately encodes the correlated-grader failure mode
(the judge "favouring" candidates attributed to its own model), proving the
split arithmetic surfaces it. Whether a real judge exhibits it is an empirical
question the live procedure below answers.

## Live procedure

Real judge quality comes from a live provider config. The judge model is
independently configurable from the actor's (`PROM_JUDGE_MODEL`, and
optionally `PROM_JUDGE_API_BASE` / `PROM_JUDGE_API_KEY` for a fully
independent grading endpoint). When the judge and actor share a model, the
runtime logs a one-line correlated-grader notice rather than staying silent.

Live runs default to the **harder discriminating set**
(`benchmarks/live_items_v2.py`, version `live-v2`, 82 items), built after
`live-v1`'s ceiling effect: its plausible-but-wrong candidates are the subtle
kind a competent judge can miss (boundary operators inside merge conditions,
zip truncation, sentinel filters that eat legitimate data, banker's-rounding
traps, keep-first-vs-keep-last and stability violations, standard-library
parsing surprises). Composition: 31 correct (including two
correct-but-suspicious-looking idioms as false-FAIL bait), 45
subtle-plausible-wrong, 6 clearly-wrong controls; 31 PASS / 51 FAIL.
Validated in-sandbox on 2026-07-04: all 82 items authoritative, zero abstains.
The earlier `live-v1` set (48 items; 16 PASS / 32 FAIL, validated 2026-07-02)
stays committed and selectable via `--item-set live-v1` (a workflow input on
the live dispatch). Ground truth for both sets is decided by the HARD verifier
executing every candidate in the sandbox — never hand-labelled; design-intent
categories are documentation, not authority.

The two-run comparison (report both, side by side):

```
# RUN A — correlated: the judge shares the actor's model.
#         The correlated-grader notice fires; capture it.
PROM_PROVIDER=remote PROM_API_BASE=<gateway> PROM_API_KEY=<key> \
PROM_MODEL=<actor-model> \
python -m prometheus_protocol.benchmarks.judge_eval --live

# RUN B — independent: the judge runs on a distinct model.
PROM_PROVIDER=remote PROM_API_BASE=<gateway> PROM_API_KEY=<key> \
PROM_MODEL=<actor-model> PROM_JUDGE_MODEL=<judge-model-A> \
python -m prometheus_protocol.benchmarks.judge_eval --live
```

Name models in this report by NEUTRAL identifiers only (`actor-model`,
`judge-model-A`); keep the identifier-to-model mapping in the operator's env
or private notes, never in the repo. Record the run date, the item-set
version, whether the two models were genuinely distinct (and whether they are
from different families — a same-family pair weakens the decorrelation
result), and the approximate model-call count (one judge call per item per
run). If a run is truncated, report the actual N — never extrapolate. All 48
items carry the neutral `bundled-fixture` attribution (no live actor produced
them), so the per-item actor-identity split is intentionally not meaningful in
live runs; the correlated-vs-independent signal is the *across-run* comparison.

### Live results — first run, 2026-07-04 (pipeline validation)

**One-line honest summary: the live measurement pipeline works end-to-end; the
numbers themselves say nothing yet — both judges scored 100% on every axis, so
the item set was too easy to tell a correlated judge from an independent one.**

Provenance: dispatched via the `judge-eval-live` workflow on hosted runners
(open egress); the auth preflight passed and both runs completed. Item set
`live-v1` (48 items); ground truth HARD-verified in the real sandbox — 48/48
authoritative (16 PASS / 32 FAIL), zero reference abstains. The actor and the
judge were genuinely distinct open-weight models **from different families**,
named here only by the neutral identifiers `actor-model` and `judge-model-A`
(the mapping lives in the operator's dispatch inputs, not in this repo).
Approximate cost: one judge call per item per run, ~96 calls total plus one
preflight request. (A first attempt on 2026-07-02 was blocked on credentials —
see history — and was resolved by running through the repo-secret workflow.)

**Run A — correlated (judge shares the actor's model, `actor-model`):**

| metric | value |
|---|---|
| judge decided / abstained | 48 / 0 |
| agreement (of decided) | 48/48 = 100.0% |
| false-PASS (judge PASS where reference FAIL) | 0/32 = 0.0% |
| false-FAIL (judge FAIL where reference PASS) | 0/16 = 0.0% |

| confidence | n | correct | accuracy |
|---|---|---|---|
| [0.00, 0.20) | 0 | 0 | - |
| [0.20, 0.40) | 1 | 1 | 100.0% |
| [0.40, 0.60) | 0 | 0 | - |
| [0.60, 0.80) | 0 | 0 | - |
| [0.80, 1.00] | 44 | 44 | 100.0% |
| unstated | 3 | 3 | 100.0% |

**Run B — independent (distinct judge model, `judge-model-A`):**

| metric | value |
|---|---|
| judge decided / abstained | 47 / 1 |
| agreement (of decided) | 47/47 = 100.0% |
| false-PASS (judge PASS where reference FAIL) | 0/31 = 0.0% |
| false-FAIL (judge FAIL where reference PASS) | 0/16 = 0.0% |

| confidence | n | correct | accuracy |
|---|---|---|---|
| [0.00, 0.20) | 0 | 0 | - |
| [0.20, 0.40) | 0 | 0 | - |
| [0.40, 0.60) | 0 | 0 | - |
| [0.60, 0.80) | 0 | 0 | - |
| [0.80, 1.00] | 45 | 45 | 100.0% |
| unstated | 2 | 2 | 100.0% |

**False-PASS delta (the decorrelation metric): Run A 0.0% vs Run B 0.0% —
delta 0.0 points.**

#### Interpretation

*What was proven.* The full live pipeline works end-to-end: repo-secret
credentials, runner egress, the harness, both models, both runs, and real
sandboxed HARD ground truth. This run is a **pipeline validation**.

*What was NOT proven.* Nothing about decorrelation. Both judges scored 100% on
every axis, so there is no false-PASS delta to interpret — a **ceiling
effect**. The `live-v1` set is insufficiently difficult to discriminate
between judges: its plausible-but-wrong candidates were caught by both, so the
metric cannot separate correlated from independent grading at this difficulty.
A 0.0% false-PASS rate here is uninformative, not reassuring — it bounds
nothing about how either judge behaves on candidates hard enough to fool a
grader.

*The one genuine finding.* The independent judge's abstain rate was 1/48: its
output parsed cleanly under the strict one-word verdict contract, so the
earlier concern that a reasoning-styled judge would wrap its verdicts
unparseably did not materialize.

*Honest caveat.* These numbers support **no** claim about judge quality,
decorrelation value, or domain readiness. A harder item set (judge-eval v2) is
required before the false-PASS metric is meaningful. It remains possible that
even with harder items the code-domain delta is ~0 — that would itself be a
real finding, and it would be recorded the same way.

*Load-bearing-ness.* N=48, single run per arm, pipeline-validation only.

### Live results — live-v2 (both arms), 2026-07-04

**One-line honest summary: on the discriminating set, the independent-family
judge let zero bad candidates through while the correlated judge passed two —
the first live evidence of the correlated-grader blind spot — with a clear
direction but small-sample, directional magnitudes.**

Provenance: dispatched via the `judge-eval-live` workflow; both arms completed
as **independent parallel jobs** (the workflow was split after an earlier
dispatch's shared 30-minute timeout cancelled the slow independent arm — that
partial dispatch's completed correlated arm is cited under run-to-run variance
below). Item set `live-v2` (82 items; 31 PASS / 51 FAIL); ground truth
HARD-verified in the real sandbox, authoritative on every judged item. The
actor and the judge were genuinely distinct open-weight models **from
different families**, named here only as `actor-model` and `judge-model-A`
(the mapping lives in the operator's dispatch inputs, not in this repo).
Approximate cost: ~164 judge calls across both arms.

**Run A — correlated (judge shares the actor's model, `actor-model`):**

| metric | value |
|---|---|
| judge decided / abstained | 82 / 0 |
| agreement (of decided) | 80/82 = 97.6% |
| false-PASS (judge PASS where reference FAIL) | 2/51 = 3.9% |
| false-FAIL (judge FAIL where reference PASS) | 0/31 = 0.0% |
| calibration, high-confidence bucket [0.80, 1.00] | 77/79 correct |

**Run B — independent (distinct-family judge, `judge-model-A`):**

| metric | value |
|---|---|
| judge decided / abstained | 80 / 2 |
| agreement (of decided) | 76/80 = 95.0% |
| false-PASS (judge PASS where reference FAIL) | 0/49 = 0.0% |
| false-FAIL (judge FAIL where reference PASS) | 4/31 = 12.9% |
| calibration, high-confidence bucket [0.80, 1.00] | 73/77 correct |

(Full per-bucket calibration tables are in each arm's Actions log.)

**False-PASS delta: Run A 3.9% vs Run B 0.0%.**

#### Interpretation

*The finding.* The independent-family judge produced **zero false-PASSes** in
this run, against the correlated judge's ~3.9% — measured decorrelation in
the code domain, and the first live evidence that a model grading its own
family's output has a blind spot for that output's mistakes. This overturns
the v1 ceiling-effect null: the harder live-v2 set discriminated, exactly as
it was built to.

*The error-profile shift (the more important framing).* This is **not**
simply "the independent judge is better" — its agreement is actually lower
(95.0% vs 97.6%). It traded false-PASS for false-FAIL: 0% false-PASS but
12.9% false-FAIL, against the correlated judge's 3.9% false-PASS and 0%
false-FAIL. The independent judge is *stricter*: it let no bad code through —
the safety-critical direction — at the cost of over-rejecting some good code.
For a grounding judge that trade is favorable: a false-PASS means bad code
passes (the dangerous error); a false-FAIL means good code gets a second look
(the safe one). Independence shifted the error mass toward the safe side.

*Caveats — read these with the finding, not after it.*

* **Small sample.** The false-PASS denominators are ~50, so a two-item swing
  moves the rate ~4 points. The *same* correlated config measured 7.8% on one
  dispatch and 3.9% on the next — live-model run-to-run variance at exactly
  the scale of the effect. These percentages are **directional, not
  precise**: the honest statement is that the independent judge's false-PASS
  was zero *in this run* and the direction of the shift is safety-favorable —
  not that independence "halves" or "eliminates" anything.
* **B abstained on 2 items** (mild reasoning-format parse loss at harder
  items), so its false-PASS denominator is 49, not 51.
* **Single run per arm, N=82, one model pair.** Not domain certification.

*What this supports.* Defaulting real runs to an independent-family judge is
now evidence-supported rather than merely principled. And the correlated
judge's non-zero false-PASS is a concrete floor under the rule that a
self-grading soft judge cannot bear much unbacked authority.

*What this does not support.* Any precise effect size; any claim of domain
readiness; or weakening, let alone dropping, the HARD backstop. In this
domain the backstop caught what both judges are for — that is why these
numbers could be measured at all.

## Live grounding admissions — grounding-v1 (both arms), 2026-07-08

**One-line honest summary: zero false-PASS on both arms across all 26
grounding traps — the judges did not leak on grounding-v1 — but with both
arms perfect on the dangerous direction the set has not yet been shown to
discriminate (the SQL-v1 / live-v1 pattern), so the number is directional;
and either way a clean soft verdict stays advisory: the gate blocks
soft-only authority by construction.**

Provenance: dispatched via the `judge-eval-live` workflow on `main` with
`item_set=grounding-v1`; both arms completed. Item set `grounding-v1`
(44 gold-labeled items; 18 supported / 26 not-supported traps across ten
families). The reference here is the **curated gold label, not an executed
program** — the domain's defining difference (see `docs/domains-grounding.md`);
nothing was sandbox-verified because nothing is executable. The actor and the
independent judge were genuinely distinct open-weight models **from different
families**, named here only as `actor-model` and `judge-model-A` (the mapping
lives in the operator's dispatch inputs, not in this repo). Approximate cost:
~88 judge calls across both arms.

**Run A — correlated (judge shares the actor's model, `actor-model`):**

| metric | value |
|---|---|
| judge decided / abstained | 44 / 0 |
| agreement (of decided) | 44/44 = 100% |
| false-PASS (judge SUPPORTED where gold NOT-SUPPORTED) | 0/26 = 0.0% |
| false-FAIL (judge NOT-SUPPORTED where gold SUPPORTED) | 0/18 = 0.0% |

**Run B — independent (distinct-family judge, `judge-model-A`):**

| metric | value |
|---|---|
| judge decided / abstained | 44 / 0 |
| agreement (of decided) | 41/44 = 93.2% |
| false-PASS (judge SUPPORTED where gold NOT-SUPPORTED) | 0/26 = 0.0% |
| false-FAIL (judge NOT-SUPPORTED where gold SUPPORTED) | 3/18 = 16.7% |

**False-PASS delta: Run A 0.0% vs Run B 0.0% — no delta; both arms were
clean on the dangerous direction.**

Per-trap-category: with zero false-PASSes overall and zero abstains, **every
trap family was fully caught by both arms** — number-drift (4), swapped-entity
(4), over-generalization (3), source-silent (3), unstated-causation (3),
wrong-fact (3), negation-flip (2), temporal-overreach (2), aggregation-error
(1), hedge-to-assertion (1). Run B's three false-FAILs all fell on supported
claims in the `paraphrase`/`stated` categories (the two-fact `combination`
items all passed on both arms).

#### Interpretation

*The finding.* **0% false-PASS on both arms** on the grounding-v1 traps: the
soft grounding judge did not leak on these faithfulness cases — not the
correlated configuration, not the independent one. Against the pre-committed
review bands from the grounding change (≤2% grant-with-backstop / ~5%
advisory / >5% defer), this lands in the **grant-with-backstop** band — where
"backstop" in this domain is not a policy knob but the structure itself: the
human review that was already mandatory stays mandatory.

*The ceiling caveat — read it with the finding, not after it.* Both arms
scoring perfectly on the dangerous direction is exactly what a
**non-discriminating set** looks like: SQL-v1's first reliability run and the
live-v1 judge eval showed the same flattering ceiling before harder items
were built. So "0% false-PASS" here is **directional** — *these judges did
not leak on these 44 items* — and not a settled domain-quality claim. The
statistics say the same thing: 0/26 bounds the true trap false-PASS rate
below only ~11.5% at 95% confidence (rule of three), the bound
`docs/domains-grounding.md` committed to **before** the run. A harder
grounding set (grounding-v2: subtler traps, longer sources, multi-claim
composites) is required before this number is load-bearing. Note also what a
ceiling costs us: with both arms at zero, this run carries **no evidence
either way about a correlated-grader blind spot in grounding** — the set
cannot separate the arms it does not stress.

*The error-profile note.* The independent judge was **stricter**: 16.7%
false-FAIL (three supported claims rejected) against the correlated arm's
0%, at lower agreement (93.2% vs 100%). That is the same safety-favorable
profile the code domain measured on live-v2 — error mass on the over-reject
side (good claims get a second look) rather than the pass-bad side. In a
domain whose only backstop is a human, a strict advisor is the right kind of
wrong.

*The structural point (the thesis).* Even at 0.0% false-PASS on both arms,
the grounding verdict is **SOFT and advisory, and the gate blocks it from
autonomous authority by construction** — a good number does not and cannot
promote a soft verdict. The harness itself prints this under every report,
and it is worth recording verbatim:

> Gold labels are a curated human reference — not executable truth. This
> measurement bounds the judge's advisory weight; it does not and cannot
> grant authority: soft-only judgments remain non-authoritative and the gate
> blocks them regardless of these numbers.

The measurement informs how much *advisory* weight the judge's flags and
triage ordering deserve; it never unlocks authority where truth is not
executable. Changing that would take a new named invariant in `spec/`, not a
clean dispatch.

*Load-bearing-ness.* N=44, a single run per arm, one model pair, one item
set. This validates the grounding measurement pipeline end to end on live
models and gives a directional admissions read; it is **not** domain
certification, and it does not make "grounding is solved" a supportable
sentence — a possibly-easy set reporting 0% is reported here as exactly
that.

## Caveats

* The scripted-reference set is ten small, single-function tasks: big enough
  to exercise every metric, far too small to characterise a real judge. Live
  runs use the 48-item `live-v1` set, which was *sized* for a directional
  correlated-vs-independent comparison — but the first live run showed it is
  **too easy to discriminate between judges** (both scored 100%; see Live
  results). The harder `live-v2` set was built in response and **did
  discriminate** (see the live-v2 results). Either way, a single-run,
  single-domain measurement cannot certify a domain for advisory-only
  verification.
* Confidence buckets use fixed 0.2-wide edges; with few items per bucket,
  bucket accuracy is noisy. The `unstated` row exists because a judge that
  states no confidence is itself a calibration finding, not an error.
* The scripted reference proves the harness; it can say nothing about any real
  model's judging ability, by design.
