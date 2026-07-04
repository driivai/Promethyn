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

## Caveats

* The scripted-reference set is ten small, single-function tasks: big enough
  to exercise every metric, far too small to characterise a real judge. Live
  runs use the 48-item `live-v1` set, which was *sized* for a directional
  correlated-vs-independent comparison — but the first live run showed it is
  **too easy to discriminate between judges** (both scored 100%; see Live
  results). A harder judge-eval v2 set is required before the false-PASS
  metric carries weight, and either way a single-run, single-domain
  measurement cannot certify a domain for advisory-only verification.
* Confidence buckets use fixed 0.2-wide edges; with few items per bucket,
  bucket accuracy is noisy. The `unstated` row exists because a judge that
  states no confidence is itself a calibration finding, not an error.
* The scripted reference proves the harness; it can say nothing about any real
  model's judging ability, by design.
