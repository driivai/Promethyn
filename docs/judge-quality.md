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

```
PROM_PROVIDER=remote PROM_API_BASE=<gateway> PROM_MODEL=<actor-model> \
PROM_JUDGE_MODEL=<judge-model> \
python -m prometheus_protocol.benchmarks.judge_eval --live
```

For the same-model vs different-model comparison, run the eval twice — once
with `PROM_JUDGE_MODEL` equal to the actor's model, once distinct — and compare
the two false-PASS rates. (The bundled candidates are fixed fixtures, so the
per-item attribution split is meaningful in the scripted mode; across live
runs, the config is what varies the actor-judge relationship.)

### Live results

_Not yet recorded. Regenerate with the command above against your provider
config and paste the output here; note the actor model, judge model, and
whether the endpoints differ._

## Caveats

* The bundled eval set is ten small, single-function tasks: big enough to
  exercise every metric, far too small to characterise a real judge. Live runs
  should extend the item set before the numbers are treated as load-bearing.
* Confidence buckets use fixed 0.2-wide edges; with few items per bucket,
  bucket accuracy is noisy. The `unstated` row exists because a judge that
  states no confidence is itself a calibration finding, not an error.
* The scripted reference proves the harness; it can say nothing about any real
  model's judging ability, by design.
