# The grounding domain: the first step past executable truth

Code and SQL close the loop because a HARD verifier exists: run the thing,
compare against reality, and the verdict is ground truth. Grounding — *does
this claim actually follow from this source?* — is the first domain where
that is impossible. There is no program whose output decides it. This
document records what was built, what was measured, and the structural
finding: **what this architecture does when there is no hard verifier**.

## Why grounding first (the gentle entry)

Grounding is deliberately the *smallest* step into non-executable truth: a
reference judgment still EXISTS — a person can read source and claim and say
supported or not — it just is not executable. That gives the domain exactly
one new hard property (no HARD verifier at runtime) while keeping the thing
that makes honest measurement possible: a gold-labeled reference to measure
the soft judge against. Fully contested domains ("is this *good*?") have no
such reference and are deliberately not attempted here.

**Ground truth in this domain is a curated human label, not a program.** The
gold labels in `benchmarks/grounding_items.py` are the reference the judge is
measured against; they are reviewable, disputable, and human — and that is
the point, not a flaw to hide.

## The verifier: SOFT by construction, ABSTAIN by discipline

`GroundingVerifier` (`verifier/grounding.py`) asks a model judge, through the
provider boundary, whether a CLAIM is fully supported by a SOURCE alone —
entailment only; outside knowledge and plausibility explicitly excluded. It
emits **`Tier.SOFT` Evidence and can never emit anything else**: it executes
nothing, so it can testify to nothing. The verdict vocabulary is the
domain's (`SUPPORTED` / `NOT-SUPPORTED` / `ABSTAIN`), parsed with the same
strictness as the code judge: first token of the first non-empty line, and
anything unrecognised — prose, `unsupported`, a bare `NOT` — is an ABSTAIN,
never a guessed verdict. The stated confidence is parsed separately and just
as strictly (one well-formed number in [0, 1] right after the verdict token;
otherwise "unstated", never coerced). An unreachable provider is "no
opinion". The bank pins the verifier's tier: evidence claiming HARD for this
verifier id is rejected loudly (`tier is fixed`), so the judge cannot be
mistaken for an authority even by bug.

## The gold set: 44 items, traps built like the SQL probes

`grounding-v1 (44 items)`: 18 supported claims (verbatim, paraphrase, and
two-fact combinations) and 26 not-supported claims over six invented,
self-contained sources. Every trap is PLAUSIBLE — the mistake a fluent
summarizer actually makes: number-drift, temporal-overreach,
unstated-causation, source-silent, over-generalization, swapped-entity,
negation-flip, wrong-fact, hedge-to-assertion, aggregation-error. Every
family in that taxonomy is represented (pinned by test), because false-PASS
opportunities are what an admissions test is made of.

## The admissions test: measure FIRST, weight second

`benchmarks/grounding_eval.py` measures the judge against gold — reusing the
code-domain eval's fixture-tested arithmetic (`compute_metrics`), with gold
labels standing in the reference position the HARD verdict occupies in code.
It is read-only by construction: no bank, no store, no ledger — measurement
grants nothing.

Offline scripted run (validates the HARNESS, not any judge; deviations are
designed and hand-checkable), 2026-07-07, verbatim:

```
judge decided : 42  |  judge abstained : 2

| metric | value |
|---|---|
| agreement (of decided) | 39/42 = 92.9% |
| false-PASS (judge SUPPORTED where gold NOT-SUPPORTED) | 2/25 = 8.0% |
| false-FAIL (judge NOT-SUPPORTED where gold SUPPORTED) | 1/17 = 5.9% |
```

with the per-category tables locating each designed deviation exactly
(false-PASSes in `unstated-causation` and `over-generalization`; the
false-FAIL in `paraphrase`; conformance pins all of these counts).

**Live numbers are an operator dispatch**, not a build-environment spend.
The `judge-eval-live` workflow accepts `item_set=grounding-v1` and runs the
same two arms as the code measurements — Run A with the actor-family judge
(the correlated, self-grading configuration) and Run B with an
independent-family judge:

```
Actions -> judge-eval-live -> Run workflow
  actor_model: <actor model id>      judge_model: <independent judge id>
  item_set:    grounding-v1
```

or locally:
`PROM_PROVIDER=remote PROM_API_BASE=... PROM_API_KEY=... PROM_JUDGE_MODEL=...
python -m prometheus_protocol.benchmarks.grounding_eval --live`.

## The structural finding: no hard verifier means no autonomy — by construction

The demo (`python -m prometheus_protocol.benchmarks.grounding_loop_demo`)
runs claims through the real bank, gate, controller, sandbox, and ledger:

```
[loop] judge   : pass (SOFT tier) — SUPPORTED 0.9
[loop] bank    : verdict=pass confidence=0.50 authoritative=False
[loop] gate    : BLOCK — blocked: judgment is not authoritative
[loop] executed: never (soft-only evidence cannot authorize — structural, not configured)
...
[loop] human   : pass (HUMAN tier, authoritative)
[loop] bank    : verdict=pass confidence=0.98 authoritative=True (judge calibrated against the human decision)
[loop] gate    : APPROVE — authorized: pass verdict, authoritative, confidence 0.98 >= 0.75 (medium risk)
[loop] publish : executed in sandbox 'namespace' (exit 0)
...
[audit] executions recorded: 4 (executed 1, blocked 3)
```

Three properties, none of them new code — the point is that they were
already true:

1. **A soft-only judgment cannot authorize, and cannot even be routed for a
   rubber stamp.** The bank marks it non-authoritative; the gate blocks every
   non-authoritative judgment (its own comment predates this domain: "a human
   is never asked to rubber-stamp a failure or an ungrounded claim"). The
   conformance test drives a confident soft-only PASS through the real
   controller at every risk class: blocked, no pending hold, executor never
   invoked. The human backstop in this domain is therefore **not a policy
   choice — it is the only path to action that exists.**
2. **The human is the authoritative tier.** A human grounding review enters
   as `Tier.HUMAN` evidence; the bank makes it the reference: the human
   decides the fused verdict, and the soft judge is *calibrated against the
   human decision* — the exact mechanism that calibrates the code judge
   against the sandbox. Humans are to grounding what execution is to code.
3. **An uncalibrated advisor carries no weight.** Beat 1's judge stated 0.9;
   the fused advisory confidence is 0.50 — maximal uncertainty — because an
   un-audited verifier's likelihood ratio is ~1 until it earns calibration
   samples. Confidence is earned through agreement with references, never
   asserted.

## The authority bound (what the live numbers can and cannot justify)

The verifier's advisory weight is bounded by its **measured false-PASS in
this domain** — the correlated and independent live runs above. But be
precise about what any grounding-v1 number can license:

* With 26 trap items, even a PERFECT live run (0 false-PASS, all decided)
  only bounds the true false-PASS rate below roughly **3/26 ≈ 12% at 95%
  confidence** (the rule of three). A single grounding-v1 dispatch can
  therefore justify *advisory* uses — triage ordering, flagging, prioritising
  human review queues — and CANNOT justify autonomous authority, no matter
  how clean the number.
* Granting the grounding judge ANY authority (for example, letting a
  high-confidence SUPPORTED execute a low-risk action without a human) would
  require: a sustained independent-family false-PASS bound far below the
  automation risk it replaces, measured across item sets larger and broader
  than this one, and — decisively — **a new named invariant in spec/**
  defining soft-tier authority and its measurement obligations. That is a
  spec-owner decision. Today the code deliberately provides no such path:
  there is no flag, threshold, or configuration that lets SOFT evidence
  authorize an action.

## Honest limits

* **Gold labels are human judgment.** They are curated and reviewable, but a
  mislabeled item mis-measures the judge. The labels ship in the repo
  precisely so disputes are diffs.
* **44 items sample a taxonomy; they do not span it.** The trap families are
  represented, not exhausted; a clean run bounds behaviour on THESE shapes.
  Live-set growth is the same path the code domain walked (v1 → v2).
* **Claims are judged in isolation** — one claim against one short source.
  Multi-claim documents, partially-supported composites, and long-source
  retrieval are all harder and deliberately out of scope here.
* **The offline run validates arithmetic, not judges.** Every offline number
  above is a designed fixture; only the operator's live dispatch measures a
  real judge, and the report records whatever it measures — including an ugly
  number, which per the admissions rule means the judge stays advisory.
* **The loop "closes" here only through a human.** That is the honest
  outcome for a domain with no executable truth: the architecture held by
  refusing exactly the autonomy it could not ground.
