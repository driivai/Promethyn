# SOFT-lever adoption rule (pre-registered) + power check

**Status: pre-registered. This document is committed BEFORE any SC-2 measurement
code changes, as its own commit, so git history proves the rule was fixed before
the frontier/instrumentation could produce a number to fit it to.** The rule
below is not edited after the power calculation. If the power calculation shows
nothing can clear the bar, the finding is recorded in bold and the rule stays —
loosening a pre-registered rule so the data can clear it is the exact failure
mode this project exists to prevent.

The numbers used in the power check are the **already-recorded live baselines**
from `docs/judge-quality.md` (dispatched in prior sprints, #39/#43). No new model
call is made in SC-2.

## The adoption rule

A candidate SOFT lever is **ADOPTED** only if ALL of the following hold.

**On the correlated arm** (`PROM_JUDGE_MODEL = ACTOR_MODEL`, judge grades its own
family — the arm where the self-grading blind spot is largest), on the
pre-declared **primary set**:

1. **false-PASS falls by ≥ 5 percentage points absolute** vs. the correlated
   baseline; and
2. **coverage** (`1 − ABSTAIN/total`) **is ≥ 90% of baseline coverage**; and
3. **cost is ≤ 2× baseline model calls**; and
4. **false-FAIL rises by ≤ 3 percentage points absolute**.

**On the independent arm** (`PROM_JUDGE_MODEL` a distinct family), the lever must:

5. **not increase false-PASS**, and
6. **not increase false-FAIL**, and
7. **not drop coverage below 95% of baseline**.

Clause (2)/(7) is the anti-abstention clause: a lever that lowers false-PASS by
refusing to decide has not calibrated the judge, it has gone quiet, and the
coverage floor rejects it. The 5-point threshold in (1) is the pre-declared
**minimum deployable effect** — a lever that moves false-PASS 1–2 points is not
worth a second model or a k× bill. It is deliberately a bar, not a p-value; the
power check below asks whether the bar is even reachable at current N.

**Primary set: `grounding-v2`.** It is declared primary because it carries the
largest correlated false-PASS signal (5/45 = 11.1%), so it has the most headroom
for a 5-point drop to be visible at all. `live-v2` is secondary. (Rationale is
structural, not chosen after seeing lever data — no lever has been run.)

## Power check (the arithmetic, shown)

Recorded baselines (`docs/judge-quality.md`), gold-negative denominators only
(false-PASS lives on gold-negative items):

| set | arm | false-PASS | rate | false-FAIL | coverage |
|---|---|---|---|---|---|
| grounding-v2 | correlated | 5/45 | 11.1% | 1/19 | 64/64 |
| grounding-v2 | independent | 0/43 | 0.0% | 0/19 | 62/64 |
| live-v2 | correlated | 2/51 | 3.9% | 0/31 | 82/82 |
| live-v2 | independent | 0/49 | 0.0% | 4/31 | 80/82 |

### (a) Item-count to move the primary rate 5 points

On grounding-v2 correlated the denominator is 45 gold-negative items and the
baseline is 5 false-PASSes. Holding the denominator fixed (no coverage loss):

```
fp=5/45 = 11.11%   drop  0.00 pp   — baseline
fp=4/45 =  8.89%   drop  2.22 pp   — no
fp=3/45 =  6.67%   drop  4.44 pp   — no  (falls just short of 5 pp)
fp=2/45 =  4.44%   drop  6.67 pp   — CLEARS 5 pp
fp=1/45 =  2.22%   drop  8.89 pp   — CLEARS 5 pp
fp=0/45 =  0.00%   drop 11.11 pp   — CLEARS 5 pp
```

**To clear the 5-point bar, the numerator must fall to ≤ 2 — the lever must
correct ≥ 3 of the 5 false-PASSes.** Not a percentage: **three specific items,
out of the five that leak, out of forty-five.**

### (b) Is correcting 3 of 5 distinguishable from noise? No.

The lever is applied to the **same 45 items** as the baseline, so the correct
test is paired (McNemar exact), not two independent samples. With the baseline's
5 false-PASSes as the discordant-eligible events and a lever that corrects `b` of
them introducing no new ones.

**Tail choice, stated once (not left as a degree of freedom).** The
pre-registered hypothesis is directional — a calibration lever can only *reduce*
false-PASS, never add one — so the **one-sided** test is the appropriate primary.
An unlabelled tail is a researcher degree of freedom this sprint exists to close,
so every p-value below is reported **both tails**, and the finding is stated so
it holds under either:

| outcome | McNemar 1-sided | McNemar 2-sided | Fisher 1-sided | Fisher 2-sided | clears 5pp? |
|---|---|---|---|---|---|
| correct 3 of 5 → 2/45 | 0.125 | 0.250 | 0.217 | 0.434 | yes (point est.) |
| correct 4 of 5 → 1/45 | 0.0625 | 0.125 | 0.101 | 0.203 | yes |
| correct 5 of 5 → 0/45 | 0.0312 | 0.0625 | 0.0278 | 0.0556 | yes |

The baseline is barely resolved either way: **5/45 has an exact 95% CI of [3.7%,
24.1%]** (Clopper–Pearson) — a 20-point band around an 11% estimate.

> **NO OUTCOME ON THIS SET IS BOTH CLEARING AND SIGNIFICANT.** The only outcome
> that clears the 5-pt bar *and* reaches one-sided significance is a clean sweep
> to 0/45 — and even that **fails a two-sided test** (McNemar 0.0625, Fisher
> 0.0556, both > 0.05), and is precisely the 0%-on-a-full-denominator result the
> SC-2 standing rule says to assume is a harness bug before a result. Whichever
> tail you pick, this set cannot both show the effect and prove it. This
> strengthens the defer decision — it does not soften it, and the rule is not
> loosened to fit it.

- **Documented run-to-run variance is at the scale of the effect.** On live-v2,
  the *same* correlated config measured false-PASS **4/51 = 7.8%** on one dispatch
  and **2/51 = 3.9%** on the next (`docs/judge-quality.md` §Caveats, lines
  298–300) — a **2-item swing = 2/51 ≈ 3.9 pp**, against a 5-point bar. This is a
  **measured** difference between two real runs, not an estimate — but it is only
  **n = 2 dispatches** (one observed difference, not a characterised
  distribution), and it is measured on **live-v2 and imported cross-set** as an
  indicative scale for grounding-v2's own run-to-run noise, which is
  **unmeasured** (single run per arm). So it is a *secondary* support; the primary
  support is the grounding-v2-native significance result above, which does not
  depend on it.
  *(Coincidence check — two quantities here are both "3.9%": live-v2's correlated
  **baseline** false-PASS is 2/51, and the run-to-run **swing** is also 2/51.
  Both are "2 events over 51", hence the same ratio — different quantities that
  happen to share a small-integer denominator, not a number copied from one place
  to another.)*

### (c) live-v2 cannot satisfy the rule at all

live-v2 correlated false-PASS is **2/51 = 3.9%**. A 5-point *absolute* drop would
require a rate of **−1.1%**. **Impossible.** There is not 5 points of false-PASS
on live-v2 to remove; the secondary set is arithmetically incapable of adopting
any lever under clause (1).

### (d) Which levers could clear the bar even if they worked perfectly?

- On **grounding-v2**: only a lever that corrects **all 5** correlated
  false-PASSes clears (1) *and* reaches significance — and that outcome is
  pre-committed to be treated as a suspected harness bug. A lever that corrects
  3–4 clears the 5-point point-estimate but is indistinguishable from noise.
- On **live-v2**: none. The baseline is below the threshold.
- The **independent arm** starts at 0/43 and 0/49; clauses (5)–(7) are guards
  against making it *worse*, not an improvement target (you cannot subtract from
  zero). So no lever can be *seen to improve* the independent floor either —
  0/43 already bounds it only to ≤ 6.98%, 0/49 to ≤ 6.12% (rule of three).

## The finding

**At the current denominators (grounding-v2 45 gold-negatives, live-v2 51), NO
lever can clear the pre-registered adoption bar with statistical confidence. On
the primary set the 5-point threshold is reachable as a point estimate only by
correcting ≥3 of 5 false-PASSes — a move that is not statistically
distinguishable from noise (McNemar p = 0.125), whose only significant version (a
clean sweep to 0/45) we are pre-committed to disbelieve, and whose target effect
is smaller than the documented run-to-run variance of the same models (~3.9 pp).
On the secondary set a 5-point absolute drop is arithmetically impossible (3.9%
baseline). The experiment as currently resourced cannot produce an adoption
decision.**

The rule is not loosened to fix this. The denominators are.

## Required N (forward pointer)

To make the experiment decidable, the gold set must grow (protocol:
`docs/gold-set-v3-protocol.md`). From the same α = 0.05, power = 0.80 targets:

Note every N below is first derived as a count of **gold-negative** items (the
false-PASS denominator), then converted to a **total** item count by dividing by
grounding-v2's gold-negative fraction **45/64 = 0.703 ≈ 0.70** (assumed to hold in
v3). Rounding is upward (ceil).

- **Bound the independent false-PASS floor below 2%** (the number a hostile
  reviewer attacks with rule-of-three). Rule of three: a `0/n` observation bounds
  the true rate at `≤ 3/n` (95%). Require `3/n < 0.02` ⇒ **n > 150 gold-negative
  items** (3/150 = 0.02 exactly, so strictly more than 150). Convert to total:
  `150 / 0.70 = 214.3` ⇒ **≈ 215 total items**. (The 150 is the rule-of-three
  number; the 215 is that number grossed up for the ~30% gold-positive items the
  set also needs.) Below 1%: `3/n < 0.01` ⇒ n > 300 gold-neg ⇒ `300/0.70 = 428.6`
  ⇒ ≈ **429 total**.
- **Detect a 5-point correlated effect (p₀ = 0.11 → p₁ = 0.06)** at α = 0.05
  (two-sided), power = 0.80, two independent proportions:

  ```
  n_perarm = ( z_{α/2}·√(2·p̄·(1−p̄)) + z_β·√(p₀(1−p₀)+p₁(1−p₁)) )² / (p₀−p₁)²
           = ( 1.960·√(2·0.085·0.915) + 0.842·√(0.11·0.89 + 0.06·0.94) )² / 0.05²
           = ( 1.960·0.3945 + 0.842·0.3928 )² / 0.0025
           = ( 0.7732 + 0.3307 )² / 0.0025  =  1.2186 / 0.0025  ≈ 487.4
  ```

  ⇒ **≈ 488 gold-negative items per arm**; convert to total: `488 / 0.70 = 697.1`
  ⇒ **≈ 700 total items**. (`p̄ = (p₀+p₁)/2 = 0.085`; `z_{0.025} = 1.960`,
  `z_{0.20} = 0.842`.)

The 20-item pilot in `docs/gold-set-v3-protocol.md` is not powered to adopt
anything — it exists to prove the construction protocol and, if it surfaces even
one independent-arm false-PASS, to put a nonzero numerator under the 0% claim.
