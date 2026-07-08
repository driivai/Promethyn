# Extending Promethyn: the domain/verifier contract

Three domains work end to end today — code (HARD, sandboxed tests), SQL
(HARD, sandboxed result-equivalence), and grounding (SOFT, gold-labeled
faithfulness). They were not special-cased in: they plug into the runtime
through a **shared seam** that this document names, stabilises, and backs
with a mechanical **conformance suite**. If you can write a verifier that
passes the suite, the runtime will consume it, the gate will govern it, and
the learn loop will admit it — without any change to the Hearth (the bank,
the gate, the held-out firewall, the executor, or the Evidence/verdict
semantics).

The single most important rule: **an extension adds capability; it can never
grant itself authority.** Authority is a property of the *tier* the platform
assigns, gated regardless of what a verifier claims. The contract below is
what makes that guarantee hold for code you did not write.

## 1. The verifier contract

A verifier implements one method:

```python
class Verifier(ABC):
    def verify(self, *, code: str, task) -> Evidence: ...
```

It receives a candidate (`code` — a program, a query, a claim) and a domain
`task`, and returns tier-tagged [`Evidence`](../src/prometheus_protocol/core/models.py).
The fields that matter to the runtime:

| field | meaning |
|---|---|
| `verdict` | `PASS` / `FAIL` / `ABSTAIN` |
| `tier` | `HARD` / `HUMAN` (authoritative) or `SOFT` / `CONSISTENCY` (advisory) |
| `verifier_id` | a stable identifier; the bank pins a tier to it |
| `confidence`-shaping fields | `passed_count`, `failures`, `detail`, `cost`, `latency_ms` |

### Required guarantees

1. **Tier honesty.** A verifier declares one tier and tags *every* Evidence —
   including an ABSTAIN — with it. It cannot emit a tier it does not hold: the
   bank pins each `verifier_id` to its tier and raises on contradicting
   Evidence (`a verifier's tier is fixed`). A SOFT verifier's judgment is
   therefore non-authoritative no matter how confident it sounds; only a
   HARD/HUMAN verifier's is authoritative. **A SOFT process cannot stamp HARD
   and thereby reach autonomous execution — this is enforced, not trusted.**

2. **Fault distinction.** A candidate at fault is a `FAIL` (a wrong answer, a
   crash on the candidate's own code, a query error on a valid schema). A
   fault that cannot be pinned on the candidate is an `ABSTAIN` (isolation did
   not start, a timeout, the run was never confirmed to begin, a broken
   reference). **Never guess a verdict** when you could not verify.

3. **Fail-closed.** If you cannot obtain isolation or ground truth, `ABSTAIN`
   (or, for an action, block) — never fall back to an unverified pass. The
   HARD verifiers do this by running through an isolating `Sandbox` that
   refuses to start when no isolating adapter is available (`NullSandbox`);
   the soft grounding judge does it by treating any provider failure as "no
   opinion".

4. **Adversarial soundness (verifier-appropriate).** A candidate crafted to
   pass by coincidence or by exploiting the comparison must be caught or
   correctly ABSTAINed. You know your domain's exploit shapes; you supply the
   probe. (Code: a candidate that *prints* a pass but returns wrong answers
   still FAILs, because ground truth is read off a result file, not stdout.
   SQL: the comparator rejects a right-shape / wrong-content result set.
   Grounding: an unparseable judge reply is an ABSTAIN, never a guess.)

### The honest limit each tier carries

The contract makes a verifier *well-behaved*; it does not make it *right*.
State your limit, as the three domains do:

- **HARD execution / result-equivalence** cannot distinguish a
  coincidentally-right candidate from a correct one — the same bound hidden
  tests have. "Verified" means indistinguishable-from-correct on the executed
  evidence, not proven-correct.
- **SOFT judgment** is advisory only. Its trustworthy weight is bounded by its
  *measured* false-PASS in the domain (see the admissions harnesses,
  `benchmarks/*_eval`), and with no HARD backstop a human decision is the only
  path to action. Measure first; a good number never promotes a soft verdict
  to authority.

## 2. The domain / task contract (to use the learn loop)

To ride the promotion pipeline, a domain's task satisfies the
[`LearnableTask`](../src/prometheus_protocol/core/interfaces.py) port —
structurally, not by inheritance:

```python
class LearnableTask(Protocol):
    id: str
    prompt: str          # the only field a proposer may see
    split: str           # "train" | "heldout"
    cluster: str | None  # the failure-concept label the forge groups by
```

Domain-specific fields (code's `entry_point`/`cases`, SQL's
schema/fixture/reference, grounding's source) are **not** part of the port —
your verifier consumes them; the loop must not require them. `split` carries
the held-out partition with one meaning everywhere: the forge may learn from
`train` only, and `heldout` exists solely for the promotion gate's firewalled
generalisation check.

**The held-out firewall is id-set arithmetic, and therefore domain-general.**
The gate calls `assert_disjoint(train_ids, heldout_ids)` before scoring any
candidate and raises `FirewallError` on any overlap; the forge refuses any
non-`train` attempt. Neither depends on what the task *is* — proven for code
and SQL, and re-checked generically by the conformance suite
(`check_firewall_is_domain_general`).

## 3. The registration surface

- A verifier is handed to the **`VerifierBank`** (or the orchestrator, which
  owns one). `bank.register(verifier_id, tier)` pins the tier; from then on
  the bank fuses the verifier's Evidence and **calibrates it against the
  authoritative reference** — a SOFT verifier earns advisory weight only by
  agreeing with a HARD/HUMAN reference over time, and starts at ~zero weight.
- The **gate** governs whatever the bank produces, unchanged: a non-PASS or
  non-authoritative judgment is blocked; an authoritative PASS is authorised
  or routed to a human by risk and confidence. You wire a verifier *in*; you
  do not wire the gate.
- A domain task type is your own dataclass satisfying `LearnableTask`; an item
  set is your own module. Neither touches the runtime.

**What the platform guarantees you:** your verifier's authority is bounded by
its tier and its measured error, and the gate governs it — so a bug in your
verifier cannot escalate past its tier. **What you guarantee in return:** the
four required guarantees above, mechanically checkable.

## 4. The boundary: what an extension can and cannot do

| CAN | CANNOT |
|---|---|
| add a verifier (any tier) | grant itself authority above its tier |
| add a domain / task type | bypass or reconfigure the gate |
| add an item set / gold set | emit HARD Evidence from a soft process |
| supply an adversarial probe | read held-out data in a promotion decision |
| bound its own advisory weight by measuring it | promote a soft verdict with a good number |

The right-hand column is enforced by construction wherever possible: the bank
pins tiers (a soft process cannot emit HARD past it), the gate blocks
non-authoritative judgments (a soft verdict cannot authorise an action), and
the firewall is checked before any held-out task is scored. The conformance
suite mechanically re-proves the first three on any candidate verifier.

## 5. The conformance suite

Run the built-in demonstration:

```
python -m prometheus_protocol.conformance                 # tier + fail-closed
PROM_REQUIRE_SANDBOX=1 python -m prometheus_protocol.conformance --require-runtime
```

It checks the three shipped verifiers (which pass unchanged — the proof the
contract is real) plus the domain-general firewall guarantee. To check **your**
verifier, describe it with a `VerifierCase` and call `check_verifier`:

```python
from prometheus_protocol.conformance import VerifierCase, check_verifier
from prometheus_protocol.core.models import Tier
from prometheus_protocol.sandbox import NullSandbox   # the fail-closed injector

case = VerifierCase(
    name="my-domain",
    verifier=MyVerifier(),
    tier=Tier.HARD,
    # a verifier whose ground truth is broken must ABSTAIN on this example:
    failclosed=(MyVerifier(sandbox=NullSandbox()), (candidate, task)),
    passing=(correct_candidate, task),     # must PASS (needs your runtime)
    failing=(faulty_candidate, task),      # must FAIL (candidate fault)
    adversarial=my_exploit_probe,          # returns (caught: bool, detail: str)
)
report = check_verifier(case)             # run_behavioural gates PASS/FAIL checks
assert report.ok, report.render()
```

The suite has **teeth**: a SOFT verifier that stamps HARD on its Evidence
fails `emits-declared-tier`; a verifier that guesses a verdict when it cannot
verify fails `fail-closed`. Both are `REJECTED`, with the failing check named
— verified by `tests/conformance/test_extension_surface.py`.

## 6. Add a new domain in N steps (the worked path)

This is exactly how SQL and grounding were added.

1. **Write the verifier** (`verifier/<domain>.py`): implement `verify(code,
   task) -> Evidence`, pick your tier honestly (executes ground truth →
   HARD; judges → SOFT), and obey the four guarantees. Run untrusted
   candidates through the existing `Sandbox` port — do not fork it. *(SQL:
   `SqlVerifier`, HARD, one statement in an in-memory DB in the sandbox.
   Grounding: `GroundingVerifier`, SOFT, a provider-backed judge.)*
2. **Write the task type**: a frozen dataclass with `id`, `prompt`, `split`,
   `cluster`, plus your domain fields. *(SQL: `SqlTask` with
   schema/fixture/reference. Grounding: `GroundingTask` with a source.)*
3. **Build an item set with ground truth**: for a HARD domain, tasks whose
   reference executes; for a SOFT domain, **gold labels** — a curated human
   reference, documented as such per item. Include plausible-but-wrong
   candidates so false-PASS has real opportunity.
4. **Measure before you trust**: a read-only admissions harness (mirror
   `benchmarks/sql_items.py` or `benchmarks/grounding_eval.py`) that reports
   the verifier's error profile against ground truth. For a SOFT verifier this
   is mandatory — its weight is bounded by this number.
5. **Pass the conformance suite**: write a `VerifierCase`, get a
   `WELL-BEHAVED` report.
6. **(Optional) wire the learn loop**: partition your item set into
   `train`/`heldout`; the shared `Orchestrator` + `LessonForge` +
   `PromotionGate` take it with the firewall unchanged (SQL did this with a
   zero-line diff to `gate/promotion.py`).

At no step do you touch the Hearth. If a step seems to require it, that is a
signal to stop and raise it with the spec owners — the surface is a contract
*around* the Hearth, not a licence to change it.

## Honest finding: how uniform is the seam, really?

Formalising the surface confirmed the seam is real but showed it is **uniform
at the Evidence boundary and deliberately not uniform before it**. Every
domain converges on the same output contract — tier-tagged Evidence the bank
consumes — and that is what the conformance suite checks and what made the
three domains compose. But the *inputs* legitimately differ: HARD verifiers
carry a `Sandbox` and fail closed when isolation won't start; the SOFT judge
carries a `Provider` and fails closed when it can't be reached. The contract
handles this honestly by making the extender supply the fail-closed injector
(`NullSandbox` for one, a raising provider for the other) rather than
pretending one mechanism fits all — the guarantee ("cannot obtain ground
truth ⇒ ABSTAIN") is uniform; the *source* of ground truth is not, and the
contract says so.

**What the suite does NOT yet catch**, stated plainly so it is not mistaken
for more than it is:

- It proves a verifier is well-behaved *at its declared tier on the examples
  the extender provides*. It cannot certify that a HARD verifier's ground
  truth is actually sound (a verifier with a wrong reference passes every
  check while being wrong) — that is what the admissions measurement is for,
  and why HARD tasks self-check their references.
- It cannot bound a SOFT verifier's error rate; it only proves the verifier is
  advisory and fails closed. The *number* comes from the live admissions run,
  which is a separate, measured step.
- The adversarial check is only as strong as the probe the extender writes;
  the suite provides reusable templates (stdout-can't-forge,
  comparator-rejects-wrong-shape, unparseable-abstains) but cannot enumerate a
  domain's exploits for it.

So: the conformance suite is necessary and mechanically enforced, but it is
an *admissions gate on behaviour*, not a *certificate of correctness*. Trust a
third-party verifier as far as its tier bounds it and its measured error
supports — never further. That is the same discipline the three built-in
domains hold themselves to.
