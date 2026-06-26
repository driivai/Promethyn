# Prometheus Protocol — Invariants

These are formal claims a conforming implementation must uphold. Each is
checked by code; the relevant tests are noted.

## I1. Held-out firewall (load-bearing)

> Let `T` be the set of task ids the forge learns from (the `train` split) and
> `H` be the set of task ids the gate scores a candidate against (the
> `heldout` split). Then `T ∩ H = ∅`, always.

Rationale: if the two sets intersect, a skill could be promoted because it
fits the very tasks it was mined from, and the held-out pass rate would no
longer be evidence of generalisation.

Enforcement:
- The forge refuses any non-`train` attempt (`forge/miner.py`).
- The gate calls `assert_disjoint(train_ids, heldout_ids)` before scoring any
  candidate and raises `FirewallError` on intersection (`gate/promotion.py`).

Tests: `tests/conformance/test_firewall.py`.

## I2. Reversibility

> Every promotion can be undone, restoring the prior observable behaviour.

Skills are plain markdown files in the registry; removing a skill returns the
runtime to its pre-promotion pass rate. Promotions are recorded in the ledger
so they can be replayed or rolled back deterministically.

Tests: `tests/conformance/test_promotion.py::test_promotion_is_reversible`.

## I3. Auditability

> From the ledger alone, one can recover what was attempted, what passed, and
> what was promoted, in order.

Every attempt and every promotion is appended to the ledger with its cycle and
phase. No state change relevant to learning happens off-ledger.

Tests: `tests/conformance/test_promotion.py::test_run_is_auditable`.

## I4. Verifier authority

> A task passes only if the verifier returns a hard pass over all its hidden
> cases. The proposer never sees the hidden cases.

The provider contract accepts only the prompt, the entry point, and retrieved
skills. Hidden cases are supplied solely to the verifier.

Tests: `tests/unit/test_verifier.py`, `tests/unit/test_provider_mock.py`.

## I5. Determinism of the reference loop

> With the simulated provider and a fixed benchmark, the loop produces the
> same outcomes on every run.

Retrieval, mining, and gating are deterministic; the simulated provider uses
no randomness and no network. (A live model provider is not bound by this
claim.)

Tests: the conformance suite asserts exact rates rather than ranges.

## I6. Authoritative dominance

> A soft-tier verdict can never override a hard-tier verdict; it may only
> inform calibration.

When any authoritative verdict (hard or human) is present, the fused result is
decided by the authoritative reference. Advisory verifiers (soft, consistency)
contribute no weight to that result; their verdicts are recorded only as
calibration samples against the reference.

Enforcement: the verifier bank fuses the reference tier's verdicts for the
result and feeds advisory verdicts solely into trust updates
(`verifier/bank.py`).

Tests: `tests/conformance/test_verifier_trust.py::test_i6_soft_cannot_override_hard`.

## I7. Earned weight

> An un-audited verifier carries zero aggregation weight until calibrated
> against trusted references.

A verifier with a non-informative prior (soft or consistency tier) and no
calibration evidence has a Youden index of 0 and contributes a
log-likelihood ratio of exactly 0 to fusion — it cannot move a verdict.
Authoritative tiers are trusted by construction through their priors; advisory
tiers must earn weight by agreeing with authoritative references.

Enforcement: tier-dependent Beta priors and the log-likelihood-ratio fusion in
`verifier/trust.py` and `verifier/aggregate.py`.

Tests: `tests/conformance/test_verifier_trust.py::test_i7_unaudited_verifier_has_zero_weight`
and `::test_trust_is_earned_through_calibration`.
