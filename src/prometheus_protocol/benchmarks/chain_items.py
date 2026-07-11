"""The instrument: HARD-verifiable multi-step chains for the composition study.

Each chain is a multi-step workflow that assembles ONE SQL query from per-step
fragments. A chain's ground truth is **executed, never hand-labelled**: the
assembled query is run by the real :class:`SqlVerifier` against the reference
(the correct fragment for every slot the chain fills), and the chain is CORRECT
iff their result sets are equivalent. Compounding is therefore *mechanical* — a
wrong fragment that survives to the final assembly makes the executed query
wrong — and recovery is mechanical too: a later step that overwrites the same
slot with the correct fragment repairs the chain.

Honest disclosure — what is authored vs. what is measured
---------------------------------------------------------
* **Measured (real system outputs):** every per-step confidence is produced by
  the real :class:`VerifierBank` (``chain_eval.py``); every chain-correctness
  verdict is produced by executing the assembled query through the real HARD SQL
  verifier. Neither is hand-set.
* **Authored (the instrument design, disclosed):** the *mix* of chains (how many
  fail, how long they are, which step carries the error) and the *fallibility of
  SOFT steps*. A SOFT step models a fallible model-judge: its grader ACCEPTS
  (PASS) the step at the profile's confidence whether or not the fragment is
  actually correct. Wrong-but-accepted SOFT fragments are injected at a rate
  chosen to match each profile's confidence (a 0.875 profile ⇒ ~12.5% of its
  steps carry a wrong fragment), so the per-step confidences we feed to
  composition are calibrated *by construction*. ``chain_eval.py`` re-measures
  that instrument calibration and prints it, so the reader can see exactly what
  per-step signal the composition rules had to work with.

Because the dependence structure (strict compounding with explicit recovery) and
the base rate are design choices, the calibration numbers characterise the rules
**on this instrument**; they are directional (small N), not a natural-workload
calibration. That conditionality is the point: it is *why* no rule can be
certified sound (see ``docs/composition-study.md``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from prometheus_protocol.core.models import Tier

# --------------------------------------------------------------------------
# per-step confidence profiles (realised against the real bank in chain_eval)
# --------------------------------------------------------------------------
# Each name maps to a documented, reproducible bank state (a fresh bank, an
# optionally pre-calibrated advisor) that yields the stated confidence for an
# ACCEPTED (PASS) step. The tier is what the step is graded at.

HARD_PASS = "hard_pass"          # lone HARD PASS               -> ~0.950  (HARD)
HARD_STRONG = "hard_strong"      # HARD + agreeing advisor      -> ~0.995  (HARD)
HARD_WEAK = "hard_weak"          # HARD + dissenting advisor    -> ~0.615  (HARD)
SOFT_UNCAL = "soft_uncal"        # lone uncalibrated SOFT       -> ~0.500  (SOFT)
SOFT_075 = "soft_075"            # SOFT advisor @ youden 0.50   -> ~0.750  (SOFT)
SOFT_0875 = "soft_0875"          # SOFT advisor @ youden 0.75   -> ~0.875  (SOFT)
SOFT_095 = "soft_095"            # SOFT advisor @ youden 0.909  -> ~0.955  (SOFT)

PROFILE_TIER: dict[str, Tier] = {
    HARD_PASS: Tier.HARD,
    HARD_STRONG: Tier.HARD,
    HARD_WEAK: Tier.HARD,
    SOFT_UNCAL: Tier.SOFT,
    SOFT_075: Tier.SOFT,
    SOFT_0875: Tier.SOFT,
    SOFT_095: Tier.SOFT,
}

# HARD profiles are authoritative: an accepted HARD step is reliably correct
# (measured ~0% false-PASS live), regardless of the confidence number the
# advisors move it to. So HARD steps in this set always carry a correct
# fragment; only SOFT steps ever carry a wrong-but-accepted one.
HARD_PROFILES = frozenset({HARD_PASS, HARD_STRONG, HARD_WEAK})

# --------------------------------------------------------------------------
# the fixture (one table; predicates and aggregates compose cleanly over it)
# --------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE sales (
  id INTEGER PRIMARY KEY,
  region TEXT NOT NULL,
  status TEXT NOT NULL,
  amount REAL NOT NULL,
  qty INTEGER NOT NULL
);
"""

FIXTURE_SQL = """
INSERT INTO sales (id, region, status, amount, qty) VALUES
  (1,  'EU',   'paid',     100.0, 2),
  (2,  'EU',   'refunded',  50.0, 1),
  (3,  'US',   'paid',     200.0, 5),
  (4,  'US',   'pending',   30.0, 3),
  (5,  'APAC', 'paid',      70.0, 4),
  (6,  'EU',   'paid',      40.0, 1),
  (7,  'US',   'refunded',  90.0, 2),
  (8,  'APAC', 'refunded',  60.0, 3),
  (9,  'EU',   'pending',   20.0, 1),
  (10, 'APAC', 'paid',     110.0, 6);
"""

# The query slots a step may fill, and the CORRECT fragment for each. A chain's
# task is defined by exactly the slots it fills; its reference is the correct
# fragment for each of those slots. Slot render order is fixed for determinism.
AGG = "agg"
REGION = "region"
STATUS = "status"
AMOUNT_MIN = "amount_min"
QTY_MIN = "qty_min"

_PRED_SLOTS = (REGION, STATUS, AMOUNT_MIN, QTY_MIN)  # everything except the agg
_SLOT_ORDER = (REGION, STATUS, AMOUNT_MIN, QTY_MIN)

CORRECT: dict[str, str] = {
    AGG: "SUM(amount)",
    REGION: "region = 'EU'",
    STATUS: "status = 'paid'",
    AMOUNT_MIN: "amount > 30",
    QTY_MIN: "qty >= 2",
}

# Wrong-but-plausible fragments a fallible SOFT step might produce and accept.
WRONG: dict[str, str] = {
    AGG: "COUNT(*)",
    REGION: "region = 'US'",
    STATUS: "status = 'refunded'",
    AMOUNT_MIN: "amount > 300",
    QTY_MIN: "qty >= 10",
}


@dataclass(frozen=True)
class ChainStep:
    """One step: it fills a query ``slot`` with a fragment and is graded at
    ``profile``. ``wrong`` marks a step that produced the WRONG fragment for its
    slot yet was still accepted (PASS) — the injected false-PASS. Only SOFT
    profiles may be wrong (HARD steps are authoritative)."""

    step_id: str
    slot: str
    profile: str
    wrong: bool = False

    def __post_init__(self) -> None:
        if self.profile not in PROFILE_TIER:
            raise ValueError(f"unknown profile {self.profile!r}")
        if self.wrong and self.profile in HARD_PROFILES:
            raise ValueError(
                f"step {self.step_id!r}: HARD steps are authoritative and "
                "cannot carry a wrong-but-accepted fragment"
            )

    @property
    def tier(self) -> Tier:
        return PROFILE_TIER[self.profile]

    def fragment(self) -> str:
        return WRONG[self.slot] if self.wrong else CORRECT[self.slot]


@dataclass(frozen=True)
class ChainCase:
    """An authored chain. ``scenario`` is a human label for the failure mode;
    the ground-truth correctness is decided by EXECUTION, not by this label."""

    chain_id: str
    scenario: str
    steps: tuple[ChainStep, ...]

    def __post_init__(self) -> None:
        if not self.steps:
            raise ValueError(f"chain {self.chain_id!r} has no steps")

    @property
    def n_steps(self) -> int:
        return len(self.steps)

    def _slots_in_order(self) -> list[str]:
        present = {s.slot for s in self.steps}
        return [s for s in _SLOT_ORDER if s in present]

    def _last_per_slot(self, *, correct: bool) -> Mapping[str, str]:
        """The fragment each slot ends with. Later steps overwrite earlier ones
        for the same slot (mechanical recovery). ``correct=True`` builds the
        reference (every slot correct); otherwise the actual candidate."""

        chosen: dict[str, str] = {}
        for step in self.steps:
            chosen[step.slot] = CORRECT[step.slot] if correct else step.fragment()
        return chosen

    def _render(self, chosen: Mapping[str, str]) -> str:
        agg = chosen.get(AGG, CORRECT[AGG])
        preds = [chosen[slot] for slot in self._slots_in_order() if slot in chosen and slot != AGG]
        where = f" WHERE {' AND '.join(preds)}" if preds else ""
        return f"SELECT {agg} FROM sales{where};"

    def candidate_query(self) -> str:
        """The query the chain actually assembled (may contain wrong fragments)."""

        return self._render(self._last_per_slot(correct=False))

    def reference_query(self) -> str:
        """The correct query for exactly the slots this chain fills."""

        return self._render(self._last_per_slot(correct=True))

    def ends_correct(self) -> bool:
        """Whether every slot ends with the correct fragment (the *design*
        expectation). The MEASURED verdict comes from executing both queries;
        this is only used by the instrument self-check to catch a wrong fragment
        that coincidentally yields an equivalent result set."""

        actual = self._last_per_slot(correct=False)
        reference = self._last_per_slot(correct=True)
        return all(actual[s] == reference[s] for s in actual)


# --------------------------------------------------------------------------
# builders — keep the authored set readable and reduce hand-error
# --------------------------------------------------------------------------


def _c(chain_id: str, scenario: str, *steps: ChainStep) -> ChainCase:
    return ChainCase(chain_id=chain_id, scenario=scenario, steps=tuple(steps))


def _step(step_id: str, slot: str, profile: str, wrong: bool = False) -> ChainStep:
    return ChainStep(step_id=step_id, slot=slot, profile=profile, wrong=wrong)


# The canonical slot sequences by length (which slots a chain of length N fills).
_SEQ_2 = (AGG, REGION)
_SEQ_3 = (AGG, REGION, STATUS)
_SEQ_5 = (AGG, REGION, STATUS, AMOUNT_MIN, QTY_MIN)


def _all_correct(chain_id: str, seq: tuple[str, ...], profiles: tuple[str, ...]) -> ChainCase:
    steps = tuple(
        _step(f"{chain_id}.s{i}", slot, prof)
        for i, (slot, prof) in enumerate(zip(seq, profiles))
    )
    return _c(chain_id, "all_correct", *steps)


def _one_wrong(
    chain_id: str, scenario: str, seq: tuple[str, ...],
    profiles: tuple[str, ...], wrong_index: int,
) -> ChainCase:
    steps = tuple(
        _step(f"{chain_id}.s{i}", slot, prof, wrong=(i == wrong_index))
        for i, (slot, prof) in enumerate(zip(seq, profiles))
    )
    return _c(chain_id, scenario, *steps)


def _recover(chain_id: str, seq: tuple[str, ...], profiles: tuple[str, ...],
             repeat_slot: str, wrong_first_profile: str) -> ChainCase:
    """Prepend a wrong step on ``repeat_slot`` that a later correct step in
    ``seq`` overwrites — the chain executes CORRECT despite an intermediate
    wrong/uncertain step (mechanical recovery)."""

    steps = [_step(f"{chain_id}.s0", repeat_slot, wrong_first_profile, wrong=True)]
    steps += [
        _step(f"{chain_id}.s{i + 1}", slot, prof)
        for i, (slot, prof) in enumerate(zip(seq, profiles))
    ]
    return _c(chain_id, "recover", *steps)


# --------------------------------------------------------------------------
# THE CHAIN SET  —  N in {2,3,5} (+3,4,6 for recovers); correct / compound /
# confident-wrong / recover.
#
# SOFT-step wrong fragments are placed so each profile's aggregate wrong-rate
# matches (1 - its confidence) — i.e. the per-step confidences we feed to
# composition are CALIBRATED by construction (chain_eval re-measures and prints
# this). Target counts: soft_095 16 steps / 1 wrong (6%), soft_0875 16 / 2
# (12.5%), soft_075 12 / 3 (25%), soft_uncal 8 / 4 (50%). HARD steps are always
# correct (authoritative; ~0% false-PASS live).
# --------------------------------------------------------------------------

_CHAINS: list[ChainCase] = []

# --- all-correct chains (the bulk): every step right -> chain executes correct.
# These carry the SOFT-CORRECT steps that calibrate each profile's wrong-rate.
_CHAINS += [
    # N=2 (agg, region)
    _all_correct("ac2-hh", _SEQ_2, (HARD_PASS, HARD_PASS)),
    _all_correct("ac2-09", _SEQ_2, (HARD_PASS, SOFT_095)),
    _all_correct("ac2-08", _SEQ_2, (HARD_PASS, SOFT_0875)),
    _all_correct("ac2-07", _SEQ_2, (HARD_PASS, SOFT_075)),
    _all_correct("ac2-0u", _SEQ_2, (HARD_PASS, SOFT_UNCAL)),
    _all_correct("ac2-strong", _SEQ_2, (HARD_STRONG, HARD_STRONG)),
    _all_correct("ac2-weak", _SEQ_2, (HARD_WEAK, HARD_PASS)),
    _all_correct("ac2-09b", _SEQ_2, (SOFT_095, HARD_PASS)),
    _all_correct("ac2-08b", _SEQ_2, (SOFT_0875, HARD_PASS)),
    _all_correct("ac2-07b", _SEQ_2, (HARD_PASS, SOFT_075)),
    _all_correct("ac2-0ub", _SEQ_2, (HARD_PASS, SOFT_UNCAL)),
    _all_correct("ac2-08c", _SEQ_2, (HARD_PASS, SOFT_0875)),
    # N=3 (agg, region, status)
    _all_correct("ac3-hhh", _SEQ_3, (HARD_PASS, HARD_PASS, HARD_PASS)),
    _all_correct("ac3-09", _SEQ_3, (HARD_PASS, HARD_PASS, SOFT_095)),
    _all_correct("ac3-08", _SEQ_3, (HARD_PASS, SOFT_0875, HARD_PASS)),
    _all_correct("ac3-07", _SEQ_3, (HARD_PASS, SOFT_075, HARD_PASS)),
    _all_correct("ac3-098", _SEQ_3, (HARD_PASS, SOFT_095, SOFT_0875)),
    _all_correct("ac3-099", _SEQ_3, (HARD_PASS, SOFT_095, SOFT_095)),
    _all_correct("ac3-088", _SEQ_3, (HARD_PASS, SOFT_0875, SOFT_0875)),
    _all_correct("ac3-strong", _SEQ_3, (HARD_STRONG, HARD_PASS, SOFT_095)),
    _all_correct("ac3-0u", _SEQ_3, (HARD_PASS, SOFT_UNCAL, HARD_PASS)),
    _all_correct("ac3-097", _SEQ_3, (HARD_PASS, SOFT_095, SOFT_075)),
    _all_correct("ac3-077", _SEQ_3, (HARD_PASS, SOFT_075, SOFT_075)),
    _all_correct("ac3-hhh2", _SEQ_3, (HARD_PASS, HARD_PASS, HARD_PASS)),
    # N=5 (agg, region, status, amount_min, qty_min)
    _all_correct("ac5-hhhhh", _SEQ_5, (HARD_PASS,) * 5),
    _all_correct("ac5-m1", _SEQ_5, (HARD_PASS, HARD_PASS, SOFT_095, SOFT_0875, SOFT_095)),
    _all_correct("ac5-m2", _SEQ_5, (HARD_PASS, SOFT_095, SOFT_0875, SOFT_095, SOFT_0875)),
    _all_correct("ac5-m3", _SEQ_5, (HARD_PASS, SOFT_0875, SOFT_095, SOFT_0875, SOFT_095)),
    _all_correct("ac5-07", _SEQ_5, (HARD_PASS, HARD_PASS, SOFT_075, HARD_PASS, SOFT_095)),
    _all_correct("ac5-strong", _SEQ_5, (HARD_STRONG, HARD_PASS, SOFT_0875, SOFT_0875, HARD_PASS)),
    _all_correct("ac5-77", _SEQ_5, (HARD_PASS, HARD_PASS, SOFT_075, SOFT_075, HARD_PASS)),
    _all_correct("ac5-hh2", _SEQ_5, (HARD_PASS,) * 5),
]

# --- compound: a low/mid-confidence SOFT step is wrong and survives -> chain
# executes INCORRECT; the weak link is visible in its OWN confidence.
_CHAINS += [
    _one_wrong("cp2-0u", "compound", _SEQ_2, (HARD_PASS, SOFT_UNCAL), 1),          # 0.50 wrong
    _one_wrong("cp3-0u", "compound", _SEQ_3, (HARD_PASS, SOFT_UNCAL, HARD_PASS), 1),
    _one_wrong("cp5-0u", "compound", _SEQ_5,
               (HARD_PASS, HARD_PASS, SOFT_UNCAL, HARD_PASS, HARD_PASS), 2),
    _one_wrong("cp2-07", "compound", _SEQ_2, (HARD_PASS, SOFT_075), 1),            # 0.75 wrong
    _one_wrong("cp5-07", "compound", _SEQ_5,
               (HARD_PASS, HARD_PASS, SOFT_075, HARD_PASS, HARD_PASS), 2),
]

# --- confident-wrong (the dangerous cases): a HIGH-confidence SOFT step is
# wrong and survives -> chain INCORRECT while the step looked trustworthy.
_CHAINS += [
    _one_wrong("cw3-08", "confident_wrong", _SEQ_3, (HARD_PASS, HARD_PASS, SOFT_0875), 2),  # 0.875
    _one_wrong("cw5-08", "confident_wrong", _SEQ_5,
               (HARD_PASS, SOFT_0875, HARD_PASS, HARD_PASS, HARD_PASS), 1),                 # 0.875
    _one_wrong("cw3-09", "confident_wrong", _SEQ_3, (HARD_PASS, SOFT_095, HARD_PASS), 1),   # 0.955
]

# --- recover: a wrong SOFT step is overwritten by a later correct step ->
# chain executes CORRECT despite the low/uncertain intermediate step.
_CHAINS += [
    _recover("rc-region-0u", _SEQ_2, (HARD_PASS, HARD_PASS), REGION, SOFT_UNCAL),   # N=3
    _recover("rc-region-07", _SEQ_3, (HARD_PASS, HARD_PASS, HARD_PASS), REGION, SOFT_075),  # N=4
]

CHAINS: tuple[ChainCase, ...] = tuple(_CHAINS)

CHAIN_SET_VERSION = f"composition-chains-v1 ({len(CHAINS)} chains)"


__all__ = [
    "ChainStep",
    "ChainCase",
    "CHAINS",
    "CHAIN_SET_VERSION",
    "SCHEMA_SQL",
    "FIXTURE_SQL",
    "CORRECT",
    "WRONG",
    "PROFILE_TIER",
    "HARD_PROFILES",
    "HARD_PASS",
    "HARD_STRONG",
    "HARD_WEAK",
    "SOFT_UNCAL",
    "SOFT_075",
    "SOFT_0875",
    "SOFT_095",
    "AGG",
    "REGION",
    "STATUS",
    "AMOUNT_MIN",
    "QTY_MIN",
]
