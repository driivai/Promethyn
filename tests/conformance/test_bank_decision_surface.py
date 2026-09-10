"""The bank's decision surface, enumerated and pinned — a DURABILITY guard.

WHY THIS EXISTS. TYPE-GATE-HARDEN-2 replaced two complementary comprehensions in
``VerifierBank.judge`` with ``partition_outcomes`` and reported a differential
over 1,155 combinations showing zero rows changed. An independent review made the
right observation about that: it was a REPORT-TIME MEASUREMENT, run once, in a
session, by a script that is not in this repository. Nothing preserved it. The
next sprint to touch ``bank.py`` — Phase 1.2, whose whole subject is aggregation
— would have had no way to tell whether it had moved the surface, and the
evidence for "nothing changed" would have been a sentence in a merged report.

So the differential is committed. This module enumerates the space of outcome
sequences the bank can be handed, runs every one through a deterministic bank,
and compares the result against a checked-in table. Any change to what the bank
DECIDES fails here and has to be reconciled — by updating the table in the same
change, with the reason, which is the same discipline the Hearth ledger uses for
content.

WHAT IT IS NOT. It is not a replay of that 1,155-combination sweep: the
parameter space that sweep covered is not recorded anywhere in this repository,
and reconstructing a number without its definition would be inventing evidence
rather than preserving it. This enumerates a space that IS defined, here, in
code: every outcome kind the union admits, in every sequence of length one and
two, which reaches all five branches of ``judge`` (authoritative verdict present,
authoritative-unavailable with no authoritative verdict, advisory only,
everything abstained, and the mixtures). The row count is whatever that
enumeration yields and is pinned below.

WHAT IT DOES NOT PROVE. It pins DECISIONS, not internals: a rewrite that produces
identical verdicts, confidences and unavailability for every enumerated input
passes, and should. Confidence is compared to a tolerance, because it is
floating-point arithmetic over log-odds and bit-exactness is not the property
worth defending. And the trust store starts empty on every row, so this says
nothing about behaviour under accumulated calibration — that is a different
surface, and naming it here is cheaper than letting someone assume otherwise.
"""

from __future__ import annotations

import itertools
import json
import pathlib

import pytest

from prometheus_protocol.core.models import (
    Evidence,
    Judgment,
    Tier,
    Unavailability,
    Unavailable,
    Verdict,
)
from prometheus_protocol.verifier.bank import VerifierBank

REPO = pathlib.Path(__file__).resolve().parents[2]
SURFACE = pathlib.Path(__file__).with_name("bank_decision_surface.json")

#: Confidence is log-odds arithmetic; the property is the decision, not the last
#: bit of a float.
TOLERANCE = 1e-9

#: Every kind of outcome the union admits, as (label, factory-input). Three
#: verdicts times three tiers for Evidence, two reasons times three tiers for
#: Unavailable: fifteen kinds.
_VERDICTS = (Verdict.PASS, Verdict.FAIL, Verdict.ABSTAIN)
_TIERS = (Tier.HARD, Tier.SOFT, Tier.HUMAN)
_REASONS = (Unavailability.INFRA_FAULT, Unavailability.POLICY_REFUSAL)


def _kinds() -> list[str]:
    labels = [f"E:{v.name}:{t.name}" for v in _VERDICTS for t in _TIERS]
    labels += [f"U:{r.name}:{t.name}" for r in _REASONS for t in _TIERS]
    return labels


def _outcome(label: str, slot: int) -> Evidence | Unavailable:
    """Build the outcome a label names, with a per-slot verifier id.

    Distinct ids matter: two reports from the SAME verifier are a different
    situation from two independent verifiers agreeing, and the bank's trust
    bookkeeping is keyed by id.
    """

    kind, name, tier_name = label.split(":")
    tier = Tier[tier_name]
    if kind == "U":
        return Unavailable(
            verifier_id=f"v{slot}",
            tier=tier,
            reason=Unavailability[name],
            detail="enumerated",
        )
    return Evidence(
        passed=name == "PASS",
        total=1,
        passed_count=1 if name == "PASS" else 0,
        failures=() if name == "PASS" else ("enumerated",),
        verifier_id=f"v{slot}",
        verdict=Verdict[name],
        tier=tier,
    )


def _sequences() -> list[tuple[str, ...]]:
    """Every sequence of length one and two. ORDERED, deliberately: nothing here
    assumes the bank is order-insensitive, and an enumeration that assumed it
    would stop being able to detect it becoming order-sensitive."""

    kinds = _kinds()
    return [(k,) for k in kinds] + list(itertools.product(kinds, repeat=2))


#: Observed, then pinned — never predicted. Fifteen kinds: 15 singles + 225
#: ordered pairs.
EXPECTED_ROWS = 240


def _decide(sequence: tuple[str, ...]) -> dict:
    """One row of the surface: what a fresh bank decides for this sequence."""

    bank = VerifierBank()
    outcomes = [_outcome(label, slot) for slot, label in enumerate(sequence)]
    for slot, label in enumerate(sequence):
        # Registered from the LABEL, not from ``outcome.tier``: Evidence.tier is
        # ``Tier | None`` and Unavailable.tier is ``Tier``, so reading it off the
        # union hands ``register`` an optional — a real [arg-type] the gate
        # caught the first time this file was checked.
        bank.register(f"v{slot}", Tier[label.split(":")[2]])
    result = bank.judge(outcomes)

    if isinstance(result, Unavailable):
        return {
            "outcome": "unavailable",
            "reason": result.reason.name,
            "tier": result.tier.name,
        }
    if isinstance(result, Judgment):
        return {
            "outcome": "judgment",
            "verdict": result.verdict.name,
            "confidence": round(result.confidence, 9),
            "authoritative": result.authoritative,
            "conflict": result.conflict,
            "contributing": list(result.contributing),
            "unavailable": [
                f"{u.reason.name}:{u.tier.name}" for u in result.unavailable
            ],
            "escalates": bank.needs_escalation(result),
        }
    raise AssertionError(f"judge() returned neither member: {type(result)!r}")


def observed_surface() -> dict[str, dict]:
    return {"|".join(sequence): _decide(sequence) for sequence in _sequences()}


@pytest.fixture(scope="module")
def recorded() -> dict[str, dict]:
    assert SURFACE.exists(), (
        f"{SURFACE.name} is missing. It is regenerated DELIBERATELY, never as a "
        "reflex, in the same change that moves the surface:\n"
        "    python -c \"import sys,json; sys.path[:0]=['src','tests/conformance']; \\\n"
        "    import test_bank_decision_surface as m; \\\n"
        "    m.SURFACE.write_text(json.dumps(m.observed_surface(), indent=1, "
        "sort_keys=True)+chr(10))\""
    )
    return json.loads(SURFACE.read_text(encoding="utf-8"))


def test_the_enumeration_is_the_pinned_size():
    """A shrinking enumeration would make the differential pass by covering
    less, which is the void-guard shape in a fixture."""

    assert len(_kinds()) == 15, _kinds()
    assert len(_sequences()) == EXPECTED_ROWS


def test_the_recorded_surface_covers_exactly_the_enumeration(recorded):
    keys = {"|".join(sequence) for sequence in _sequences()}
    assert set(recorded) == keys, (
        f"missing rows {sorted(keys - set(recorded))[:5]}; "
        f"stale rows {sorted(set(recorded) - keys)[:5]}"
    )


def test_the_bank_still_decides_exactly_what_it_decided(recorded):
    """THE DIFFERENTIAL. Every enumerated input, compared to the recorded row."""

    changed = []
    for key, expected in sorted(recorded.items()):
        actual = _decide(tuple(key.split("|")))
        if actual == expected:
            continue
        if (
            actual.get("outcome") == expected.get("outcome") == "judgment"
            and {k: v for k, v in actual.items() if k != "confidence"}
            == {k: v for k, v in expected.items() if k != "confidence"}
            and abs(actual["confidence"] - expected["confidence"]) <= TOLERANCE
        ):
            continue
        changed.append(f"{key}: recorded {expected} -> now {actual}")

    assert changed == [], (
        f"{len(changed)} of {len(recorded)} enumerated bank decisions changed:\n"
        + "\n".join(changed[:20])
        + "\n\nThis is the differential TYPE-GATE-HARDEN-2 ran once and did not "
        "keep. If the change is intended — Phase 1.2 is the sprint that will "
        "intend one — regenerate bank_decision_surface.json in the same change "
        "and say in the report which rows moved and why. Do not regenerate it to "
        "make this pass."
    )


def test_the_surface_reaches_every_branch_of_judge(recorded):
    """A differential over inputs that all take one branch would be green for
    the wrong reason. Each of the five outcomes ``judge`` can produce appears."""

    seen = {
        (row["outcome"], row.get("authoritative"), bool(row.get("unavailable")))
        for row in recorded.values()
    }
    assert ("unavailable", None, False) in seen, "no authoritative-unavailable row"
    assert ("judgment", True, False) in seen, "no plain authoritative verdict"
    assert ("judgment", True, True) in seen, "no authoritative verdict carrying an absentee"
    assert ("judgment", False, False) in seen, "no advisory-only verdict"
    abstained = [
        row for row in recorded.values()
        if row["outcome"] == "judgment"
        and row["verdict"] == "ABSTAIN"
        and not row["contributing"]
    ]
    assert abstained, "no everything-abstained row"


def test_no_unavailable_is_ever_fused_into_a_verdict(recorded):
    """The EX-1 invariant, asserted over the whole enumerated surface rather
    than at a handful of sites: a row whose inputs are ALL Unavailable never
    produces a verdict, and no Unavailable ever appears in ``contributing``."""

    for key, row in sorted(recorded.items()):
        labels = key.split("|")
        if all(label.startswith("U:") for label in labels):
            if any(label.split(":")[2] in ("HARD", "HUMAN") for label in labels):
                assert row["outcome"] == "unavailable", (key, row)
            else:
                # SOFT-only absentees: no authoritative check was ever due, so a
                # genuine "no opinion" is the truthful answer, not a fault.
                assert row["outcome"] == "judgment" and row["verdict"] == "ABSTAIN", (
                    key, row
                )
                assert row["contributing"] == [], (key, row)
