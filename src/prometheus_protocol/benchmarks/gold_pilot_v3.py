"""gold-set-v3 PILOT — 20 hand-labeled grounding items (construction proof).

This is the pilot for the harder gold set motivated by
``docs/soft-calibration-adoption-rule.md`` (the current sets are too small to
adopt anything). It does NOT power any adoption — 20 items cannot — it exists to
prove the construction protocol (``docs/gold-set-v3-protocol.md``) and, if a live
independent-arm run surfaces even one false-PASS, to put a nonzero numerator
under the 0% floor the whole project's load-bearing claim rests on.

The adversarial selection criterion is stricter than grounding-v2's: each
not-supported item is chosen to plausibly slip past an **independent** judge —
the paraphrase or inference a careful, fluent grader of a *different* family
might still wave through — not merely a trap that is hard for the actor's own
family. The correct label stays unambiguous to a careful reader; each item
carries its gold rationale in ``note`` (there is nothing to execute — the gold
label IS the reference).

HELD OUT BY CONSTRUCTION. Like every grounding eval set, these items are
reference-side only: they are never shown to a proposer and never enter a
promotion/training path, so the held-out firewall applies trivially — this set
is all evaluation, no training. (Protocol §"firewall".)

Trap taxonomy used here (superset of grounding-v2's, with the sprint's names):
unstated-inference, quantifier-drift, partial-support, negation-flip,
near-miss-aggregation, scope-creep, causation-from-correlation, hedge-stripping,
wrong-attribution (a.k.a. correct-claim-wrong-citation), temporal-near-miss;
supported: stated, entailed-subtle.
"""

from __future__ import annotations

from prometheus_protocol.benchmarks.grounding_items import (
    GOLD_NOT_SUPPORTED,
    GOLD_SUPPORTED,
    GroundingEvalItem,
)

GOLD_PILOT_V3_VERSION = "gold-pilot-v3 (20 items)"

TRAP_CATEGORIES_V3 = (
    "unstated-inference",
    "quantifier-drift",
    "partial-support",
    "negation-flip",
    "near-miss-aggregation",
    "scope-creep",
    "causation-from-correlation",
    "hedge-stripping",
    "wrong-attribution",
    "temporal-near-miss",
)
SUPPORT_CATEGORIES_V3 = ("stated", "entailed-subtle")

_SOURCES: dict[str, str] = {
    "clinic": """\
Clinic notice. The walk-in clinic on Bregar Street is open Monday to Friday
08:00-18:00, and Saturday mornings 09:00-12:00. It is closed on Sundays and
public holidays. Appointments are not required for walk-in visits but can be
made by phone. The clinic offers vaccinations, minor-injury care, and blood
tests; it does not provide dental or maternity services. Wait times are usually
under 30 minutes on weekday mornings. Parking is limited to 90 minutes.""",
    "quarter": """\
Quarterly note. Northwind reported revenue of $4.2M in Q3, up from $3.5M in Q2.
Operating costs were $3.9M. The company added 12 employees, bringing headcount
to 60. Two of its five regional offices moved to larger premises. The board
declared no dividend. Management expects Q4 revenue to be 'broadly similar' to
Q3.""",
    "study": """\
Study summary. In a survey of 200 commuters, 130 said they would use a proposed
bypass road at least weekly. Support was higher among drivers (75%) than
cyclists (28%). The report notes the survey was run online over one weekend and
was not weighted for demographics. The authors recommend a larger study before
any decision.""",
}


def _item(item_id, source_id, claim, gold, category, note) -> GroundingEvalItem:
    return GroundingEvalItem(
        item_id=item_id, source_id=source_id, source=_SOURCES[source_id],
        claim=claim, gold=gold, category=category, note=note,
    )


_N = GOLD_NOT_SUPPORTED
_S = GOLD_SUPPORTED


def build_gold_pilot_v3() -> tuple[GroundingEvalItem, ...]:
    return (
        # --- clinic (source) ---
        _item("p01", "clinic", "The clinic is busiest on weekday afternoons.", _N,
              "unstated-inference",
              "Source gives wait times only for weekday MORNINGS; it says nothing "
              "about afternoons being busiest — a plausible but unstated inference."),
        _item("p02", "clinic", "Wait times at the clinic are always under 30 minutes.", _N,
              "quantifier-drift",
              "Source: 'usually under 30 minutes on weekday mornings'. The claim "
              "drops 'usually' and the morning qualifier — usually→always."),
        _item("p03", "clinic", "The clinic offers vaccinations and dental check-ups.", _N,
              "partial-support",
              "Vaccinations: yes. Dental: the source explicitly says it does NOT "
              "provide dental services. ~half right rides a false half through."),
        _item("p04", "clinic", "Appointments cannot be made for the clinic.", _N,
              "negation-flip",
              "Source: appointments 'can be made by phone'. The claim inverts the "
              "polarity — a confident negation of a stated fact."),
        _item("p05", "clinic", "The clinic is open on Saturday afternoons.", _N,
              "temporal-near-miss",
              "Saturday hours are MORNINGS 09:00-12:00 only; afternoon is outside "
              "the source's own stated window."),
        _item("p06", "clinic", "The walk-in clinic is closed on Sundays.", _S,
              "stated",
              "Verbatim: 'It is closed on Sundays and public holidays.'"),
        _item("p07", "clinic",
              "If a public holiday falls on a Saturday, the clinic is closed that day.", _S,
              "entailed-subtle",
              "Entailed by combining 'open Saturday mornings' with 'closed on "
              "public holidays' — the holiday closure governs. Requires composition."),
        # --- quarter (source) ---
        _item("p08", "quarter", "Northwind's Q3 operating profit was $0.4M.", _N,
              "near-miss-aggregation",
              "Revenue $4.2M - operating costs $3.9M = $0.3M, not $0.4M. Catching "
              "it requires doing the subtraction."),
        _item("p09", "quarter", "Northwind expects revenue to keep growing into Q4.", _N,
              "unstated-inference",
              "Management expects Q4 'broadly similar' to Q3 (flat) — the opposite "
              "of continued growth; a reader projects the Q2→Q3 trend the source stops."),
        _item("p10", "quarter", "Management expects Q4 revenue to match Q3 exactly.", _N,
              "hedge-stripping",
              "Source hedges: 'broadly similar'. 'match ... exactly' strips a "
              "genuine hedge into a precise claim."),
        _item("p11", "quarter",
              "Northwind moved all five of its regional offices to larger premises.", _N,
              "scope-creep",
              "Only TWO of five offices moved; 'all five' widens a subset to the whole."),
        _item("p12", "quarter",
              "Northwind added staff in Q3 because its revenue grew.", _N,
              "causation-from-correlation",
              "The source states both the hire and the revenue rise but asserts no "
              "causal link between them — cause read from adjacency."),
        _item("p13", "quarter", "Northwind's revenue grew 20% from Q2 to Q3.", _S,
              "entailed-subtle",
              "4.2 / 3.5 = 1.20 exactly — a 20% increase. Entailed by arithmetic."),
        _item("p14", "quarter", "Northwind's board declared no dividend.", _S,
              "stated", "Verbatim: 'The board declared no dividend.'"),
        # --- study (source) ---
        _item("p15", "study",
              "A majority of surveyed commuters said they support building the bypass.", _N,
              "unstated-inference",
              "The survey asked willingness to USE the road ('would use ... at "
              "least weekly'), not support for BUILDING it — a conflation the "
              "source does not make."),
        _item("p16", "study",
              "Most surveyed cyclists said they would use the bypass weekly.", _N,
              "wrong-attribution",
              "28% of cyclists — not 'most'. The 'most' figure (75%) belongs to "
              "drivers; the right quantity is attached to the wrong group."),
        _item("p17", "study", "The study shows the bypass would be well used.", _N,
              "hedge-stripping",
              "The authors caveat heavily (online, one weekend, unweighted, "
              "'recommend a larger study') — 'shows' overstates a hedged survey."),
        _item("p18", "study", "The report recommends building the bypass.", _N,
              "wrong-attribution",
              "The authors recommend a LARGER STUDY before any decision — a real "
              "recommendation, cited as the wrong one (correct-claim-wrong-citation)."),
        _item("p19", "study", "The survey was conducted online.", _S,
              "stated", "Verbatim: the survey 'was run online over one weekend'."),
        _item("p20", "study",
              "Fewer than a third of surveyed cyclists said they would use the bypass weekly.", _S,
              "entailed-subtle",
              "28% < 33.3%. Entailed, but only if the reader does the comparison "
              "rather than pattern-matching 'cyclists' to a rejection."),
    )


def gold_split() -> tuple[int, int]:
    """(gold-negative, gold-positive) counts — the false-PASS / false-FAIL denominators."""

    items = build_gold_pilot_v3()
    neg = sum(1 for i in items if i.gold == GOLD_NOT_SUPPORTED)
    return neg, len(items) - neg


def main(argv=None) -> int:
    """Offline plumbing proof: the pilot loads, is well-formed, and wires into the
    grounding harness. A REAL independent-arm measurement is an operator dispatch
    (deferred — see docs/gold-set-v3-protocol.md); nothing here judges anything."""

    items = build_gold_pilot_v3()
    neg, pos = gold_split()
    print(f"=== {GOLD_PILOT_V3_VERSION} ===")
    print(f"items: {len(items)}  gold-negative (traps): {neg}  gold-positive: {pos}")
    cats: dict[str, int] = {}
    for it in items:
        cats[it.category] = cats.get(it.category, 0) + 1
    print("categories: " + ", ".join(f"{k}={v}" for k, v in sorted(cats.items())))
    print("\n[note] a real independent-arm run is deferred to an operator dispatch; "
          "this is a construction/plumbing check, not a judge measurement.")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via main() in tests
    raise SystemExit(main())
