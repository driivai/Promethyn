"""The gold-labeled grounding item set: claims judged against sources.

Each item is (source text, candidate claim, gold label). The gold label —
``supported`` or ``not-supported`` — is a curated human reference: it is what
makes the soft grounding judge MEASURABLE (the admissions test in
``grounding_eval``) in a domain where ground truth is **not executable**.
There is no program whose output decides these labels; they are the labelled
reference itself, reviewed by a person. That is the deliberate, documented
difference from the code and SQL domains.

The not-supported items are built the way the SQL set's designed-wrong probes
were: PLAUSIBLE. Each makes the kind of mistake a fluent summarizer actually
makes — the claim sounds like the source, and a lazy grader passes it. The
trap taxonomy:

* ``number-drift`` — a quantity silently changed;
* ``temporal-overreach`` — a bounded time claim stretched beyond its bound;
* ``unstated-causation`` — a cause asserted where the source states none;
* ``source-silent`` — right topic, but the specific fact is simply absent;
* ``over-generalization`` — a specific statement widened past the source;
* ``swapped-entity`` — the right fact attached to the wrong thing (or the
  relation reversed);
* ``negation-flip`` — the source's polarity inverted;
* ``wrong-fact`` — right topic, different stated value;
* ``hedge-to-assertion`` — the source's "expected/likely" stated as fact;
* ``aggregation-error`` — "all/none" where the source has an exception.

Supported items carry categories too (``stated``, ``paraphrase``,
``combination`` — the last requires joining two stated facts), so false-FAIL
can be broken down as well. Sources are invented and self-contained; no item
depends on outside knowledge, which is exactly what the judge is instructed
to exclude.
"""

from __future__ import annotations

from dataclasses import dataclass

from prometheus_protocol.verifier.grounding import GroundingTask

GROUNDING_ITEM_SET_VERSION = "grounding-v1 (44 items)"

GOLD_SUPPORTED = "supported"
GOLD_NOT_SUPPORTED = "not-supported"
GOLD_LABELS = (GOLD_SUPPORTED, GOLD_NOT_SUPPORTED)

#: Trap categories a not-supported item may carry (see module docstring).
TRAP_CATEGORIES = (
    "number-drift",
    "temporal-overreach",
    "unstated-causation",
    "source-silent",
    "over-generalization",
    "swapped-entity",
    "negation-flip",
    "wrong-fact",
    "hedge-to-assertion",
    "aggregation-error",
)
#: Categories a supported item may carry.
SUPPORT_CATEGORIES = ("stated", "paraphrase", "combination")


@dataclass(frozen=True)
class GroundingEvalItem:
    """One gold-labeled grounding judgment: is the claim entailed by the source?"""

    item_id: str
    source_id: str
    source: str
    claim: str
    gold: str
    category: str
    note: str


_FESTIVAL = """\
Harbor festival notice. The annual harbor festival takes place on Saturday
12 April, starting at 10:00. The boat parade is at noon. Admission is free.
The pier is closed to vehicles from 08:00 on the day. If it rains, stage
events move to the community hall. Thirty stalls have been booked. The
festival has been organized by the harbor association since 1987."""

_GLASSWORKS = """\
Works memo. The Vetra glassworks will shut furnace 2 for relining for three
weeks in May; furnace 1 continues to operate. Output is expected to drop by a
fifth during the work. Ten temporary contractors have been hired. The site
passed its safety audit in March. Shipping schedules are unaffected."""

_WREN_LOG = """\
Garden log. A pair of wrens nested in the elm on 3 June and laid five eggs.
Four had hatched by 19 June; one egg did not hatch. The chicks were fed
mainly caterpillars. They fledged on 2 July. The elm also has an old
woodpecker hole, unoccupied this season."""

_TRAM = """\
City transit notice. The line 4 extension adds three stops and opens in
autumn. Night service on the extension runs on Fridays and Saturdays only.
Fares are unchanged this year. Sixty percent of the new track was laid with
recycled rails. The mural at the depot was painted by local students."""

_ORCHARD = """\
Harvest report. The orchard picked twelve tonnes of apples this season, up
from nine last year. Pears were flat at four tonnes. A late frost thinned
the plum crop. Two new cold rooms were installed over winter. Cider pressing
begins in October. Eight pickers are employed in season."""

_OBSERVATORY = """\
Observatory bulletin. The hillside observatory has reopened after a two-year
renovation. The main dome now houses an 80 cm reflector, replacing the 60 cm
instrument, which was donated to a university. Public open nights are held on
the first Friday of each month; school groups visit by booking. Entry is by
donation."""

_SOURCES = {
    "festival": _FESTIVAL,
    "glassworks": _GLASSWORKS,
    "wren-log": _WREN_LOG,
    "tram": _TRAM,
    "orchard": _ORCHARD,
    "observatory": _OBSERVATORY,
}


def _item(item_id: str, source_id: str, claim: str, gold: str,
          category: str, note: str) -> GroundingEvalItem:
    return GroundingEvalItem(
        item_id=item_id,
        source_id=source_id,
        source=_SOURCES[source_id],
        claim=claim,
        gold=gold,
        category=category,
        note=note,
    )


def build_grounding_items() -> tuple[GroundingEvalItem, ...]:
    S, N = GOLD_SUPPORTED, GOLD_NOT_SUPPORTED
    return (
        # -- festival ------------------------------------------------------
        _item("g01", "festival", "Admission to the festival is free.",
              S, "stated", "verbatim fact"),
        _item("g02", "festival", "The boat parade takes place at midday.",
              S, "paraphrase", "noon -> midday"),
        _item("g03", "festival",
              "The festival, organized by the harbor association, begins at 10:00.",
              S, "combination", "joins organizer + start time"),
        _item("g04", "festival", "The festival has more than forty stalls.",
              N, "number-drift", "thirty booked"),
        _item("g05", "festival", "The pier is closed to vehicles all week.",
              N, "temporal-overreach", "closed from 08:00 on the day only"),
        _item("g06", "festival",
              "The pier is closed to vehicles because of past accidents.",
              N, "unstated-causation", "no reason is given"),
        _item("g07", "festival", "Parking is available at the community hall.",
              N, "source-silent", "hall mentioned; parking never"),
        _item("g08", "festival",
              "The harbor association organizes all events in the town.",
              N, "over-generalization", "only this festival is attributed"),
        # -- glassworks ----------------------------------------------------
        _item("g09", "glassworks",
              "Furnace 2 will be out of service for about three weeks.",
              S, "stated", "verbatim fact"),
        _item("g10", "glassworks",
              "Production is expected to fall by roughly twenty percent during the work.",
              S, "paraphrase", "a fifth -> twenty percent"),
        _item("g11", "glassworks",
              "Temporary contractors have been brought in for the relining period.",
              S, "paraphrase", "ten hired"),
        _item("g12", "glassworks", "Furnace 1 will be relined in May.",
              N, "swapped-entity", "furnace 2 is relined; 1 keeps running"),
        _item("g13", "glassworks",
              "Shipping schedules will be affected by the relining.",
              N, "negation-flip", "source says unaffected"),
        _item("g14", "glassworks", "Output will drop by exactly one fifth.",
              N, "hedge-to-assertion", "source says EXPECTED to drop"),
        _item("g15", "glassworks", "The safety audit takes place in May.",
              N, "wrong-fact", "passed in March"),
        _item("g16", "glassworks", "The contractors will operate furnace 1.",
              N, "source-silent", "contractor duties are unstated"),
        # -- wren log ------------------------------------------------------
        _item("g17", "wren-log", "Four of the five eggs hatched.",
              S, "stated", "verbatim fact"),
        _item("g18", "wren-log", "The wren chicks left the nest at the start of July.",
              S, "paraphrase", "fledged on 2 July"),
        _item("g19", "wren-log", "The chicks' diet was mostly caterpillars.",
              S, "paraphrase", "fed mainly caterpillars"),
        _item("g20", "wren-log", "All the eggs in the elm hatched.",
              N, "aggregation-error", "one egg did not"),
        _item("g21", "wren-log", "A woodpecker raised chicks in the elm this season.",
              N, "swapped-entity", "the hole was unoccupied"),
        _item("g22", "wren-log", "The wrens laid six eggs.",
              N, "number-drift", "five laid"),
        _item("g23", "wren-log",
              "One egg failed to hatch because the weather turned cold.",
              N, "unstated-causation", "no cause is given"),
        # -- tram ----------------------------------------------------------
        _item("g24", "tram", "Fares will stay the same this year.",
              S, "stated", "verbatim fact"),
        _item("g25", "tram", "The extension adds three new stops.",
              S, "stated", "verbatim fact"),
        _item("g26", "tram",
              "The line 4 extension, which opens in autumn, uses recycled rails "
              "for more than half of its new track.",
              S, "combination", "joins opening season + sixty percent"),
        _item("g27", "tram", "Fares will never increase.",
              N, "temporal-overreach", "unchanged THIS YEAR only"),
        _item("g28", "tram", "The extension runs a night service every day.",
              N, "over-generalization", "Fridays and Saturdays only"),
        _item("g29", "tram", "The depot mural was painted by a visiting artist.",
              N, "wrong-fact", "local students painted it"),
        _item("g30", "tram", "About sixteen percent of the new track uses recycled rails.",
              N, "number-drift", "sixty percent, digits swapped"),
        # -- orchard -------------------------------------------------------
        _item("g31", "orchard", "The apple harvest rose compared with last year.",
              S, "paraphrase", "twelve up from nine"),
        _item("g32", "orchard", "Pear volumes were unchanged at four tonnes.",
              S, "stated", "verbatim fact"),
        _item("g33", "orchard", "Cider pressing starts in October.",
              S, "stated", "verbatim fact"),
        _item("g34", "orchard",
              "Apple volumes rose because of the new cold rooms.",
              N, "unstated-causation", "both stated; the link is not"),
        _item("g35", "orchard", "A late frost thinned the apple crop.",
              N, "swapped-entity", "the frost thinned the PLUM crop"),
        _item("g36", "orchard", "The orchard picked twelve tonnes of pears.",
              N, "number-drift", "twelve is the APPLE figure; pears were four"),
        _item("g37", "orchard",
              "The eight pickers are hired from the neighboring village.",
              N, "source-silent", "their origin is unstated"),
        # -- observatory ---------------------------------------------------
        _item("g38", "observatory",
              "The new reflector is larger than the instrument it replaced.",
              S, "combination", "80 cm vs 60 cm, both stated"),
        _item("g39", "observatory", "Public open nights happen once a month.",
              S, "paraphrase", "first Friday of each month"),
        _item("g40", "observatory", "The old telescope went to a university.",
              S, "paraphrase", "donated to a university"),
        _item("g41", "observatory",
              "School groups may drop in without booking.",
              N, "negation-flip", "school groups visit BY booking"),
        _item("g42", "observatory", "The renovation took five years.",
              N, "wrong-fact", "two years"),
        _item("g43", "observatory",
              "The observatory is open to the public every Friday.",
              N, "over-generalization", "first Friday of the month only"),
        _item("g44", "observatory",
              "A university donated a telescope to the observatory.",
              N, "swapped-entity", "the donation ran the other way"),
    )


def task_for(item: GroundingEvalItem) -> GroundingTask:
    """The runtime-shaped task for one eval item (source only — never the gold)."""

    return GroundingTask(id=f"grounding/{item.item_id}", source=item.source)
