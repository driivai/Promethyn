"""grounding-v2: the harder, discriminating grounding item set.

grounding-v1 produced a CEILING: both the correlated and the independent
judge scored 0/26 false-PASS — every trap caught — which cannot separate
judge quality from set easiness (exactly the pattern sql-v1 and live-v1
showed before harder items were built). This set exists to break that
ceiling: every not-supported item here is engineered to be *nearly* right —
the mistake a fluent, well-meaning summarizer makes and a shallow grader
passes — while the correct label remains unambiguous to a careful reader.

The subtle trap families (harder than v1's):

* ``quantifier-drift`` — the source's "some/often/most" strengthened one
  notch ("most/usually/nearly all");
* ``scope-creep`` — a statement true of a stated subset asserted of the
  whole;
* ``unstated-inference`` — the conclusion a reasonable reader would draw,
  which the source nevertheless does not state (the hardest and most
  important family);
* ``wrong-attribution`` — the right fact attached to the wrong actor, where
  both attributions are plausible;
* ``partial-support`` — a claim ~80% grounded, with one unstated qualifier
  or condition riding along;
* ``near-miss-aggregation`` — a derived quantity slightly wrong: catching it
  requires actually doing the arithmetic;
* ``temporal-near-miss`` — a time claim wrong only against the source's own
  frame (unstated "now", bounded windows, quarter-vs-month);
* ``hedge-stripping`` — a genuinely hedged source stated a shade too
  confidently (subtler than v1's expected→exactly);
* ``causation-from-correlation`` — adjacency or credit stated as cause,
  phrased cautiously enough to tempt.

A few deliberately EASY not-supported controls (category ``easy-control``)
anchor the scale, and the supported items include ``entailed-subtle`` cases
(entailments that require arithmetic or careful reading), so a judge that
protects itself by rejecting everything pays a measurable false-FAIL price.

LABEL INTEGRITY. Ground truth here is a curated human reference — there is
nothing to execute — so every item carries its gold rationale in ``note``,
and the whole set went through an adversarial label-review pass: each trap
was independently attacked with the question "could a reasonable, careful
reader legitimately argue the opposite label?" Items that failed that test
were rewritten or removed before this file was committed; an ambiguous
faithfulness item is worse than an easy one, because a judge error and a
label error become indistinguishable. The residual limit stands: these
labels are reviewable human judgment, shipped in-repo so disputes are diffs.
"""

from __future__ import annotations

from prometheus_protocol.benchmarks.grounding_items import (
    GOLD_NOT_SUPPORTED,
    GOLD_SUPPORTED,
    GroundingEvalItem,
)

GROUNDING_ITEM_SET_VERSION_V2 = "grounding-v2 (64 items)"

#: The subtle trap families of this set (see module docstring), plus the
#: deliberately easy anchors.
TRAP_CATEGORIES_V2 = (
    "quantifier-drift",
    "scope-creep",
    "unstated-inference",
    "wrong-attribution",
    "partial-support",
    "near-miss-aggregation",
    "temporal-near-miss",
    "hedge-stripping",
    "causation-from-correlation",
    "easy-control",
)
SUPPORT_CATEGORIES_V2 = (
    "stated",
    "paraphrase",
    "entailed-combination",
    "entailed-subtle",
)

_WATER = """\
Millbrook municipal water report. The treatment plant processed an average
of 12.4 million litres per day, peaking at 16.1 million litres during the
July fair week. Nitrate levels were within the national limit in eleven of
twelve monthly samples; the February sample exceeded the limit, and a
re-test one week later was within it. The report attributes the February
reading to agricultural runoff after unusually heavy rain, citing the
regional laboratory's analysis. Two of the town's five wells were taken
offline in autumn for scheduled maintenance; both returned to service
within the quarter. Residents on private wells are advised to test
annually."""

_STATION = """\
Kestrel Ridge research station newsletter. The station has operated
continuously since March 2021. Its weather mast records temperature and
wind every ten minutes; readings are transmitted daily, and station staff
review them each weekday morning. This spring the station hosted twelve
visiting researchers, most of them for stays of two weeks or less. The
glacier survey, run jointly with the valley museum, found the ice margin
had retreated eight metres since the previous survey three years earlier.
Snowfall was frequent in April, and staff often reached the mast on skis.
A new bunk room, finished in May, raised overnight capacity from six to
nine."""

_COOP = """\
Ovenshare bakery cooperative, annual note. Membership stood at 84
households, up from 71 the year before. The committee believes the new
Saturday market stall contributed to the rise, though it notes the
neighbouring district's cooperative grew by a similar amount without one.
Flour costs rose by roughly a tenth, and the committee expects prices may
need to rise next year if costs continue to climb. The wood-fired oven,
rebuilt two winters ago, now bakes about three hundred loaves a week.
Volunteers staff the stall on most Saturdays; twice it closed for lack of
volunteers."""

_LIBRARY = """\
Renovation update, Harden Street library. The children's wing reopened in
June after four months of work; the upper reading room remains closed and
is expected to reopen in the autumn. Lending of children's titles in July
was the highest for any month on record. The architect praised the
builders' handling of the original beams, and the council's heritage
officer signed off on the completed wing. Saturday opening hours were
extended by two hours. A fundraising drive covered a fifth of the
renovation cost; the remainder came from the council."""

_FERRY = """\
Ferry service review, Saltmere route. The crossing ran on 361 of 365
scheduled days; the four cancellations were all weather-related, and all
fell in the first quarter. Average occupancy was 58 percent across the
year, rising to 92 percent on summer weekends. The operator introduced a
second sailing on Fridays from May onward. Ticket prices were unchanged
for the third consecutive year. Some passengers surveyed asked for a later
final departure; the operator said it would review the timetable."""

_GARDEN = """\
Minutes of the Fernway community garden. Twenty-two of the thirty plots
were cultivated this season. The water butts installed last year
overflowed twice during storms, and the committee agreed to fit lids.
Slug damage was reported by plot holders on the eastern side, beside the
stream. The annual produce swap drew its largest attendance yet. Three
plots will be re-let in spring; the waiting list holds nine names. The
treasurer reported a small surplus, which the committee voted to spend on
tool maintenance."""

_NIGHTBUS = """\
Night-bus pilot summary, route N7. The pilot ran from October to March,
with buses hourly between midnight and five. Ridership averaged 41
passengers a night in October and 63 a night in March, with the busiest
nights at weekends. Two incidents were logged over the pilot, both
resolved without injury; drivers had received de-escalation training
beforehand, which the operator credits for the outcomes. A survey found 7
in 10 riders would use the service weekly if it became permanent. The
council will decide on permanence after the fare-revenue analysis is
complete."""

_MUSEUM = """\
Tidegate maritime museum, annual note. Visitor numbers reached 18,200, the
second-highest in the museum's history; the record of 19,050 was set the
year the tall ships visited. The lighthouse lens gallery, opened in
February, accounted for a fifth of all visits. Two of the museum's six
boats were restored by the volunteer wharf group, which meets on Tuesdays.
School visits doubled after the education officer post was made full-time
in spring. Admission remains free for children; adult tickets rose by one
pound. The museum shop's takings covered the cost of the new cataloguing
software."""

_SOURCES_V2 = {
    "water": _WATER,
    "station": _STATION,
    "coop": _COOP,
    "library": _LIBRARY,
    "ferry": _FERRY,
    "garden": _GARDEN,
    "nightbus": _NIGHTBUS,
    "museum": _MUSEUM,
}


def _item(item_id: str, source_id: str, claim: str, gold: str,
          category: str, note: str) -> GroundingEvalItem:
    return GroundingEvalItem(
        item_id=item_id,
        source_id=source_id,
        source=_SOURCES_V2[source_id],
        claim=claim,
        gold=gold,
        category=category,
        note=note,
    )


def build_grounding_items_v2() -> tuple[GroundingEvalItem, ...]:
    S, N = GOLD_SUPPORTED, GOLD_NOT_SUPPORTED
    return (
        # -- water ----------------------------------------------------------
        _item("h01", "water",
              "The plant's peak daily throughput was about 40 percent above "
              "its average.",
              N, "near-miss-aggregation",
              "16.1 vs 12.4 is +29.8%, not about 40%; catching it requires "
              "doing the division a shallow read skips"),
        _item("h02", "water",
              "The regional laboratory attributed the February exceedance to "
              "agricultural runoff.",
              N, "wrong-attribution",
              "THE REPORT makes the attribution, citing the lab's analysis; "
              "whether the lab itself drew the causal conclusion is unstated"),
        _item("h03", "water",
              "Millbrook's tap water was safe to drink throughout the year.",
              N, "unstated-inference",
              "the natural gist of one resolved exceedance, but the source "
              "never makes any safety claim"),
        _item("h04", "water",
              "The plant processed an average of 12.4 million litres per "
              "day, comfortably below its capacity.",
              N, "partial-support",
              "the average is exact; plant capacity is never mentioned, so "
              "'comfortably below capacity' rides along unsupported"),
        _item("h05", "water",
              "The two wells taken offline were back in service within a "
              "month.",
              N, "temporal-near-miss",
              "'within the quarter' bounds it at three months; 'within a "
              "month' is a tighter claim the source does not make"),
        _item("h06", "water",
              "Most monthly nitrate samples exceeded the national limit.",
              N, "easy-control",
              "inverted: eleven of twelve were within the limit"),
        _item("h07", "water",
              "Exactly one monthly nitrate sample exceeded the national "
              "limit.",
              S, "entailed-combination",
              "eleven of twelve within + February exceeded = exactly one"),
        _item("h08", "water",
              "A re-test taken a week after the February sample was within "
              "the national limit.",
              S, "stated", "stated directly"),
        # -- station --------------------------------------------------------
        _item("h09", "station",
              "The station has been operating for over five years.",
              N, "temporal-near-miss",
              "'since March 2021' plus no stated document date: the duration "
              "cannot be computed from the source alone"),
        _item("h10", "station",
              "In April, staff usually reached the mast on skis.",
              N, "quantifier-drift",
              "'often' does not entail 'usually' (more often than not); one "
              "notch of strengthening"),
        _item("h11", "station",
              "Nearly all of the visiting researchers stayed under two "
              "weeks.",
              N, "quantifier-drift",
              "'most' is not 'nearly all', and 'two weeks or less' includes "
              "exactly two weeks, which 'under two weeks' excludes"),
        _item("h12", "station",
              "The new bunk room added four overnight places.",
              N, "near-miss-aggregation",
              "six to nine is three added places; the plausible off-by-one "
              "is only caught by subtracting"),
        _item("h13", "station",
              "Station staff review the mast readings every morning.",
              N, "scope-creep",
              "each WEEKDAY morning; the claim silently extends to weekends"),
        _item("h14", "station",
              "The glacier is retreating because local temperatures are "
              "rising.",
              N, "causation-from-correlation",
              "retreat is measured; no cause, and no temperature trend, is "
              "stated anywhere in the source"),
        _item("h15", "station",
              "Between the two surveys the ice margin retreated less than "
              "three metres per year on average.",
              S, "entailed-subtle",
              "eight metres over three years is 2.67 m/yr < 3; entailed, but "
              "only via arithmetic a strict judge may refuse to do"),
        _item("h16", "station",
              "The station can now sleep nine people overnight.",
              S, "paraphrase", "capacity raised from six to nine"),
        # -- coop -----------------------------------------------------------
        _item("h17", "coop",
              "The committee expects prices to rise next year.",
              N, "hedge-stripping",
              "the source hedges twice — 'may need to rise' and 'if costs "
              "continue to climb'; the claim keeps 'expects' but drops both"),
        _item("h18", "coop",
              "The Saturday market stall drove the growth in membership.",
              N, "causation-from-correlation",
              "the committee BELIEVES it contributed — and the source itself "
              "notes a neighbouring co-op grew similarly without a stall"),
        _item("h19", "coop",
              "Membership grew by fifteen households.",
              N, "near-miss-aggregation",
              "84 minus 71 is thirteen; fifteen is the plausible slip only "
              "subtraction catches"),
        _item("h20", "coop",
              "The stall has operated every Saturday except two.",
              N, "partial-support",
              "'most Saturdays' plus 'twice it closed for lack of "
              "volunteers' does not entail those were the only closures"),
        _item("h21", "coop",
              "Flour costs rose by roughly a tenth, the third consecutive "
              "annual increase.",
              N, "partial-support",
              "the rise is stated; its history is not — 'third consecutive' "
              "rides along unsupported"),
        _item("h22", "coop",
              "The rebuilt oven produces roughly three hundred loaves a "
              "week.",
              S, "paraphrase", "stated directly, reworded"),
        _item("h23", "coop",
              "Membership rose in a year when flour costs also rose.",
              S, "entailed-combination",
              "joins two stated facts without adding a link between them"),
        _item("h24", "coop",
              "Membership stood at 84 households.",
              S, "stated", "verbatim"),
        # -- library --------------------------------------------------------
        _item("h25", "library",
              "July lending at the library was the highest for any month on "
              "record.",
              N, "scope-creep",
              "the record was for lending of CHILDREN'S TITLES; the claim "
              "silently widens it to all lending"),
        _item("h26", "library",
              "The council's heritage officer praised the builders' handling "
              "of the original beams.",
              N, "wrong-attribution",
              "the ARCHITECT praised the beam work; the heritage officer "
              "signed off — both plausible, only one stated"),
        _item("h27", "library",
              "The council funded about two thirds of the renovation cost.",
              N, "near-miss-aggregation",
              "fundraising covered a fifth, so the council's share is four "
              "fifths (80%); 'about two thirds' is decisively off — but only "
              "to a reader who computes the complement"),
        _item("h28", "library",
              "The reopening of the children's wing produced July's record "
              "lending of children's titles.",
              N, "causation-from-correlation",
              "reopening (June) and the record (July) are adjacent facts; "
              "the source states no causal link"),
        _item("h29", "library",
              "The upper reading room has been closed since the spring.",
              N, "unstated-inference",
              "plausible from the renovation timeline, but when the reading "
              "room closed is never stated"),
        _item("h30", "library",
              "A fifth of the renovation cost was raised by fundraising and "
              "the council paid the rest.",
              S, "paraphrase", "stated directly, reworded"),
        _item("h31", "library",
              "Work on the children's wing lasted about a third of a year.",
              S, "entailed-subtle",
              "four months of work is 4/12 ≈ a third of a year; entailed, "
              "but only via arithmetic a strict judge may refuse"),
        _item("h32", "library",
              "The children's wing reopened in June.",
              S, "stated", "verbatim"),
        # -- ferry ----------------------------------------------------------
        _item("h33", "ferry",
              "Most passengers surveyed wanted a later final departure.",
              N, "quantifier-drift",
              "'some passengers asked' strengthened to 'most wanted' — one "
              "notch, same topic, different truth"),
        _item("h34", "ferry",
              "A second sailing ran on Fridays throughout the year.",
              N, "temporal-near-miss",
              "the second Friday sailing began in May; 'throughout the "
              "year' overreaches the stated window"),
        _item("h35", "ferry",
              "The ferry was cancelled on five days.",
              N, "near-miss-aggregation",
              "361 of 365 leaves four cancellations; five is the plausible "
              "off-by-one only subtraction catches"),
        _item("h36", "ferry",
              "The operator committed to adding a later final departure.",
              N, "unstated-inference",
              "'said it would review the timetable' is the classic "
              "noncommittal response; a commitment to ADD that specific "
              "change is nowhere stated, however responsive the adjacency "
              "makes it feel"),
        _item("h37", "ferry",
              "Weather cancelled at least one sailing in every quarter of "
              "the year.",
              N, "easy-control",
              "contradicted: all four cancellations fell in the first "
              "quarter"),
        _item("h38", "ferry",
              "Ticket prices have not risen for three years running.",
              S, "paraphrase", "'unchanged for the third consecutive year'"),
        _item("h39", "ferry",
              "The second Friday sailing was available for most of the "
              "year.",
              S, "entailed-subtle",
              "May onward is eight of twelve months — most of the year; "
              "entailed, but it reads like an overreach and tempts a strict "
              "judge to reject"),
        _item("h40", "ferry",
              "Summer weekend crossings were much fuller than the yearly "
              "average.",
              S, "entailed-subtle",
              "92% vs 58% average — 'much fuller' is safely entailed by a "
              "34-point gap"),
        # -- garden ---------------------------------------------------------
        _item("h41", "garden",
              "The eastern plots suffered slug damage because they lie "
              "beside the stream.",
              N, "unstated-inference",
              "the flagship trap: location and damage are juxtaposed in one "
              "sentence and every reader supplies the cause — the source "
              "never states it"),
        _item("h42", "garden",
              "The garden's waiting list has grown since last year.",
              N, "unstated-inference",
              "the list is a single snapshot (nine names); no prior-year "
              "figure exists in the source, so growth is not computable — "
              "the growth gestalt around the record swap is the reader's"),
        _item("h43", "garden",
              "A third of the plots went uncultivated this season.",
              N, "near-miss-aggregation",
              "eight of thirty uncultivated is 27%, closer to a quarter; 'a "
              "third' is the plausible misfraction"),
        _item("h44", "garden",
              "The committee voted to spend the surplus on tool maintenance "
              "and new signage.",
              N, "partial-support",
              "tool maintenance is stated; 'new signage' rides along "
              "unsupported"),
        _item("h45", "garden",
              "The treasurer proposed spending the surplus on tool "
              "maintenance.",
              N, "wrong-attribution",
              "the treasurer REPORTED the surplus; the spending decision was "
              "the committee's vote, and no proposer is named"),
        _item("h46", "garden",
              "Slug damage was reported across the whole garden.",
              N, "easy-control",
              "contradicted: damage was reported on the eastern side"),
        _item("h47", "garden",
              "More people are waiting for a plot than there are plots "
              "coming free in spring.",
              S, "entailed-combination",
              "nine names waiting vs three plots to re-let — entailed by "
              "comparing two stated numbers"),
        _item("h48", "garden",
              "The committee agreed to fit lids to the water butts.",
              S, "stated", "verbatim"),
        # -- nightbus -------------------------------------------------------
        _item("h49", "nightbus",
              "Driver training prevented injuries in the two logged "
              "incidents.",
              N, "causation-from-correlation",
              "the OPERATOR CREDITS the training for the outcomes — a stated "
              "belief; prevention-as-fact is not established by the source"),
        _item("h50", "nightbus",
              "Most riders already use the night bus weekly.",
              N, "quantifier-drift",
              "7 in 10 WOULD use it weekly IF it became permanent — a "
              "hypothetical, flipped to a present-tense habit"),
        _item("h51", "nightbus",
              "Ridership grew in every month of the pilot.",
              N, "unstated-inference",
              "only the October and March averages are reported; a "
              "month-on-month trend is the reader's interpolation"),
        _item("h52", "nightbus",
              "The council will make the route permanent once the "
              "fare-revenue analysis is complete.",
              N, "hedge-stripping",
              "the council will DECIDE on permanence after the analysis; the "
              "claim quietly resolves the decision in one direction"),
        _item("h53", "nightbus",
              "The night bus ran through the summer months.",
              N, "easy-control",
              "contradicted: the pilot ran from October to March"),
        _item("h54", "nightbus",
              "March ridership averaged 63 a night, driven by weekend "
              "travellers.",
              N, "partial-support",
              "the average is exact; 'driven by weekend travellers' adds a "
              "cause the source does not state (busiest nights ≠ cause)"),
        _item("h55", "nightbus",
              "Both logged incidents were resolved without injury.",
              S, "stated", "verbatim"),
        _item("h56", "nightbus",
              "Average nightly ridership was more than half again higher in "
              "March than in October.",
              S, "entailed-subtle",
              "63 vs 41 is +53.7% — 'more than half again' is entailed, but "
              "only by doing the division"),
        # -- museum ---------------------------------------------------------
        _item("h57", "museum",
              "Visitor numbers fell about two thousand short of the "
              "museum's record.",
              N, "near-miss-aggregation",
              "19,050 minus 18,200 is 850; 'about two thousand' survives "
              "only if nobody subtracts"),
        _item("h58", "museum",
              "Making the education officer post full-time doubled school "
              "visits.",
              N, "causation-from-correlation",
              "visits doubled AFTER the post went full-time; after is not "
              "because, however tempting the adjacency"),
        _item("h59", "museum",
              "Admission to the museum is free.",
              N, "scope-creep",
              "admission is free FOR CHILDREN; adult tickets exist and just "
              "rose by one pound"),
        _item("h60", "museum",
              "Museum staff restored two of the six boats.",
              N, "wrong-attribution",
              "the VOLUNTEER WHARF GROUP restored them; staff is the "
              "plausible wrong actor"),
        _item("h61", "museum",
              "The lens gallery, the museum's most popular attraction, "
              "accounted for a fifth of all visits.",
              N, "partial-support",
              "the fifth is stated; 'most popular attraction' is not — a "
              "fifth of visits does not establish a ranking"),
        _item("h62", "museum",
              "The tall ships' visit lifted the museum's attendance to its "
              "record.",
              N, "unstated-inference",
              "the record was set the year the ships visited; the lift is "
              "the reader's causal story, not the source's"),
        _item("h63", "museum",
              "Adult ticket prices went up by one pound.",
              S, "paraphrase", "stated directly, reworded"),
        _item("h64", "museum",
              "Roughly 3,600 visits were to the lens gallery.",
              S, "entailed-subtle",
              "a fifth of 18,200 is 3,640 ≈ roughly 3,600; entailed via "
              "arithmetic a strict judge may refuse"),
    )
