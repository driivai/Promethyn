"""The limits of `docs/assurance-ledger-sprint-0.md`, as passing tests.

Doctrine #5: a named gap is a passing test, so it cannot erode quietly. Sprint 0
stated four limits on what an assurance ledger over this repository could
establish, and found a fifth. Four of the five reduce to a derivation over the
tree, and those four are here. The one that does not is §5's second limit — *an
isolating proof establishes that the proof notices the mechanism's removal, not
that the mechanism is correct* — which is a statement about what proof means and
has no expression as a test.

Nothing here is a floor. Every pin is an exact set or an exact count, and every
derivation carries a positive control proving it can say no (doctrine #8).
Counts come from the artifact that produced them, never from a filtered view
(doctrine #11); where a filter defines a population, the filter is stated beside
its count.

These tests are expected to REDDEN when the tree changes. That is their purpose:
a number that changes is re-measured and the sprint document re-dated, not
edited to match.
"""

from __future__ import annotations

import ast
import dataclasses
import re
from pathlib import Path

from prometheus_protocol.core.config import Config

REPO = Path(__file__).resolve().parents[2]
SPRINT = REPO / "docs" / "assurance-ledger-sprint-0.md"
BUILD = REPO / "src" / "prometheus_protocol" / "runtime" / "security_build.py"
TRACKER = REPO / "docs" / "OPEN-GAPS.md"


# ===========================================================================
# LIMIT 1 — a ledger over the claims you can find says nothing about claims
# nobody wrote down.
#
# The only mechanical form this limit can take is the inverse: pin the sources
# the ledger DID read, and name the ones it did not. An unread source is then a
# named number rather than an unknown, and a new document arrives as a red line
# instead of as silence.
# ===========================================================================

#: The claim sources Sprint 0 read, in full, and derived counts from. Pinned as
#: a SET rather than a count: two sets of the same size are indistinguishable by
#: count (OPEN-GAPS G25), and what matters here is WHICH documents were read.
CLAIM_SOURCES_READ = frozenset({
    "docs/DOCTRINE.md",
    "docs/OPEN-GAPS.md",
    "docs/threat-model.md",
    "README.md",
    "site/index.html",
})

#: Read for a specific fact and not inventoried for claims. Named apart, because
#: "I looked at it" and "I enumerated its claims" are different states and
#: collapsing them is the overclaim this whole sprint is about.
CONSULTED_NOT_INVENTORIED = frozenset({
    "docs/reachability-build.md",
    "docs/reachability-readers.md",
    "docs/live-state-pinning-design.md",
    "site/thanks.html",
    "site/README.md",
})


def _markdown_under(directory: str) -> set[str]:
    root = REPO / directory
    return {
        str(path.relative_to(REPO))
        for path in root.rglob("*.md")
        if path.is_file()
    }


def test_every_source_the_ledger_read_still_exists():
    """A pinned source that was renamed away makes the ledger's counts
    unreproducible, which is worse than not having them."""

    missing = sorted(name for name in CLAIM_SOURCES_READ | CONSULTED_NOT_INVENTORIED
                     if not (REPO / name).is_file())
    assert missing == [], (
        f"claim source(s) named by docs/assurance-ledger-sprint-0.md no longer exist: "
        f"{missing}. Re-measure the sprint's counts against the new path rather "
        "than editing the list."
    )


def test_the_documents_the_ledger_did_not_read_are_counted_and_named():
    """LIMIT 1, made mechanical in the only direction available.

    The population is every Markdown file under ``docs/``. The subset the sprint
    inventoried is pinned above. The remainder is the ledger's blind spot, and
    this asserts its exact size so that a new document cannot join it silently.

    The filter is stated beside the count, as doctrine #11 requires: this counts
    MARKDOWN under ``docs/`` and nothing else. It does not see claims carried in
    ``src/`` docstrings, in ``spec/``, in ``CHANGELOG.md`` or in commit messages.
    Those are named in the sprint document's own "what I could not reach" and are
    NOT covered here -- naming a limit is not closing it.
    """

    population = _markdown_under("docs")
    inventoried = {n for n in CLAIM_SOURCES_READ if n.startswith("docs/")}
    consulted = {n for n in CONSULTED_NOT_INVENTORIED if n.startswith("docs/")}
    # The sprint's own output is not one of its sources. Held apart rather than
    # folded into either bucket: counting a document as read because this sprint
    # wrote it is the shape of crediting a component the guard never saw.
    output = {str(SPRINT.relative_to(REPO)), "docs/assurance-ledger-sprint-1.md"} & population
    unread = population - inventoried - consulted - output

    # The tie-back: every member of the population lands in exactly one bucket,
    # so a file the partition cannot see is a red line and not a quiet shortfall.
    assert len(inventoried) + len(consulted) + len(output) + len(unread) == len(population)

    assert len(population) == 49, (
        f"docs/ now holds {len(population)} markdown files, not 49. Re-measure "
        "docs/assurance-ledger-sprint-0.md §1.5 rather than editing this number."
    )
    # THE SET, not the size. Review finding on #131, and it was right: the
    # comparand below used to be RECOMPUTED from the same checkout by the same
    # expression, so it was identical to ``unread`` by construction. A rename
    # that held the totals at 49 and 41 passed, and the two diagnostics under a
    # genuine count change were always empty. The instrument could not fail in
    # the direction the document said it pinned.
    assert unread == _UNREAD_AT_SPRINT_0, (
        f"the ledger's unread set is now {len(unread)} documents, not 41:\n"
        f"  newly unread: {sorted(unread - _UNREAD_AT_SPRINT_0)}\n"
        f"  no longer unread: {sorted(_UNREAD_AT_SPRINT_0 - unread)}\n"
        "A new document is a new claim source. Either inventory it and move it "
        "into CLAIM_SOURCES_READ, or re-measure this SET deliberately."
    )
    # Kept beside the set so the number the document cites is pinned by name
    # and not only implied by the membership above.
    assert len(unread) == 41, f"the unread count is now {len(unread)}, not 41"


#: The unread set as measured on 2026-09-18 by the derivation in the test above,
#: WRITTEN OUT. A snapshot recomputed from the tree it is meant to check is not
#: a snapshot: it agrees with that tree whatever the tree says. These are the
#: forty-one filenames, so a rename is a failure and the diagnostics above name
#: which document moved rather than reporting an empty difference.
_UNREAD_AT_SPRINT_0 = frozenset({
    "docs/DEPENDENCY-LICENSES.md",
    "docs/IP-READINESS.md",
    "docs/LICENSE-HISTORY.md",
    "docs/adr/0001-architecture.md",
    "docs/architecture.md",
    "docs/audit-source-acceptance.md",
    "docs/authorization-record.md",
    "docs/chokepoint-threat-model.md",
    "docs/composition-study.md",
    "docs/demo-stale-branches.md",
    "docs/domains-grounding.md",
    "docs/domains-sql.md",
    "docs/execution-authorization-record.md",
    "docs/execution-descriptor.md",
    "docs/extending-promethyn.md",
    "docs/gold-set-v3-protocol.md",
    "docs/judge-quality.md",
    "docs/key-custody.md",
    "docs/ledger-integrity.md",
    "docs/observability.md",
    "docs/open-core-boundary.md",
    "docs/operations.md",
    "docs/orchestration.md",
    "docs/pre-disclosure-audit.md",
    "docs/reachability-inventory-proof.md",
    "docs/reachability-type-proof.md",
    "docs/readiness-assessment.md",
    "docs/reconciliation.md",
    "docs/repository-identity.md",
    "docs/reviews/PROM-F11-checkpoint-2a.md",
    "docs/reviews/PROM-F11-checkpoint-2b.md",
    "docs/reviews/PROM-F11-checkpoint-3.md",
    "docs/reviews/PROM-F11-close-out.md",
    "docs/reviews/opened-substrate-1a-1b.md",
    "docs/sandbox.md",
    "docs/security-model.md",
    "docs/shakeout-report.md",
    "docs/skip-sweep.md",
    "docs/soft-calibration-adoption-rule.md",
    "docs/soft-calibration.md",
    "docs/swarm-roles.md",
})


def test_the_source_partition_is_not_universally_true():
    """Doctrine #8: the positive control for the derivation above.

    ``_markdown_under`` returning an empty set would make the partition vacuous
    and the tie-back trivially true, and an empty instrument reads downstream as
    a pass. So: it finds the files it must, and does not find one that is not
    there.
    """

    population = _markdown_under("docs")
    assert "docs/OPEN-GAPS.md" in population
    assert "docs/assurance-ledger-sprint-0.md" in population
    assert "docs/a-file-that-is-not-here-xyz.md" not in population
    assert _markdown_under("docs") != set(), "the collector found nothing"


# ===========================================================================
# LIMIT 3 — a mutation demonstrates one path around a guard, never the absence
# of a second.
#
# The PRESENCE of a second mechanism behind one label IS mechanically
# detectable, and that is the strongest available form of this limit. Sprint 0
# §4 Entry C measured the consequence: deleting `validate_ledger`'s
# adapter-type check left `test_injected_anchor_cannot_substitute_another_witness`
# GREEN, because the destination check answered in its place.
# ===========================================================================


def _build_refusal_labels() -> dict[str, list[int]]:
    """``label -> [line, ...]`` for every ``raise BuildRefused(...)`` in the
    build guard, keyed on the FIRST argument as written.

    The filter, stated: a label spelled as a literal is keyed on its text; one
    spelled as a name is keyed on ``<name>`` and is NOT resolved, because
    resolving it would require evaluating the module. So the literal counts
    below are a LOWER BOUND on how many sites can raise a given label -- the
    three ``<name>`` sites raise whichever property the loop is on. Stating that
    is the point: the understatement runs in the safe direction for this test's
    claim, and in the unsafe direction for anyone reading it as complete.
    """

    tree = ast.parse(BUILD.read_text(encoding="utf-8"))
    labels: dict[str, list[int]] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)):
            continue
        function = node.exc.func
        if getattr(function, "id", getattr(function, "attr", None)) != "BuildRefused":
            continue
        if not node.exc.args:
            continue
        argument = node.exc.args[0]
        if isinstance(argument, ast.Constant):
            key = str(argument.value)
        elif isinstance(argument, ast.Name):
            key = f"<{argument.id}>"
        else:
            key = f"<{type(argument).__name__}>"
        labels.setdefault(key, []).append(node.lineno)
    return labels


def test_a_refusal_label_raised_from_several_sites_cannot_be_isolated_alone():
    """LIMIT 3. The map is pinned EXACTLY, both directions.

    A label with more than one raise site cannot be isolated by a single-target
    mutation: delete one site and another answers, and the proof stays green
    while the mechanism it names is gone. That is OPEN-GAPS G44's shape, and the
    remedy G44 prescribes -- a COMPANION EDIT that neuters every mechanism
    carrying the property -- is only available to someone who knows how many
    there are.

    So this names them. When a label gains a site, this reddens, and the runner
    rows that pin that label must be re-run at that moment rather than at the
    end of the sprint (G44's standing rule).
    """

    labels = _build_refusal_labels()
    shared = {label: len(lines) for label, lines in labels.items() if len(lines) > 1}
    assert shared == {"ledger_anchor": 3, "<name>": 3, "Config": 5}, (
        f"the shared-label map changed: {shared}. Every runner that pins a "
        "refusal on a changed label must be re-run NOW -- see docs/OPEN-GAPS.md "
        "G44, 'THE STANDING RULE'. Then re-measure "
        "docs/assurance-ledger-sprint-0.md §4 Entry C."
    )
    # The instance Sprint 0 measured, held apart from the map so a reader meets
    # it at the mechanism: three sites, one label, one proof.
    assert labels["ledger_anchor"] == [271, 280, 288]


def test_the_refusal_label_derivation_is_not_universally_true():
    """Doctrine #8: the positive control for the derivation above.

    An empty AST walk would make the pin vacuous -- no labels found, no shared
    labels, green. So: it finds the sites it must, and does not find one that is
    not there.
    """

    labels = _build_refusal_labels()
    assert len(labels) >= 1 and sum(len(v) for v in labels.values()) == 18, (
        "the BuildRefused population changed; re-measure rather than relax"
    )
    assert "reobservation" in labels, "the derivation stopped seeing literal labels"
    assert "a_label_that_is_not_raised_xyz" not in labels


# ===========================================================================
# LIMIT 5 — the one Sprint 0 found and the brief did not name: there is no
# IDENTITY for a claim in this repository. The same property is stated in
# several registers, in several vocabularies, and none of them keys on another.
# ===========================================================================

_REGISTERS = {
    "OPEN-GAPS": "docs/OPEN-GAPS.md",
    "threat-model": "docs/threat-model.md",
    "README": "README.md",
}


def _registers_naming(field: str) -> tuple[str, ...]:
    return tuple(sorted(
        name for name, path in _REGISTERS.items()
        if field in (REPO / path).read_text(encoding="utf-8")
    ))


def test_every_build_matrix_property_is_restated_in_at_least_one_other_register():
    """LIMIT 5, in the direction that is measurable.

    The build guard's 22 rows are derived from ``dataclasses.fields(Config)``.
    Every one of them is ALSO named, in prose, in at least one other register --
    so a ledger that counted registers would count each of these properties more
    than once, and a ledger that counted properties would have to decide, by
    hand, which sentences are the same claim.

    The filter is stated: this is a SUBSTRING search for the field's name. It
    establishes that the name appears, not that the sentence containing it is a
    claim about the same property -- which is precisely G17's distinction
    between a name appearing and a control being enforced, and precisely why
    this limit is not closed by this test.
    """

    fields = [f.name for f in dataclasses.fields(Config) if f.metadata.get("security")]
    assert len(fields) == 22, f"the matrix is now {len(fields)} rows; re-measure §1.3"

    coverage = {field: _registers_naming(field) for field in fields}
    unnamed = sorted(field for field, registers in coverage.items() if not registers)
    assert unnamed == [], (
        f"security field(s) named in no other register: {unnamed}. That is a "
        "property the prose registers do not mention at all, which is a "
        "different finding from the one this test records."
    )

    # Exact, both directions, AND PER PROPERTY. The histogram alone was the
    # #131 review's third finding, and it was right: with five properties at one
    # register each, `verifier_cpu_seconds` could leave OPEN-GAPS for
    # threat-model and the distribution would still read {1: 5, 2: 16, 3: 1}.
    # Two properties trading registers cancels the same way. A histogram is a
    # count of a filtered view of the mapping (doctrine #11), so the mapping is
    # what gets pinned.
    assert coverage == _REGISTER_COVERAGE_AT_SPRINT_0, (
        "register coverage changed per property:\n"
        + "\n".join(
            f"  {field}: {_REGISTER_COVERAGE_AT_SPRINT_0.get(field)} -> {registers}"
            for field, registers in sorted(coverage.items())
            if _REGISTER_COVERAGE_AT_SPRINT_0.get(field) != registers
        )
        + "\nRe-measure docs/assurance-ledger-sprint-0.md §1.4."
    )

    # The distribution the document quotes, kept beside the mapping so the
    # number in §1.4 is pinned by name and not only implied by it.
    by_count = {n: sum(1 for r in coverage.values() if len(r) == n) for n in (1, 2, 3)}
    assert by_count == {1: 5, 2: 16, 3: 1}, (
        f"register coverage changed: {by_count}. Re-measure "
        "docs/assurance-ledger-sprint-0.md §1.4."
    )
    assert coverage["sandbox"] == ("OPEN-GAPS", "README", "threat-model")


#: The ``field -> registers`` mapping as measured on 2026-09-18. Written out,
#: for the same reason ``_UNREAD_AT_SPRINT_0`` is: a comparand recomputed from
#: the tree agrees with the tree whatever it says.
_REGISTER_COVERAGE_AT_SPRINT_0 = {
    "verifier_timeout_s": ("OPEN-GAPS", "threat-model"),
    "verifier_memory_mb": ("OPEN-GAPS", "threat-model"),
    "verifier_cpu_seconds": ("OPEN-GAPS",),
    "verifier_max_processes": ("OPEN-GAPS",),
    "sandbox": ("OPEN-GAPS", "README", "threat-model"),
    "require_digest_pin": ("OPEN-GAPS", "threat-model"),
    "gate_threshold": ("OPEN-GAPS", "threat-model"),
    "escalate_below": ("OPEN-GAPS", "threat-model"),
    "pending_ttl_seconds": ("OPEN-GAPS", "threat-model"),
    "max_role_calls": ("OPEN-GAPS",),
    "request_timeout_s": ("OPEN-GAPS", "threat-model"),
    "allow_insecure_loopback": ("OPEN-GAPS", "threat-model"),
    "provider_max_response_bytes": ("OPEN-GAPS", "threat-model"),
    "ledger_anchor": ("OPEN-GAPS", "threat-model"),
    "ledger_anchor_retention_days": ("OPEN-GAPS", "threat-model"),
    "require_ledger_anchor": ("OPEN-GAPS", "threat-model"),
    "require_external_signer": ("OPEN-GAPS", "threat-model"),
    "require_verified_substrate": ("OPEN-GAPS", "threat-model"),
    "allow_unverified_substrate": ("OPEN-GAPS", "threat-model"),
    "config_attestation_target": ("OPEN-GAPS",),
    "require_config_attestation": ("OPEN-GAPS", "threat-model"),
    "verification_profile": ("OPEN-GAPS",),
}


def test_the_register_search_is_not_universally_true():
    """Doctrine #8: the positive control for the register search.

    A substring search that says yes to everything would make the coverage map
    above meaningless in the passing direction.
    """

    assert _registers_naming("a_config_field_that_does_not_exist_xyz") == ()
    assert "OPEN-GAPS" in _registers_naming("require_verified_substrate")


# ===========================================================================
# LIMIT 4 — judgment-dependent modes cannot be audited mechanically.
#
# Sprint 0 §3.1 split the taxonomy 7 mechanical / 4 partial / 1 not. The
# measurable consequence is §1.3's: an entry SCHEMA that nothing enforces is
# followed by one entry in fifty-six. That number is what justifies building the
# ledger as a tool wherever the population is derivable, so it is pinned here
# rather than left in prose where it would go stale the way the schema did.
# ===========================================================================

_SCHEMA_FIELDS = {
    "What": r"\*\*What\b",
    "Measured": r"\*\*Measured\b",
    "Why not closed": r"\*\*Why not closed",
    "What closes it": r"\*\*What closes it",
    "Test": r"\*\*Test\b",
}


def _tracker_entries() -> list[tuple[str, str]]:
    text = TRACKER.read_text(encoding="utf-8")
    parts = re.split(r"^(## G\d+ —.*)$", text, flags=re.M)[1:]
    return [(parts[i], parts[i + 1]) for i in range(0, len(parts), 2)]


def test_the_tracker_states_an_entry_schema_that_nothing_enforces():
    """LIMIT 4's measurable consequence, and Sprint 0's load-bearing number.

    ``docs/OPEN-GAPS.md:12-14`` states that each entry carries five fields. This
    derives the actual adherence from the artifact. It is not a criticism of the
    entries -- several run to a hundred lines and carry measured tables -- it is
    the evidence that a stated-but-unenforced format does not survive contact
    with a year of sprints, which is the finding the sprint document turns into
    a recommendation.

    If this reddens because adherence IMPROVED, that is the good direction and
    the numbers are re-measured. If it reddens because an entry was added, the
    same. Either way the sprint document is re-dated, not edited to match.
    """

    entries = _tracker_entries()
    # 56 -> 57 on 2026-09-18: G56 (the fail-open harness facts). Re-measured
    # from the artifact after the entry landed, never predicted before it.
    assert len(entries) == 57, (
        f"the tracker now has {len(entries)} headings, not 57; re-measure §1.3"
    )

    adherence = {
        field: sum(1 for _, body in entries if re.search(pattern, body))
        for field, pattern in _SCHEMA_FIELDS.items()
    }
    # Re-measured 2026-09-18 with G56 added: What 38->39, Measured 27->28,
    # Test 23->24. The new entry carries three of the five stated fields, which
    # is the median and is itself the finding this test records.
    assert adherence == {
        "What": 39,
        "Measured": 28,
        "Why not closed": 2,
        "What closes it": 12,
        "Test": 24,
    }, f"tracker schema adherence changed: {adherence}; re-measure §1.3"

    complete = [
        head for head, body in entries
        if all(re.search(p, body) for p in _SCHEMA_FIELDS.values())
    ]
    assert len(complete) == 1, (
        f"{len(complete)} entries now carry all five stated fields, not 1: "
        f"{[h[:60] for h in complete]}"
    )


def test_the_tracker_derivation_is_not_universally_true():
    """Doctrine #8: the positive control for the tracker derivation.

    Zero entries parsed would make every adherence count above vacuous, and an
    empty body would read as "schema not followed" for the wrong reason.
    """

    entries = _tracker_entries()
    assert entries, "the heading split found no entries"
    heads = [head for head, _ in entries]
    assert any(head.startswith("## G1 —") for head in heads)
    assert not any("## G999" in head for head in heads)
    # And the bodies are real bodies, not empty strings: an empty body would
    # match no pattern and read as "schema not followed" for the wrong reason.
    assert all(body.strip() for _, body in entries)


# ===========================================================================
# The sprint document itself must keep saying what these tests pin, or the
# tests are guarding a document that no longer makes the claim.
# ===========================================================================


def test_the_sprint_document_still_states_the_limits_these_tests_pin():
    """A test that outlives the claim it was written for is a void guard.

    This is deliberately a text check and it is deliberately weak -- it pins
    that the document still carries its five limits, not that it carries them
    correctly. Naming its own weakness is the point: this is taxonomy mode 9
    (a guard keyed on a name), shipped knowingly, because the alternative is no
    link at all between the tests and the reasoning they encode.
    """

    # Whitespace-normalised, because the document is wrapped at 80 columns and a
    # marker that straddles a line break would make this fail for the formatting
    # rather than for the claim -- which is a false red, and a guard that cries
    # for the wrong reason teaches its reader to discount it (OPEN-GAPS G38).
    text = " ".join(SPRINT.read_text(encoding="utf-8").split())
    for marker in (
        "says nothing about claims nobody wrote down",
        "not that the mechanism is correct",
        "never the absence of a second",
        "cannot be audited mechanically",
        "no identity for a claim in this repository",
    ):
        assert marker in text, f"docs/assurance-ledger-sprint-0.md no longer states: {marker}"


# ===========================================================================
# THE RULE THE #131 REVIEW'S FIRST AND THIRD FINDINGS ARE INSTANCES OF.
#
# Both are the same defect in two places: a comparand that is not independent
# of the thing it is compared against. One was RECOMPUTED from the tree it
# checks; the other was an AGGREGATE of the mapping it stood in for. Neither
# could go red for the change its sentence claimed to pin.
#
# Fixing the two instances is not the same as closing the class, so the class
# gets a derivation of its own and the aggregate gets its counter-example.
# ===========================================================================


def test_a_pinned_snapshot_is_never_recomputed_from_the_tree_it_checks():
    """Derived over the SHAPE of the assignment, not over a list of names.

    ``_UNREAD_AT_SPRINT_0`` was built by the same expression, over the same
    checkout, as the value the test compared against it. It therefore agreed
    with that checkout whatever the checkout said: a rename holding the totals
    at 49 and 41 passed, and the "newly unread" / "no longer unread"
    diagnostics were empty even under a real count change.

    A snapshot has to be a MEASUREMENT WRITTEN DOWN. This requires every
    ``*_AT_SPRINT_0`` binding in this module to be a literal -- to reference
    none of the live sources its subject is derived from -- so the next
    snapshot cannot quietly become a restatement of the thing it pins.
    """

    live_sources = {
        "_markdown_under",
        "CLAIM_SOURCES_READ",
        "CONSULTED_NOT_INVENTORIED",
        "_registers_naming",
        "dataclasses",
        "Config",
        "REPO",
        "read_text",
    }

    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    snapshots = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        name = getattr(node.targets[0], "id", "")
        if not name.endswith("_AT_SPRINT_0"):
            continue
        referenced = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
        referenced |= {n.attr for n in ast.walk(node.value) if isinstance(n, ast.Attribute)}
        snapshots[name] = sorted(referenced & live_sources)

    # Doctrine #8: an empty sweep would hold this rule vacuously for every
    # snapshot at once, which is the failure mode the rule itself is about.
    assert sorted(snapshots) == [
        "_REGISTER_COVERAGE_AT_SPRINT_0",
        "_UNREAD_AT_SPRINT_0",
    ], f"the snapshot population changed: {sorted(snapshots)}"

    recomputed = {name: refs for name, refs in snapshots.items() if refs}
    assert recomputed == {}, (
        f"snapshot(s) recomputed from their own subject: {recomputed}. A "
        "comparand derived from the tree agrees with the tree whatever it "
        "says. Write the measured value out."
    )


def test_the_snapshot_shape_rule_is_not_universally_true():
    """Doctrine #8: the positive control for the rule above.

    The pre-fix form of ``_UNREAD_AT_SPRINT_0``, planted, must be recognised
    as recomputed -- otherwise the rule passes for a reason unrelated to the
    assignments it is reading.
    """

    planted = ast.parse(
        "_UNREAD_AT_SPRINT_0 = frozenset(\n"
        '    _markdown_under("docs")\n'
        '    - {n for n in CLAIM_SOURCES_READ if n.startswith("docs/")}\n'
        ")\n"
        '_OTHER_AT_SPRINT_0 = frozenset({"docs/sandbox.md"})\n'
    )
    live_sources = {"_markdown_under", "CLAIM_SOURCES_READ"}
    verdicts = []
    for node in planted.body:
        referenced = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
        verdicts.append(sorted(referenced & live_sources))

    assert verdicts == [["CLAIM_SOURCES_READ", "_markdown_under"], []], verdicts


def test_the_histogram_cannot_stand_in_for_the_register_mapping():
    """Doctrine #5: the gap the third finding named, as a passing test.

    A COMPENSATING MOVE, constructed: ``verifier_cpu_seconds`` trades
    OPEN-GAPS for threat-model. It is a one-register property before and
    after, so the distribution does not move by a single count while the
    mapping is materially different. That is the proof that the histogram
    cannot be the thing that holds, and therefore that the per-property
    assertion above is load-bearing rather than decorative.
    """

    def histogram(mapping: dict[str, tuple[str, ...]]) -> dict[int, int]:
        return {n: sum(1 for r in mapping.values() if len(r) == n) for n in (1, 2, 3)}

    moved = dict(_REGISTER_COVERAGE_AT_SPRINT_0)
    assert moved["verifier_cpu_seconds"] == ("OPEN-GAPS",)
    moved["verifier_cpu_seconds"] = ("threat-model",)

    assert moved != _REGISTER_COVERAGE_AT_SPRINT_0
    assert histogram(moved) == histogram(_REGISTER_COVERAGE_AT_SPRINT_0) == {1: 5, 2: 16, 3: 1}

    # And the same cancellation between two properties, which no single-property
    # rule would catch either: one gains the register the other loses.
    traded = dict(_REGISTER_COVERAGE_AT_SPRINT_0)
    traded["verifier_cpu_seconds"] = ("OPEN-GAPS", "threat-model")
    traded["verifier_timeout_s"] = ("threat-model",)
    assert traded != _REGISTER_COVERAGE_AT_SPRINT_0
    assert histogram(traded) == {1: 5, 2: 16, 3: 1}
