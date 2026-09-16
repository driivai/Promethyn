"""The open gaps that can be stated as PASSING TESTS — doctrine #5.

``docs/OPEN-GAPS.md`` is the tracker. A gap that lives only in prose has a
countdown; the ones here are pinned so they can close and cannot quietly grow.
Each test names its entry in the tracker. A ratchet moves DOWN only: when a
count falls, lower the pin in the same change; a count that rises fails here.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from tests.support.positional_sweep import (
    SweepIncomplete,
    positional_constructions,
    wide_dataclasses,
)

#: Observed 2026-09-15. Was documented as 49, measured 2026-09-12; the tracker's
#: figure was one stale and is corrected with the measurement, not the reverse.
WIDE_DATACLASSES = 50

REPO = pathlib.Path(__file__).resolve().parents[2]
TRACKER = REPO / "docs" / "OPEN-GAPS.md"

#: OPEN-GAPS G2. Positional constructions of wide (>= 6 field) dataclasses, per
#: class, as the sweep observed them on 2026-09-12 after ``Evidence`` and
#: ``Judgment`` became kw_only. The classes are what remains; the numbers may
#: only fall. ``MigrationResult`` and ``ReconciliationResult`` gained a trailing
#: defaulted field this sprint and their positional sites are unchanged.
POSITIONAL_SITES_CEILING: dict[str, int] = {
    "DbTarget": 11,
    "Coverage": 7,
    "GateRead": 7,
    "SubstrateReport": 6,
    "SignEvent": 4,
    "MigrationResult": 2,
    "ReconciliationResult": 2,
    "UnparsedEntry": 2,
    "PagedSignAuditSource": 2,
    "MountEntry": 1,
    "KeyPin": 1,
    "JudgedRow": 1,
    "TrustStats": 1,
}


def test_the_tracker_exists_and_names_every_gap_pinned_here():
    text = TRACKER.read_text(encoding="utf-8")
    for gap in ("G1", "G2", "G3", "G4", "G5"):
        assert re.search(rf"^## {gap}\b", text, re.M), f"docs/OPEN-GAPS.md has no entry {gap}"


def test_positional_construction_of_wide_dataclasses_does_not_grow():
    """G2. The sweep instrument, run live, against the ceiling."""

    wide = wide_dataclasses()
    # PINNED, not a floor. `>= 40` against a population of fifty permitted ten
    # to vanish unnoticed, and the sweep used to let them: it swallowed import
    # errors and reported the remainder as whole. It now raises SweepIncomplete
    # instead, so the population can only move by a real code change — and an
    # exact pin is what turns such a move into a decision rather than a drift.
    assert len(wide) == WIDE_DATACLASSES, (
        f"the sweep measured {len(wide)} wide dataclasses, pinned at "
        f"{WIDE_DATACLASSES}. If a class was added or widened, re-pin here and "
        "in docs/OPEN-GAPS.md G2 with the date. If it FELL, say which class "
        "stopped being wide and why."
    )
    for name in ("Evidence", "Judgment"):
        assert wide[name][1] is True, f"{name} is no longer kw_only; the closed half of G2 reopened"
    hits = positional_constructions(wide)
    grown = {
        name: (len(sites), POSITIONAL_SITES_CEILING.get(name, 0))
        for name, sites in hits.items()
        if len(sites) > POSITIONAL_SITES_CEILING.get(name, 0)
    }
    assert grown == {}, (
        f"positional constructions grew past the ceiling: {grown}. A wide "
        "dataclass built positionally can mis-slot a field without raising; "
        "construct by keyword, or make the class kw_only."
    )
    # And the ratchet is honest: a ceiling with nothing under it is stale.
    stale = sorted(name for name in POSITIONAL_SITES_CEILING if name not in hits)
    assert stale == [], f"ceilings with no sites behind them (lower or remove them): {stale}"


def test_evidence_and_judgment_cannot_be_built_positionally():
    """The closed half of G2, kept closed."""

    import pytest

    from prometheus_protocol.core.models import Evidence, Judgment, Verdict

    # Called through a local name so the sweep in this same file does not count
    # its own control as a positional construction site.
    for cls, positional in ((Evidence, (True, 1, 1, ())), (Judgment, (Verdict.PASS, 1.0, True))):
        with pytest.raises(TypeError):
            cls(*positional)


def test_the_sweep_refuses_a_module_it_cannot_import(monkeypatch):
    """G2's instrument must REFUSE a narrowed population, not report it.

    Probed by making one real module raise on import. Before this change the
    sweep swallowed the error, returned a smaller dict, and the caller's floor
    of `>= 40` let it through — nine could have vanished with nothing red.
    """

    import importlib

    real = importlib.import_module

    def _raise_for_one(name, *args, **kwargs):
        if name == "prometheus_protocol.core.bounds":
            raise ImportError("probe: this module cannot be imported")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(
        "tests.support.positional_sweep.importlib.import_module", _raise_for_one
    )
    with pytest.raises(SweepIncomplete) as refusal:
        wide_dataclasses()
    # It NAMES what it skipped; "something went wrong" would leave the reader
    # unable to tell a broken module from a narrowed sweep.
    assert "prometheus_protocol.core.bounds" in str(refusal.value)


def test_the_sweep_refuses_a_file_it_cannot_parse(tmp_path, monkeypatch):
    """The other half. An unparseable file is a file whose positional
    constructions cannot be seen, so reporting the rest understates the count."""

    import tests.support.positional_sweep as sweep

    root = tmp_path / "src"
    root.mkdir()
    (root / "broken.py").write_text("def (:\n", encoding="utf-8")
    monkeypatch.setattr(sweep, "REPO", tmp_path)
    monkeypatch.setattr(sweep, "ROOTS", ("src",))
    with pytest.raises(SweepIncomplete) as refusal:
        sweep.positional_constructions({"Anything": (6, False)})
    assert "src/broken.py" in str(refusal.value)


def test_the_sweep_does_not_refuse_a_healthy_tree(tmp_path, monkeypatch):
    """The positive control. Without it, both refusals above are consistent
    with a sweep that refuses everything — which would be a different defect
    and would make the instrument useless rather than dishonest."""

    import tests.support.positional_sweep as sweep

    root = tmp_path / "src"
    root.mkdir()
    (root / "fine.py").write_text("x = Anything(1, 2, 3)\n", encoding="utf-8")
    monkeypatch.setattr(sweep, "REPO", tmp_path)
    monkeypatch.setattr(sweep, "ROOTS", ("src",))
    hits = sweep.positional_constructions({"Anything": (6, False)})
    assert hits == {"Anything": ["src/fine.py:1"]}


# ---------------------------------------------------------------------------
# G38 — the `$` anchor in the TLS diagnostic guard
#
# Pinned as a PASSING TEST rather than left as prose (doctrine #5). The gap is
# RECORDED and deliberately NOT FIXED on the change that found it: a different
# module, a different guard, unrelated to the review finding that surfaced the
# class. These tests hold it at exactly its measured size, so it can close but
# cannot grow while nobody is looking.
# ---------------------------------------------------------------------------


def _tls_reason_accepted(value: str) -> bool:
    """Whether the GUARD accepts ``value`` — through the real constructor.

    THIS WENT THROUGH THE REGEX OBJECT FIRST, AND THAT WAS THE WRONG SUBJECT.
    Measured: with the pin reading ``_TLS_REASON.match(...)``, the mutation
    changing the CALL SITE from ``.match`` to ``.fullmatch`` — which genuinely
    closes this gap — left every assertion green. The pin's sentence was about
    the guard and its reach was the pattern, one of the two things that
    determine the outcome. The same defect as G37, in the instrument written to
    record G37's sibling.

    Going through ``Diagnostic`` makes the derivation total over both: the
    anchor AND the method the call site uses.
    """

    from prometheus_protocol.core.diagnostics import (
        REASON_CODES,
        Diagnostic,
        UnboundedDiagnostic,
    )

    try:
        Diagnostic(reason=sorted(REASON_CODES)[0], context={"tls_reason": value})
    except UnboundedDiagnostic:
        return False
    return True


def test_G38_the_tls_reason_guard_is_loose_by_exactly_one_trailing_newline():
    """The gap, at its measured size. Written to FAIL when it is fixed.

    ``$`` matches at end-of-string or immediately before a single final
    newline, and ``[A-Z0-9_]`` cannot consume a newline — so the widening is
    exactly one trailing ``\\n`` and there is no second character that can
    follow. This is NOT a text-injection channel, and the assertions below say
    which half is which so a reader cannot take the gap for more than it is.
    """

    # The gap itself. When the guard is corrected — by the anchor OR by the
    # call site's method — this line fails, which is the intent: closing a gap
    # should require deleting its pin deliberately.
    assert _tls_reason_accepted("CERT_EXPIRED\n"), (
        "G38 appears to be FIXED — the guard no longer accepts a trailing "
        "newline. Remove this pin and the tracker entry in the same change."
    )

    # The boundary, so the gap is never read as wider than it is.
    for refused in ("CERT_EXPIRED\n\n", "CERT_EXPIRED\nX", "CERT_EXPIRED\r\n",
                    "CERT_EXPIRED\r", "CERT_EXPIRED\nsecret leaked here"):
        assert not _tls_reason_accepted(refused), (
            f"G38 is WIDER than recorded: {refused!r} now passes the guard, so "
            "the tracker's 'exactly one trailing newline' is no longer true"
        )


def test_G38_the_newline_reaches_the_RENDERED_message_not_just_the_field():
    """Why the gap is worth a pin at all, measured at the sink.

    A value that passes the guard but is dropped before rendering would cost
    nothing. It is not dropped: ``message()`` is the only rendering, and it
    emits the newline verbatim — so one diagnostic becomes two lines in any
    line-oriented sink. That is the whole exposure, stated at the point where
    it lands rather than at the point where it is admitted.
    """

    from prometheus_protocol.core.diagnostics import REASON_CODES, Diagnostic

    rendered = Diagnostic(
        reason=sorted(REASON_CODES)[0], context={"tls_reason": "CERT_EXPIRED\n"}
    ).message()

    assert rendered.endswith("CERT_EXPIRED\n"), rendered
    assert "\n" in rendered, (
        "the newline no longer reaches the rendered message, so G38 is closed "
        "at the sink even if the guard still admits it — re-measure and rewrite"
    )


def test_G38_the_paired_positive_control_the_guard_still_works():
    """Doctrine #4. Without it the assertions above are equally consistent with
    a guard that has stopped refusing anything at all.

    THIS CONTROL HAD THE BLIND SPOT THE NEGATIVES WERE JUST REWRITTEN TO CLOSE,
    and the review that found it was right. The negatives moved onto
    ``_tls_reason_accepted`` — the real ``Diagnostic`` constructor — and this
    one was left on ``_TLS_REASON.match``, the regex object. So a change that
    made ``__post_init__`` start REFUSING legitimate OpenSSL reasons would have
    left this green, because the pattern still matches them: the control named
    the guard and measured the pattern, which is the third appearance of that
    shape in one change.

    It goes through the guard now, end to end, exactly as the negatives do.

    WHAT THE FIX IS AND IS NOT WORTH, measured rather than asserted. With the
    guard mutated to refuse legitimate reasons: the corrected control reddens
    (5 red), the old one did not (4 red) — and DELETING the old one's body
    entirely also gives 4 red, the same four. So the old control was not merely
    blind, it was fully redundant: it added no discrimination the suite did not
    already have. The four that redden regardless include
    ``test_a_real_self_signed_certificate_reaches_the_bounded_diagnostic`` and
    ``test_a_tls_failure_keeps_the_distinction_an_operator_acts_on`` in
    ``test_secret_sink_regressions.py``, which exercise the guard end to end.

    **So nothing would have shipped unobserved.** The review is right that this
    control was blind; it is not the case that the property was undefended. The
    fix makes the control mean what its name says, which matters because a
    registered positive control is read as evidence for its negatives — and
    that reading was false. Both halves are recorded so neither is overstated.
    """

    for accepted in ("CERT_EXPIRED", "WRONG_VERSION_NUMBER",
                     "CERTIFICATE_VERIFY_FAILED", "A"):
        assert _tls_reason_accepted(accepted), (
            f"the guard now REFUSES {accepted!r}, a legitimate OpenSSL symbolic "
            "reason, so the negatives above are passing against a guard that "
            "has stopped accepting anything"
        )

    for refused in ("cert_expired", "1CERT", "CERT EXPIRED", "", "A" * 65):
        assert not _tls_reason_accepted(refused), refused


def test_G38_the_sibling_regex_swept_alongside_it_is_NOT_the_same_shape():
    """The sweep's NEGATIVE result, recorded as a measurement rather than a
    silence (doctrine #8). ``_GCP_KEY`` has three users and every one calls
    ``.fullmatch`` on the same object — the regex IS the rule there, with no
    stricter wrapper to diverge from. Pinned so that if a fourth user is added
    with ``.match``, this says so."""

    import ast
    import pathlib

    module = REPO / "src" / "prometheus_protocol" / "chokepoint" / "audit_normalization.py"
    tree = ast.parse(pathlib.Path(module).read_text(encoding="utf-8"))

    methods = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "_GCP_KEY"
    }

    assert methods == {"fullmatch"}, (
        f"_GCP_KEY is now consulted with {sorted(methods)}; a '.match' user "
        "would make it the G37/G38 shape and it must be assessed, not assumed"
    )


def test_G38_is_named_in_the_tracker():
    """The gap lives in both places or in neither."""

    text = TRACKER.read_text(encoding="utf-8")
    for gap in ("G36", "G37", "G38"):
        assert re.search(rf"^## {gap}\b", text, re.M), f"no tracker entry {gap}"
