"""Unit tests: the judge-quality evaluation harness.

The harness's arithmetic must be exactly right (fixture-verified), and running
an evaluation must be read-only — no calibration samples, no trust rows, no
ledger rows. Evaluation is not experience.
"""

from __future__ import annotations

from pathlib import Path

from prometheus_protocol.benchmarks.judge_eval import (
    BUCKET_EDGES,
    EVAL_JUDGE_SYSTEM_PROMPT,
    SCRIPTED_JUDGE_MODEL,
    SCRIPTED_REPLIES,
    Bucket,
    JudgedRow,
    ScriptedJudgeProvider,
    build_eval_items,
    compute_metrics,
    main,
    parse_confidence,
    run_judge_eval,
    split_by_actor,
)
from prometheus_protocol.core.interfaces import Verifier
from prometheus_protocol.core.models import Evidence, Tier, Verdict
from prometheus_protocol.verifier.model_judge import ModelJudgeVerifier

#: Ground truth of the bundled eval set, as the HARD verifier decides it by
#: executing each candidate (verified by the committed reference run).
_TRUTH = {
    "c01": Verdict.PASS, "c02": Verdict.FAIL, "c03": Verdict.PASS,
    "c04": Verdict.FAIL, "c05": Verdict.PASS, "c06": Verdict.FAIL,
    "c07": Verdict.PASS, "c08": Verdict.FAIL, "c09": Verdict.FAIL,
    "c10": Verdict.PASS,
}


class _FakeReference(Verifier):
    """Authoritative stand-in keyed by the item marker (no sandbox needed)."""

    def verify(self, *, code: str, task) -> Evidence:
        for item_id, verdict in _TRUTH.items():
            if f"# eval-item: {item_id}" in code:
                return Evidence(
                    passed=(verdict == Verdict.PASS), total=1,
                    passed_count=1 if verdict == Verdict.PASS else 0,
                    verifier_id="fake-reference", verdict=verdict, tier=Tier.HARD,
                )
        return Evidence(passed=False, total=0, passed_count=0,
                        verifier_id="fake-reference", verdict=Verdict.ABSTAIN,
                        tier=Tier.HARD)


def _scripted_rows():
    judge = ModelJudgeVerifier(
        ScriptedJudgeProvider(SCRIPTED_REPLIES),
        system_prompt=EVAL_JUDGE_SYSTEM_PROMPT,
    )
    return run_judge_eval(build_eval_items(), judge=judge, reference=_FakeReference())


# -- confidence parsing -------------------------------------------------------


def test_parse_confidence():
    assert parse_confidence("PASS 0.85") == 0.85
    assert parse_confidence("fail 0.3") == 0.3
    assert parse_confidence("PASS 1") == 1.0
    assert parse_confidence("FAIL 0") == 0.0
    assert parse_confidence("PASS") is None          # the production one-word reply
    assert parse_confidence("ABSTAIN") is None
    assert parse_confidence("") is None
    assert parse_confidence("PASS 10") is None        # not a [0,1] confidence
    assert parse_confidence("PASS 2.5") is None
    assert parse_confidence("PASS: 0.75") == 0.75
    # Only the first non-empty line counts, mirroring the verdict parser.
    assert parse_confidence("PASS 0.9\nbut also 0.1") == 0.9
    assert parse_confidence("\n\nFAIL 0.4") == 0.4


def test_parse_confidence_never_coerces_malformed_numbers():
    # A malformed confidence is unstated, never rounded into range: recording
    # a wrong number would pollute the very calibration table being measured.
    assert parse_confidence("PASS 1.5") is None       # not truncated to 1
    assert parse_confidence("PASS -0.5") is None      # sign not dropped
    assert parse_confidence("PASS 0,9") is None       # not read as 0
    assert parse_confidence("PASS 0.5e-1") is None    # exponent not split
    assert parse_confidence("PASS 0.5.7") is None     # dotted runs rejected


# -- exact arithmetic on hand-made rows ---------------------------------------


def _row(item_id, ref, judged, conf, actor="a"):
    return JudgedRow(item_id=item_id, actor_model=actor, reference=ref,
                     judged=judged, confidence=conf)


def test_compute_metrics_exact_arithmetic():
    rows = (
        _row("r1", Verdict.PASS, Verdict.PASS, 0.2),      # correct, boundary bucket
        _row("r2", Verdict.FAIL, Verdict.PASS, 1.0),      # false-PASS, top bucket
        _row("r3", Verdict.PASS, Verdict.FAIL, None),     # false-FAIL, unstated
        _row("r4", Verdict.FAIL, Verdict.ABSTAIN, None),  # judge abstained
        _row("r5", Verdict.ABSTAIN, Verdict.PASS, 0.9),   # no ground truth: excluded
    )
    m = compute_metrics(rows)
    assert m.n_items == 5
    assert m.n_reference == 4          # r5 has no authoritative reference
    assert m.n_decided == 3            # r4 abstained
    assert m.n_abstained == 1
    assert m.n_agree == 1 and m.agreement == 1 / 3
    assert m.reference_fails_decided == 1     # r2 (r4 abstained)
    assert m.false_pass == 1 and m.false_pass_rate == 1.0
    assert m.reference_passes_decided == 2    # r1, r3
    assert m.false_fail == 1 and m.false_fail_rate == 0.5
    by_range = {(b.lo, b.hi): b for b in m.buckets}
    assert by_range[(0.2, 0.4)] == Bucket(0.2, 0.4, count=1, correct=1)  # 0.2 -> [0.2,0.4)
    assert by_range[(0.8, 1.0)] == Bucket(0.8, 1.0, count=1, correct=0)  # 1.0 -> last
    assert m.unstated_count == 1 and m.unstated_correct == 0             # r3
    assert sum(b.count for b in m.buckets) + m.unstated_count == m.n_decided


def test_empty_denominators_are_none_not_zero():
    m = compute_metrics(())
    assert m.agreement is None
    assert m.false_pass_rate is None and m.false_fail_rate is None
    assert all(b.accuracy is None for b in m.buckets)


def test_bucket_boundaries():
    lows = compute_metrics((_row("x", Verdict.PASS, Verdict.PASS, 0.0),)).buckets
    assert lows[0].count == 1                       # 0.0 -> first bucket
    tops = compute_metrics((_row("y", Verdict.PASS, Verdict.PASS, 1.0),)).buckets
    assert tops[-1].count == 1                      # 1.0 -> last bucket, inclusive
    assert BUCKET_EDGES[0] == 0.0 and BUCKET_EDGES[-1] == 1.0


# -- the scripted reference run has exactly the designed numbers --------------


def test_scripted_run_overall_metrics():
    m = compute_metrics(_scripted_rows())
    assert (m.n_items, m.n_reference, m.n_decided, m.n_abstained) == (10, 10, 9, 1)
    assert m.n_agree == 6 and m.agreement == 6 / 9
    assert (m.false_pass, m.reference_fails_decided) == (2, 4)   # 50.0%
    assert (m.false_fail, m.reference_passes_decided) == (1, 5)  # 20.0%
    by_range = {(b.lo, b.hi): (b.count, b.correct) for b in m.buckets}
    assert by_range[(0.0, 0.2)] == (0, 0)
    assert by_range[(0.2, 0.4)] == (1, 0)   # the low-confidence false-FAIL
    assert by_range[(0.4, 0.6)] == (2, 1)
    assert by_range[(0.6, 0.8)] == (1, 1)
    assert by_range[(0.8, 1.0)] == (4, 3)   # the overconfident false-PASS lives here
    assert (m.unstated_count, m.unstated_correct) == (1, 1)


def test_scripted_run_actor_identity_split():
    split = split_by_actor(_scripted_rows(), judge_model=SCRIPTED_JUDGE_MODEL)
    same, different = split["same_model"], split["different_model"]
    assert (same.n_decided, same.n_agree) == (5, 3)
    assert (same.false_pass, same.reference_fails_decided) == (2, 3)      # 66.7%
    assert (same.false_fail, same.reference_passes_decided) == (0, 2)
    assert (different.n_decided, different.n_agree) == (4, 3)
    assert (different.false_pass, different.reference_fails_decided) == (0, 1)
    assert (different.false_fail, different.reference_passes_decided) == (1, 3)


def test_confidences_come_from_the_judge_detail():
    rows = {r.item_id: r for r in _scripted_rows()}
    assert rows["c01"].confidence == 0.95
    assert rows["c10"].confidence is None    # decided without a stated confidence
    assert rows["c09"].judged == Verdict.ABSTAIN and rows["c09"].confidence is None


# -- read-only: evaluation is not experience ----------------------------------


def test_full_run_creates_no_trust_or_ledger_state(monkeypatch, tmp_path, capsys):
    ledger = tmp_path / "state" / "ledger.db"
    trust = tmp_path / "state" / "trust.db"
    monkeypatch.setenv("PROM_LEDGER_PATH", str(ledger))
    monkeypatch.setenv("PROM_TRUST_STORE_PATH", str(trust))
    monkeypatch.setenv("PROM_REGISTRY_DIR", str(tmp_path / "skills"))

    assert main([]) == 0

    out = capsys.readouterr().out
    assert "6/9 = 66.7%" in out and "2/4 = 50.0%" in out and "1/5 = 20.0%" in out
    # Nothing was created at the configured state paths — not even empty DBs.
    assert not ledger.exists() and not trust.exists()
    assert not (tmp_path / "state").exists()


def test_full_run_leaves_an_existing_trust_store_byte_identical(
    monkeypatch, tmp_path, capsys
):
    from prometheus_protocol.verifier.store import SqliteTrustStore
    from prometheus_protocol.verifier.trust import TrustStats

    trust = tmp_path / "trust.db"
    store = SqliteTrustStore(trust)
    store.put("model-judge", TrustStats(verifier_id="model-judge", tier=Tier.SOFT))
    snapshot_stats = store.all()
    snapshot_bytes = Path(trust).read_bytes()

    monkeypatch.setenv("PROM_TRUST_STORE_PATH", str(trust))
    monkeypatch.setenv("PROM_LEDGER_PATH", str(tmp_path / "ledger.db"))
    assert main([]) == 0
    capsys.readouterr()

    assert Path(trust).read_bytes() == snapshot_bytes
    assert SqliteTrustStore(trust).all() == snapshot_stats


def test_run_fails_loudly_without_an_authoritative_reference(
    monkeypatch, capsys
):
    # With the fail-closed backstop sandbox, the reference ABSTAINs everywhere:
    # the harness must refuse to report metrics, not fabricate them.
    from prometheus_protocol.sandbox.unsafe import NullSandbox
    from prometheus_protocol.verifier import runner

    original = runner.SubprocessVerifier
    monkeypatch.setattr(
        runner, "SubprocessVerifier",
        lambda **kw: original(sandbox=NullSandbox(), **kw),
    )
    assert main([]) == 1
    err = capsys.readouterr().err
    assert "no authoritative reference" in err
