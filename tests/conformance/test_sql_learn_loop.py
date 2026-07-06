"""Conformance: the SQL domain rides the SAME promotion pipeline and firewall.

The held-out firewall must hold for SQL exactly as it holds for code — same
``assert_disjoint`` in the same unmodified gate, same forge-side refusal of
non-training attempts — and promotion must be earned: a lesson that
generalises to held-out SQL tasks promotes, an overfit one is refused, a
promotion reverses exactly, and a promoted SQL skill does not leak into the
code domain's behaviour.

The firewall tests need no sandbox (a firewall breach aborts before any query
runs). The cycle tests execute real queries through the HARD SQL verifier, so
they need the isolation runtime (skip without it; FAIL under
PROM_REQUIRE_SANDBOX=1). The full cycle runs ONCE per module; the
reversibility test deliberately mutates that shared state and therefore runs
LAST in this file (plain pytest executes tests in definition order).
"""

from __future__ import annotations

import os

import pytest

from harness.benchmarks.python_functions import build_benchmark, build_solution_book
from prometheus_protocol import Config, FirewallError, build_orchestrator
from prometheus_protocol.benchmarks.sql_items import (
    CLUSTER_DISTINCT,
    CLUSTER_NULL,
    build_sql_tasks,
)
from prometheus_protocol.benchmarks.sql_learn_demo import (
    SQL_LESSONS,
    build_learn_corpus,
    build_learn_orchestrator,
)
from prometheus_protocol.core.models import (
    SPLIT_HELDOUT,
    SPLIT_TRAIN,
    Attempt,
    Evidence,
    Skill,
)
from prometheus_protocol.forge.miner import LessonForge
from prometheus_protocol.gate.promotion import PromotionGate
from prometheus_protocol.sandbox import NamespaceSandbox
from prometheus_protocol.verifier.sql import SqlTask

_REQUIRE = (os.environ.get("PROM_REQUIRE_SANDBOX", "") or "").strip().lower() in {
    "1", "true", "yes", "on",
}

OVERFIT_SKILL = f"skill-{CLUSTER_DISTINCT}"
GENUINE_SKILL = f"skill-{CLUSTER_NULL}"


def _require_runtime() -> None:
    if not NamespaceSandbox.available():
        reason = "namespace isolation runtime (unprivileged user namespaces) unavailable"
        if _REQUIRE:
            pytest.fail(f"PROM_REQUIRE_SANDBOX=1 but {reason}")
        pytest.skip(reason)


def _sql_task(task_id: str, split: str) -> SqlTask:
    return SqlTask(
        id=task_id,
        prompt="probe",
        schema_sql="CREATE TABLE t (v INTEGER);",
        fixture_sql="",
        reference_query="SELECT v FROM t",
        split=split,
    )


# --------------------------------------------------------------------------
# the firewall, for SQL — no sandbox needed (a breach aborts before scoring)
# --------------------------------------------------------------------------


def test_gate_blocks_overlapping_sql_ids():
    """The UNMODIFIED gate fires on SQL ids exactly as on code ids."""

    train, _ = build_learn_corpus()
    leaky = _sql_task(train[0].id, SPLIT_HELDOUT)  # a train id posing as held-out

    def never_called(tasks, skill):  # pragma: no cover - must not run
        raise AssertionError("score_fn ran despite a firewall breach")

    with pytest.raises(FirewallError):
        PromotionGate().evaluate(
            candidate=Skill(id="skill-x", title="x", body="x"),
            train_ids=[task.id for task in train],
            heldout_tasks=[leaky],
            score_fn=never_called,
            rate_before=0.0,
        )


def test_forge_refuses_heldout_sql_attempts():
    """The forge side of the firewall refuses held-out SQL attempts."""

    held = Attempt(
        task_id="sql/05-customers-without-orders",
        split=SPLIT_HELDOUT,
        entry_point="",  # SQL tasks have none
        code="SELECT 1",
        evidence=Evidence(passed=False, total=1, passed_count=0),
    )
    with pytest.raises(ValueError, match="held-out"):
        LessonForge(SQL_LESSONS).mine([held], tasks_by_id={})


def test_sql_corpus_partition_is_disjoint_and_clusters_span_splits():
    tasks = build_sql_tasks()
    train_ids = {t.id for t in tasks if t.split == SPLIT_TRAIN}
    heldout_ids = {t.id for t in tasks if t.split == SPLIT_HELDOUT}
    assert train_ids and heldout_ids
    assert train_ids.isdisjoint(heldout_ids)
    assert len(train_ids) + len(heldout_ids) == len(tasks)  # split is total
    # Every labelled cluster spans both splits, so generalisation is testable.
    for cluster in (CLUSTER_DISTINCT, CLUSTER_NULL):
        splits = {t.split for t in tasks if t.cluster == cluster}
        assert splits == {SPLIT_TRAIN, SPLIT_HELDOUT}, cluster


def test_sql_task_rejects_unknown_split():
    with pytest.raises(ValueError, match="unknown split"):
        _sql_task("sql/x", "evaluation")


# --------------------------------------------------------------------------
# the cycle — real queries, real sandbox, shared pipeline end to end
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def learn_cycle(tmp_path_factory):
    """One real learning cycle through the shared pipeline (runs once)."""

    _require_runtime()
    registry_dir = tmp_path_factory.mktemp("sql-skills")
    orchestrator = build_learn_orchestrator(registry_dir)
    train, heldout = build_learn_corpus()
    report = orchestrator.run_cycle(train, heldout, cycle=1)
    return orchestrator, report, train, heldout


def test_sql_cycle_promotes_generalizing_and_refuses_overfit(learn_cycle):
    orchestrator, report, _, _ = learn_cycle
    assert report.baseline_heldout_rate == 0.2
    decisions = {d.skill_id: d for d in report.decisions}
    # The overfit lesson is scored first (its cluster sorts first), against
    # the clean baseline: no held-out lift, refused, never enters the registry.
    overfit = decisions[OVERFIT_SKILL]
    assert overfit.approved is False
    assert overfit.rate_after == report.baseline_heldout_rate
    assert orchestrator.registry.get(OVERFIT_SKILL) is None
    # The genuine lesson lifts held-out tasks it was never mined from.
    genuine = decisions[GENUINE_SKILL]
    assert genuine.approved is True
    assert genuine.rate_after == 0.6
    assert report.promoted == (GENUINE_SKILL,)
    assert report.post_heldout_rate == 0.6
    assert orchestrator.registry.get(GENUINE_SKILL) is not None


def test_no_heldout_leakage_into_the_promotion_path(learn_cycle):
    """Held-out results reach promotion ONLY through the gate's own scoring.

    Auditable from the ledger alone: training-phase attempts touch train ids
    exclusively (what the forge mined from), held-out ids appear only under
    the held-out measurement kinds (the firewalled check), and no candidate
    skill's provenance lists a held-out task.
    """

    orchestrator, report, train, heldout = learn_cycle
    train_ids = {t.id for t in train}
    heldout_ids = {t.id for t in heldout}

    rows = orchestrator.ledger.attempts()
    assert rows, "the cycle must be auditable from the ledger"
    train_kind_ids = {r["task_id"] for r in rows if r["kind"] == "train"}
    heldout_kind_ids = {
        r["task_id"]
        for r in rows
        if r["kind"] in ("heldout-before", "gate-score", "heldout-after")
    }
    assert train_kind_ids == train_ids
    assert heldout_kind_ids == heldout_ids
    assert train_kind_ids.isdisjoint(heldout_ids)

    # No mined candidate cites a held-out task: the forge saw train only.
    for skill in report.mined:
        for heldout_id in heldout_ids:
            assert heldout_id not in skill.body, (skill.id, heldout_id)
        assert any(train_id in skill.body for train_id in train_ids)


def test_promoted_sql_skill_is_scoped_to_its_domain(tmp_path):
    """A promoted SQL skill leaves the code domain's behaviour untouched.

    Scoping is by retrieval relevance: the SQL lesson's triggers occur in no
    code-benchmark prompt, so with the SQL skill sitting in the registry the
    code baseline is bit-identical (0.4, the pinned code-domain number). The
    skill is minted through the shared forge from train failures directly, so
    this test needs no SQL sandbox run.
    """

    train, _ = build_learn_corpus()
    by_id = {t.id: t for t in train}
    failures = [
        Attempt(task_id=t.id, split=SPLIT_TRAIN, entry_point="", code="x",
                evidence=Evidence(passed=False, total=1, passed_count=0))
        for t in train
        if t.cluster == CLUSTER_NULL
    ]
    (sql_skill,) = LessonForge(SQL_LESSONS).mine(failures, by_id)
    assert sql_skill.id == GENUINE_SKILL

    config = Config(
        provider="mock",
        registry_dir=tmp_path / "skills",
        ledger_path=":memory:",
        verifier_memory_mb=0,
    )
    code_orchestrator = build_orchestrator(
        config, solution_book=build_solution_book()
    )
    code_orchestrator.registry.add(sql_skill)
    benchmark = build_benchmark()
    assert code_orchestrator.baseline(benchmark.heldout).pass_rate == 0.4


def test_promoted_sql_skill_is_reversible(learn_cycle):
    """Rollback restores the pre-promotion held-out behaviour exactly.

    Runs LAST: it removes the promoted skill from the module-scoped cycle's
    registry (that mutation IS the property under test).
    """

    orchestrator, report, _, heldout = learn_cycle
    assert orchestrator.run_split(heldout, cycle=1, kind="pre-rollback").pass_rate == 0.6
    orchestrator.registry.remove(GENUINE_SKILL)
    assert orchestrator.registry.get(GENUINE_SKILL) is None
    restored = orchestrator.run_split(heldout, cycle=1, kind="post-rollback").pass_rate
    assert restored == report.baseline_heldout_rate == 0.2
    orchestrator.ledger.record_promotion(
        skill_id=GENUINE_SKILL, action="rollback", cycle=1,
        rate_before=report.post_heldout_rate, rate_after=restored,
    )
    actions = [
        (row["skill_id"], row["action"]) for row in orchestrator.ledger.promotions()
    ]
    assert actions == [(GENUINE_SKILL, "promote"), (GENUINE_SKILL, "rollback")]
