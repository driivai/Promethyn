"""The SQL learn loop: verified wins become a promoted, reversible skill.

This closes the LEARN loop for the SQL domain through the SHARED promotion
pipeline — the same :class:`Orchestrator` sequencing, the same
:class:`LessonForge`, the same :class:`PromotionGate` with its held-out
firewall, the same markdown skill registry, and the same ledger the code
domain uses. Nothing is forked; the only SQL-specific parts are the task type
(``SqlTask``, with the same train/held-out split semantics as the code
``Task``), the HARD verifier, and the frozen proposer simulation below.

HONEST DESCRIPTION of the proposer: like the code domain's ``MockProvider``,
``ScriptedSqlProvider`` is a SIMULATION of a frozen model, not a model. Its
book maps each corpus prompt to two canned queries: a *baseline* that makes
the cluster's characteristic mistake, and an *improved* one used only when a
retrieved skill is relevant to the prompt (same criterion as the code mock:
a skill trigger appears in the prompt). The model never changes — a promoted
skill changes the CONTEXT a proposal is made in, never any weights.

The corpus is built so the one cycle demonstrates both gate outcomes:

* ``sql-null-absence`` — the lesson GENERALISES: with the skill in context
  the provider also writes correct queries for the held-out absence tasks it
  never trained on, so the held-out rate rises and the gate promotes.
* ``sql-distinct-shortcut`` — the lesson is OVERFIT by construction: its
  held-out members' improved queries are the same wrong queries (the lesson
  fixed only the tasks it was mined from), so the held-out rate does not
  move and the gate refuses promotion. The cluster name sorts before the
  genuine one, so it is scored before anything has been promoted — the
  refusal is measured against the clean baseline.

Both verdicts come from the real machinery: every pass/fail is the HARD SQL
verifier executing queries in the sandbox, and the promotion decision is the
unmodified ``PromotionGate`` behind the unmodified held-out firewall.
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path
from typing import Callable, Mapping, Sequence

from prometheus_protocol.benchmarks.sql_items import (
    CLUSTER_DISTINCT,
    CLUSTER_NULL,
    build_sql_tasks,
)
from prometheus_protocol.core.interfaces import Provider
from prometheus_protocol.core.models import SPLIT_HELDOUT, SPLIT_TRAIN, Skill
from prometheus_protocol.forge.miner import Lesson, LessonForge
from prometheus_protocol.gate.promotion import PromotionGate, assert_disjoint
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.provider.mock import MockSolution, has_relevant_skill
from prometheus_protocol.registry.markdown_registry import MarkdownSkillRegistry
from prometheus_protocol.runtime.orchestrator import Orchestrator
from prometheus_protocol.sandbox import NamespaceSandbox
from prometheus_protocol.verifier.sql import SqlTask, SqlVerifier

#: The learn corpus: five train and five held-out tasks from sql-v1, chosen so
#: each labelled cluster has two members in each split plus one clean task per
#: split (its baseline is already correct — it anchors the pass rates).
TRAIN_IDS = (
    "sql/03-paid-revenue",  # clean
    "sql/04-customers-with-orders",  # sql-distinct-shortcut
    "sql/16-no-manager",  # sql-null-absence
    "sql/18-managers",  # sql-distinct-shortcut
    "sql/24-duration-per-user",  # sql-null-absence
)
HELDOUT_IDS = (
    "sql/05-customers-without-orders",  # sql-null-absence
    "sql/26-login-users",  # sql-distinct-shortcut
    "sql/29-day5-count",  # clean
    "sql/31-avg-call-duration",  # sql-null-absence
    "sql/32-distinct-kind-days",  # sql-distinct-shortcut
)

#: The curated SQL lessons the shared forge mines from its clusters. Trigger
#: phrases are chosen from the corpus prompts deterministically: every member
#: of a cluster (both splits) contains one of its lesson's triggers, and no
#: other corpus prompt contains any of them.
SQL_LESSONS: dict[str, Lesson] = {
    CLUSTER_NULL: Lesson(
        title="Test absence with IS NULL semantics",
        triggers=("never", "no manager", "missing"),
        guidance=(
            "SQL NULL never equals anything, including NULL: a `= NULL` "
            "comparison matches no rows. Test absence with IS NULL / IS NOT "
            "NULL, and exclude missing values from aggregates explicitly "
            "rather than coalescing them into real values."
        ),
    ),
    CLUSTER_DISTINCT: Lesson(
        title="Deduplicate result rows explicitly",
        triggers=("each once", "distinct"),
        guidance=(
            "A join or filter that can match a source row more than once "
            "duplicates it in the result. When the ask is for distinct "
            "values or 'each once', deduplicate explicitly with SELECT "
            "DISTINCT (or an equivalent grouping)."
        ),
    ),
}

#: The baseline (wrong) query per afflicted task — each is that task's
#: characteristic designed-wrong probe from ``sql_items``. Tasks absent from
#: this map are the clean ones: their baseline is the reference itself.
_BASELINES: dict[str, str] = {
    "sql/04-customers-with-orders":
        "SELECT c.name FROM customers c JOIN orders o ON o.customer_id = c.id",
    "sql/16-no-manager":
        "SELECT name FROM employees WHERE manager_id = NULL",
    "sql/18-managers":
        "SELECT m.name FROM employees m JOIN employees e ON e.manager_id = m.id",
    "sql/24-duration-per-user":
        "SELECT user_id, SUM(duration) FROM events GROUP BY user_id",
    "sql/05-customers-without-orders":
        "SELECT c.name FROM customers c "
        "LEFT JOIN orders o ON o.customer_id = c.id WHERE o.id = NULL",
    "sql/26-login-users":
        "SELECT user_id FROM events WHERE kind = 'login'",
    "sql/31-avg-call-duration":
        "SELECT AVG(COALESCE(duration, 0)) FROM events WHERE kind = 'call'",
    "sql/32-distinct-kind-days":
        "SELECT kind, day FROM events",
}

#: Held-out tasks whose lesson does NOT transfer: with the (overfit) skill in
#: context the provider still writes the wrong query. This is the simulation
#: of a lesson that fixed only the tasks it was mined from.
_NON_TRANSFER = frozenset({
    "sql/26-login-users",
    "sql/32-distinct-kind-days",
})


def build_learn_corpus() -> tuple[tuple[SqlTask, ...], tuple[SqlTask, ...]]:
    """Select the learn corpus from sql-v1, partitioned by each task's split."""

    by_id = {task.id: task for task in build_sql_tasks()}
    train = tuple(by_id[i] for i in TRAIN_IDS)
    heldout = tuple(by_id[i] for i in HELDOUT_IDS)
    # The selection must agree with the corpus's own partition metadata.
    mismatched = [t.id for t in train if t.split != SPLIT_TRAIN] + [
        t.id for t in heldout if t.split != SPLIT_HELDOUT
    ]
    if mismatched:
        raise ValueError(f"corpus selection disagrees with task splits: {mismatched}")
    return train, heldout


def build_sql_book() -> dict[str, MockSolution]:
    """The prompt-keyed solution book behind the frozen SQL proposer."""

    train, heldout = build_learn_corpus()
    book: dict[str, MockSolution] = {}
    for task in (*train, *heldout):
        baseline = _BASELINES.get(task.id, task.reference_query)
        improved = baseline if task.id in _NON_TRANSFER else task.reference_query
        book[task.prompt] = MockSolution(baseline=baseline, improved=improved)
    return book


class ScriptedSqlProvider(Provider):
    """Frozen offline proposer simulation for SQL. See module docstring.

    SQL tasks have no entry point, so the book is keyed by the prompt; the
    improvement criterion is the same one the code-domain mock uses.
    """

    def __init__(self, book: Mapping[str, MockSolution] | None = None) -> None:
        self._book = dict(build_sql_book() if book is None else book)

    def propose_solution(
        self,
        *,
        prompt: str,
        entry_point: str = "",
        skills: Sequence[Skill] = (),
    ) -> str:
        solution = self._book.get(prompt)
        if solution is None:
            raise ValueError(
                f"no scripted SQL proposal for prompt {prompt!r}; the frozen "
                "simulation must never be asked off-book"
            )
        if has_relevant_skill(prompt, skills):
            return solution.improved
        return solution.baseline


def build_learn_orchestrator(
    registry_dir: Path | str, *, ledger_path: str = ":memory:"
) -> Orchestrator:
    """The shared pipeline, instantiated for the SQL domain.

    Every component below is the same class the code domain runs on; only the
    verifier, the proposer simulation, and the lesson book are SQL's.
    """

    return Orchestrator(
        provider=ScriptedSqlProvider(),
        verifier=SqlVerifier(),
        registry=MarkdownSkillRegistry(registry_dir),
        gate=PromotionGate(),
        ledger=SqliteLedger(ledger_path),
        forge=LessonForge(SQL_LESSONS),
    )


def run_learn_demo(
    registry_dir: Path | str, *, out: Callable[[str], None] = print
) -> dict:
    """One learning cycle plus a rollback, printing every beat. Returns a summary."""

    train, heldout = build_learn_corpus()
    train_ids = [t.id for t in train]
    heldout_ids = [t.id for t in heldout]
    assert_disjoint(train_ids, heldout_ids)
    out(f"[learn] corpus: {len(train)} train / {len(heldout)} held-out tasks")
    out("[learn] firewall: train and held-out id sets verified disjoint")

    orchestrator = build_learn_orchestrator(registry_dir)
    cycle = orchestrator.run_cycle(train, heldout, cycle=1)

    out(f"[learn] held-out baseline rate: {cycle.baseline_heldout_rate:.0%}")
    train_rows = [r for r in orchestrator.ledger.attempts() if r["kind"] == "train"]
    failed_rows = [r for r in train_rows if not r["passed"]]
    out(f"[learn] train run: {len(failed_rows)}/{len(train_rows)} verified "
        "failures -> forge mines from them (train split only)")
    for skill in cycle.mined:
        out(f"[learn]   candidate {skill.id} (triggers: {', '.join(skill.triggers)})")

    for decision in cycle.decisions:
        verdict = "PROMOTED" if decision.approved else "REFUSED"
        out(f"[gate] {decision.skill_id}: held-out {decision.rate_before:.0%} "
            f"-> {decision.rate_after:.0%} : {verdict}"
            + ("" if decision.approved else " (no held-out improvement — the "
               "lesson fits its training tasks only)"))

    out(f"[learn] held-out rate after promotion: {cycle.post_heldout_rate:.0%}")
    promoted_id = cycle.promoted[0] if cycle.promoted else None
    if promoted_id is not None:
        path = Path(registry_dir) / f"{promoted_id}.md"
        out(f"[learn] promoted skill on disk: {path.name} "
            f"(versioned markdown row — reviewable, deletable)")

    # Rollback: remove the promoted skill, record the reversal in the ledger,
    # and re-measure — the pre-promotion behaviour must return exactly.
    rollback_rate = None
    if promoted_id is not None:
        orchestrator.registry.remove(promoted_id)
        rollback_rate = orchestrator.run_split(
            heldout, cycle=1, kind="heldout-after-rollback"
        ).pass_rate
        orchestrator.ledger.record_promotion(
            skill_id=promoted_id,
            action="rollback",
            cycle=1,
            rate_before=cycle.post_heldout_rate,
            rate_after=rollback_rate,
        )
        out(f"[learn] rollback: removed {promoted_id}; held-out rate restored "
            f"to {rollback_rate:.0%}")

    out("[audit] promotions ledger (in order):")
    for row in orchestrator.ledger.promotions():
        out(f"[audit]   #{row['id']} {row['action']} {row['skill_id']}: "
            f"{row['rate_before']:.0%} -> {row['rate_after']:.0%}")

    return {
        "baseline_heldout_rate": cycle.baseline_heldout_rate,
        "decisions": {d.skill_id: d.approved for d in cycle.decisions},
        "promoted": cycle.promoted,
        "post_heldout_rate": cycle.post_heldout_rate,
        "rollback_rate": rollback_rate,
        "promotions": orchestrator.ledger.promotions(),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m prometheus_protocol.benchmarks.sql_learn_demo",
        description="SQL learn loop: promote, refuse the overfit, roll back.",
    )
    parser.parse_args(argv)
    if not NamespaceSandbox.available():
        print("[demo] the namespace isolation runtime is unavailable; the SQL "
              "verifier would only ABSTAIN, so the demo refuses to run.")
        return 1
    with tempfile.TemporaryDirectory(prefix="prom-sql-skills-") as registry_dir:
        print(f"[demo] skill registry: {registry_dir}")
        summary = run_learn_demo(registry_dir)
    ok = (
        summary["promoted"] == (f"skill-{CLUSTER_NULL}",)
        and summary["decisions"].get(f"skill-{CLUSTER_DISTINCT}") is False
        and summary["rollback_rate"] == summary["baseline_heldout_rate"]
    )
    print("[demo] " + ("learn loop closed: earned promotion, overfit refused, "
                       "rollback exact" if ok else "UNEXPECTED OUTCOME (see above)"))
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover - exercised via main() in tests
    raise SystemExit(main())
