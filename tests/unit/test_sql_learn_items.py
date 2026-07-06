"""Unit pins for the SQL learn corpus and its frozen proposer simulation.

The learning-cycle conformance numbers are deterministic only if these
preconditions hold, so they are pinned directly: the book covers the corpus
with the intended baseline/improved shapes, lesson triggers select exactly
their own cluster's prompts, and no trigger crosses the domain boundary in
either direction (that is what makes retrieval-based scoping deterministic).
"""

from __future__ import annotations

import pytest

from harness.benchmarks.python_functions import build_benchmark
from prometheus_protocol.benchmarks.sql_items import (
    CLUSTER_DISTINCT,
    CLUSTER_NULL,
    build_sql_tasks,
)
from prometheus_protocol.benchmarks.sql_learn_demo import (
    _NON_TRANSFER,
    SQL_LESSONS,
    ScriptedSqlProvider,
    build_learn_corpus,
    build_sql_book,
)
from prometheus_protocol.core.models import Skill


def _corpus():
    train, heldout = build_learn_corpus()
    return (*train, *heldout)


def test_book_covers_the_corpus_with_the_intended_shapes():
    book = build_sql_book()
    for task in _corpus():
        solution = book[task.prompt]  # KeyError here means an off-book task
        if task.cluster is None:
            # Clean anchors: already correct, skill or not.
            assert solution.baseline == solution.improved == task.reference_query
        elif task.id in _NON_TRANSFER:
            # The overfit lesson's held-out members: improved is still wrong.
            assert solution.improved == solution.baseline
            assert solution.baseline != task.reference_query
        else:
            # Afflicted members a relevant lesson genuinely repairs.
            assert solution.baseline != task.reference_query
            assert solution.improved == task.reference_query


def test_lesson_triggers_select_exactly_their_cluster():
    for cluster, lesson in SQL_LESSONS.items():
        for task in _corpus():
            prompt = task.prompt.lower()
            hit = any(t.lower() in prompt for t in lesson.triggers)
            assert hit == (task.cluster == cluster), (cluster, task.id)


def test_no_trigger_crosses_the_domain_boundary():
    sql_prompts = [t.prompt.lower() for t in build_sql_tasks()]
    code_prompts = [
        t.prompt.lower() for t in build_benchmark().tasks
    ]
    # The code lesson's trigger appears in no SQL corpus prompt...
    assert all("empty" not in p for p in (t.prompt.lower() for t in _corpus()))
    # ...and no SQL lesson trigger appears in any code-benchmark prompt.
    for lesson in SQL_LESSONS.values():
        for trigger in lesson.triggers:
            assert all(trigger.lower() not in p for p in code_prompts), trigger
    # The full 32-task corpus keeps prompts and triggers well-defined.
    assert len(sql_prompts) == len(set(sql_prompts))  # prompts stay unique keys


def test_scripted_provider_is_frozen_and_skill_gated():
    provider = ScriptedSqlProvider()
    train, heldout = build_learn_corpus()
    null_train = next(t for t in train if t.cluster == CLUSTER_NULL)
    lesson = SQL_LESSONS[CLUSTER_NULL]
    skill = Skill(id="skill-x", title="x", body="x", triggers=lesson.triggers)

    bare = provider.propose_solution(prompt=null_train.prompt)
    with_skill = provider.propose_solution(prompt=null_train.prompt, skills=[skill])
    assert bare != with_skill  # the skill unlocks the improved query
    assert with_skill == null_train.reference_query
    # Deterministic: same inputs, same output, every time.
    assert provider.propose_solution(prompt=null_train.prompt) == bare

    overfit_heldout = next(
        t for t in heldout if t.id in _NON_TRANSFER
    )
    distinct_skill = Skill(
        id="skill-y", title="y", body="y",
        triggers=SQL_LESSONS[CLUSTER_DISTINCT].triggers,
    )
    assert provider.propose_solution(
        prompt=overfit_heldout.prompt, skills=[distinct_skill]
    ) == provider.propose_solution(prompt=overfit_heldout.prompt)

    with pytest.raises(ValueError, match="off-book"):
        provider.propose_solution(prompt="not a corpus prompt")
