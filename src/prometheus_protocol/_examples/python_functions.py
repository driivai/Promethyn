"""A small Python-function benchmark with train and held-out splits.

The benchmark is designed around a single failure cluster, ``empty-input``:
several tasks ask for a function over a list that must behave on the empty
list. The simulated baseline neglects that edge case, so at baseline a fixed
fraction of each split fails. One mined skill — "guard against empty input" —
repairs the whole cluster.

Concrete, asserted behaviour (see ``tests/conformance``):

  * Held-out baseline pass rate is 2/5 = 40% (multiply, repeat pass; median,
    last, minimum fail on the empty list).
  * After one learning cycle the skill is promoted and held-out reaches 5/5.
  * The skill's ablation contribution is 3/5 = +60%.
  * A second cycle finds nothing to learn (the train cluster now passes too).

The train and held-out splits use *different* functions for the same cluster,
so a promoted skill demonstrates generalisation rather than memorisation. The
two id sets are disjoint, satisfying the held-out firewall.
"""

from __future__ import annotations

from dataclasses import dataclass

from prometheus_protocol.core.models import (
    SPLIT_HELDOUT,
    SPLIT_TRAIN,
    Case,
    Task,
)
from prometheus_protocol.provider.mock import MockSolution

CLUSTER_EMPTY_INPUT = "empty-input"


@dataclass(frozen=True)
class Benchmark:
    """A train/held-out split of tasks."""

    train: tuple[Task, ...]
    heldout: tuple[Task, ...]

    @property
    def tasks(self) -> tuple[Task, ...]:
        return self.train + self.heldout


# --------------------------------------------------------------------------
# Tasks. Prompts for empty-input tasks mention "empty" (the retrieval/relevance
# trigger) and state the required empty-input result so the hidden cases are
# fair. Non-empty tasks never mention "empty".
# --------------------------------------------------------------------------

_TRAIN_TASKS: tuple[Task, ...] = (
    Task(
        id="train/mean",
        entry_point="mean",
        prompt=(
            "Return the arithmetic mean of a list of numbers `xs`. "
            "For an empty list, return 0.0."
        ),
        split=SPLIT_TRAIN,
        cluster=CLUSTER_EMPTY_INPUT,
        cases=(
            Case(args=([1, 2, 3],), expected=2.0),
            Case(args=([2, 4],), expected=3.0),
            Case(args=([],), expected=0.0),
        ),
    ),
    Task(
        id="train/maximum",
        entry_point="maximum",
        prompt=(
            "Return the largest value in the list `xs`. "
            "For an empty list, return None."
        ),
        split=SPLIT_TRAIN,
        cluster=CLUSTER_EMPTY_INPUT,
        cases=(
            Case(args=([3, 1, 2],), expected=3),
            Case(args=([5],), expected=5),
            Case(args=([],), expected=None),
        ),
    ),
    Task(
        id="train/first",
        entry_point="first",
        prompt="Return the first element of the list `xs`, or None if it is empty.",
        split=SPLIT_TRAIN,
        cluster=CLUSTER_EMPTY_INPUT,
        cases=(
            Case(args=([9, 8],), expected=9),
            Case(args=([],), expected=None),
        ),
    ),
    Task(
        id="train/add",
        entry_point="add",
        prompt="Return the sum of two numbers `a` and `b`.",
        split=SPLIT_TRAIN,
        cluster=None,
        cases=(
            Case(args=(2, 3), expected=5),
            Case(args=(-1, 1), expected=0),
        ),
    ),
    Task(
        id="train/concat",
        entry_point="concat",
        prompt="Return the concatenation of strings `a` and `b`.",
        split=SPLIT_TRAIN,
        cluster=None,
        cases=(
            Case(args=("ab", "cd"), expected="abcd"),
            Case(args=("x", "y"), expected="xy"),
        ),
    ),
)

_HELDOUT_TASKS: tuple[Task, ...] = (
    Task(
        id="heldout/median",
        entry_point="median",
        prompt=(
            "Return the median of the list `xs` (the middle value of the sorted "
            "elements). Return None if the list is empty."
        ),
        split=SPLIT_HELDOUT,
        cluster=CLUSTER_EMPTY_INPUT,
        cases=(
            Case(args=([3, 1, 2],), expected=2),
            Case(args=([5],), expected=5),
            Case(args=([],), expected=None),
        ),
    ),
    Task(
        id="heldout/last",
        entry_point="last",
        prompt="Return the last element of the list `xs`, or None if it is empty.",
        split=SPLIT_HELDOUT,
        cluster=CLUSTER_EMPTY_INPUT,
        cases=(
            Case(args=([1, 2, 3],), expected=3),
            Case(args=([],), expected=None),
        ),
    ),
    Task(
        id="heldout/minimum",
        entry_point="minimum",
        prompt=(
            "Return the smallest value in the list `xs`. "
            "For an empty list, return None."
        ),
        split=SPLIT_HELDOUT,
        cluster=CLUSTER_EMPTY_INPUT,
        cases=(
            Case(args=([3, 1, 2],), expected=1),
            Case(args=([5],), expected=5),
            Case(args=([],), expected=None),
        ),
    ),
    Task(
        id="heldout/multiply",
        entry_point="multiply",
        prompt="Return the product of two numbers `a` and `b`.",
        split=SPLIT_HELDOUT,
        cluster=None,
        cases=(
            Case(args=(2, 3), expected=6),
            Case(args=(0, 5), expected=0),
        ),
    ),
    Task(
        id="heldout/repeat",
        entry_point="repeat",
        prompt="Return the string `s` repeated `n` times.",
        split=SPLIT_HELDOUT,
        cluster=None,
        cases=(
            Case(args=("ab", 2), expected="abab"),
            Case(args=("x", 0), expected=""),
        ),
    ),
)


def build_benchmark() -> Benchmark:
    """Return the train/held-out benchmark used by the demo and tests."""

    return Benchmark(train=_TRAIN_TASKS, heldout=_HELDOUT_TASKS)


# --------------------------------------------------------------------------
# The mock provider's "solution book". Each baseline overlooks the empty-list
# case; each improved version guards it. Non-empty tasks have identical
# baseline and improved implementations (there is no edge case to miss).
# --------------------------------------------------------------------------

_BOOK: dict[str, MockSolution] = {
    "mean": MockSolution(
        baseline="def mean(xs):\n    return sum(xs) / len(xs)\n",
        improved=(
            "def mean(xs):\n"
            "    if not xs:\n"
            "        return 0.0\n"
            "    return sum(xs) / len(xs)\n"
        ),
    ),
    "maximum": MockSolution(
        baseline="def maximum(xs):\n    return max(xs)\n",
        improved=(
            "def maximum(xs):\n"
            "    if not xs:\n"
            "        return None\n"
            "    return max(xs)\n"
        ),
    ),
    "first": MockSolution(
        baseline="def first(xs):\n    return xs[0]\n",
        improved=(
            "def first(xs):\n"
            "    if not xs:\n"
            "        return None\n"
            "    return xs[0]\n"
        ),
    ),
    "median": MockSolution(
        baseline="def median(xs):\n    return sorted(xs)[len(xs) // 2]\n",
        improved=(
            "def median(xs):\n"
            "    if not xs:\n"
            "        return None\n"
            "    return sorted(xs)[len(xs) // 2]\n"
        ),
    ),
    "last": MockSolution(
        baseline="def last(xs):\n    return xs[-1]\n",
        improved=(
            "def last(xs):\n"
            "    if not xs:\n"
            "        return None\n"
            "    return xs[-1]\n"
        ),
    ),
    "minimum": MockSolution(
        baseline="def minimum(xs):\n    return min(xs)\n",
        improved=(
            "def minimum(xs):\n"
            "    if not xs:\n"
            "        return None\n"
            "    return min(xs)\n"
        ),
    ),
    "add": MockSolution(
        baseline="def add(a, b):\n    return a + b\n",
        improved="def add(a, b):\n    return a + b\n",
    ),
    "concat": MockSolution(
        baseline="def concat(a, b):\n    return a + b\n",
        improved="def concat(a, b):\n    return a + b\n",
    ),
    "multiply": MockSolution(
        baseline="def multiply(a, b):\n    return a * b\n",
        improved="def multiply(a, b):\n    return a * b\n",
    ),
    "repeat": MockSolution(
        baseline="def repeat(s, n):\n    return s * n\n",
        improved="def repeat(s, n):\n    return s * n\n",
    ),
}


def build_solution_book() -> dict[str, MockSolution]:
    """Return the canned solutions backing :class:`MockProvider` for the demo."""

    return dict(_BOOK)
