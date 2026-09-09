"""Human-readable renderings of the outcome unions. Reporting only.

The demos, evaluators and loop narratives print what a verifier or the bank
produced. Every one of them used to reach straight for ``.verdict.value``,
which crashes on an :class:`Unavailable` — an object that deliberately has no
verdict — and that is five of the eleven crashes the independent review
reproduced.

These helpers render **either** member without inventing anything: an
unavailability prints as an explicit could-not-run, carrying its reason and
detail, and is never rendered as a verdict or an abstention. They are
deliberately presentation-only. A caller that *branches* on the outcome must
still narrow the union itself — there is no "get me a verdict from this"
function here, because for an Unavailable there is no answer to give.
"""

from __future__ import annotations

from prometheus_protocol.core.models import (
    Evidence,
    Judgment,
    Unavailable,
    assert_never,
)


def render_outcome(outcome: Evidence | Unavailable) -> str:
    """One line for what a verifier produced: a verdict, or a could-not-run."""

    if isinstance(outcome, Unavailable):
        return (
            f"UNAVAILABLE (could not run — {outcome.reason.value}: "
            f"{outcome.detail or 'no detail'})"
        )
    if isinstance(outcome, Evidence):
        return (
            f"{outcome.decided.value.upper()}"
            + (f" — {outcome.detail}" if outcome.detail else "")
        )
    assert_never(outcome)


def render_judgment(judgment: Judgment | Unavailable) -> str:
    """One line for what the bank reached: a fused judgment, or a could-not-judge."""

    if isinstance(judgment, Unavailable):
        return (
            f"UNAVAILABLE (no judgment — {judgment.reason.value}: "
            f"{judgment.detail or 'no detail'})"
        )
    if isinstance(judgment, Judgment):
        return (
            f"verdict={judgment.verdict.value} "
            f"confidence={judgment.confidence:.2f} "
            f"authoritative={judgment.authoritative}"
        )
    assert_never(judgment)
