"""A bound that is deliberately not enforced, and how far it travels.

WHY THIS IS ITS OWN MODULE. ``UNBOUNDED`` used to be resolved to ``0`` at the
composition root, in ``runtime/factory.py``, before any adapter saw it. That is
one flattening point for three substrates that read ``0`` differently, and the
Codex review on PR #106 found the consequence: ``ContainerSandbox`` coerces the
memory limit with ``max(bytes, 16 MiB)`` and always emits ``--memory``, so
"unbounded" arrived at the container runtime as **a 16 MiB cap** — the tightest
in the tree — while the same posture on the namespace and unsafe adapters
correctly imposed nothing.

So the sentinel now survives to the point where EACH ADAPTER BUILDS ITS COMMAND,
and each decides for itself what it means there. ``resolve_bound`` still exists
and still returns ``0``, but it is called at the last line before an argv or an
rlimit, not at the root — an adapter that must distinguish (the container one)
asks :func:`is_unbounded` first and omits the flag entirely.

WHY NOT JUST FIX THE CONTAINER ADAPTER. Special-casing zero inside
``ContainerSandbox.run`` fixes this instance and leaves the shape that produced
it: a deliberate operator choice flattened into a value two substrates read
differently. The next adapter, or the next coercion in this one, reintroduces it
silently. ``test_sandbox_unbounded_reaches_the_command.py`` is the class-level
guard, and it is parametrised over every name in ``SANDBOX_NAMES`` so a new
adapter cannot be added without an answer.

WHAT ``0`` STILL MEANS. Unchanged, everywhere it already meant it:
``SubprocessVerifier``, ``Limits``, the namespace bootstrap's argv and the POSIX
rlimits all read ``0`` as "do not impose this one". Inside the library, where
the value arrives from a caller who wrote it on the same line, ``0`` is
unambiguous. What is refused is a bare ``0`` at the ``Config`` surface, where it
is what an unset variable and a slipped keystroke also look like (OPEN-GAPS
G21).
"""

from __future__ import annotations

#: The canonical spelling of "this bound is deliberately not enforced".
UNBOUNDED = "unbounded"

#: The spellings ``Config`` accepts for it. An ALLOWLIST over what varies — the
#: permitted spellings — so a near-miss is refused rather than falling back to
#: a bound or to unbounded. A further spelling is added by writing it down here.
UNBOUNDED_SPELLINGS = frozenset({UNBOUNDED})

#: A positive cap, or ``UNBOUNDED``. Spelled out at every boundary this travels
#: through so the union is visible in the signature rather than in a comment.
Bound = int | str


def is_unbounded(value: Bound) -> bool:
    """True when the operator NAMED this bound as unenforced.

    Distinct from ``resolve_bound(value) == 0`` on purpose: an adapter that must
    omit a flag rather than pass a zero needs to know which of the two it has,
    and that is the distinction PR #106's finding turned on.
    """

    return isinstance(value, str)


def resolve_bound(value: Bound) -> int:
    """The integer the ``0 = no limit`` APIs take.

    Call this at the line that builds an argv or sets an rlimit, never earlier:
    resolving at a composition root is what let one substrate read the result as
    "no cap" and another as "16 MiB".
    """

    # Statement form, not a ternary: narrowing a union in expression position is
    # refused by `test_no_union_is_narrowed_in_expression_position`, and it was
    # right to — this is the one line that decides whether a cap is imposed.
    if isinstance(value, str):
        return 0
    return value
