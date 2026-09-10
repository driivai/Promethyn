"""The approval-validity clock model, and the admission decision it supports.

F7: an approval carries a signed expiry, and the runner sampled the wall clock
ONCE — at ``runner.py`` STEP 1 — then did an unbounded amount of preparation
before calling the executor. An independent review reproduced an approval that
expired at t=1001 being executed at t=5000: ``executed=True``,
``state=committed``, nonce spent, intent and outcome both durably appended.

Everything between that single sample and the executor can consume a TTL:
store/descriptor preparation and SQLite configuration, ownership substrate
checks, the reconciliation lock (no TTL-derived acquisition timeout), audit
verification (a remote anchor history read plus a full chain recompute), a
second ``chained_events()`` read with intent/outcome matching, a per-intent
receipt lookup (password provider, PostgreSQL connect/auth, advisory lock,
relation and receipt queries — ``connect_timeout=10`` bounds the CONNECT, not
the lookup), recovered-outcome persistence, approval consumption under
``BEGIN IMMEDIATE`` with ``busy_timeout=30000`` (thirty seconds alone exceeds
many TTLs), the intent ledger append with up to sixteen collision retries, and
intent anchor publication — which against an https anchor is FOUR HTTP requests,
each with its own deadline, so four individually successful slow exchanges at
the factory's 30s default exceed the 90s default TTL on their own.

WHAT THIS MODULE IS. One fixed deadline per invocation, and a check that can be
made at every boundary that matters. Getting the clock model wrong here would
open a different hole than the one it closes, so each rule is stated with the
attack it answers.

**One fixed deadline, never refreshed.** It is derived once, from the validity
remaining at the moment the invocation begins. A deadline recomputed on retry
would let a caller that retries forever hold an approval open forever.

**The elapsed clock is sampled BEFORE the wall clock.** The budget is
``expires_at - wall``, and the deadline is ``elapsed + budget``. Sample elapsed
first and a pause between the two samples lands in ``wall``, which SHRINKS the
budget. Sample wall first and the same pause lands in ``elapsed``, which moves
the elapsed deadline later while the budget stays large — a pause would enlarge
the invocation. The order is the safety property, not an implementation detail.

**Both clocks must agree, and either can refuse.** Wall-clock alone is
insufficient: a backward step extends the invocation. Elapsed alone is
insufficient: a forward step lets an approval that is genuinely expired run.
:meth:`ExecutionDeadline.admit` refuses when EITHER is reached.

**The elapsed source is suspend-aware where the platform offers one.** A host
suspended for an hour must resume with an hour less validity, not with the
budget it had when it went to sleep — an approval's TTL is a statement about
how long the authorization is good for, not about how much CPU time it gets.
``time.monotonic()`` is CLOCK_MONOTONIC on Linux, which EXCLUDES suspend, so
this module does not assume its semantics: it uses ``CLOCK_BOOTTIME`` (which
includes suspend) where the platform provides it, records which source it got
in :attr:`ExecutionDeadline.elapsed_source`, and says so in the audit payload.
Where only ``time.monotonic`` is available the deadline still holds — the
wall-clock arm is unaffected by suspend and refuses on its own.

**No monotonic value crosses a restart.** CLOCK_BOOTTIME and CLOCK_MONOTONIC
epochs are not portable across boots, processes or hosts; a persisted elapsed
timestamp compared against a fresh one is a comparison between two different
origins. Nothing here is serialized: :class:`ExecutionDeadline` is
process-local by construction, and the audit payload records only wall-clock
values plus the source's NAME.

**Clock trust is explicit.** ``expires_at`` is a UTC instant, so evaluating it
requires trusting UTC on this host. Two local clocks do not repair untrusted
UTC — CLOCK_BOOTTIME says how long this box has been up, not what time it is —
so a deployment that cannot trust UTC must say so, and then admission refuses
rather than pretending the elapsed arm substitutes for it. Within trusted UTC a
tolerated uncertainty is still declared, and an invocation whose remaining
validity is inside that margin is refused rather than raced.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Callable

#: Refusal reasons this module produces. ``EXPIRED`` matches
#: ``approval.EXPIRED`` so a ledger keying on it sees one identifier for "the
#: approval was not current", whichever boundary noticed.
EXPIRED = "expired"
INVALID_TIME = "invalid_time"
CLOCK_UNTRUSTED = "clock_untrusted"
CLOCK_MARGIN = "clock_margin_insufficient"

#: How much the local UTC clock may be wrong before an admission is refused
#: rather than raced. One second is the default because it is larger than the
#: step a well-behaved NTP client applies while slewing and small enough that a
#: 90-second default TTL is not meaningfully shortened. A deployment with a
#: worse clock must RAISE this, which shortens every usable window — that is
#: the honest trade and it belongs in configuration, not in a comment.
DEFAULT_CLOCK_UNCERTAINTY_S = 1.0

#: PostgreSQL: ``statement_timeout = 0`` DISABLES the timeout. A remaining
#: budget that rounds down to zero milliseconds must never be written as ``0``,
#: because that turns the last sliver of a TTL into "no limit at all" — the
#: precise inversion of what the setting is for.
MINIMUM_TIMEOUT_MS = 1


class ClockUntrusted(RuntimeError):
    """UTC cannot be trusted on this host, so a signed expiry cannot be read."""


class InvalidApprovalInterval(ValueError):
    """The signed validity interval is not a usable finite interval."""


def _finite(value: object, *, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidApprovalInterval(f"{name} must be a finite number")
    number = float(value)
    if not math.isfinite(number):
        raise InvalidApprovalInterval(f"{name} must be a finite number")
    return number


def elapsed_source() -> tuple[Callable[[], float], str]:
    """The suspend-aware elapsed clock, or the best available, and its NAME.

    Returned as a pair so the caller records WHICH clock answered rather than
    assuming. ``CLOCK_BOOTTIME`` advances across suspend; ``CLOCK_MONOTONIC``
    (what ``time.monotonic()`` is on Linux) does not, so on a fallback platform
    a suspended host consumes no elapsed budget and only the wall-clock arm
    refuses. That is a real difference in coverage and it is named here rather
    than left for someone to discover.
    """

    boottime = getattr(time, "CLOCK_BOOTTIME", None)
    if boottime is not None:
        try:
            time.clock_gettime(boottime)
        except (AttributeError, OSError, ValueError):
            pass
        else:
            return (lambda: time.clock_gettime(boottime)), "CLOCK_BOOTTIME"
    return time.monotonic, "time.monotonic"


@dataclass(frozen=True)
class Admission:
    """Whether work may begin, and how much validity is left if it may."""

    admitted: bool
    reason: str = ""
    detail: str = ""
    #: Seconds of validity remaining, the MINIMUM of the two arms. Zero on a
    #: refusal — never negative, so a caller cannot turn it into a timeout.
    remaining_s: float = 0.0


@dataclass(frozen=True)
class ExecutionDeadline:
    """One invocation's fixed deadline, on two clocks.

    PROCESS-LOCAL BY CONSTRUCTION. ``opened_elapsed`` and ``elapsed_deadline``
    are readings of a clock whose epoch is not portable across boots, processes
    or hosts. Never serialize them, never persist them, never compare one from
    another process against one from this one. :meth:`as_payload` exists so the
    audit record carries what is portable — the wall-clock instants and the name
    of the elapsed source — and nothing that is not.
    """

    expires_at: float
    opened_wall: float
    opened_elapsed: float
    elapsed_deadline: float
    elapsed_source: str
    uncertainty_s: float
    _clock: Callable[[], float] = field(repr=False, compare=False)
    _elapsed: Callable[[], float] = field(repr=False, compare=False)

    @classmethod
    def open(
        cls,
        *,
        issued_at: float,
        expires_at: float,
        clock: Callable[[], float],
        uncertainty_s: float = DEFAULT_CLOCK_UNCERTAINTY_S,
        trust_utc: bool = True,
        elapsed: Callable[[], float] | None = None,
    ) -> ExecutionDeadline:
        """Fix the deadline for ONE invocation. Call once; never refresh it.

        Raises :class:`InvalidApprovalInterval` for an unusable signed interval
        and :class:`ClockUntrusted` when the deployment declares UTC untrusted.
        An interval that is already spent is NOT an error here — it produces a
        deadline whose first :meth:`admit` refuses, so expiry is reported
        through one path with one reason.
        """

        if not trust_utc:
            raise ClockUntrusted(
                "this deployment declares local UTC untrusted, so a signed "
                "wall-clock expiry cannot be evaluated. An elapsed clock does "
                "not repair that: it measures duration, not the time of day."
            )
        checked_issued = _finite(issued_at, name="issued_at")
        checked_expires = _finite(expires_at, name="expires_at")
        if checked_expires <= checked_issued:
            raise InvalidApprovalInterval("approval expiry must be after issuance")
        margin = _finite(uncertainty_s, name="uncertainty_s")
        if margin < 0:
            raise InvalidApprovalInterval("clock uncertainty must not be negative")

        # ``elapsed`` is injectable for the same reason ``clock`` is: the two
        # arms have to be testable independently, and a deployment that knows
        # better than this module about its own elapsed clock should be able to
        # say so. Injecting it names the source "injected" so the audit payload
        # never claims a suspend-aware clock it did not use.
        if elapsed is None:
            read_elapsed, source = elapsed_source()
        else:
            read_elapsed, source = elapsed, "injected"
        # ELAPSED FIRST. See the module docstring: a pause between these two
        # samples must shorten the budget, never lengthen it.
        opened_elapsed = read_elapsed()
        opened_wall = _finite(clock(), name="now")
        budget = checked_expires - opened_wall
        return cls(
            expires_at=checked_expires,
            opened_wall=opened_wall,
            opened_elapsed=opened_elapsed,
            elapsed_deadline=opened_elapsed + budget,
            elapsed_source=source,
            uncertainty_s=margin,
            _clock=clock,
            _elapsed=read_elapsed,
        )

    def admit(self) -> Admission:
        """May work begin right now?

        Refuses when EITHER arm is reached, and when what remains is inside the
        declared clock uncertainty. Takes no clock argument on purpose: the
        deadline carries the clock it was opened with, so a later boundary — in
        particular the executor, in another module — cannot accidentally judge
        it against a different one.
        """

        # ELAPSED FIRST here too, for the same reason as in ``open``.
        elapsed_now = self._elapsed()
        try:
            wall_now = _finite(self._clock(), name="now")
        except InvalidApprovalInterval as exc:
            return Admission(False, INVALID_TIME, str(exc))

        wall_remaining = self.expires_at - wall_now
        elapsed_remaining = self.elapsed_deadline - elapsed_now
        remaining = min(wall_remaining, elapsed_remaining)

        if wall_remaining <= 0:
            return Admission(
                False,
                EXPIRED,
                "the approval's signed expiry has passed "
                f"({-wall_remaining:.3f}s ago on the wall clock)",
            )
        if elapsed_remaining <= 0:
            return Admission(
                False,
                EXPIRED,
                "this invocation has used its whole validity window "
                f"({-elapsed_remaining:.3f}s past the fixed deadline on "
                f"{self.elapsed_source})",
            )
        if remaining <= self.uncertainty_s:
            return Admission(
                False,
                CLOCK_MARGIN,
                f"only {remaining:.3f}s of validity remains, inside the "
                f"declared clock uncertainty of {self.uncertainty_s:.3f}s; "
                "refusing rather than racing a clock this work cannot trust "
                "to that precision",
            )
        return Admission(True, remaining_s=remaining)

    def as_payload(self) -> dict[str, object]:
        """What the audit record may carry: portable values only.

        Deliberately excludes ``opened_elapsed`` and ``elapsed_deadline``. A
        reader of the ledger — on another host, after a restart — cannot
        interpret them, and a value that cannot be interpreted but looks like a
        timestamp is worse than no value.
        """

        return {
            "approval_expires_at": self.expires_at,
            "invocation_opened_at": self.opened_wall,
            "invocation_budget_s": self.expires_at - self.opened_wall,
            "elapsed_clock": self.elapsed_source,
            "clock_uncertainty_s": self.uncertainty_s,
        }


def timeout_ms(remaining_s: float, *, cap_ms: int) -> int:
    """Milliseconds for a server-side timeout, never rounded down to zero.

    ``statement_timeout`` and ``lock_timeout`` both treat ``0`` as DISABLED, so
    a positive remaining budget that rounds to zero milliseconds must clamp UP
    to :data:`MINIMUM_TIMEOUT_MS`. Rounding it down would convert the last
    fraction of a TTL into an unbounded statement — the exact inversion of what
    the setting is being installed for.
    """

    if not math.isfinite(remaining_s) or remaining_s <= 0:
        return MINIMUM_TIMEOUT_MS
    return max(MINIMUM_TIMEOUT_MS, min(int(remaining_s * 1000), cap_ms))


def connect_timeout_s(remaining_s: float, *, cap_s: int) -> int:
    """Whole seconds for libpq's ``connect_timeout``, floored at 1.

    libpq treats ``connect_timeout=0`` as "wait indefinitely" and rounds values
    below 2 up to 2, so this cannot express a sub-second connect budget. The
    residual is stated where it matters: a connect started with under two
    seconds of validity left can outlive the deadline by up to two seconds.
    That is why the boundary check happens BEFORE the connect rather than being
    left to this timeout, and why the next boundary re-checks after it.
    """

    if not math.isfinite(remaining_s) or remaining_s <= 0:
        return 1
    return max(1, min(int(remaining_s), cap_s))
