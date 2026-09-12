"""The repository's platform contract, and the one gate that enforces it.

THE CONTRACT. This runtime targets **Linux**. That is not a preference: the
chokepoint's execution-ownership proof rests on filesystem and mount facilities
(`/proc/self/mountinfo`, `O_PATH` descriptor inspection, namespace identities)
that exist on Linux and have no portable equivalent. ``pyproject.toml`` says so
in its classifiers — it previously said ``Operating System :: POSIX``, which
macOS satisfies, and so promised support this code does not deliver.

WHY A GATE RATHER THAN A FAILURE. Off Linux the production code is correctly
FAIL-CLOSED: ``probe_substrate`` reports "no filesystem probe is implemented for
<platform>" and the runner refuses to build rather than proceed on an unverified
substrate. That refusal is right, and it makes the tests that construct a runner
raise ``ConfigError``. A developer on macOS therefore sees a wall of failures
that look exactly like a regression — which is the condition under which a real
regression hides.

WHY IT CAN FAIL, NOT ONLY SKIP. A skip that can never be observed to fire is a
guard that cannot fail, the shape the repository's own scanner looks for. So
this follows the idiom already used by ``PROM_REQUIRE_SANDBOX``,
``PROM_REQUIRE_PG`` and ``PROM_REQUIRE_PRIVILEGED``: CI sets
``PROM_REQUIRE_LINUX=1``, and under it a gated test FAILS rather than skipping.
A skip on a developer's macOS is information; a skip in CI is a broken promise.

TWO CHANNELS, and the reason the second exists. The refusal reaches a test one
of two ways. It is RAISED — ``UnsupportedPlatform`` at runner construction, or
``_PlatformUnsupported`` wrapped in ``_OwnershipUnavailable`` from the execution
guard — and the ``pytest_runtest_call`` hook below converts it, keyed on the
exception's TYPE. Or it is RETURNED: ``BrokeredMigrationRunner.execute`` and
``reconcile_unfinished`` catch that same guard refusal and hand back a
``MigrationResult`` / ``ReconciliationResult`` with ``reason=STORE_UNAVAILABLE``,
and the test then asserts an outcome the refusal made impossible. That
assertion's message quotes the result's repr, which is how the first,
string-matching version of this gate came to convert genuine assertion failures
into skips. Measured on this tree under a simulated non-Linux platform: 80 tests
arrive through the raised channel and 18 through the returned one, and an
exception-keyed hook alone cannot see the 18. The returned channel is keyed on
the result's TYPED ``platform_unsupported`` field — set by the runner from the
cause's type, never from prose — observed by an autouse fixture that wraps the
two returning methods, and converted by the same hook, under the same flag.
"""

from __future__ import annotations

import functools
import os
import sys
import threading

import pytest

from prometheus_protocol.core.booleans import parse_env_bool

#: Set in CI. Under it, a gated test that cannot run is a FAILURE, so the gate
#: is never a silent no-op on the platform this project actually supports.
REQUIRE_LINUX_ENV = "PROM_REQUIRE_LINUX"


def is_linux() -> bool:
    """Whether the supported platform is the one running.

    Read through a function so a test can exercise both branches without
    reaching into ``sys`` at import time, when a module-level constant would
    already have been frozen.
    """

    return sys.platform.startswith("linux")


def require_linux() -> None:
    """Skip off Linux — or FAIL when CI promised Linux and did not deliver it."""

    if is_linux():
        return
    reason = (
        f"requires Linux: this test exercises filesystem/ownership facilities "
        f"with no equivalent on {sys.platform!r}. See tests/support/platform_gate.py."
    )
    require_or_skip(reason)


def require_or_skip(reason: str) -> None:
    """Skip with ``reason``, or fail if ``PROM_REQUIRE_LINUX=1``."""

    if parse_env_bool(
        REQUIRE_LINUX_ENV, os.environ.get(REQUIRE_LINUX_ENV), default=False
    ):
        pytest.fail(f"{REQUIRE_LINUX_ENV}=1 but {reason}")
    pytest.skip(reason)


# -- channel 1: the refusal is RAISED ------------------------------------------


def _unsupported_platform_types() -> tuple[type[BaseException], ...]:
    """The TYPES that mean "this platform has no implementation".

    Imported lazily so this module stays importable on a machine where the
    chokepoint's dependencies are not installed.

    TYPED, NOT TEXTUAL, and that is the whole point. An earlier version of this
    matched four substrings of the probe's diagnostics —
    ``"no filesystem probe is implemented for"`` and friends. A cause set
    spelled as prose is an enumeration of sentences: the first rewording of a
    diagnostic silently drops a case out of the set, and the gate stops
    recognising a refusal it used to convert. Nothing fails when that happens;
    the platform mismatch simply becomes indistinguishable from a regression
    again, which is precisely the condition this gate exists to remove. It is
    the allowlist failure this repository has already recorded three times —
    file basenames, trigger names, identifier spellings — in its fourth
    costume.

    ``UnsupportedPlatform`` (a ``ConfigError`` subclass, so every existing
    handler is unaffected) and ``_PlatformUnsupported`` are facts the production
    code asserts about itself. They cannot be reworded.
    """

    from prometheus_protocol.chokepoint.runner import _PlatformUnsupported
    from prometheus_protocol.chokepoint.substrate import UnsupportedPlatform

    return (UnsupportedPlatform, _PlatformUnsupported)


def is_platform_refusal(exc: BaseException) -> bool:
    """Whether ``exc`` is the fail-closed refusal of an unsupported platform.

    Walks the ``__cause__``/``__context__` chain, because the refusal is
    usually re-raised wrapped and testing only the outermost type would miss
    it. Deliberately narrow: an ordinary ``ConfigError`` — a real
    misconfiguration — is never converted into a skip. On Linux the probe
    succeeds, so this cannot fire at all, which is why it adds no risk to the
    platform CI actually runs on.
    """

    types = _unsupported_platform_types()
    cursor: BaseException | None = exc
    for _ in range(8):  # bounded: a cause cycle must not hang the run
        if cursor is None:
            return False
        if isinstance(cursor, types):
            return True
        cursor = cursor.__cause__ or cursor.__context__
    return False


# -- channel 2: the refusal is RETURNED ----------------------------------------

#: Results carrying ``platform_unsupported=True`` observed during the CURRENT
#: test, from any thread. The runner may be driven from a worker thread (one
#: recovery test does exactly that), so this is a registry the hook reads after
#: the call phase rather than an exception raised at the observation site — a
#: ``pytest.skip`` raised inside a worker thread would not skip anything.
_RETURNED: list[object] = []
_RETURNED_LOCK = threading.Lock()

#: The runner methods whose RETURN VALUE can carry the guard's refusal.
RETURNING_METHODS: tuple[str, ...] = ("execute", "reconcile_unfinished")

#: Refusals RAISED IN A WORKER THREAD during the current test. A thread's
#: exception never reaches the test function — it goes to
#: ``threading.excepthook`` and the thread dies — so the test then fails on
#: whatever it was waiting for (an event that is never set), with no marker
#: anywhere in its own traceback. Measured: one recovery test drives the runner
#: from a thread and was the single residual left after both channels above.
#: The fixture installs an excepthook that records refusals by TYPE; the hook
#: below treats them exactly like the raised channel.
_RAISED_IN_THREADS: list[BaseException] = []


def note_raised_in_thread(exc: BaseException) -> bool:
    """Record ``exc`` if it is a typed platform refusal; True when recorded."""

    if not is_platform_refusal(exc):
        return False
    with _RETURNED_LOCK:
        _RAISED_IN_THREADS.append(exc)
    return True


def raised_in_threads() -> list[BaseException]:
    with _RETURNED_LOCK:
        return list(_RAISED_IN_THREADS)


def is_returned_platform_refusal(value: object) -> bool:
    """Whether ``value`` is a result whose TYPED ``platform_unsupported`` is True.

    ``reconcile_unfinished`` returns a tuple of results, so a tuple counts when
    any member does. The field, never the repr: a result whose ``detail`` quotes
    the marker but whose field is False is NOT a platform refusal.
    """

    from prometheus_protocol.chokepoint.runner import (
        MigrationResult,
        ReconciliationResult,
    )

    items = value if isinstance(value, tuple) else (value,)
    for item in items:
        if (
            isinstance(item, (MigrationResult, ReconciliationResult))
            and item.platform_unsupported is True
        ):
            return True
    return False


def note_returned(value: object) -> None:
    """Record ``value`` for the current test if it is a returned refusal."""

    if is_returned_platform_refusal(value):
        with _RETURNED_LOCK:
            _RETURNED.append(value)


def returned_platform_refusals() -> list[object]:
    with _RETURNED_LOCK:
        return list(_RETURNED)


def clear_returned_platform_refusals() -> None:
    with _RETURNED_LOCK:
        _RETURNED.clear()
        _RAISED_IN_THREADS.clear()


@pytest.fixture(autouse=True)
def convert_returned_platform_refusals(monkeypatch):
    """Observe every returned result of the two runner methods for the test.

    Autouse where the chokepoint conftest imports it. The wrapper records and
    returns; it never raises, so a test that asserts the refusal-shaped outcome
    it actually got still passes. Conversion happens in the hook below, and
    only when the test FAILED — a passing test observed nothing it minds.
    """

    from prometheus_protocol.chokepoint import runner as runner_module

    clear_returned_platform_refusals()
    previous_excepthook = threading.excepthook

    def excepthook(args):
        if not note_raised_in_thread(args.exc_value):
            previous_excepthook(args)

    monkeypatch.setattr(threading, "excepthook", excepthook)
    for name in RETURNING_METHODS:
        original = getattr(runner_module.BrokeredMigrationRunner, name)

        def observed(self, *args, _original=original, **kwargs):
            result = _original(self, *args, **kwargs)
            note_returned(result)
            return result

        # Keeps the wrapped method introspectable (name, doc, __wrapped__) for
        # the revert-proof runners, which read a method's source by reference.
        functools.update_wrapper(observed, original)
        monkeypatch.setattr(runner_module.BrokeredMigrationRunner, name, observed)
    try:
        yield
    finally:
        clear_returned_platform_refusals()


# -- the conversion, one hook for both channels --------------------------------


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    outcome = yield
    excinfo = outcome.excinfo
    if excinfo is None:
        return
    exc = excinfo[1]
    raised = isinstance(exc, BaseException) and is_platform_refusal(exc)
    returned = returned_platform_refusals()
    in_threads = raised_in_threads()
    if not raised and not returned and not in_threads:
        return
    if raised:
        channel = f"raised: {type(exc).__name__}: {exc}"
    elif returned:
        first = returned[0]
        head = first[0] if isinstance(first, tuple) else first
        channel = (
            f"returned as {type(head).__name__}(reason={head.reason!r}, "
            "platform_unsupported=True)"
        )
    else:
        head_exc = in_threads[0]
        channel = f"raised in a worker thread: {type(head_exc).__name__}: {head_exc}"
    try:
        require_or_skip(
            f"unsupported platform: the substrate/ownership probe refused "
            f"({channel}). The refusal is correct; this platform is outside the "
            "declared contract."
        )
    except BaseException as converted:  # pytest.skip.Exception or Failed
        outcome.force_exception(converted)
