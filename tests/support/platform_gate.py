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
"""

from __future__ import annotations

import os
import sys

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
