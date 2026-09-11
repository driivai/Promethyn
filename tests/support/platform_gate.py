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


#: The substrate probe's own words when it has no implementation for the running
#: platform, and the ownership probe's marker. Keyed on the CAUSE the production
#: code reports rather than on a list of test names, because the tests that hit
#: it cannot be enumerated at module or function granularity: measured on this
#: tree, the affected tests are 1 of 105 in one module, 5 of 142 in another, and
#: within a single parametrised function some parameters hit it and others do
#: not. A name-keyed allowlist would be a list over exactly the thing that
#: varies — the failure the threat model already records.
PLATFORM_UNSUPPORTED_MARKERS = (
    "no filesystem probe is implemented for",
    "descriptor mount metadata unavailable on this platform",
    "Linux O_PATH inspection is unavailable",
    "_PlatformUnsupported",
)


def is_platform_refusal(exc: BaseException) -> bool:
    """Whether ``exc`` is the fail-closed refusal of an unsupported platform.

    Deliberately narrow. It matches the substrate/ownership probe's own
    diagnostic text, so an ordinary ``ConfigError`` — a real misconfiguration —
    is never converted into a skip. On Linux the probe succeeds and this cannot
    fire at all, which is why it adds no risk to the platform CI actually runs.
    """

    seen: list[str] = []
    cursor: BaseException | None = exc
    while cursor is not None and len(seen) < 8:
        seen.append(f"{type(cursor).__name__}: {cursor}")
        cursor = cursor.__cause__ or cursor.__context__
    blob = " || ".join(seen)
    return any(marker in blob for marker in PLATFORM_UNSUPPORTED_MARKERS)
