"""Make an unsupported platform distinguishable from a regression.

Off Linux the production code is correctly FAIL-CLOSED: ``probe_substrate``
cannot verify the filesystem behind the consumed-approval store, so the runner
refuses to build. Measured on this tree with the probe forced to report a
non-Linux platform: **107 chokepoint tests fail**, every one of them with that
refusal or the matching ownership-unavailable marker, and none of them with a
wrong answer — ``MigrationResult(executed=False, refused=True,
reason='approval_store_unavailable', audit_recorded=True)``.

That is the code behaving correctly and the test suite reporting it as a wall of
failures indistinguishable from a real regression. This hook converts exactly
that refusal into a SKIP, keyed on the diagnostic the production code emits.

WHY NOT skipif ON THE TESTS. Because the affected set cannot be named at module
or function granularity without over-skipping. Measured per module
(failures/total): 1/105, 1/30, 1/15, 1/35, 5/142, 5/41, 6/25, 7/21, 10/75,
10/12, 11/15, 13/29, 13/46, 16/25. Gating those modules would skip 566 tests to
gate 107, and within a single parametrised function some parameters hit the
refusal while others pass. A name-keyed list would be an allowlist over the one
thing that varies.

WHY IT IS SAFE ON LINUX. On Linux the probe succeeds, so no test raises the
refusal and the hook cannot fire. CI additionally sets ``PROM_REQUIRE_LINUX=1``,
under which the hook FAILS instead of skipping — so if it ever did fire on the
supported platform, that is a loud failure and not a silent skip.
"""

from __future__ import annotations

import pytest

from tests.support.platform_gate import is_platform_refusal, require_or_skip


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    outcome = yield
    excinfo = outcome.excinfo
    if excinfo is None:
        return
    exc = excinfo[1]
    if not isinstance(exc, BaseException) or not is_platform_refusal(exc):
        return
    try:
        require_or_skip(
            f"unsupported platform: the substrate/ownership probe refused "
            f"({type(exc).__name__}: {exc}). The refusal is correct; this "
            f"platform is outside the declared contract."
        )
    except BaseException as converted:  # pytest.skip.Exception or Failed
        outcome.force_exception(converted)
