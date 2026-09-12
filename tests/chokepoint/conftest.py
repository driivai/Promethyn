"""Make an unsupported platform distinguishable from a regression.

Off Linux the production code is correctly FAIL-CLOSED: ``probe_substrate``
cannot verify the filesystem behind the consumed-approval store, so the runner
refuses to build. Measured on this tree with the probe forced to report a
non-Linux platform (a plugin flips ``sys.platform`` after collection): of the
912 tests here, 80 fail with that refusal RAISED, 18 fail with it RETURNED as a
``MigrationResult(executed=False, refused=True,
reason='approval_store_unavailable', ...)`` that a later assertion trips over,
8 skip through the explicit ``linux_only`` gate, 14 skip for want of a database,
and 792 pass. None fails with a wrong answer.

That is the code behaving correctly and the test suite reporting it as a wall of
failures indistinguishable from a real regression. The hook and the autouse
fixture imported here convert exactly those refusals into SKIPS, each keyed on a
TYPE the production code asserts about itself — the exception's type on the
raised channel, the result's ``platform_unsupported`` field on the returned one.
They live in ``tests.support.platform_gate`` so that the conformance suite can
load the same implementation into a sub-session and prove both channels
skip without ``PROM_REQUIRE_LINUX`` and FAIL under it.

WHY NOT skipif ON THE TESTS. Because the affected set cannot be named at module
or function granularity without over-skipping. Measured per module
(failures/total): 1/105, 1/30, 1/15, 1/35, 5/142, 5/41, 6/25, 7/21, 10/75,
10/12, 11/15, 13/29, 13/46, 16/25. Gating those modules would skip 566 tests to
gate 107, and within a single parametrised function some parameters hit the
refusal while others pass. A name-keyed list would be an allowlist over the one
thing that varies.

WHY IT IS SAFE ON LINUX. On Linux the probe succeeds, so no test raises the
refusal and no result carries the field, and neither channel can fire. CI
additionally sets ``PROM_REQUIRE_LINUX=1``, under which a conversion FAILS
instead of skipping — so if it ever did fire on the supported platform, that is
a loud failure and not a silent skip.
"""

from __future__ import annotations

from tests.support.platform_gate import (  # noqa: F401 - registered by name
    convert_returned_platform_refusals,
    pytest_runtest_call,
)
