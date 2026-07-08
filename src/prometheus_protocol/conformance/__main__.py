"""Run the verifier conformance suite from the command line.

    python -m prometheus_protocol.conformance

Checks the three built-in verifiers (code, SQL, grounding) plus the
domain-general held-out firewall guarantee, and prints a report. Exit code is
0 iff every check passes (behavioural checks that need the isolation runtime
are skipped, not failed, when it is unavailable — pass ``--require-runtime``,
or set ``PROM_REQUIRE_SANDBOX=1`` and use the pytest harness, to force them).

An extender points the same machinery at their own verifier by importing
:func:`prometheus_protocol.conformance.check_verifier` and handing it a
:class:`VerifierCase`; this entry point is the built-in demonstration.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Sequence

from prometheus_protocol.conformance.cases import builtin_cases
from prometheus_protocol.conformance.contract import (
    check_firewall_is_domain_general,
    check_verifier,
)
from prometheus_protocol.sandbox import NullSandbox, build_sandbox


def _runtime_available() -> bool:
    """True when an isolating sandbox other than the null backstop is active."""

    try:
        return build_sandbox().isolating and not isinstance(build_sandbox(), NullSandbox)
    except Exception:
        return False


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m prometheus_protocol.conformance",
        description="Check the built-in verifiers against the extension contract.",
    )
    parser.add_argument(
        "--require-runtime", action="store_true",
        help="run behavioural checks even if isolation looks unavailable "
        "(they will fail rather than skip if it truly is)",
    )
    args = parser.parse_args(argv)

    run_behavioural = args.require_runtime or _runtime_available()
    if not run_behavioural:
        print("[note] no isolating runtime detected; HARD verifiers' PASS/FAIL "
              "checks will be skipped (tier-honesty and fail-closed still run).\n")

    all_ok = True
    for case in builtin_cases():
        report = check_verifier(case, run_behavioural=run_behavioural)
        print(report.render())
        print()
        all_ok = all_ok and report.ok

    firewall = check_firewall_is_domain_general()
    mark = "PASS" if firewall.ok else "FAIL"
    print(f"[{mark}] {firewall.name}: {firewall.detail}")
    all_ok = all_ok and firewall.ok

    print()
    print("conformance suite: " + ("ALL WELL-BEHAVED" if all_ok else "REJECTED"))
    return 0 if all_ok else 1


if __name__ == "__main__":  # pragma: no cover - exercised via main() in tests
    raise SystemExit(main(sys.argv[1:] if len(sys.argv) > 1 else None))
