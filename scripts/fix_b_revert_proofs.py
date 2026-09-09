"""Executed PROM-FIX-B guard reverts: mutate each guard in memory, run the
tests that must go red, restore, and refuse a shortfall against the pinned
counts. Same discipline as the F11 runners: a mutation that produces no
call-phase failure, or a run that executes fewer reversions than pinned, is
itself a failure. Production files are never edited.

Run with the repository's test environment: python scripts/fix_b_revert_proofs.py
"""

from __future__ import annotations

import ast
import contextlib
import inspect
import io
import tempfile
import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from prometheus_protocol.chokepoint import ownership, runner
from prometheus_protocol.core import booleans, transport

BOOLEANS = "tests/conformance/test_strict_booleans.py"
LOCKS = "tests/chokepoint/test_lock_identity.py"
OWNERS = "tests/chokepoint/test_owner_identity.py"
HEADERS = "tests/conformance/test_header_integrity.py"

#: Pinned after the first observed run. A runner that executes fewer
#: reversions than it is pinned to would print a smaller number and exit 0;
#: the count is itself an assertion, before the run (list size) and after it
#: (call-phase failures). Change both pins only with the mutation list.
EXPECTED_REVERTS = 12
EXPECTED_CALL_FAILURES = 143


def enforce_expected(caught: int, failures: int) -> None:
    """Refuse a shortfall or an excess against the pinned counts."""

    if caught != EXPECTED_REVERTS or failures != EXPECTED_CALL_FAILURES:
        raise AssertionError(
            f"revert proof count drifted: {caught} reverts / {failures} call-phase "
            f"failures observed, {EXPECTED_REVERTS} / {EXPECTED_CALL_FAILURES} "
            "pinned. A proof was added, removed or stopped executing; update the "
            "pin in the same change that changes the mutation list, never alone."
        )


def mutations():
    """(name, function, [(old, new)], test file, -k selection)."""

    return [
        (
            "env-bool-unknown-word-read-as-false",
            booleans.parse_env_bool,
            [
                (
                    '    raise ConfigError(\n        f"{name}={value!r} is not a boolean: set one of "',
                    '    return False\n    raise ConfigError(\n        f"{name}={value!r} is not a boolean: set one of "',
                )
            ],
            BOOLEANS,
            "invalid_does_not or parses_every_boolean_variable_strictly or misspelled_requirement",
        ),
        (
            "programmatic-bool-coerced",
            booleans.require_bool,
            [("if type(value) is not bool:", "if False:")],
            BOOLEANS,
            "require_bool_refuses or string_false_no_longer_enables or refuses_a_non_bool",
        ),
        (
            "link-count-ignored",
            runner._singly_linked,
            [("return info.st_nlink == 1", "return True")],
            LOCKS,
            "refused_at_construction or hard_linked_after_construction",
        ),
        (
            "guard-keyed-to-pathname",
            runner.ConsumedApprovals.execution_guard.__wrapped__,
            [
                (
                    "fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)",
                    'fcntl.flock(os.open(self.path.with_name(self.path.name + ".execution.lock"), '
                    "os.O_RDWR | os.O_CREAT, 0o600), fcntl.LOCK_EX | fcntl.LOCK_NB)",
                )
            ],
            LOCKS,
            "aliased_stores_resolve_to_one_lock or review_reproduction",
        ),
        (
            "in-process-mutex-removed",
            runner.ConsumedApprovals.execution_guard.__wrapped__,
            [("if not self._guard_mutex.acquire(blocking=False):", "if False:")],
            LOCKS,
            "two_threads_of_one_process",
        ),
        (
            "same-kernel-without-same-lock",
            ownership.assess_owner,
            [
                (
                    "if recorded_lock is not None and lock_id is not None and recorded_lock == lock_id:",
                    "if True:",
                )
            ],
            LOCKS,
            "same_boot_id_without_the_same_lock or copied_store_cannot_recover",
        ),
        (
            "legacy-intent-established",
            ownership.assess_owner,
            [
                (
                    "            established=False,\n            basis=OWNER_LEGACY,",
                    "            established=True,\n            basis=OWNER_LEGACY,",
                )
            ],
            OWNERS,
            "legacy_intent_stays_pending",
        ),
        (
            "header-line-unchecked",
            transport._StrictHeaderReader.readline,
            [("if _HEADER_LINE.fullmatch(line) is None:", "if False:")],
            HEADERS,
            "raw_check_stands_on_its_own or obsolete_folding or space_before_colon or bare_cr",
        ),
        (
            "status-line-unchecked",
            transport._StrictHeaderReader.readline,
            [
                (
                    "if len(line) > _FRAMING_LINE_LIMIT or _STATUS_LINE.fullmatch(line) is None:",
                    "if False:",
                )
            ],
            HEADERS,
            "malformed_status_lines",
        ),
        (
            "unterminated-header-block-accepted",
            transport._StrictHeaderReader.readline,
            [
                (
                    # inspect.getsource is dedented to the method's own level
                    '    if not line:\n        raise MalformedResponseHeaders(\n            "connection closed inside the response headers; the header block "\n            "was never terminated"\n        )',
                    "    if not line:\n        return line",
                )
            ],
            HEADERS,
            "connection_closes_inside",
        ),
        (
            "parser-defects-ignored",
            transport._StrictHTTPResponse.begin,
            [("if defects:", "if False:")],
            HEADERS,
            "parser_defect_check_stands_on_its_own",
        ),
        (
            "malformed-classified-as-generic-transport",
            transport.classify_open_error,
            [("if isinstance(exc, MalformedResponseHeaders):", "if False:")],
            HEADERS,
            "provider_reply_is_malformed_never_pass",
        ),
    ]


def main() -> int:
    plan = mutations()
    if len(plan) != EXPECTED_REVERTS:
        raise AssertionError(
            f"{len(plan)} reversions listed, {EXPECTED_REVERTS} pinned: the mutation "
            "list changed without its pin (or a proof was dropped); nothing was run"
        )
    total = 0
    with tempfile.TemporaryDirectory(prefix="prom-fix-b-reverts-") as directory:
        for name, function, edits, test_file, selection in plan:
            original = function.__code__
            source = textwrap.dedent(inspect.getsource(function))
            for old, new in edits:
                if old not in source:
                    raise AssertionError(f"{name}: revert target disappeared: {old!r}")
                source = source.replace(old, new)
            tree = ast.parse(source)
            # ast.Module.body is Sequence[stmt]; only a function/class def carries a
            # decorator_list. Narrowed rather than asserted-away: the mutation source is
            # always one def, and if that ever stops being true the runner must say so
            # rather than silently strip nothing and mutate the wrong object.
            definition = tree.body[0]
            if not isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                raise AssertionError(
                    f"{name}: mutation source is {type(definition).__name__}, not a def"
                )
            definition.decorator_list = []
            namespace: dict = {}
            exec(  # noqa: S102 - reviewed test-only in-memory mutations, no user code
                compile(tree, f"<FIX-B-revert:{name}>", "exec"),
                function.__globals__,
                namespace,
            )
            mutated = namespace[function.__name__]
            assert original.co_freevars == mutated.__code__.co_freevars
            report = Path(directory) / f"{name}.xml"
            captured = io.StringIO()
            try:
                function.__code__ = mutated.__code__
                with (
                    contextlib.redirect_stdout(captured),
                    contextlib.redirect_stderr(captured),
                ):
                    result = pytest.main(
                        ["-q", "-p", "no:cacheprovider", test_file, "-k", selection,
                         f"--junitxml={report}"]
                    )
            finally:
                function.__code__ = original
            cases = list(ET.parse(report).iter("testcase")) if report.exists() else []
            failed = [c for c in cases if c.find("failure") is not None]
            if (
                result != pytest.ExitCode.TESTS_FAILED
                or not failed
                or any(
                    c.find("error") is not None or c.find("skipped") is not None
                    for c in cases
                )
            ):
                print(captured.getvalue())
                raise AssertionError(f"{name}: no valid executed revert proof")
            total += len(failed)
            print(f"CAUGHT {name}: {len(failed)} call-phase failure(s); {test_file} -k {selection!r}")
        enforce_expected(len(plan), total)
        print(
            f"{len(plan)} reverts caught; {total} call-phase failures; zero errors/skips; "
            f"pinned {EXPECTED_REVERTS} / {EXPECTED_CALL_FAILURES}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
