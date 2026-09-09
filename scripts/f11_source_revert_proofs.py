"""Executed F11-2b guard reverts, in memory only; never edit production files.

Run with the repo's test environment: python scripts/f11_source_revert_proofs.py.
Each mutation must produce call-phase failures, not collection/setup errors or
skips. This is a developer proof runner, not a reconciliation/operator CLI.
"""

from __future__ import annotations

import ast
from typing import Any
import contextlib
import inspect
import io
import tempfile
import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from prometheus_protocol.chokepoint import audit_normalization as normalizers
from prometheus_protocol.chokepoint import audit_source as port
from prometheus_protocol.chokepoint import audit_source_model as model

TEST = "tests/chokepoint/test_audit_source.py"

#: Pinned to the checkpoint-2b report. A runner that executes fewer reversions
#: than it is pinned to would print a smaller number and exit 0 — a mutation
#: proof that silently ran less than it claims. The count is itself an
#: assertion, checked before the run (list size) and after it (call-phase
#: failures); CI fails on either. Change both pins only with the mutation list.
EXPECTED_REVERTS = 15
EXPECTED_CALL_FAILURES = 21


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
    return [
        (
            "observed-provenance",
            port.DigestEvidence.__post_init__,
            [('self.provenance != "observed"', "False")],
            "digest_provenance_cannot",
        ),
        (
            "metadata-model-storage",
            model._Medium.sign,
            [('if self.profile == "digest_bound"', "if True")],
            "profiles_observed_digest",
        ),
        (
            "metadata-model-injection",
            model.normalize_model_event,
            [
                (
                    'if d["digest"] is not None or d["provenance"] != "absent":',
                    "if False:",
                )
            ],
            "administrator_digest_injection",
        ),
        (
            "all-pages-not-attestation",
            port.SignRead.state.fget,
            [
                ("or not c.source_attested", "or False"),
                ("or c.complete_through is None", "or False"),
                (
                    "c.complete_through < c.requested.end",
                    "(c.complete_through or c.requested.end) < c.requested.end",
                ),
            ],
            "every_page_is_not",
        ),
        (
            "page-omission",
            port.collect_sign_records,
            [("page.ordinal != ordinal", "False")],
            "omitted_page_is_incomplete",
        ),
        (
            "duplicate-conflict",
            port.collect_sign_records,
            [("old is not None and old != event", "False")],
            "conflicting_duplicate_payload",
        ),
        (
            "duplicate-identity",
            port.collect_sign_records,
            [("events[event.event_id] = event", "events[str(row_count)] = event")],
            "duplicates_collapse",
        ),
        (
            "delivery-frontier",
            model._Medium.read,
            [("if d.delivered_at > now", "if False")],
            "delayed_delivery_limits",
        ),
        (
            "gap-reporting",
            model._Medium.read,
            [("gaps.append(CoverageGap(Interval(a, b), gap.reason))", "pass")],
            "retention_boundary_and_reported_gap",
        ),
        (
            "malformed-not-dropped",
            port.collect_sign_records,
            [('issues.append(SourceIssue("malformed_event", ordinal, row))', "pass")],
            "malformed_row_is_retained",
        ),
        (
            "response-byte-bound",
            port.collect_sign_records,
            [("byte_count > limits.bytes", "False")],
            "response_limits_preserve",
        ),
        (
            "AWS-digest-absence",
            normalizers.normalize_aws_event,
            [
                (
                    "ABSENT_DIGEST,",
                    'DigestEvidence(bytes(32), "observed", "untrusted:gate"),',
                )
            ],
            "aws_mapping_is_metadata",
        ),
        (
            "GCP-digest-encoding",
            normalizers.normalize_gcp_event,
            [("base64.b64decode(encoded, validate=True)", "bytes.fromhex(encoded)")],
            "gcp_base64_digest",
        ),
        (
            "GCP-method-format",
            normalizers.normalize_gcp_event,
            [('or p["methodName"] != "AsymmetricSign"', "or False")],
            "gcp_unknown_method",
        ),
        (
            "controls-both-no-synthetic-gap",
            model._Medium.read,
            [
                (
                    "gaps = []",
                    'gaps = [CoverageGap(requested, "synthetic-tombstone")] if not self.history else []',
                )
            ],
            "administrator_controls_both_residual",
        ),
    ]


def main() -> int:
    plan = mutations()
    if len(plan) != EXPECTED_REVERTS:
        raise AssertionError(
            f"{len(plan)} reversions listed, {EXPECTED_REVERTS} pinned: the mutation "
            "list changed without its pin (or a proof was dropped); nothing was run"
        )
    with tempfile.TemporaryDirectory(prefix="prom-f11-2b-reverts-") as directory:
        total_failures = 0
        for name, function, edits, selection in plan:
            original_code = function.__code__
            source = textwrap.dedent(inspect.getsource(function))
            for old, new in edits:
                if old not in source:
                    raise AssertionError(f"{name}: revert target disappeared: {old}")
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
            # What exec() puts here is the mutated function object; typing the
            # values as `object` would lose the __code__ the swap below reads.
            namespace: dict[str, Any] = {}
            exec(  # noqa: S102 - execute only this checkout's reviewed guard mutations
                compile(tree, f"<F11-revert:{name}>", "exec"),
                function.__globals__,
                namespace,
            )
            mutated = namespace[function.__name__]
            assert original_code.co_freevars == mutated.__code__.co_freevars
            report = Path(directory) / f"{name}.xml"
            captured = io.StringIO()
            try:
                function.__code__ = mutated.__code__
                with (
                    contextlib.redirect_stdout(captured),
                    contextlib.redirect_stderr(captured),
                ):
                    result = pytest.main(
                        ["-q", TEST, "-k", selection, f"--junitxml={report}"]
                    )
            finally:
                function.__code__ = original_code
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
            total_failures += len(failed)
            print(f"CAUGHT {name}: {len(failed)} call-phase failure(s); {selection}")
        enforce_expected(len(plan), total_failures)
        print(
            f"{len(plan)} reverts caught; {total_failures} call-phase failures; zero "
            f"errors/skips; pinned {EXPECTED_REVERTS} / {EXPECTED_CALL_FAILURES}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
