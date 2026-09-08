"""Executed F11-2b guard reverts, in memory only; never edit production files.

Run with the repo's test environment: python scripts/f11_source_revert_proofs.py.
Each mutation must produce call-phase failures, not collection/setup errors or
skips. This is a developer proof runner, not a reconciliation/operator CLI.
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

from prometheus_protocol.chokepoint import audit_normalization as normalizers
from prometheus_protocol.chokepoint import audit_source as port
from prometheus_protocol.chokepoint import audit_source_model as model

TEST = "tests/chokepoint/test_audit_source.py"


def main() -> int:
    mutations = [
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
    with tempfile.TemporaryDirectory(prefix="prom-f11-2b-reverts-") as directory:
        total_failures = 0
        for name, function, edits, selection in mutations:
            original_code = function.__code__
            source = textwrap.dedent(inspect.getsource(function))
            for old, new in edits:
                if old not in source:
                    raise AssertionError(f"{name}: revert target disappeared: {old}")
                source = source.replace(old, new)
            tree = ast.parse(source)
            tree.body[0].decorator_list = []
            namespace = {}
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
        print(
            f"{len(mutations)} reverts caught; {total_failures} call-phase failures; zero errors/skips"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
