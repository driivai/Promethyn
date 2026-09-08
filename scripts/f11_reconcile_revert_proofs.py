"""Executed F11-3 regressions; mutate reviewed functions in memory, restore them.

Some defenses are deliberately redundant. Such proofs revert both guards in
one named mutation, rather than claiming an unrelated failure proves a bypass.
Only isolated pytest temporary ledgers are touched by the read-only mutation.
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

from prometheus_protocol.chokepoint import reconcile_gate as gate
from prometheus_protocol.chokepoint import reconciliation as rec
from prometheus_protocol.cli import reconcile as cli

TEST = "tests/chokepoint/test_reconciliation.py"

#: Pinned to the checkpoint-3 report. A runner that executes fewer reversions
#: than it is pinned to — an entry deleted from ``mutations``, a target that
#: vanished — would otherwise print a smaller number and exit 0: a mutation
#: proof that silently ran less than it claims is the void guard this
#: repository exists to catch. The count is therefore itself an assertion,
#: checked before the run (list size) and after it (call-phase failures), and
#: CI fails on either. Change both pins only together with the mutation list.
EXPECTED_REVERTS = 43
EXPECTED_CALL_FAILURES = 72


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
            "null-transfer-pin-cannot-disable-verification",
            [
                (
                    cli.main,
                    [
                        ('hex_bytes(config["anchor_sha256"], 32)', "pass"),
                        ('hex_bytes(config["source_sha256"], 32)', "pass"),
                    ],
                )
            ],
            "cli_versioned_json_secret_free",
        ),
        (
            "native-provenance-not-configurable-to-local",
            [
                (
                    rec.reconcile,
                    [
                        (
                            "pin.digest_location != native_locations[scope.provider]",
                            "False",
                        )
                    ],
                )
            ],
            "operator_cannot_enable_gate",
        ),
        (
            "secret-reference-redaction",
            [
                (
                    rec._reference,
                    [
                        (
                            '"sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()',
                            "value",
                        )
                    ],
                )
            ],
            "source_diagnostics_and_references",
        ),
        (
            "source-diagnostic-allowlist",
            [(rec.reconcile, [("i.reason in SOURCE_REASONS", "True")])],
            "source_diagnostics_and_references",
        ),
        (
            "gate-snapshot-size",
            [
                (
                    gate.read_gate,
                    [
                        (
                            "count > 100_000 or size > 64 * 1024 * 1024 or largest > 131_072",
                            "False",
                        )
                    ],
                )
            ],
            "gate_size_bound",
        ),
        (
            "invoke-only-signal",
            [(rec.reconcile, [('status="UNEXPLAINED"', 'status="MATCHED"')])],
            "invoke_only_forgery",
        ),
        (
            "normal-batch-positive-control",
            [(rec._compatible, [("event.algorithm == pin.algorithm", "False")])],
            "normal_concurrent_batch",
        ),
        (
            "disk-digest-recompute",
            [
                (
                    rec._compatible,
                    [
                        (
                            "record.recompute_approval_digest()",
                            'record.to_dict()["approval_digest"]',
                        )
                    ],
                )
            ],
            "disk_digest_is_recomputed",
        ),
        (
            "digest-not-proximity-or-alias",
            [
                (
                    rec.reconcile,
                    [
                        (
                            'by_digest.get(\n                event.digest.value.hex() if event.digest.value is not None else "", []\n            )',
                            "selected",
                        )
                    ],
                ),
                (
                    rec._compatible,
                    [
                        (
                            "event.digest.value.hex() == record.recompute_approval_digest()",
                            "True",
                        )
                    ],
                ),
            ],
            "binding_mismatch and (digest or alias)",
        ),
        (
            "principal-binding",
            [
                (
                    rec._compatible,
                    [("event.caller.subject == pin.caller_subject", "True")],
                )
            ],
            "binding_mismatch and principal",
        ),
        (
            "independent-provenance-location",
            [
                (
                    rec._compatible,
                    [("event.digest.location == pin.digest_location", "True")],
                ),
                (
                    rec.reconcile,
                    [("or event.digest.location != pin.digest_location", "or False")],
                ),
            ],
            "absent_or_locally_asserted and local",
        ),
        (
            "algorithm-binding",
            [(rec._compatible, [("event.algorithm == pin.algorithm", "True")])],
            "binding_mismatch and algorithm",
        ),
        (
            "time-binding",
            [
                (
                    rec._compatible,
                    [("window.start <= event.signed_at < window.end", "True")],
                )
            ],
            "binding_mismatch and time",
        ),
        (
            "half-open-sign-window",
            [
                (
                    rec._compatible,
                    [("event.signed_at < window.end", "event.signed_at <= window.end")],
                )
            ],
            "success_at_absence_upper",
        ),
        (
            "refused-never-explains",
            [
                (rec.reconcile, [('if value["decision"] == "refused":', "if False:")]),
                (
                    rec._compatible,
                    [('record.to_dict()["decision"] == "authorised"', "True")],
                ),
            ],
            "refused_decision_cannot",
        ),
        (
            "pre-sign-crash-not-forgery",
            [(rec.reconcile, [('status="UNWITNESSED"', 'status="UNEXPLAINED"')])],
            "pre_sign_crash_unwitnessed",
        ),
        (
            "no-result-crash-window",
            [
                (
                    rec.reconcile,
                    [
                        (
                            "_compatible(event, r, w, pin)",
                            '_compatible(event, r, w, pin) and lifecycle.get(r.authorization_id) == "signed"',
                        )
                    ],
                )
            ],
            "crash_after_sign_before_result",
        ),
        (
            "one-attempt-per-decision",
            [(rec.reconcile, [("used.add(record.authorization_id)", "pass")])],
            "excess_distinct_real",
        ),
        (
            "event-id-not-digest-dedup",
            [
                (
                    rec._checked_source,
                    [
                        (
                            "unique[event.event_id] = event",
                            "unique[event.digest.value.hex() if event.digest.value else event.event_id] = event",
                        )
                    ],
                )
            ],
            "distinct_ids_not_digest",
        ),
        (
            "conflicting-event-identity",
            [(rec._checked_source, [("unique[event.event_id] != event", "False")])],
            "conflicting_source_identity",
        ),
        (
            "export-conflict-before-filter",
            [
                (
                    cli.ExportSource.read_sign_records,
                    [("identities[event.event_id] != event", "False")],
                )
            ],
            "export_conflict_outside",
        ),
        (
            "denied-not-forgery",
            [(rec.reconcile, [('if event.outcome == "denied":', "if False:")])],
            "denied_diagnostic and denied",
        ),
        (
            "unknown-not-success",
            [
                (
                    rec.reconcile,
                    [('successful = event.outcome == "success"', "successful = True")],
                )
            ],
            "denied_diagnostic and unknown",
        ),
        (
            "HMAC-no-independent-source",
            [(rec.reconcile, [('if pin.backend == "local-hmac":', "if False:")])],
            "local_hmac_never_clean",
        ),
        (
            "metadata-only-never-clean",
            [
                (
                    rec.reconcile,
                    [
                        (
                            'evidence.coverage.capability != "digest_bound" or scope.provider in (',
                            "False and scope.provider in (",
                        )
                    ],
                )
            ],
            "empty_metadata_only_range",
        ),
        (
            "settling-required",
            [
                (
                    rec.reconcile,
                    [("now < retry", "False"), ("now < range_retry", "False")],
                )
            ],
            "settling_boundary_requires",
        ),
        (
            "attestation-not-timer",
            [
                (
                    rec._coverage_ok,
                    [
                        ("c.source_attested", "True"),
                        ("c.complete_through is not None", "True"),
                        (
                            "c.complete_through >= interval.end",
                            "(c.complete_through or interval.end) >= interval.end",
                        ),
                    ],
                )
            ],
            "source_contract_refusals and no_attestation",
        ),
        (
            "all-pages-required",
            [(rec._coverage_ok, [("c.pages_exhausted", "True")])],
            "source_contract_refusals and missing_pages",
        ),
        (
            "source-frontier-required",
            [(rec._coverage_ok, [("c.complete_through >= interval.end", "True")])],
            "source_contract_refusals and frontier",
        ),
        (
            "gap-required",
            [
                (
                    rec._coverage_ok,
                    [
                        (
                            "not any(_overlaps(g.interval, interval) for g in c.gaps)",
                            "True",
                        )
                    ],
                )
            ],
            "useful_findings_retained",
        ),
        (
            "gate-lookback-required",
            [(rec.reconcile, [("extended.start - policy.lookback", "extended.start")])],
            "lookback_not_just_extended",
        ),
        (
            "source-window-extension",
            [
                (
                    rec.reconcile,
                    [
                        (
                            "max([requested.end] + [w.end for _, w in selected])",
                            "requested.end",
                        )
                    ],
                )
            ],
            "gate_lookback_and_source_extension",
        ),
        (
            "anchor-tail-required",
            [(gate.read_gate, [("or checkpoint.tip not in tips", "or False")])],
            "gate_checkpoint_refusals and unanchored",
        ),
        (
            "chain-before-decode",
            [(gate.read_gate, [("if not verification.ok:", "if False:")])],
            "disk_tamper_chain_verified",
        ),
        (
            "legacy-history-refusal",
            [
                (
                    gate._decode_rows,
                    [('raise LookupError("missing legacy history")', "continue")],
                )
            ],
            "missing_legacy_history",
        ),
        (
            "key-mapping-pin",
            [(rec.reconcile, [("if not _identity(record, scope, pin):", "if False:")])],
            "conflicting_identity_mapping",
        ),
        (
            "bounded-TTL",
            [
                (
                    rec.decision_window,
                    [
                        (
                            "Fraction(expires) - Fraction(issued) > Fraction(policy.record_ttl_seconds)",
                            "False",
                        )
                    ],
                )
            ],
            "record_ttl_and_absence_window",
        ),
        (
            "full-absence-window",
            [
                (
                    rec.decision_window,
                    [
                        (
                            "_seconds(expires) + _seconds(policy.sign_attempt_seconds) + policy.skew",
                            "_seconds(issued) + _seconds(policy.sign_attempt_seconds) + policy.skew",
                        )
                    ],
                )
            ],
            "record_ttl_and_absence_window",
        ),
        (
            "strict-numeric-policy",
            [
                (
                    rec.SettlingPolicy.__post_init__,
                    [
                        (
                            "validate(getattr(self, name), name=name)",
                            "float(getattr(self, name))",
                        )
                    ],
                )
            ],
            "numeric_policy or positive_policy",
        ),
        (
            "non-clean-exit",
            [
                (
                    rec.ReconciliationReport.exit_code.fget,
                    [('return 0 if self.to_dict()["clean"] else 1', "return 0")],
                )
            ],
            "incomplete_source_never_empty_clean",
        ),
        (
            "secret-free-projection",
            [
                (
                    rec.reconcile,
                    [
                        (
                            "result = {",
                            'result = {"unsafe_records": [r.to_dict() for r, _ in selected],',
                        )
                    ],
                )
            ],
            "cli_versioned_json_secret_free",
        ),
        (
            "read-only-and-F2-boundary",
            [
                (
                    gate.read_gate,
                    [
                        ("PRAGMA query_only=ON", "PRAGMA query_only=OFF"),
                        (
                            "records, lifecycle = _decode_rows(rows)",
                            "records, lifecycle = _decode_rows(rows)\n            connection.execute(\"UPDATE audit_chain SET subject='mutated' WHERE seq=1\")\n            connection.commit()",
                        ),
                    ],
                )
            ],
            "matched_sign_never_resolves_unknown",
        ),
        (
            "controls-both-no-synthetic-alarm",
            [
                (
                    rec._checked_source,
                    [
                        (
                            "issues = list(result.issues)",
                            'issues = list(result.issues) + ([SourceIssue("synthetic-gap")] if not result.events else [])',
                        )
                    ],
                )
            ],
            "controls_both_residual",
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
    with tempfile.TemporaryDirectory(prefix="prom-f11-3-reverts-") as directory:
        for name, changes, selection in plan:
            originals = []
            captured = io.StringIO()
            report = Path(directory) / (name + ".xml")
            try:
                for function, edits in changes:
                    original = function.__code__
                    source = textwrap.dedent(inspect.getsource(function))
                    for old, new in edits:
                        if old not in source:
                            raise AssertionError(f"{name}: target disappeared: {old}")
                        source = source.replace(old, new)
                    tree = ast.parse(source)
                    tree.body[0].decorator_list = []
                    namespace = {}
                    exec(  # noqa: S102 - reviewed test-only in-memory mutations, no user code
                        compile(tree, f"<F11-3-revert:{name}>", "exec"),
                        function.__globals__,
                        namespace,
                    )
                    mutated = namespace[function.__name__]
                    assert original.co_freevars == mutated.__code__.co_freevars
                    originals.append((function, original))
                    function.__code__ = mutated.__code__
                with (
                    contextlib.redirect_stdout(captured),
                    contextlib.redirect_stderr(captured),
                ):
                    result = pytest.main(
                        ["-q", TEST, "-k", selection, f"--junitxml={report}"]
                    )
            finally:
                for function, original in reversed(originals):
                    function.__code__ = original
            cases = list(ET.parse(report).iter("testcase")) if report.exists() else []
            failures = [c for c in cases if c.find("failure") is not None]
            if (
                result != pytest.ExitCode.TESTS_FAILED
                or not failures
                or any(
                    c.find("error") is not None or c.find("skipped") is not None
                    for c in cases
                )
            ):
                print(captured.getvalue())
                raise AssertionError(f"{name}: no executed call-phase proof")
            total += len(failures)
            print(f"CAUGHT {name}: {len(failures)} call-phase failure(s); {selection}")
        enforce_expected(len(plan), total)
        print(
            f"{len(plan)} reverts caught; {total} call-phase failures; zero errors/skips; "
            f"pinned {EXPECTED_REVERTS} / {EXPECTED_CALL_FAILURES}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
