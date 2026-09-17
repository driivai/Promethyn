"""Executed mutation proofs for the F-3 classification and the report tokens.

Run PYTHONDONTWRITEBYTECODE=1 python scripts/receipt_classification_proofs.py.

BOTH ATTACK CLASSES on every new mechanism, because a deletion probe alone
passes on a comparison that was already meaningless:

* DELETION removes the new behaviour and must redden a named proof.
* CROSS-CONTEXT SUBSTITUTION puts a RIGHT-LOOKING check on the WRONG source —
  the tampered set standing in for the unreceipted one, the finding's table
  standing in for the table SQLite reported, the result's ids standing in for
  themselves. Each of those passes every deletion probe and detects nothing.

Second-order: each row is re-run with every ``assert`` in the proof module
replaced by ``pass``, ``pytest.raises`` retained. A row that stays red under
that has an oracle other than the deleted assertion; a row that goes green
does not, and is reported as such rather than described as proving anything.
"""
from __future__ import annotations

import ast
import os

from mutation_worktree import MutationWorktree

LEDGER = "src/prometheus_protocol/ledger/sqlite_ledger.py"
RECEIPTS = "src/prometheus_protocol/ledger/receipts.py"
BUILD = "src/prometheus_protocol/runtime/security_build.py"
POLICY = "src/prometheus_protocol/policy/execution.py"
CLASSIFICATION = "tests/conformance/test_receipt_classification.py"
SECURITY = "tests/conformance/test_security_build.py"

# name, path, before, after, proof module, proof selector
MUTATIONS = (
    # ---- F-3: the classification itself ------------------------------------
    ("unreceipted-reclassified-as-tampered", RECEIPTS,
     "UNRECEIPTED_REASONS = frozenset({DECISION_ENTRY_MISSING, OUTCOME_ENTRY_MISSING})",
     "UNRECEIPTED_REASONS = frozenset()",
     CLASSIFICATION, "test_a_pre_receipt_row_does_not_stop_a_runtime_root_from_opening"),
    # CROSS-CONTEXT: the right shape (a membership test against a named set)
    # on the WRONG source — the union instead of the absence side. Every
    # finding then reads as merely old, so a rewrite is treated as age.
    ("classification-substituted-from-the-union", RECEIPTS,
     "        return self.reason in UNRECEIPTED_REASONS",
     "        return self.reason in RECEIPT_FINDING_REASONS",
     CLASSIFICATION, "test_a_rewritten_row_still_refuses_every_read"),
    ("read-scope-deleted-every-finding-condemns-again", LEDGER,
     "        reached = self._unreceipted_reached(receipts, touched, result)",
     "        reached = receipts.unreceipted[0] if receipts.unreceipted else None",
     CLASSIFICATION, "test_a_pre_receipt_row_does_not_stop_a_runtime_root_from_opening"),
    ("read-scope-widened-nothing-is-refused", LEDGER,
     "        reached = self._unreceipted_reached(receipts, touched, result)",
     "        reached = None",
     CLASSIFICATION, "test_a_pre_receipt_row_is_still_refused_as_evidence"),
    ("tampered-branch-deleted", LEDGER,
     "        if receipts.tampered:",
     "        if False:",
     CLASSIFICATION, "test_a_rewritten_row_still_refuses_every_read"),
    # ---- the two scopes, each substituted for the other ---------------------
    ("table-scope-substituted-from-the-finding", LEDGER,
     "            if touched and finding.table not in touched:",
     "            if touched and finding.table not in {finding.table}:",
     CLASSIFICATION, "test_a_row_id_in_one_table_does_not_condemn_the_same_id_in_another"),
    ("result-scope-substituted-for-itself", LEDGER,
     "            if exposed is None or (ids & exposed):",
     "            if exposed is None or (exposed & exposed):",
     CLASSIFICATION, "test_a_receipted_row_still_reads_alongside_an_unreceipted_one"),
    ("projection-treated-as-an-empty-result", LEDGER,
     "        return None\n\n    @staticmethod\n    def _unreceipted_reached(",
     "        return set()\n\n    @staticmethod\n    def _unreceipted_reached(",
     CLASSIFICATION, "test_a_scalar_projection_cannot_escape_the_unreceipted_refusal"),
    ("authorizer-never-installed", LEDGER,
     "            self._conn.set_authorizer(observe)",
     "            pass",
     CLASSIFICATION, "test_a_projection_over_an_unrelated_table_still_reads"),
    ("touched-tables-substituted-from-the-snapshot", LEDGER,
     "            if action == sqlite3.SQLITE_READ and first:\n                touched.add(first)",
     "            if action == sqlite3.SQLITE_READ and first:\n                touched.add(EXECUTION_TABLE)",
     CLASSIFICATION, "test_a_projection_over_an_unrelated_table_still_reads"),
    # ---- the classification pins --------------------------------------------
    ("finding-emitted-without-a-classification", RECEIPTS,
     'findings.append(ReceiptFinding(subject, OUTCOME_ENTRY_MISSING, table=EXECUTION_TABLE))',
     'findings.append(ReceiptFinding(subject, "an_unclassified_reason", table=EXECUTION_TABLE))',
     CLASSIFICATION, "test_every_reason_the_module_emits_is_classified_exactly"),
    ("classification-sets-overlap", RECEIPTS,
     "UNRECEIPTED_REASONS = frozenset({DECISION_ENTRY_MISSING, OUTCOME_ENTRY_MISSING})",
     "UNRECEIPTED_REASONS = frozenset({DECISION_ENTRY_MISSING, OUTCOME_ENTRY_MISSING, OUTCOME_DIFFERS})",
     CLASSIFICATION, "test_the_two_classifications_partition_the_population"),
    ("verdict-softened-to-ok", RECEIPTS,
     "        return self.status == VALID",
     "        return self.status in (VALID, RECEIPTS_NOT_VERIFIABLE)",
     CLASSIFICATION, "test_the_verdict_distinguishes_unreceipted_from_rewritten"),
    # ---- F-6: the report tokens ---------------------------------------------
    ("disabled-requirement-reported-as-applied-again", BUILD,
     "            if not value:\n                # Nothing was asked for, so nothing was checked. Saying APPLIED\n                # here claimed a digest-pinning mechanism had been verified on\n                # a build that never looked at one.\n                report[name] = NOT_REQUESTED\n                continue",
     "            if not value:\n                report[name] = APPLIED\n                continue",
     SECURITY, "test_a_disabled_requirement_is_not_reported_as_applied"),
    ("anchor-rows-reported-as-applied-again", BUILD,
     "            if not value:\n                # An unconfigured witness and an unrequested requirement are\n                # both \"nothing was asked for\". Neither is evidence that the\n                # anchoring mechanism reached a ledger.\n                report[name] = NOT_REQUESTED\n                continue",
     "            if not value:\n                report[name] = APPLIED\n                continue",
     SECURITY, "test_a_disabled_requirement_is_not_reported_as_applied"),
    ("requested-anchor-downgraded-to-not-requested", BUILD,
     "            applied = True\n        elif name == \"ledger_anchor_retention_days\":",
     "            applied = None\n            report[name] = NOT_REQUESTED\n            continue\n        elif name == \"ledger_anchor_retention_days\":",
     SECURITY, "test_a_requested_anchor_is_still_reported_as_applied"),
    ("a-sixth-token-arrives-unnamed", BUILD,
     "            report[name] = DEFAULT_NOT_APPLICABLE",
     '            report[name] = "default_absent"',
     SECURITY, "test_the_report_vocabulary_is_pinned_exactly"),
    # ---- F-2: the F1 proof must need the REACH, not merely a refusal ---------
    ("publication-refused-before-it-is-reached", BUILD,
     "                    attestor = attestation.attest_at_startup(checked, signer=resolved)",
     '                    raise BuildRefused("config_attestation_target", "refused before publication")',
     SECURITY, "test_f1_required_attestation_reaches_startup"),
    ("signer-branch-substituted-for-the-publication-branch", BUILD,
     "                    resolved = attestation.resolve_attestation_signer(\n                        checked, signer=signer, signing_key=None\n                    )",
     "                    resolved = attestation.resolve_attestation_signer(\n                        checked, signer=None, signing_key=None\n                    )",
     SECURITY, "test_f1_required_attestation_reaches_startup"),
    # The raise the F2 proof ACTUALLY reaches: an injected ledger with no
    # anchor at all. The adapter-mismatch raise below is a different branch and
    # gets its own row, because aiming a mutation at the wrong one of two
    # neighbouring raises measures nothing.
    ("f2-refusal-cause-substituted", BUILD,
     '        raise BuildRefused("ledger_anchor", "ledger has no supported tip anchor")',
     '        raise BuildRefused("component", "ledger has no supported tip anchor")',
     SECURITY, "test_f2_injected_unanchored_ledger_is_refused"),
    ("witness-refusal-cause-substituted", BUILD,
     '        raise BuildRefused("ledger_anchor", "injected anchor has a different destination")',
     '        raise BuildRefused("component", "injected anchor has a different destination")',
     SECURITY, "test_injected_anchor_cannot_substitute_another_witness"),
    # ---- 1.4: the traversal limit is MEASURED, not merely written down -------
    ("traversal-silently-widened-to-sets", BUILD,
     "_WALKED_CONTAINERS = (tuple, list, dict)",
     "_WALKED_CONTAINERS = (tuple, list, dict, set, frozenset)",
     SECURITY, "test_an_unreachable_component_reads_as_not_applicable_not_as_a_refusal"),
    ("shipped-graph-hiding-check-substituted-for-itself", SECURITY,
     "        for obj in _exhaustive(runtime)\n        if id(obj) not in reachable",
     "        for obj in _objects(runtime)\n        if id(obj) not in reachable",
     SECURITY, "test_the_shipped_graph_hides_nothing_from_the_traversal"),
    # ---- the undecodable ledger, reported on #123 ---------------------------
    # DELETION: the chain verifier reads the two tables it does not verify
    # again, so a malformed column in either raises out of the diagnostic that
    # exists to diagnose it. This IS the reported defect, restored.
    ("chain-verifier-borrows-the-decoding-snapshot-again", LEDGER,
     '            rows = [dict(row) for row in self._conn.execute(\n'
     '                "SELECT * FROM audit_chain ORDER BY id"\n'
     '            ).fetchall()]',
     "            rows = self._receipt_source().events",
     CLASSIFICATION, "test_a_malformed_row_does_not_crash_the_chain_verifier"),
    # DELETION: the couldn't-check verdict removed, so the decoder error is
    # what `verify_ledger_file` and the CLI audit hand their caller.
    ("couldnt-decode-verdict-deleted", RECEIPTS,
     "        return ReceiptVerification(0, 0, (), checked=False)",
     "        raise",
     CLASSIFICATION, "test_a_malformed_row_makes_the_file_verifier_report_not_verifiable"),
    # CROSS-CONTEXT: the right shape (a verification carrying no findings) with
    # the WRONG flag -- couldn't-check presented as a completed check. Nothing
    # crashes and no finding is emitted, which is doctrine #8 exactly: an empty
    # instrument reading downstream as a pass.
    ("couldnt-decode-reported-as-a-completed-check", RECEIPTS,
     "        return ReceiptVerification(0, 0, (), checked=False)",
     "        return ReceiptVerification(0, 0, (), checked=True)",
     CLASSIFICATION, "test_the_undecodable_verdict_is_not_checked_rather_than_clean"),
    # DELETION: the guarded read hands back its decoder error instead of a
    # refusal in the closed vocabulary. A caller catching the typed refusal
    # catches nothing.
    ("undecodable-read-hands-back-its-decoder-error", LEDGER,
     '            raise ExecutionNotAuthorized(\n'
     '                "authoritative ledger read refused: the stored rows could not "\n'
     '                "be decoded",\n'
     '                reason="ledger_rows_unreadable",\n'
     '            ) from exc',
     "            raise",
     CLASSIFICATION, "test_every_guarded_reader_refuses_an_undecodable_row_in_the_typed_vocabulary"),
    # CROSS-CONTEXT: a real typed refusal naming the WRONG cause -- the chain's
    # reason for a fault that is not the chain's. It passes every "does it
    # refuse" probe and tells the operator to go and look at the hash walk.
    ("undecodable-refusal-cause-substituted", LEDGER,
     '                reason="ledger_rows_unreadable",',
     '                reason="chain_did_not_verify",',
     CLASSIFICATION, "test_every_guarded_reader_refuses_an_undecodable_row_in_the_typed_vocabulary"),
    # CROSS-CONTEXT on the closed set itself, keeping its SIZE: G25, a count is
    # not a composition. A membership pin catches this; a `len(...) == 24`
    # pin does not.
    ("refusal-reason-renamed-keeping-the-count", POLICY,
     '    "ledger_rows_unreadable",        # a JSON column would not decode at all',
     '    "ledger_chain_unreadable",       # a JSON column would not decode at all',
     CLASSIFICATION, "test_every_guarded_reader_refuses_an_undecodable_row_in_the_typed_vocabulary"),
)


def without_asserts(text: str) -> str:
    lines = text.splitlines(keepends=True)
    spans = sorted(
        ((n.lineno - 1, n.end_lineno) for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Assert)),
        reverse=True,
    )
    for start, end in spans:
        indent = len(lines[start]) - len(lines[start].lstrip())
        lines[start:end] = [" " * indent + "pass  # second-order assertion deletion\n"]
    return "".join(lines)


def main() -> None:
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    survivors: list[str] = []
    for second_order in (False, True):
        for name, path, before, after, module, selector in MUTATIONS:
            # A fresh worktree per row: neither a stale .pyc nor another row's
            # source can satisfy this proof.
            with MutationWorktree(include_dirty=True) as tree:
                target = module + "::" + selector
                red, baseline = tree.pytest([target])
                if red or "passed" not in baseline or "error" in baseline:
                    raise RuntimeError(f"baseline invalid: {selector}: {baseline}")
                tree.apply(path, before, after)
                if second_order:
                    original = (tree.path / module).read_text()
                    tree.apply(module, original, without_asserts(original))
                red, summary = tree.pytest([target])
                if "error" in summary or not any(w in summary for w in ("passed", "failed")):
                    raise RuntimeError(f"invalid measurement: {name}: {summary}")
                print(("SECOND " if second_order else "FIRST ") + name + ": " + summary, flush=True)
                for node in red:
                    print("  " + node, flush=True)
                if not red:
                    if not second_order:
                        raise RuntimeError(f"first-order mutation survived: {name}")
                    survivors.append(name)
    if survivors:
        print("\nSECOND-ORDER SURVIVORS (no oracle but the deleted assertion):", flush=True)
        for name in survivors:
            print("  " + name, flush=True)


if __name__ == "__main__":
    main()
