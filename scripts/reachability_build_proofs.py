"""Executed first/second-order build probes, isolated from the primary tree.

Run PYTHONDONTWRITEBYTECODE=1 python scripts/reachability_build_proofs.py.
Second-order removes assert statements from the proof, NOT pytest.raises:
the report distinguishes that surviving refusal oracle from value/reason claims.
"""
from __future__ import annotations

import ast
import os

from mutation_worktree import MutationWorktree

BUILD = "src/prometheus_protocol/runtime/security_build.py"
FACTORY = "src/prometheus_protocol/runtime/factory.py"
TEST = "tests/conformance/test_security_build.py"

# name, path, before, after, proof selector
MUTATIONS = (
    ("execution-authorizer-policy-check-deleted", BUILD,
     "a._supplier() == selected for a in instances(ExecutionAuthorizer)",
     "a._supplier() == selected for a in ()",
     "test_build_checks_policy_at_both_bank_and_execution_authorizer"),
    ("execution-authorizer-policy-substituted-from-bank", BUILD,
     "a._supplier() == selected for a in instances(ExecutionAuthorizer)",
     "bank._policy_supplier() == selected for bank in banks",
     "test_build_checks_policy_at_both_bank_and_execution_authorizer"),
    ("bank-policy-check-deleted", BUILD,
     "bank.has_policy_supplier and bank._policy_supplier() == selected for bank in banks",
     "bank.has_policy_supplier and bank._policy_supplier() == selected for bank in ()",
     "test_build_checks_policy_at_both_bank_and_execution_authorizer"),
    ("bank-policy-substituted-from-authorizer", BUILD,
     "bank.has_policy_supplier and bank._policy_supplier() == selected for bank in banks",
     "a._supplier() == selected for a in instances(ExecutionAuthorizer)",
     "test_build_checks_policy_at_both_bank_and_execution_authorizer"),
    ("remove-root-guard", FACTORY, "install_build_guards(globals())",
     "# root guard deleted", "test_f1_required_attestation_reaches_startup"),
    ("skip-publication", BUILD, "attestor = attestation.attest_at_startup(checked, signer=resolved)",
     "attestor = None", "test_startup_positive_publishes_and_retains_attestor"),
    ("foreign-publication-success", BUILD,
     'raise BuildRefused("config_attestation_target", "startup publication did not complete")',
     "pass", "test_configured_optional_publication_failure_is_not_credited"),
    ("restore-direct-workflow-ledger", FACTORY,
     "shared_ledger = ledger if ledger is not None else build_ledger(config)",
     "shared_ledger = ledger if ledger is not None else SqliteLedger(config.ledger_path)",
     "test_f2_workflow_applies_required_anchor"),
    ("delete-injection-check", BUILD,
     'if not (required or config.ledger_anchor):', "if True:",
     "test_f2_injected_unanchored_ledger_is_refused"),
    ("foreign-witness", BUILD,
     "if destination(actual) is None or destination(actual) != destination(expected):",
     "if False:", "test_injected_anchor_cannot_substitute_another_witness"),
    ("hand-listed-schema", BUILD,
     'return tuple(item.name for item in declared if item.metadata.get("security", False))',
     'from prometheus_protocol.core.config import SECURITY_FIELDS\n    return SECURITY_FIELDS',
     "test_future_config_field_cannot_escape_derivation"),
    ("unknown-field-defaulted-nonsecurity", BUILD,
     'if type(item.metadata.get("security")) is not bool:', "if False:",
     "test_future_config_field_cannot_escape_derivation"),
    ("new-aliased-root-not-wrapped", BUILD,
     "namespace[name] = guarded_root(function)", "namespace[name] = function",
     "test_new_root_with_alias_and_indirect_none_is_still_guarded"),
    ("default-bound-discarded", BUILD,
     "elif applied is None and value == defaults[name]:", "elif value == defaults[name]:",
     "test_default_value_is_not_permission_to_discard_a_bound"),
    ("public-root-classification-deleted", FACTORY, "install_build_guards(globals())",
     "# root guard deleted", "test_all_factory_roots_classified_without_name_allowlist"),
    ("publication-refusal-not-reached", FACTORY, "install_build_guards(globals())",
     "# root guard deleted", "test_startup_publication_failure_never_returns_runtime"),
    ("positive-anchor-not-built", FACTORY,
     "return SqliteLedger(location, tip_anchor=anchor)",
     "return SqliteLedger(location)", "test_required_anchor_positive_is_real_runtime_anchor"),
    ("default-config-ignored", BUILD, "bound.apply_defaults()", "# defaults discarded",
     "test_config_in_new_root_default_argument_is_not_discarded"),
    ("default-escalation-discarded", BUILD,
     'comparisons = [g._escalate_below == value for g in instances(ActionGate)]',
     'comparisons = [g._escalate_below == value for g in instances(ActionGate) if g._escalate_below is not None]',
     "test_default_escalation_cannot_be_relabelled_not_applicable"),
    ("variadic-config-ignored", BUILD, "for item in nested:",
     "for item in ():",
     "test_variadic_root_cannot_hide_requested_config"),
    ("migration-publication-skipped", "src/prometheus_protocol/chokepoint/runner.py",
     "install_build_guards(globals())", "# migration guard deleted",
     "test_migration_startup_publication_is_required_and_uses_its_signer"),
    ("legacy-env-guard-deleted", "src/prometheus_protocol/chokepoint/runner.py",
     "install_build_guards(globals())", "# migration guard deleted",
     "test_runner_without_settings_does_not_drop_environment_anchor_requirement"),
    ("unused-custody-credited", BUILD,
     "if signer is not None and (config.config_attestation_target or config.require_config_attestation):",
     "if signer is not None:",
     "test_unused_signer_argument_cannot_satisfy_custody_requirement"),
    ("nested-contract-comparison-deleted", BUILD,
     "if nested_contract != active_contract:", "if False:",
     "test_nested_root_cannot_discard_a_different_security_contract"),
    ("nested-contract-substituted-from-parent", BUILD,
     "nested_contract = {item.name: getattr(checked, item.name) for item in fields(checked)}",
     "nested_contract = active_contract",
     "test_nested_root_cannot_discard_a_different_security_contract"),
    ("nested-positive-publication-deleted", BUILD,
     "attestor = attestation.attest_at_startup(checked, signer=resolved)",
     "attestor = None",
     "test_nested_root_with_the_same_contract_is_validated_and_published_once"),
    ("external-subclass-refusal-deleted", BUILD,
     'raise BuildRefused("component", "unsupported external subclass in security runtime")',
     "pass", "test_external_security_subclass_is_not_an_absent_default_domain"),
    ("external-subclass-substituted-as-absent", BUILD,
     'elif any(base.__module__.startswith("prometheus_protocol.") for base in type(obj).__mro__):',
     "elif False:", "test_external_security_subclass_is_not_an_absent_default_domain"),
    # ---- F-5: the six credit paths that no proof reached ---------------------
    # Each was deleted in a MutationWorktree BEFORE its control existed and all
    # six SURVIVED, `70 passed`. The mechanisms were real; nothing would have
    # noticed them stopping. Each row now names the control that reddens.
    ("custody-credit-for-the-supplied-signer-deleted", BUILD,
     "                signers.append(signer)", "                pass",
     "test_an_external_attestation_signer_earns_the_custody_credit"),
    ("digest-pin-credited-without-any-sandbox", BUILD,
     "            applied = bool(sandboxes)\n            for obj in sandboxes:",
     "            applied = True\n            for obj in sandboxes:",
     "test_a_pin_requirement_with_no_sandbox_at_all_is_refused"),
    ("retention-anchors-never-collected", BUILD,
     "                    applicable.append(a)", "                    pass",
     "test_a_retaining_anchor_earns_the_retention_credit"),
    ("role-budget-credited-without-comparison", BUILD,
     "            applied = all(obj._budget.limit == value for obj in engines) if engines else None",
     "            applied = True if engines else None",
     "test_a_role_budget_disagreeing_with_the_config_is_refused"),
    ("provider-bounds-credited-without-comparison", BUILD,
     '            applied = matches(RemoteModelProvider, "timeout_s" if name == "request_timeout_s" else "max_response_bytes", value)',
     "            applied = True",
     "test_a_remote_provider_disagreeing_with_the_bound_is_refused"),
    ("runtime-endpoint-never-revalidated", BUILD,
     '                validate_endpoint(endpoint, name="runtime endpoint", allow_insecure_loopback=value)',
     "                pass",
     "test_an_endpoint_swapped_after_construction_is_still_revalidated"),
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
    # Printed from the table so a report reads the row count off this line
    # rather than counting FIRST/SECOND lines through a filter (doctrine #11,
    # OPEN-GAPS G53).
    print(f"rows: {len(MUTATIONS)} first-order, {2 * len(MUTATIONS)} runs including the second-order variants", flush=True)
    for second_order in (False, True):
        for name, path, before, after, selector in MUTATIONS:
            # Fresh worktree for EACH row: neither stale pyc nor another
            # mutation's source can satisfy this proof.
            with MutationWorktree(include_dirty=True) as tree:
                red, baseline = tree.pytest([TEST + "::" + selector])
                if red or "passed" not in baseline or "error" in baseline:
                    raise RuntimeError(f"baseline invalid: {selector}: {baseline}")
                tree.apply(path, before, after)
                if second_order:
                    original = (tree.path / TEST).read_text()
                    tree.apply(TEST, original, without_asserts(original))
                red, summary = tree.pytest([TEST + "::" + selector])
                if "error" in summary or not any(word in summary for word in ("passed", "failed")):
                    raise RuntimeError(f"invalid measurement: {name}: {summary}")
                print(("SECOND " if second_order else "FIRST ") + name + ": " + summary, flush=True)
                for node in red:
                    print("  " + node, flush=True)
                if not second_order and not red:
                    raise RuntimeError(f"first-order mutation survived: {name}")


if __name__ == "__main__":
    main()
