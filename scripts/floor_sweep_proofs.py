"""PART 3 — proofs for every population pin converted from a floor to an exact.

WHAT EACH ROW PROVES, and why the mutation is applied to the PIN rather than to
the population it is compared against.

The property is ``pin == population``. Deleting a credential field from the
package to prove the sweep notices would redden half the suite for reasons that
are not this pin, so each mutation is applied to the pinned side instead, which
is exactly equivalent and reaches only the pin:

  SHORTFALL    the pin names a member the population does not have
               == a member LEFT the population.  Must redden.
  EXCESS       the pin drops a member the population still has
               == a member ARRIVED in the population.  Must redden.
  SUBSTITUTION both at once, so the SIZE IS UNCHANGED.  Must redden.
               This is the case a count passes and the one that matters; on a
               pin that is deliberately a COUNT it cannot reach, and the runner
               reports INERT rather than SURVIVED.
  SECOND-ORDER the assertion naming the property is deleted and EXCESS is
               applied again. GREEN means the assertion was load-bearing. RED
               means some OTHER assertion carries that half of the property,
               and the runner names which — never recorded as weak.

Every row measures its own CONTROL first: unmutated, the named test must be
green, or a red from any mutation below proves nothing.

INERT IS NOT SURVIVED. A mutation that cannot reach the pin it targets is
reported INERT. Sprint 0's probe was inert on 5 of 22 rows and printed
SURVIVED, and "12 of 22 unproved" would have been wrong by five.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutation_worktree import MutationWorktree, MutationWorktreeError  # noqa: E402

CANARY = "tests/conformance/test_secret_canary_sweep.py"
STRICT = "tests/conformance/test_strict_booleans.py"
SINKS = "tests/conformance/test_secret_sink_regressions.py"
REGISTRY = "tests/conformance/test_implementation_registry.py"
SBOM = "tests/conformance/test_dependency_closure.py"
TYPEGATE = "tests/conformance/test_type_gate.py"
GITREF = "tests/conformance/test_git_ref_format.py"
SELECTORS = "tests/conformance/test_proof_selectors_exist.py"
DOCTRINE = "tests/conformance/test_doctrine_index.py"
COMPOSITION = "tests/conformance/test_proof_composition.py"
PRODFIX2 = "tests/conformance/test_prod_fix_2_revert_pins.py"
GROUNDING = "tests/unit/test_grounding.py"
GROUNDINGV2 = "tests/unit/test_grounding_v2.py"
GOLD = "tests/conformance/test_gold_pilot_v3.py"

PROBE = '"__floor_sweep_probe__"'


def _set_row(label, file, test, const, open_literal, drop_member, assertion):
    """A MEMBERSHIP pin: all four probes are reachable."""
    return {
        "label": label, "file": file, "test": f"{file}::{test}", "kind": "set",
        "shortfall": (open_literal, f"{open_literal}\n    {PROBE},"),
        "excess": (drop_member, ""),
        "substitution": [(open_literal, f"{open_literal}\n    {PROBE},"),
                         (drop_member, "")],
        "assertion": assertion,
    }


def _count_row(label, file, test, pinned_line, value, assertion):
    """A COUNT pin: substitution cannot reach it, and is reported INERT."""
    return {
        "label": label, "file": file, "test": f"{file}::{test}", "kind": "count",
        "shortfall": (pinned_line, pinned_line.replace(str(value), str(value + 1), 1)),
        "excess": (pinned_line, pinned_line.replace(str(value), str(value - 1), 1)),
        "substitution": None,     # INERT by construction
        "assertion": assertion,
    }


ROWS = [
    _set_row("canary-credential-fields", CANARY,
             "test_discovery_actually_finds_the_known_credential_fields",
             "KNOWN_CREDENTIAL_FIELDS", "KNOWN_CREDENTIAL_FIELDS = frozenset({",
             '    "prometheus_protocol.ledger.spend.SpendState.idempotency_key",\n',
             "    assert not extra, ("),
    _set_row("canary-assignment-files", CANARY,
             "test_the_assignment_sweep_is_not_vacuous",
             "CREDENTIAL_ASSIGNMENT_FILES", "CREDENTIAL_ASSIGNMENT_FILES = frozenset({",
             '    "signer.py",        # the signing key\n',
             "    assert files == CREDENTIAL_ASSIGNMENT_FILES, ("),
    _set_row("canary-cli-subcommands", CANARY,
             "test_the_cli_exposes_subcommands_to_sweep",
             "CLI_SUBCOMMANDS", "CLI_SUBCOMMANDS = frozenset({",
             '    "verify-config",\n',
             "    assert set(_cli_subcommands()) == CLI_SUBCOMMANDS, ("),
    _set_row("strict-boolean-env-names", STRICT,
             "test_no_boolean_security_setting_is_read_outside_the_strict_parser",
             "BOOLEAN_ENV_NAMES", "BOOLEAN_ENV_NAMES = {",
             '    "PROM_REQUIRE_SANDBOX",\n',
             "    assert names == BOOLEAN_ENV_NAMES, ("),
    _set_row("reason-codes", SINKS,
             "test_the_reason_code_set_is_small_enough_to_read_and_large_enough_to_triage",
             "PINNED_REASON_CODES", "PINNED_REASON_CODES = frozenset({",
             '    "tls_failure", "unavailable", "unexpected_status",\n',
             "    assert set(REASON_CODES) == PINNED_REASON_CODES, ("),
    _set_row("shipped-identities", REGISTRY,
             "test_every_declared_site_reports_its_identity_by_reference",
             "SHIPPED_IDENTITIES", "SHIPPED_IDENTITIES = frozenset({",
             '    "swarm-checks",\n',
             "    assert set(shipped) == SHIPPED_IDENTITIES, ("),
    _set_row("sbom-components", SBOM,
             "test_the_sbom_is_a_cyclonedx_document_with_components",
             "SBOM_COMPONENTS", "SBOM_COMPONENTS = frozenset({",
             '    "typing_extensions",\n',
             "    assert names == SBOM_COMPONENTS, ("),
    _set_row("proof-runners-carrying-selectors", SELECTORS,
             "test_the_runner_population_is_not_empty",
             "RUNNERS_CARRYING_SELECTORS", "RUNNERS_CARRYING_SELECTORS = frozenset({",
             '    "spend_proofs.py",\n',
             "    assert set(runners) == RUNNERS_CARRYING_SELECTORS, ("),
    # Hand-written rather than ``_set_row``: this pin holds INTS, so injecting
    # the string probe would be a syntax error rather than a mutation, and a
    # file that will not parse is a DRIFT to refuse, never a result.
    {
        "label": "doctrine-cited-numbers", "file": DOCTRINE, "kind": "set",
        "test": f"{DOCTRINE}::test_the_tree_cites_doctrines_and_the_index_has_rows",
        "shortfall": ("CITED_NUMBERS = frozenset({1, 2, 4, 5, 8, 9, 10, 11})",
                      "CITED_NUMBERS = frozenset({1, 2, 4, 5, 8, 9, 10, 11, 99})"),
        "excess": ("CITED_NUMBERS = frozenset({1, 2, 4, 5, 8, 9, 10, 11})",
                   "CITED_NUMBERS = frozenset({1, 2, 4, 5, 8, 9, 10})"),
        # same SIZE, different membership: the case a count passes
        "substitution": [("CITED_NUMBERS = frozenset({1, 2, 4, 5, 8, 9, 10, 11})",
                          "CITED_NUMBERS = frozenset({1, 2, 4, 5, 8, 9, 10, 99})")],
        "assertion": "    assert set(_citations()) == CITED_NUMBERS, (",
    },
    _set_row("manifest-named-gaps", COMPOSITION,
             "test_the_manifest_records_what_it_deliberately_left_alone",
             "LEFT_AS_COUNTS_ONLY", "LEFT_AS_COUNTS_ONLY = frozenset({",
             '    "substrate-proofs",\n',
             "    assert set(left) == LEFT_AS_COUNTS_ONLY, ("),
    _set_row("gold-trap-taxonomy", GOLD,
             "test_flagship_unstated_inference_traps_are_present",
             "GOLD_TRAP_CATEGORIES", "GOLD_TRAP_CATEGORIES = frozenset({",
             '    "temporal-near-miss", "unstated-inference", "wrong-attribution",\n',
             "    assert set(cats) == GOLD_TRAP_CATEGORIES, ("),

    _count_row("package-modules", TYPEGATE,
               "test_the_checked_tree_really_is_every_module_in_the_package",
               "EXPECTED_PACKAGE_MODULES = 146", 146,
               "    assert len(modules) == EXPECTED_PACKAGE_MODULES, ("),
    _count_row("git-ref-corpus", GITREF,
               "test_the_corpus_is_not_trivially_small_or_one_sided",
               "CORPUS_SIZE = 449", 449,
               "    assert len(corpus) == CORPUS_SIZE, (len(corpus), CORPUS_SIZE)"),
    _count_row("git-ref-accepted", GITREF,
               "test_the_corpus_is_not_trivially_small_or_one_sided",
               "ACCEPTED_SIZE = 377", 377,
               "    assert len(accepted) == ACCEPTED_SIZE, ("),
    _count_row("selector-total", SELECTORS,
               "test_the_runner_population_is_not_empty",
               "TOTAL_SELECTORS = 106", 106,
               "    assert sum(len(v) for v in runners.values()) == TOTAL_SELECTORS, ("),
    _count_row("prod-fix-2-wrapper", PRODFIX2,
               "test_the_runner_covers_both_halves_of_the_finding",
               "WRAPPER_MUTATIONS = 7", 7,
               "    assert wrapper == WRAPPER_MUTATIONS, f\"{wrapper} wrapper mutations, pinned {WRAPPER_MUTATIONS}\""),
    _count_row("prod-fix-2-vocabulary", PRODFIX2,
               "test_the_runner_covers_both_halves_of_the_finding",
               "VOCABULARY_MUTATIONS = 8", 8,
               "    assert vocabulary == VOCABULARY_MUTATIONS, ("),
    _count_row("grounding-items", GROUNDING,
               "test_item_set_is_well_formed", "GROUNDING_ITEMS = 44", 44,
               "    assert len(items) == GROUNDING_ITEMS"),
    _count_row("grounding-v2-items", GROUNDINGV2,
               "test_v2_composition_is_as_declared", "V2_ITEMS = 64", 64,
               "    assert len(items) == V2_ITEMS"),
    _count_row("grounding-v2-traps", GROUNDINGV2,
               "test_v2_composition_is_as_declared", "V2_TRAPS = 45", 45,
               "    assert len(traps) == V2_TRAPS"),
    _count_row("gold-flagship-family", GOLD,
               "test_flagship_unstated_inference_traps_are_present",
               "GOLD_UNSTATED_INFERENCE = 3", 3,
               "    assert cats.count(\"unstated-inference\") == GOLD_UNSTATED_INFERENCE"),
]


def _run(tree, row, edits):
    for relative, old, new in edits:
        tree.apply(relative, old, new)
    red, summary = tree.pytest([row["test"]])
    tree.revert()
    return red, summary


def main() -> int:
    results = []
    with MutationWorktree() as tree:
        print(f"worktree package: {tree.imported_package_file()}\n")
        print(f"{'row':34} {'control':8} {'shortfall':10} {'excess':9} "
              f"{'substitution':13} second-order")
        print("-" * 104)
        for row in ROWS:
            f, test = row["file"], row["test"]

            # CONTROL — unmutated, the named test must be green, or nothing below counts.
            red, _ = tree.pytest([test])
            control = "GREEN" if not red else "RED"

            def probe(edits):
                try:
                    red, summary = _run(tree, row, edits)
                except MutationWorktreeError:
                    tree.revert()
                    return "DRIFT"          # the string moved: refuse, never score
                if test in red or any(test in r for r in red):
                    return "CAUGHT"
                # A run that ERRORED never exercised the pin, so calling it
                # SURVIVED would invent a gap — the mirror of a false GREEN and
                # just as wrong. Same for a summary this parser cannot read.
                if "error" in summary.lower():
                    return "ERROR"
                if " passed" not in summary:
                    return f"UNCLEAR({summary})"
                return "SURVIVED"

            shortfall = probe([(f, *row["shortfall"])])
            excess = probe([(f, *row["excess"])])

            if row["substitution"] is None:
                # A count cannot see a same-size swap. Reported INERT, never
                # SURVIVED: the mutation does not reach the pin it targets.
                substitution = "INERT"
            else:
                substitution = probe([(f, *m) for m in row["substitution"]])

            # SECOND ORDER: neutralise the assertion, re-apply EXCESS. GREEN
            # means the assertion carried the property; RED means something
            # else did, and the runner names which rather than scoring it weak.
            #
            # Only the CONDITION is replaced, never the whole line: most of
            # these asserts carry a multi-line message, so blanking the first
            # line orphans its continuation and the file stops parsing. The
            # first version of this probe did exactly that and produced
            # "(no summary)" on 15 of 21 rows — refused, not scored, which is
            # why it was visible at all.
            assertion = row["assertion"]
            indent = assertion[: len(assertion) - len(assertion.lstrip())]
            disabled = (f"{indent}assert True, ("
                        if assertion.rstrip().endswith(", (")
                        else f"{indent}assert True")
            second = probe([(f, assertion, disabled), (f, *row["excess"])])
            second = {"CAUGHT": "OTHER-CARRIES", "SURVIVED": "LOAD-BEARING"}.get(second, second)

            results.append((row["label"], control, shortfall, excess, substitution, second))
            print(f"{row['label']:34} {control:8} {shortfall:10} {excess:9} "
                  f"{substitution:13} {second}")

    print(f"\nrows: {len(results)}")
    bad = [
        r for r in results
        if r[1] != "GREEN"
        or any(v in ("SURVIVED", "DRIFT", "ERROR") or v.startswith("UNCLEAR")
               for v in r[2:6])
    ]
    for r in bad:
        print("REFUSED:", r)
    counts = {
        "CAUGHT": sum(v == "CAUGHT" for r in results for v in r[2:5]),
        "INERT": sum(v == "INERT" for r in results for v in r[2:5]),
        "SURVIVED": sum(v == "SURVIVED" for r in results for v in r[2:5]),
    }
    print("first-order probes:", counts)
    print("second-order:", {
        k: sum(r[5] == k for r in results)
        for k in ("LOAD-BEARING", "OTHER-CARRIES")
    })
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
