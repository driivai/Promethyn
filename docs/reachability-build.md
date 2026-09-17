# Requested configuration must reach a mechanism

## Limits first

This is a contract for supported Python composition, not an isolation boundary
against a caller who can edit trusted code. Config classification, component
classification, validators, and the guard itself are trusted and reviewable.
The attestation resolver still re-resolves adapters rather than inventorying
every live object; F17 is **not** closed. A WORM URI does not certify the physical
mount. Startup publication does not implement a periodic scheduler.

The runtime installer covers every public function defined in
`runtime/factory.py` and `chokepoint/runner.py`, except explicitly classified
partial components. It does not key on constructor names. The package-wide
inventory catches Config-bearing public functions added in another module
without that classification/installation, including ordinary import and type
aliases. Arbitrary dynamically generated code, private functions, methods, and
wholly unannotated parameters named something other than config/settings are
outside that static inventory. Opaque objects containing a Config are not
introspected as arguments. Built-in argument containers, variadic arguments,
and default-valued Config arguments are covered.

Nested roots must carry the same complete resolved Config, not merely the same
security flags: ordinary fields such as provider selection affect how a
security requirement is applied. A different nested configuration refuses
before construction. Foreign subclasses of package-owned components refuse
rather than disappearing as a supposedly absent/default domain.

Public direct constructors remain available for tests/integrators. They do not
receive a Config contract by magic. The persisted-hold obligation is enforced
at the reader independently of factory use; see
[the reader report](reachability-readers.md). Alternate ledger implementations
and deliberate private SQL access do not acquire SQLite's reader guarantee.

## What changed, and what was actually reproduced

Base: `9141936ea474c6ad7c0b41509b964814344f59b9`, not the brief's older
`03010a9`. Before implementation:

```text
test_f1_required_attestation_reaches_startup
  Failed: DID NOT RAISE ConfigError
test_f2_workflow_applies_required_anchor
  assert None is not None
test_f2_injected_unanchored_ledger_is_refused[execution]
  Failed: DID NOT RAISE ConfigError
test_f2_injected_unanchored_ledger_is_refused[swarm]
  Failed: DID NOT RAISE ConfigError
4 failed in 0.04s
```

The F3 red-first result was `1 failed, 1 passed`, with
`Failed: DID NOT RAISE StateUnreadable`; its exact reload probe and subsequent
results are in the reader report.

An initial local F2 test incorrectly expected the existing builder to forbid
memory-backed anchored ledgers. That presupposition is withdrawn: the builder
allowed them. F2 was a missing anchor, not an existing memory-store refusal.
Both injection paths had the same missing validation as workflow assembly,
although only workflow also bypassed the default builder.

Evidence locations at the named base commit: workflow's direct construction
is `runtime/factory.py:610`, execution injection is `runtime/factory.py:585`,
swarm injection is `runtime/factory.py:397`, and F3's early MATCHED return is
`execution/pending.py:755` (all under `src/prometheus_protocol/`). F1 was
measured by the permanent root-construction probes above, not inferred merely
from the existence of an attestation helper. The base type pin was actually
326 with tolerance 2 (`scripts/type_gate.py:100`), not the brief's 320.

* The four runtime roots publish before returning when an attestation target is
  configured, and refuse when publication cannot complete. They require an
  explicit `attestation_signer`; they do not generate a key. The returned
  `config_attestor` can be driven by an integrator's cadence.
* Both migration roots use their actual authority's signer and also pass through
  the guard. With no Config supplied, configuration is loaded from their
  explicit environment, or the process environment when omitted. Non-Config
  settings objects are refused instead of silently dropping unknown fields.
* Workflow uses `build_ledger`. Injected ledgers are checked before an execution
  controller's sweep and again in the returned graph. A required anchor must
  be present, append-only, and the configured adapter/destination. An opaque
  custom anchor is not credited from a boolean alone.
* An observed hold reopened without an observer records Unavailable and refuses;
  missing observation capability is not a MATCHED observation.
* The Config schema explicitly classifies every field. The security population
  is derived from dataclass fields, including subclasses. Missing classification
  refuses; a new security field without an application validator refuses.
* Guard validation examines returned components, not a source read, helper
  mention, constructor name, or hand-written list of requested properties.
  Assembly receives the resolved Config that the guard checks.

Implementation entry points in this change (under `src/prometheus_protocol/`):
schema derivation `runtime/security_build.py:38`, injected-anchor validation
`:79`, application matrix `:109`, root wrapper `:265`, nested-context refusal
`:324`, startup call `:349`; persisted-obligation comparison
`execution/pending.py:737`; reader derivation `ledger/readers.py:31` and
authoritative snapshot validation `ledger/sqlite_ledger.py:307`. The four
runtime roots are `runtime/factory.py:294`, `:366`, `:562`, and `:624`;
migration roots are `chokepoint/runner.py:2355` and `:2430`.

Documentation corrections are explicit in `docs/threat-model.md:1215` and
`docs/OPEN-GAPS.md:1258`; `runtime/factory.py:240` bounds the former
"every builder" claim. `gate/authorization.py:149` now emits "halted without an
approvable hold", matching the controller's refusal rather than promising
human routing for an unavailable required check.

## Application matrix

Roots: **O** orchestrator, **S** swarm, **E** execution controller, **W** workflow,
**M** migration runtime, **R** migration runner. W includes its actual bound
execution controller. An unsupported non-default tuning refuses rather than
claiming application. Defaults on genuinely absent domains are reported as
`default_not_applicable`; an existing component disagreeing with a default
refuses too. A disabled requirement is not evidence its mechanism exists — and
the first implementation contradicted that sentence in code, writing `applied`
on three unrequested rows. The report vocabulary is now five named constants
(`applied`, `not_requested`, `default_not_applicable`, `publication_pending`,
`published`), pinned as an exact membership against the tokens the source
actually writes.

> **CORRECTED 2026-09-17, and the correction enlarges the finding.** This
> paragraph said `default_not_applicable` reports an ABSENT domain and an
> UNREACHED one identically. That was true and it understated the case, and the
> #122 review record understates it the same way — which matters, because that
> text is now the historical account. `default_not_applicable` requires NO
> reachable consumer. When a compliant sibling IS present, which is the ordinary
> case on a real graph, `all()` over the reachable ones is True and an unreached
> component's row read **`applied`** — the strongest token this report has, the
> one that says the property was compared against the live components that
> honour it. Measured on a real `build_orchestrator` graph with one
> `PromotionGate` planted at `threshold=0.25` against a config value of `0.0`:
> three container shapes refused and **seven reported `applied`**.
>
> Both outcomes were real; which one you got depended on whether a compliant
> sibling happened to be in the graph. Neither is possible now for an object
> carrying a compared attribute: non-discovery REFUSES
> (`component_not_discovered`). `default_not_applicable` retains its original
> meaning — an absent domain at a default value — for everything else.

| Config property | Applied by / checked on | Other roots or limitations |
|---|---|---|
| sandbox | O/S/E/W sandbox instances | M/R have no sandbox; non-default request refuses |
| require_digest_pin | O/S/E/W container adapter's active pin requirement | Namespace/no-image roots cannot honor true |
| allow_insecure_loopback | Known remote-provider/HTTP-anchor endpoints, revalidated against permission | No active HTTP client: non-default request refuses |
| escalate_below | O/S/W banks and S/E/W action gates | M/R: non-default request refuses |
| gate_threshold | O promotion gate | S/E/W/M/R: non-default request refuses |
| pending_ttl_seconds | E/W pending service | O/S/M/R: non-default request refuses |
| verifier_timeout_s | O/S verifier and E/W executor limits | M/R: non-default request refuses |
| verifier_memory_mb | O/S verifier and E/W converted memory limit | M/R: non-default request refuses |
| verifier_cpu_seconds | O/S verifier and E/W executor limits | M/R: non-default request refuses |
| verifier_max_processes | O/S verifier and E/W executor limits | M/R: non-default request refuses |
| request_timeout_s | Known remote providers and HTTP ledger-anchor clients, when present | An attestation-only HTTP client is not yet in the prepublication graph; unsupported non-default tuning refuses |
| provider_max_response_bytes | O/S actual remote provider when present | Other roots: non-default request refuses |
| max_role_calls | S synthesis budget | Other roots: non-default request refuses |
| ledger_anchor | All six roots' actual supported ledgers | Requested witness must match adapter and destination |
| ledger_anchor_retention_days | Actual object-lock ledger anchors in all roots | No such anchor: non-default request refuses; attestation-only retention remains unsupported by this graph check |
| require_ledger_anchor | All six; also environment-only runner startup | True with absent/non-append-only anchor refuses |
| require_external_signer | M/R actual authority; O/S/E/W signer consumed by requested startup attestation | An unused signer argument does not satisfy custody |
| require_verified_substrate | M/R consumed-store resolved policy | O/S/E/W have no consumed-store mechanism; true refuses |
| allow_unverified_substrate | M/R consumed-store resolved opt-out policy | O/S/E/W: non-default request refuses |
| config_attestation_target | All six, startup publication | Configured-but-unsuccessful publication refuses even if requirement flag is false |
| require_config_attestation | All six, target/signing/publication | Missing signer/target or failed publication refuses |
| verification_profile | O/S/W banks, E/W authorizers, M issuance authorizer | R-only has no issuance authorizer; non-default selection refuses |

This matrix is intentionally not a claim that reflection proves arbitrary
adapter implementations enforce their attributes. The shipped adapters'
behavioral tests remain necessary. Unknown injected implementations are not
automatically discovered through arbitrary object internals.

## Independent checks caught holes in the first guard draft

The first implementation was not ready merely because its initial probes
passed. Independent checks found, and permanent regressions now cover:

1. Default-valued Config arguments were absent from `signature.bind`;
   `bound.apply_defaults()` is now required.
2. A gate with `_escalate_below=None` was filtered out and mislabeled not
   applicable. All actual gates now participate; factory banks/gates receive
   the configured threshold.
3. The legacy runner-only branch bypassed the guard for environment-only anchor
   requirements. That branch no longer returns an unchecked runtime.
4. Config inside `*args`/`**kwargs` was invisible. Discovery now walks standard
   argument containers, rejects cycles/ambiguous multiple configs, and passes
   the checked configuration to assembly.
5. An unused signer argument could be credited as applied custody. It is now
   credited only for a requested startup publication, or as the actual migration
   authority's signer.
6. A nested root could request required publication while the outer Config
   requested none; the draft returned a runtime without an attestor. The
   permanent tests initially reported `2 failed, 1 passed, 34 deselected`, then
   added provider-context substitution too. Complete nested Config equality
   now refuses a different context; the positive publishes exactly once.
7. An external-module subclass of `PendingActionService` disappeared from the
   object graph, allowing its TTL of zero to be labeled `default_not_applicable`
   against a requested 86400. External subclasses are now refused, not credited
   or silently treated as missing.
8. When both a bank and an execution authorizer existed, the draft checked the
   bank's policy only. The independent probe observed bank `defense-in-depth`,
   gate `baseline`, yet report `applied`; no executor bypass is asserted.
   Four permanent swarm/workflow cases initially gave `2 failed, 2 passed`,
   and now all banks and authorizers must match. The reader report separately
   records the cached-descriptor discovery gap found and closed in final review.

These are withdrawn draft claims, not hidden by rewriting history. They were
fixed before the first push.

## Reproduction and mutation commands

```sh
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q \
  tests/conformance/test_security_build.py \
  tests/conformance/test_security_build_inventory.py \
  tests/conformance/test_reachability_readers.py
PYTHONDONTWRITEBYTECODE=1 python scripts/reachability_build_proofs.py
PYTHONDONTWRITEBYTECODE=1 python scripts/reachability_reader_proofs.py
```

All source mutations in those runners use `MutationWorktree`; each build row
uses a fresh disposable checkout and validates its unmutated baseline first.
The complete executable edits and named selectors are in the build proof
script. Observed first-order rows:

| Mutation | Literal summary, timing omitted |
|---|---|
| execution-authorizer-policy-check-deleted | 2 failed, 2 passed |
| execution-authorizer-policy-substituted-from-bank | 2 failed, 2 passed |
| bank-policy-check-deleted | 2 failed, 2 passed |
| bank-policy-substituted-from-authorizer | 2 failed, 2 passed |
| remove-root-guard | 1 failed |
| skip-publication | 4 failed |
| foreign-publication-success | 1 failed |
| restore-direct-workflow-ledger | 1 failed |
| delete-injection-check | 2 failed |
| foreign-witness | 1 failed |
| hand-listed-schema | 1 failed, 1 passed |
| unknown-field-defaulted-nonsecurity | 1 failed, 1 passed |
| new-aliased-root-not-wrapped | 4 failed |
| default-bound-discarded | 1 failed |
| public-root-classification-deleted | 1 failed |
| publication-refusal-not-reached | 4 failed |
| positive-anchor-not-built | 4 failed |
| default-config-ignored | 1 failed |
| default-escalation-discarded | 1 failed |
| variadic-config-ignored | 2 failed |
| migration-publication-skipped | 2 failed |
| legacy-env-guard-deleted | 1 failed |
| unused-custody-credited | 1 failed |
| nested-contract-comparison-deleted | 3 failed |
| nested-contract-substituted-from-parent | 3 failed |
| nested-positive-publication-deleted | 1 failed |
| external-subclass-refusal-deleted | 1 failed |
| external-subclass-substituted-as-absent | 1 failed |

For each row, the second-order run deletes every `assert` in the new proof
module but retains `pytest.raises` and ordinary operations. Those runs retained
the same reds **except** public-root-classification-deleted, which became
`1 passed`. The surviving oracle in negative cases is exception/refusal, not
the deleted reason/value assertion. Positive probes can still fail because
construction raises or a required object is absent; deleting their value
assertions does not preserve proof of correct receipt contents. No assertion-
deletion run is described as proving the removed assertion.

Inventory deletion/substitution and its surviving second-order halves are in
[the inventory report](reachability-inventory-proof.md). Exact type-count
enforcement, the corrected base count, and its second-order survivor are in
[the F10 report](reachability-type-proof.md). The pin rejects both shortfall
and excess; it is not a file-identity or semantic-coverage proof.

## Validation and publication status

Observed before first push: 89 focused proofs (43 build, 13 inventory, 33
reader), zero skips; whole-tree mypy checked exactly 333 files clean and the
receipt was accepted. The type-proof CI group passed 68 tests. Hearth checks
passed after explicitly re-sanctioning changed protected content.

An earlier broad macOS run reported `17 failed, 2733 passed, 199 skipped, 1 error`.
Every one of those 17 failures and the setup error was then rerun on untouched
base `9141936` in a disposable worktree with the same environment: `17 failed,
1 error in 52.55s`. They concern unsupported platform/substrate/isolation or
platform-sensitive limits and diagnostics; this comparison establishes that
these specific failures predate this change, not that they may be ignored in
Linux CI. The final constrained-dependency run, with the additional guard
regressions, reported `18 failed, 2744 passed, 199 skipped, 1 error in 183.00s`.
It started before the final count re-pin and caught exactly that stale 78-vs-89
population, in addition to the same 17 failures/setup error. After re-pinning,
`test_ci_collection_pins.py` reported `5 passed in 0.68s`; the separately run
composition proof accepted all 89 cases and 37 required test names. This does
not relabel the broad run green.

These broad fixture runs explicitly used `PROM_ALLOW_UNSAFE_EXEC=1` for authored
test candidates on macOS. A supplementary run without that opt-in, deselecting
the 18 base-confirmed nonpasses, reported `50 failed, 2684 passed, 199 skipped,
18 deselected`: the host has no isolating sandbox, and unavailable execution
does not provide the fixtures' expected verdicts. Neither run establishes an
isolation guarantee. Local full-suite attempts are **not green Linux/PostgreSQL evidence**.
The CI job still provisions PostgreSQL and requires the Linux/platform proofs.
The PR must not be merged by this task. A follow-up push is **unreviewed by
default** until a review explicitly lands on that exact commit.
