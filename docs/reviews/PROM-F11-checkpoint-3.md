# PROM-F11 checkpoint 3 — six-part implementation report

Base: merged checkpoint 2b, `353a8081bb5d4fe00390db5305bd6ec8023ef106`.
Implementation complete locally; publication/Linux CI and maintainer acceptance
remain release gates. No auto-merge. No validated live cloud/HSM adapter is claimed.

## 1. Outcomes and matching

`chokepoint/reconciliation.py::reconcile` reads actual 2a disk records and the
2b `SignAuditSource`; it accepts no cached/local approval digest set.
MATCHED is one authorised decision and one successful independently observed
digest-bound event, agreeing on pinned scope/key/public-key mapping, caller,
algorithm and admissible time. UNWITNESSED is a mature decision without a
successful witness under complete evidence, **not forgery**. UNEXPLAINED is an
unexplained successful digest-bound Sign, including `excess_sign_attempts`.
INDETERMINATE is couldn't reconcile, never clean.

Digests/preimages/record hashes are recomputed from disk. Refusals, proximity,
copied aliases, missing or local asserted digests cannot explain signing.
Known provider provenance locations cannot be configured to a local gate field.
Missing post-Sign results do not invalidate a decision. Denied attempts are
non-forgery diagnostics; unknown outcomes remain indeterminate. Exact delivery
IDs deduplicate; conflicting IDs invalidate the source. Identical digest groups
use one-to-one accounting, not a claim about which indistinguishable attempt
was malicious. Local HMAC always lacks an independent Sign source.

## 2. Coverage, settling, lookback and integrity

`reconcile_gate.read_gate` opens SQLite read-only, in one read transaction.
The raw chain is verified against the entire independently supplied anchor
history and exact auditor-pinned checkpoint **before** the 2a typed decoder
runs. An unanchored tail, corrupt row, stale snapshot or missing legacy execution
binding prevents a clean result. The checkpoint's coverage is an independent
attestation, not inferred from a chain tip or timestamp.

Binary64 times convert using exact rational arithmetic and outward rounding.
The absence window is issuance − skew through expiry + bounded Sign duration +
skew. Missing send/result timestamps never shrink it. The source read extends to
each selected decision window; gate coverage includes the extended-start
lookback (maximum TTL + Sign duration + skew) through extended end plus skew.
Both requested range and affected window settle after their upper bound plus
settling (default 900 seconds); skew/TTL/deadline are explicit strict pins.
Elapsed time still requires source-attested coverage/frontier, all pages and no
affected gaps. Unaffected findings survive a partly incomplete range, but the
top level remains non-clean.

The synchronous API cannot preempt arbitrary injected anchor/source readers.
Real adapters must enforce their I/O/size deadlines. Bounded exports and SQLite
query limits refuse rather than truncate. No whole-reconciler hard wall-clock
guarantee or live-cloud deadline proof is claimed.

## 3. Operator interface

`promethyn-reconcile` (also `python -m prometheus_protocol.cli.reconcile`)
reads pinned configuration, a consistent gate SQLite snapshot, full independent
anchor-history NDJSON, and a 2b source-result NDJSON export. Hashes pin transfer
bytes, not source authenticity/completeness; independent acquisition is mandatory.
No arbitrary adapter loading, SDK, signing, execution, recovery, nonce release,
or anchor writes. [Full input/output schema and procedure](../reconciliation.md).

JSON version 1 contains scope, requested/extended intervals, policy, retry time,
chain/anchor/checkpoint evidence, source coverage/issues, per-record/event status
and reason, aggregate and separate counts, refusals, denied attempts, limitations
and forgery signal. Raw envelopes, nonces, preimages, SQL and exception text are
not projected. Free-form references are fingerprinted; unknown source diagnostic
reasons are replaced with stable generic codes. Non-secret source/caller IDs remain
available for operator correlation.

Exit **0** only for a fully checked discrepancy-free range; **1** for valid but
non-clean reconciliation; **2** for invalid/unreadable configuration or exports.
A minimal versioned INDETERMINATE JSON replaces unavailable detailed evidence.
Argument syntax errors use argparse's stderr/exit 2.

## 4. Tests and executed guard reversions

**105 new tests; 276 combined 2a/2b/3 proofs passed locally, zero skips.**
The CI JUnit gate requires each of all three files to produce cases and rejects
every skip/failure/error. New cases include invoke-only detection, concurrent
normal issuance across disk reopen and a fresh interpreter, both lost-reply
branches, record-before-Sign and Sign-before-result crashes, settling edges,
gaps/retention/unreadable/missing pages, metadata-only self-certification,
principal/digest/algorithm/time/alias mismatches, refusals, duplicates/excess,
unknown/denied outcomes, mapping conflicts, gate integrity/anchor failures,
source-extension/lookback, CLI redaction/read-only behavior and the F2 boundary.

A native GCP-shaped normalization-to-match composition uses an independently
model-observed digest, not a digest filled from the gate. It is **not** live
GCP acceptance. The controls-both test intentionally erases unauthorized history
and replaces coverage: no forgery signal or synthetic gap remains.

**43 deliberate checkpoint-3 guard reversions caught; 72 call-phase failures,
zero setup/collection errors or skips.** Functions are mutated in memory and
restored. Redundant guards are reverted together where necessary. The read-only
mutation writes only an isolated pytest temporary ledger, never operator state.
Run `python scripts/f11_reconcile_revert_proofs.py`; each selection below
names what actually went red in `tests/chokepoint/test_reconciliation.py`.

| Deliberate reversion | Executed test selection | Call failures |
|---|---|---|
| null-transfer-pin-cannot-disable-verification | `cli_versioned_json_secret_free` | 1 |
| native-provenance-not-configurable-to-local | `operator_cannot_enable_gate` | 1 |
| secret-reference-redaction | `source_diagnostics_and_references` | 1 |
| source-diagnostic-allowlist | `source_diagnostics_and_references` | 1 |
| gate-snapshot-size | `gate_size_bound` | 1 |
| invoke-only-signal | `invoke_only_forgery` | 1 |
| normal-batch-positive-control | `normal_concurrent_batch` | 1 |
| disk-digest-recompute | `disk_digest_is_recomputed` | 1 |
| digest-not-proximity-or-alias | `binding_mismatch and (digest or alias)` | 2 |
| principal-binding | `binding_mismatch and principal` | 1 |
| independent-provenance-location | `absent_or_locally_asserted and local` | 1 |
| algorithm-binding | `binding_mismatch and algorithm` | 1 |
| time-binding | `binding_mismatch and time` | 1 |
| half-open-sign-window | `success_at_absence_upper` | 1 |
| refused-never-explains | `refused_decision_cannot` | 1 |
| pre-sign-crash-not-forgery | `pre_sign_crash_unwitnessed` | 1 |
| no-result-crash-window | `crash_after_sign_before_result` | 1 |
| one-attempt-per-decision | `excess_distinct_real` | 1 |
| event-id-not-digest-dedup | `distinct_ids_not_digest` | 1 |
| conflicting-event-identity | `conflicting_source_identity` | 1 |
| export-conflict-before-filter | `export_conflict_outside` | 1 |
| denied-not-forgery | `denied_diagnostic and denied` | 1 |
| unknown-not-success | `denied_diagnostic and unknown` | 1 |
| HMAC-no-independent-source | `local_hmac_never_clean` | 1 |
| metadata-only-never-clean | `empty_metadata_only_range` | 1 |
| settling-required | `settling_boundary_requires` | 2 |
| attestation-not-timer | `source_contract_refusals and no_attestation` | 1 |
| all-pages-required | `source_contract_refusals and missing_pages` | 1 |
| source-frontier-required | `source_contract_refusals and frontier` | 1 |
| gap-required | `useful_findings_retained` | 1 |
| gate-lookback-required | `lookback_not_just_extended` | 1 |
| source-window-extension | `gate_lookback_and_source_extension` | 1 |
| anchor-tail-required | `gate_checkpoint_refusals and unanchored` | 1 |
| chain-before-decode | `disk_tamper_chain_verified` | 1 |
| legacy-history-refusal | `missing_legacy_history` | 1 |
| key-mapping-pin | `conflicting_identity_mapping` | 1 |
| bounded-TTL | `record_ttl_and_absence_window` | 1 |
| full-absence-window | `record_ttl_and_absence_window` | 1 |
| strict-numeric-policy | `numeric_policy or positive_policy` | 22 |
| non-clean-exit | `incomplete_source_never_empty_clean` | 7 |
| secret-free-projection | `cli_versioned_json_secret_free` | 1 |
| read-only-and-F2-boundary | `matched_sign_never_resolves_unknown` | 1 |
| controls-both-no-synthetic-alarm | `controls_both_residual` | 1 |

The existing 2b runner also remains mandatory:
`python scripts/f11_source_revert_proofs.py` (15 reverts / 21 call failures).

## 5. Corrected claims

`key-custody.md` and `threat-model.md` now describe operational reconciliation,
the four outcomes, strict coverage/settling, source trust, per-provider capability
and controls-both residual, replacing the open missing-control claim. README,
the approved design and adapter checklist point to the operational consumer.
The signer module's unconditional witness claim is corrected without changing
its executable signing code.

- **GCP:** observed digest can support detection with independently validated
  adapter, pinned immutable mapping and complete trustworthy evidence.
- **AWS CloudTrail:** metadata-only → **INDETERMINATE, not detection**.
- **PKCS#11:** vendor-dependent; absent independent digest/coverage means
  INDETERMINATE.
- **Local HMAC:** no independent signing witness.

No claim that logging is always enabled, retained or complete; no claim that
audit logging failure stops Sign; no claim that MATCHED resolves execution.
This implements design §5 without changing its detection semantics. The explicit
auditor checkpoint makes its gate-completeness assumption concrete.

## 6. Suite, CI and publication

Local focused tests (276, zero skips), type gate (21 files), Ruff, hygiene
(295 files), IP consistency and package build passed. Full local suite:
**1,381 passed, 64 failed, 94 skipped, one warning**. The exact set of 64 failure
names matches the checkpoint-2b baseline: no new failures, none suppressed.
This is not a locally green suite; Darwin substrate/ownership and existing
platform limitations remain visible.

Pinned Voidguard on a clean staged-tree export: **0 VOID, 3 WARN, 2 UNKNOWN**.
Findings are unchanged: PostgreSQL service-container consumer warnings, static
skip conditions and unavailable scheduled-run history. No suppression/baseline
was added. Zero VOID is not zero findings or complete assurance.

**Linux CI is a required release gate, not yet a passing claim in this file.**
The PR must show all 3.10/3.11/3.12 builds green, including existing mandatory
PostgreSQL/isolation/privilege/Hearth checks, all F11 no-skip proofs and both
mutation runners. Voidguard must report zero VOID while keeping WARN/UNKNOWN
visible. The final PR report records exact-head observations.

Local commits use DriivAIDev <will@driivai.com> with no trailers/footer.
Any publication identity exception requires the maintainer's approval for this
PR. Stop for maintainer read; no auto-merge and no deployed-adapter acceptance
is inferred from shipping the reconciler.
