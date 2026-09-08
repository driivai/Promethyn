# PROM-F11 checkpoint 2b — source input, not reconciliation

Base: merged checkpoint 2a, `main` at
`2ba1d46807b91849d0e8d86ddfd68b2b68b29407`.
**F11 remains OPEN. Stop at this checkpoint for maintainer review. No auto-merge.**

There is no deployed cloud adapter, live cloud call, bundled SDK, reconciler,
matching verdict, or operator CLI in this change. The model demonstrates both
the input contract and the controls-both adversary it cannot expose. A source
administrator can still replace history and completeness assertions together.
Existing production approval/signing/execution paths are unchanged.

## 1. Port surface and coverage

`chokepoint/audit_source.py` exposes the read-only `SignAuditSource` protocol and
`PagedSignAuditSource` composition. `read_sign_records(scope, start, end)` returns
immutable `SignRead(events, coverage, issues)`; times are integer epoch nanoseconds
and intervals are half-open. The scope pins provider/source/domain/region/key,
not the expected caller. Unknown principals are not filtered out.

Events carry immutable key scope, source event ID, authenticated caller, service
time, success/denied/unknown outcome, algorithm and provenance, and observed or
absent digest evidence. Absent means `None / absent / metadata_only`, never an
inferred digest. AWS request ID and message type are diagnostics only.

Coverage contains requested/covered interval, complete-through frontier, gaps,
observation time, capability, completeness-evidence basis and pages-exhausted.
Both frontier and covered interval can be unknown. Input `complete` requires
every page plus an adequate source completeness assertion, no issues and no gaps.
It is not a reconciliation verdict and does not establish digest binding for a
metadata-only source. Conflicting normalized payloads under one source event ID
produce `unusable`; other read/parse/bound failures remain explicitly incomplete.

The default read budget is 64 pages, 10,000 deliveries, 4 MiB aggregate raw bytes,
64 KiB per event, and three seconds. Empty continuation pages are consumed;
ordinal/snapshot/scope/coverage discontinuities and token loops fail closed.
Late replies are rejected, including normalization completing after the deadline.
An injected real page adapter must independently bound its I/O/allocations; this
synchronous collector cannot preempt a blocked adapter. That remains a mandatory
real-adapter acceptance item, not a claimed live transport proof.

## 2. Model capabilities and failure modes

`MemorySignAudit` is the trusted factory. `ModelSigner` exposes Sign and public
key retrieval for its bound authenticated caller; `ModelAuditReader` exposes
only the read operation; `ModelAuditAdministrator` can replace history and
coverage independently. Returned snapshots and their nested fields are immutable.
Python introspection is not modeled as a remote privilege boundary.

Actual P-256 signatures are independently verified in the tests. The model
records permitted and denied Sign requests. It supports delayed audit delivery,
late read and Sign replies, a lost successful Sign reply, reader unavailability,
omitted pages, retention boundaries, coverage gaps, duplicate deliveries,
conflicting payloads, and malformed raw events. Reader operations never alter
history or assertions. Clock advancement simulates a delayed reply, not a write
to the audit history.

The controls-both test signs directly, deletes its source history, and replaces
the coverage assertions. The reader returns a complete empty interval with no
synthetic gap or tombstone. This is intentionally an undetectable residual.
The invoke-only holder cannot perform those administrator operations.

## 3. Profiles and missing-digest proof

| Profile | Provider label | Digest evidence |
|---|---|---|
| GCP-shaped | `model-gcp` | Observed 32-byte Sign input with model provenance. |
| CloudTrail-shaped | `model-cloudtrail` | Explicitly absent, metadata-only. No digest/signature stored in its history. |

The metadata-only test composes the model signer with the real 2a production
authority and private SQLite journal. A matching gate decision exists on disk,
yet the source stays digest-free. There is no gate-record parameter/import at
the source boundary. Administrator-injected digest fields become malformed
input, not digest-bearing output. Inferred provenance is rejected by construction.

## 4. Provider mappings and acceptance

- AWS: supported CloudTrail 1.08/1.09 Sign JSON, IAMUser/AssumedRole identity,
  recipient account/region, immutable resource ARN, algorithm, message type and
  request/event IDs. Digest/signature absent; unexpected digest fields cannot
  upgrade the source. LookupEvents coverage reports its 90-day retention boundary.
  No native completeness frontier is fabricated from pagination.
- GCP: exact documented `AsymmetricSign`, scoped Data Access log, full version,
  principal and timestamp; canonical padded base64 SHA-256 decoded to 32 bytes.
  Event identity incorporates timestamp plus insertId within the log scope.
  Missing digest remains metadata-only. Unknown method spelling/encoding refuses;
  absent status stays unknown. Algorithm provenance comes from a separately
  trusted, same-version GetPublicKey export, not from the digest algorithm or gate.
- PKCS#11: no portable audit-read schema is invented. The normalizer refuses;
  unavailable coverage is explicit and metadata-only. Device/vendor evidence is
  required before adding a real mapping.

These are documentation-validated normalizers with synthetic provider-shaped
fixtures, not redacted captures from a deployed adapter. See
[design §6](../authorization-record.md#6-audit-source-port-and-real-source-feasibility)
for primary-source links and the
[runnable/offline plus deployment acceptance checklist](../audit-source-acceptance.md).
The copied-correlation-alias test preserves the attacker's different digest;
it does not implement checkpoint 3's matcher or claim a live adapter passed.

Explicit refinements of the approved design: nanosecond interval encoding;
GCP algorithm pinned from separate key-version evidence; compound GCP event
identity; absent status conservatively unknown. No missing provider evidence is
filled from the gate. No design claim was silently upgraded into a guarantee.

## 5. Tests and executed revert evidence

**99 source tests; 171 combined 2a/2b tests pass locally, zero skips.**
The suite covers every requested input property: metadata absence despite a
durable matching gate row; observed provenance; all/omitted/empty continuation
pages; retention/gaps; same-ID deduplication versus different Sign calls; conflict
unusability; delayed completeness; immutable read-only capabilities; controls-both
erasure; AWS/PKCS#11 limits; malformed rows; bounds; scope/method/encoding failures.

`python scripts/f11_source_revert_proofs.py` executes these mutations in memory,
restores the original code after each, and requires JUnit call-phase failures
with zero setup/collection errors or skips. No repository source is rewritten.

| Removed/corrupted guard | Test selection that went red | Failures |
|---|---|---:|
| Observed-only digest provenance | `digest_provenance_cannot` | 1 |
| Metadata-only model storage | `profiles_observed_digest` | 1 |
| Metadata model digest-injection refusal | `administrator_digest_injection` | 1 |
| Page exhaustion distinct from attestation | `every_page_is_not` | 1 |
| Page ordinal continuity | `omitted_page_is_incomplete` | 3 |
| Conflicting duplicate rejection | `conflicting_duplicate_payload` | 1 |
| Deduplication by source ID | `duplicates_collapse` | 1 |
| Pending delivery frontier | `delayed_delivery_limits` | 1 |
| Explicit coverage-gap reporting | `retention_boundary_and_reported_gap` | 1 |
| Malformed row retained as failure | `malformed_row_is_retained` | 1 |
| Aggregate response-byte limit | `response_limits_preserve` | 1 |
| AWS absent digest | `aws_mapping_is_metadata` | 1 |
| GCP base64, not hex | `gcp_base64_digest` | 1 |
| GCP known method spelling | `gcp_unknown_method` | 5 |
| No invented controls-both tombstone | `administrator_controls_both_residual` | 1 |

Total: **15 reverts caught, 21 call-phase failures, zero errors/skips**.

## 6. CI, suite and publication evidence

CI runs Python 3.10, 3.11 and 3.12 on Linux. The existing JUnit gate now names
both persistence and source files and requires each to contribute cases, then
rejects every skip/failure/error. The 15 revert proofs also run as a mandatory
step. Existing mandatory PostgreSQL, namespaces, cross-user denial, Hearth,
full-suite and package-build checks remain in place. A local pass is not a Linux
pass: the PR's exact-head check runs and final publication report provide the
Linux results, not an assertion based on this local report.

Type checking covers all three new modules (18 checked files total). Ruff,
repository hygiene, package build and IP consistency pass. Final local full
suite: **1,276 passed, 64 failed, 94 skipped, one warning**. The 64 failure names
match the previous baseline; no new failures. These Darwin substrate/ownership
and existing platform limitations are not a green Linux claim and are not
suppressed. The PR report records exact-head Linux CI links and suite results.

Pinned Voidguard `d371f9cd18eb880b3e49336134c476136ee515d2` reports **0 VOID,
3 WARN, 2 UNKNOWN**: existing PostgreSQL service environment-consumer warnings
and static skip/scheduled-run-history uncertainty. This is zero decisive VOID
findings, not zero findings or complete assurance. No baseline/suppression added.
The workflow now includes the source changes and blocks VOID findings, while
retaining the visible report and scanner-error failure.

The maintainer explicitly authorized the GitHub connector's default identity
for this PR after local Git push authentication was unavailable. Local commits
retain `DriivAIDev <will@driivai.com>`. Publication must verify the uploaded tree
matches the tested snapshot and the remote commit message has no added footer
or trailers. Do not auto-merge or begin checkpoint 3.
