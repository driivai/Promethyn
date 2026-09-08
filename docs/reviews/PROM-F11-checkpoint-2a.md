# PROM-F11 — checkpoint 2a: persistence review

This checkpoint stops at the persistence boundary. **F11 is still open:** no
KMS audit-source port/model, operational reconciler or detection verdict is
implemented here. The full local suite is not green, and publication is blocked
by Git authentication. These are not hidden behind passing focused tests.

Baseline: main `3c27cc1dd97f363e85c61555f65d70d533a6d3a2`. Branch:
`codex/authorization-record-design-f11`. Checkpoint 1 was approved before code.

## 1. Design

[Authorization record design](../authorization-record.md) retains the limits
first, pinned schema/encoding, state machine and four-outcome reconciliation
design. Its section 8 identifies implemented code versus future requirements.
This is retrospective evidence, not prevention of Sign-invoke abuse, proof of
honest policy decisions, or atomicity across SQLite, anchor, KMS and PostgreSQL.

## 2. Production wiring and proofs

`build_migration_runtime` now requires a private file-backed ledger and trusted
`AuthorizationContext`. `RecordedApprovalAuthority.authorize` writes a durable
decision through `AuthorizationJournal` before its Sign call and a separate
result before returning an approval. Direct production `mint` refuses. The
primitive signer/low-level authority remains available for verification and
explicit invoke-holder adversarial cases; it is not the production gate.

Decisions and results are `audit_chain` events under the existing chain and
configured anchor. Per-operation journal connections use `BEGIN IMMEDIATE`,
`synchronous=FULL`, readback, integrity/anchor confirmation and directory fsync.
Duplicate decision/request IDs and nonces are rejected. A configured anchor
failure is a refusal even if SQLite already committed. Existing insecure ledger
permissions are refused, not silently changed. Signed results contain bearer
approvals and must stay in private trusted-zone storage.

The load-bearing tests in `tests/chokepoint/test_authorization_record.py` are:

- `test_runtime_records_before_sign`: the model KMS opens the actual disk file
  during Sign and recomputes its requested digest from the already committed
  decision. Execution intent/outcome bindings independently reproduce it too.
- `test_digest_recomputed_from_disk`: close the runtime/ledger, launch a fresh
  interpreter with only the SQLite path, reconstruct from persisted fields,
  and compare with `approval_digest(live_approval)` computed before shutdown.
- `test_record_failure_stops_real_runtime`: failed writes, invalid receipts and
  post-commit errors produce zero KMS invocations, no approval, no executor call.
- `test_record_failure_leaves_database_untouched_with_positive_control`: an
  actual temporary SQLite database remains unchanged on failure; the same
  executor inserts a row when authorization and execution succeed. This is a
  port-boundary proof, not a live PostgreSQL proof.
- Process termination after append, four-process issuance, threaded issuance,
  durable refusals, permission/principal changes, lost Sign responses, expired
  intervals and failed sign-result writes are exercised without skips.
- Recovery retains valid binding evidence, refuses malformed or substituted
  artifact/target/nonce bindings, and labels absent legacy binding as null.
  Signed authorization never turns an UNKNOWN database outcome into success.

Each authority is bound to one trusted requester context; context is an input,
not authentication. Real provider identity mapping remains deployment/adapter
work. The journal verifies full history on each operation, so cost grows with
history; an expired interval refuses rather than bypassing evidence checks.
Issuance uses independent connections across threads/processes. The caller-owned
generic `SqliteLedger` used by the execution runner retains SQLite's thread
affinity: construct execution runner/ledger pairs in their owning worker.

## 3. Audit-source port and mapping

Deferred to checkpoint 2b. The approved design's source mapping remains:
AWS CloudTrail Sign does not expose the signed digest; GCP documents
`protoPayload.request.digest.sha256`; PKCS#11 audit access/fields are
vendor-specific. Key/caller/time proximity is not a digest match. No SDK,
real-source adapter or audit coverage/settling model was added in 2a.

## 4. Reconciler and revert evidence

Deferred to checkpoint 3: MATCHED / UNWITNESSED / UNEXPLAINED / INDETERMINATE,
settling/coverage, invoke-only forgery detection and controls-both residual.
The existing set helpers do not become an operational control at this checkpoint.

Fourteen deliberate in-memory source regressions were tested in separate
interpreters, without changing repository files or Git history. Every one
produced the named test's call-phase failures (25 total), with zero setup errors
or skips. These are executed mutation checks, not merely proposed revert names:

| Removed/regressed guard | Test that failed | Failing cases |
|---|---|---:|
| Sign before decision append | `test_runtime_records_before_sign` | 1 |
| Return refusal without append | `test_runtime_persists_refusals` | 3 |
| Swallow append error and supply fake receipt | `test_record_failure_stops_real_runtime` | 4 |
| Drop required signed-result write | `test_signed_result_failure_withholds_approval` | 1 |
| Drop decision uniqueness | `test_duplicate_decision_is_never_resigned` | 1 |
| Ignore expiry after append | `test_expiry_during_recording_never_signs` | 1 |
| Drop record length prefixes | `test_authorization_record_encoding_vectors` | 1 |
| Trust stored digest without recomputation | `test_invalid_record_fields_are_rejected` | 1 |
| Skip result semantic validation | `test_loader_rejects_invalid_results_even_in_a_valid_chain` | 4 |
| Skip permission recheck | `test_permission_change_refuses_before_sign` | 1 |
| Omit runner binding evidence | `test_runtime_records_before_sign` | 1 |
| Skip post-append caller identity check | `test_principal_change_after_record_blocks_sign` | 1 |
| Accept any recovered binding | `test_recovery_preserves_binding_or_refuses_invalid_evidence` | 4 |
| Ignore required external anchor | `test_production_requirements_cannot_be_silently_dropped` | 1 |

## 5. Documentation

`key-custody.md` and `threat-model.md` now distinguish existing durable
persistence from still-unimplemented reconciliation; neither closes F11. The
demo uses the real production authority/private ledger, no longer dumps bearer
payloads, and illustrates tampering on copied rows instead of corrupting its
durable history. Its synthetic policy PASS/local HMAC limits are explicit.

## 6. Validation and publication

Local Python 3.12/macOS results:

| Check | Observed result |
|---|---|
| New persistence proofs | 71 passed, zero skipped |
| Focused persistence/custody/durability/substrate suite | 198 passed, zero skipped |
| Full suite | 1,176 passed, 64 failed, 94 skipped; one warning |
| Failure comparison with pinned baseline | No newly failing tests; 13 old fixture failures now pass with explicit macOS substrate opt-out |
| Mypy gate | 15 source files passed, including all three new production modules |
| Ruff | All five new production/test/helper files passed |
| Build, hygiene and IP consistency | Passed |
| Pinned Voidguard dogfood | 0 VOID, 3 WARN, 2 UNKNOWN; no suppressions added |
| Hosted CI / PR | Not run / not opened: Git authentication unavailable |

The full suite was run with `PROM_SANDBOX=unsafe PROM_ALLOW_UNSAFE_EXEC=1`, as
on the baseline; it is not an isolation proof. Of the 64 failures, 55 directly
refuse the unsupported Darwin substrate, three concurrency fixtures cannot
start their owners for that reason, and six are existing platform/unsafe-mode
failures. No production guards were relaxed. The focused persistence fixtures
explicitly opt out on macOS only; Linux CI uses the real substrate probe.
Linux namespaces and live PostgreSQL remain unproven locally.

CI now runs this entire new persistence file separately on Python 3.10/3.11/3.12
and rejects an empty test list or any skip/failure/error in its JUnit output.
The full suite also collects it. This config has not been validated by a hosted
run yet. Existing live PostgreSQL and sandbox requirements remain in place.

Voidguard was run on a clean staged-tree export using its existing CI pin
`d371f9cd18eb880b3e49336134c476136ee515d2`. Its three warnings are the pre-existing
PostgreSQL service variables (the static consumer model does not see the
container); unknowns are aggregated capability skips and scheduled-run history.
These results are unchanged, not a claim of warning-free scanning. Its existing
report-only/path-filtered workflow is not evidence of a passing F11 CI run.

HTTPS Git has no configured credentials. A strict SSH check against GitHub's
published host key also returned `Permission denied (publickey)`. No remote
branch or PR was created. Publication must preserve the requested author and
committer, `DriivAIDev <will@driivai.com>`, without trailers or injected footer.
Stop here for checkpoint 2a review; do not implement 2b or merge anything.
