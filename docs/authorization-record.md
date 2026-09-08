# Durable authorization records and KMS reconciliation — PROM-F11

Status: **checkpoint 3 operational reconciler implemented; awaiting exact-head
Linux CI and maintainer acceptance. F11's missing-control implementation is
complete, not a claim of deployed cloud/HSM acceptance.**
Baseline: `main` at `3c27cc1dd97f363e85c61555f65d70d533a6d3a2`.
Checkpoint 2b is based on merged `main` at
`2ba1d46807b91849d0e8d86ddfd68b2b68b29407`. Checkpoint 3 is based on merged 2b
`353a8081bb5d4fe00390db5305bd6ec8023ef106`.
Below, “must” specifies the full sprint acceptance requirement; sections 6 and
8 distinguish implemented boundaries from the remaining design.

## 1. Honest limits first

This is retrospective evidence, not prevention. An insider holding Sign-invoke
can still obtain a valid signature. Detection requires two independently
trustworthy inputs: the gate's authorization history and the signing service's
history. The auditor and its pinned key/scope configuration must also be outside
the compromised host's control.

- If the insider can also delete or replace the signing history and its coverage
  evidence, an unauthorized signature can disappear. A passing residual test must
  demonstrate that this adversary is **not detected**, not manufacture a gap
  indicator the real adversary would remove. Independently retained witnesses
  can narrow that residual; this design does not assume an extra witness.
- A valid hash chain proves consistency with its anchors, not that a gate made
  an honest decision. An insider who can append a false `authorised` decision
  before invoking Sign can create matching histories. Reconciliation does not
  re-run verification, authenticate a human's intent, or cure a compromised gate.
- Coverage is explicit: exact provider/account/project/device, region, immutable
  key resource/version, principals and time interval. Other keys, out-of-scope
  signatures and expired retention are not covered. Do not filter out an unknown
  caller using an in-scope key: that is the principal attack being sought.
- Local HMAC has no independent KMS witness. It must report
  `INDETERMINATE / no_independent_sign_source`, never a clean external-signing
  result. A model passing CI is not evidence of a deployed cloud adapter.
- **AWS CloudTrail alone does not expose the signed digest in its documented
  Sign event.** A key/caller/time match is not a digest match. GCP documents a
  digest-bearing audit field; PKCS#11 does not standardize an audit-read API.
  Section 6 pins these distinctions. A missing field must remain missing, not
  be filled from the very gate record being checked.
- `MATCHED` means a signing event has an eligible, binding-consistent gate
  explanation. It does not prove delivery of an approval, single-use execution,
  a database commit, absence of other attacks, or complete coverage elsewhere.

The gate history uses the existing ledger chain and external anchor. Their
limits remain those in [ledger integrity](ledger-integrity.md): an ordinary
directory named WORM is not inherently immutable, anchoring follows the local
commit, and control of both storage and witness defeats tamper evidence.

## 2. Current implementation and intended production boundary

At the pinned baseline:

- `chokepoint/approval.py::ApprovalAuthority.authorize` accepts an authoritative
  PASS, then `mint` generates the nonce/times and immediately signs. Refusals
  return `None`. Neither path writes an authorization record.
- `approval_digest` hashes the v2 canonical binding. The v3 envelope also names
  scheme/key; those names are checked by `verify`, but are **not** fields in the
  v2 signature preimage. Preserve that distinction.
- `runner.py::build_migration_runtime` exposes a shared `runtime.authority` and
  runner. Its authority has no audit dependency. The shipped demo calls that
  authority; there is no production call to the digest/reconciliation helpers.
- The runner consumes a nonce and writes `execute_intent` before execution.
  Its events do not persist issuance/expiry. `MemoryKms.sign_log` is an immediate,
  digest-bearing model log; the existing set-based helpers have no coverage or
  settling semantics. They are not the proposed operational reconciler.

Checkpoint 2 must wire durable issuance into the authority built by
`build_migration_runtime`, not merely add a parallel helper. `authorize` must
record both decisions. Its minting helper must accept only the durable decision
it just wrote; public low-level `mint` must not be an unrecorded issuance path
on this production authority. Verify-only use must remain credential-free.
The primitive KMS Sign operation remains available to invoke holders: bypassing
the gate through it is the explicit adversarial test, not a hidden fallback.

Use the gate's file-backed `SqliteLedger.audit_chain`, via `record_chained`,
for decisions and append-only lifecycle events; do not use the consumed-nonce
table as the authorization source of truth. That table remains replay state.
Require a durability-capable sink for issuance, including refusal recording.
The protected production posture requires the existing external append-only
anchor requirement as well as external signing; an in-memory/no-anchor fixture
does not establish the insider property.

A successful append receipt must identify the ledger, sequence and entry hash.
Durable means the transaction committed on the supported substrate with the
required synchronous policy and the configured anchor acknowledged it. An
exception, malformed receipt or anchor failure means **no Sign and no approval**,
even if the SQLite row committed before the error. The caller must not recover
by silently selecting a different sink. Concurrent writers must not share an
unsafe SQLite connection or race into two signing attempts for one decision.

## 3. Record schema and pinned encoding

### 3.1 Immutable authorization decision, version 1

One `authorization_decision` event per evaluation. `subject` is the lowercase
hex authorization ID. The payload contains the fields below and
`authorization_record_hash`. It contains no SQL, password, DSN, token, private
key, raw authentication assertion or free-form exception text.

`?` means a tagged optional field, not omission from the schema. Every
`authorised` record must have every optional field present. A refusal retains
every safely validated field available; invalid/missing input is null, never a
fabricated hash, target, identity or timestamp. It has no signature and cannot
explain a successful Sign, even if its candidate digest happens to match.

| Order | Field | Exact content |
|---|---|---|
| 1 | `record_version` | Unsigned integer `1`. |
| 2 | `authorization_id` | Fresh 16 random bytes; record identifier, not an approval nonce. |
| 3 | `request_id` | Fresh gate-generated 16-byte evaluation ID; caller labels cannot replace it. |
| 4 | `recorded_at` | Finite UTC epoch seconds, encoded as the float-hex text below. |
| 5 | `requester` | Ordered `(identity_source, issuer, subject)`. Source is `local_os`, `authenticated_service`, or `unknown`. |
| 6 | `gate_identity` | Stable non-secret deployment/issuer identity, from trusted configuration. |
| 7 | `policy_sha256` | 32-byte digest of the pinned policy/verification configuration used for this decision. |
| 8 | `decision` | Exactly `authorised` or `refused`. |
| 9 | `reason` | Stable allowlisted reason code, not a traceback or caller-supplied justification. |
| 10 | `artifact_sha256?` | 32 bytes, SHA-256 of the exact immutable UTF-8 artifact bytes. |
| 11 | `target?` | Ordered `(host, port, database, user, schema)`; full credential-independent `MigrationTarget`. |
| 12 | `nonce?` | 16 random bytes; same nonce as the approval. |
| 13 | `issued_at?` | Exact approval issuance float, not a rounded display timestamp. |
| 14 | `expires_at?` | Exact approval expiry float. |
| 15 | `approval_version?` | Integer `3` for the current envelope. |
| 16 | `binding_version?` | Integer `2` for the current signature preimage. |
| 17 | `scheme?` | Current approval scheme identifier. |
| 18 | `approval_key_id?` | Exact key identifier accepted by the existing approval verifier. |
| 19 | `signer?` | Ordered `(backend, scope, key_resource, public_key_sha256, caller_issuer, caller_subject)`. |
| 20 | `approval_digest?` | 32 bytes, SHA-256 of the v2 approval preimage. |
| 21 | `approval_preimage?` | Exact canonical bytes sent to `ApprovalSigner.sign`, before hashing for KMS. |

For `requester`, trusted entry-point code supplies identity, not the proposed
artifact or agent environment. `local_os` identifies the actual OS principal
with its host identity; `authenticated_service` identifies the authenticated
issuer and subject. `unknown` requires empty issuer/subject and a refusal.
Neither local OS identity nor an application assertion proves a human identity
against root. The requester is distinct from the database user and from the KMS
service credential, which often represents many requesters.

`signer.backend` is `model`, `aws-kms`, `gcp-kms`, `pkcs11`, or `local-hmac`.
`scope` identifies the exact KMS security domain. `key_resource` is the resolved
immutable key ARN, full CryptoKeyVersion, or device identity plus stable object
ID; never only a mutable alias or ephemeral PKCS#11 handle.
`public_key_sha256` is SHA-256 of the pinned SPKI DER, optional only for HMAC.
Caller fields identify the credential expected to invoke Sign, not a string
supplied to persuade a real adapter to impersonate someone. Resolve this mapping
before persisting the decision; refuse an unresolvable or changed mapping.

The current envelope limits `key_id` to 128 printable ASCII characters. Keep
`approval_key_id` separate from the potentially longer provider resource and
pin a one-to-one mapping for its lifetime. Do not truncate provider identifiers
or silently change envelope validation in this sprint. The mapping, public key
and old key versions must remain available to the independent auditor.

Reason codes initially cover `authoritative_pass`, `verdict_fail`,
`verifier_unavailable`, `non_authoritative`, `invalid_request`,
`requester_unavailable`, and `security_configuration_unavailable`.
`authoritative_pass` is the only authorised reason. Failure to record a decision
is a separate operational error, not a durably recorded refusal. If policy or
gate identity cannot be established at all, startup refuses before evaluation;
an error log is not a substitute authorization record.

### 3.2 Deterministic byte representation

The record hash uses a new domain; the existing approval binding is unchanged:

```text
lp(b) = u64_be(number_of_bytes(b)) || b
optional(null) = 0x00
optional(value) = 0x01 || lp(encode(value))
record_bytes = b"promethyn-authorization-record-v1\x00"
               || lp(encode(field_1)) || ... || lp(encode(field_21))
authorization_record_hash = SHA256(record_bytes)
```

Each fixed-schema tuple uses `lp(encode(member))` in its stated order. Optional
fields include their tag inside the outer field length. Required unsigned
integers are exactly eight big-endian bytes, booleans rejected. IDs and digests
are their fixed-length raw bytes. Text is strict UTF-8, with no trimming, case
folding, Unicode normalization or implicit conversion. Decode rejects unknown
versions/fields, missing fields, duplicate keys, noncanonical encodings, invalid
lengths, trailing bytes and invalid UTF-8. Distinct byte strings remain distinct.

Times use the ASCII output of Python binary64 `float.hex()` after strict finite
numeric validation (reject bool). Readers require `float.fromhex(s).hex() == s`;
thus the exact bits, including signed zero, survive restart. Approval validity
still requires `expires_at > issued_at`; production issuance requires positive,
finite TTL and refuses addition overflow or rounding that yields no increase.
Do not convert these values through integer seconds or an ISO display string.
Target validation is exactly `MigrationTarget`; port is an integer 1–65535.

In JSON storage, bytes are lowercase hex of the exact required size; times are
float-hex strings; tuple members are named fields with an exact allowed key set.
All text fields are bounded at 4096 UTF-8 bytes, subject to narrower existing
envelope constraints; the full record/preimage is bounded at 64 KiB. Reject
oversize inputs, do not truncate them into different valid identities. Malformed
request details may be omitted from a refused record; raw content is not logged.

The v2 approval preimage is explicitly pinned to existing `approval.py::_canonical`:

```text
b"promethyn-approval-v2\x00"
|| lp(ASCII(lowercase_artifact_sha256_hex))
|| lp(ASCII(target.canonical))
|| lp(ASCII(lowercase_nonce_hex))
|| lp(ASCII(issued_at.hex()))
|| lp(ASCII(expires_at.hex()))
```

`target.canonical` has exactly database/host/port/schema/user, with the existing
`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)` encoding.
The loader recomputes this preimage from the structured fields, requires byte
equality with stored `approval_preimage`, then recomputes `approval_digest` and
`authorization_record_hash`. A stored digest is not trusted as an assertion.
The extra requester, decision, scheme and signer metadata are committed by the
authorization record hash/ledger chain, **not added to the v2 KMS signature**.

The ledger retains its existing outer preimage and commits to the exact stored
payload bytes. Verification must check that chain and its external history
before decoding these typed records. Duplicate IDs, conflicting nonce bindings,
invalid projections or unanchored evidence are not eligible explanations.
Changing either encoding requires a new version and pinned test vectors, not
an opportunistic reserialization of old records.

### 3.3 Sign and execution evidence are later immutable events

The decision contains enough to reconstruct the unsigned approval; a signature
cannot exist before Sign. Append `authorization_sign_result` afterwards, never
update the decision. Its v1 payload has the authorization ID/hash, observed time,
state (`signed`, `denied`, `unavailable`, `outcome_unknown`, `malformed`), safe
reason, optional provider request/event ID, and the exact v3 signed envelope
only for a locally verified signature. Persist this result before releasing the
approval. An append failure withholds it; it cannot undo a completed KMS call.
The result is chained using the existing ledger encoding, with strict schema
and bounded fields. Its envelope must reconstruct the decision's exact binding.

One decision permits **one outbound Sign attempt**. No automatic SDK retry or
restart re-signing: an uncertain send may already have signed. A fresh attempt
requires a fresh decision and nonce. Atomic ownership of the issuance attempt
must prevent concurrent callers from both signing one decision. Duplicate audit
deliveries are deduplicated by stable source event ID, never by digest alone.

Runner intent, refusal and outcome evidence must carry either a validated
`(ledger_id, authorization_id, authorization_record_hash)` reference or the full
reconstructable approval binding. A split verify-only runner retains the full
binding and any supplied reference as **untrusted until resolved** against the
gate ledger. It must not invent an authorised decision for an imported approval.
F11 does not turn missing gate history into a new execution authorization rule:
the invoke-only forgery residual still exists and must be observable in tests.

`execution_id` and F2's receipt remain separate from authorization ID, nonce and
provider event ID. KMS reconciliation never completes an execution intent or
releases a consumed nonce. A persisted signed envelope is itself a bearer
capability until expiry: keep it in trusted-zone storage, out of routine logs
and reports, even though it contains no signing key or database password.

## 4. State machine and failure windows

Normal sequence is **evaluate → durable decision/anchor → one Sign → verified
signature → durable sign result → release approval → existing runner protocol**.
No database access occurs on the issuance path.

| State / transition | Durable evidence and allowed next action | Auditor may conclude / must not conclude |
|---|---|---|
| Evaluation started; crash before any append | Possibly no record. No Sign or approval. | No durable decision observed; absence does not prove “never asked.” |
| Evaluation refused → refusal appended | `refused` plus reason; return refusal, never Sign. | Asked and denied. Not a signed approval, and not UNWITNESSED merely for having no signature. |
| Decision append/anchor fails | Row may be absent, or committed but unanchored; surface audit-unavailable, stop. | Storage/witness failure; not a successful refusal record or authorization receipt. No Sign may follow. |
| Authorised decision durable; crash before Sign | Unsigned binding remains; do not re-sign it on restart. | After settling/coverage checks: UNWITNESSED, possible pre-Sign crash; **not forgery**. |
| Decision durable; KMS demonstrably unreachable before send | Append unavailable result if possible; `SignerUnavailable`, no approval. | No approval issued. A generic timeout alone cannot prove the request never arrived. |
| Sign sent; reply lost / process crashes | Decision remains; KMS might have signed; append outcome-unknown if alive. No approval returned and no automatic retry. | Successful matching KMS event can yield MATCHED; no event can yield UNWITNESSED only with mature coverage. Neither proves database state. |
| KMS denies Sign | Decision plus denied sign result; `SignerDenied`, no approval. | A failed signing attempt, not a forged signature. Keep denied-event diagnostics distinct from successful-sign alerts. |
| KMS replies with malformed or wrong-key signature | Record malformed result if possible; `SignerMalformed`, no approval. | KMS may record success even though this response was rejected locally; matching proves the request, not approval issuance. |
| Signature verified; crash or result append/anchor fails | Durable decision explains KMS success; signed-result evidence may be missing. Withhold approval. | MATCHED is possible without a persisted signature; do not infer release/execution. |
| Signed result durable; no execution attempted | Signed envelope available; caller may execute only before expiry under all existing runner checks. | Signing/issuance evidence, not a database commit. Crash before delivery leaves delivery unknown. |
| Runner rejects signature/binding/expiry, replay, unavailable store or ownership | Existing runner refusal with binding/reference; no new execution. | A signed action was refused; rejection does not remove its gate/KMS history. |
| Nonce consumed; execution intent append/anchor fails | Nonce remains spent; no executor call. | Approval cannot be retried as fresh; do not infer SQL ran. |
| Execution intent durable; crash before/during database call | Pending intent, existing owner guard and receipt protocol apply. | Database state remains unknown until F2 proves it. A Sign record is not a commit receipt. |
| Executor proves committed / not committed | Append the corresponding terminal outcome; if append fails the intent remains pending on disk. | Distinguish acknowledged evidence from what may have happened; preserve receipt-based recovery. |
| Executor outcome UNKNOWN or lost COMMIT reply | Append nonterminal `execution_unknown` if possible; keep intent pending, nonce spent. | Signing may be MATCHED while execution is UNKNOWN. Never label UNKNOWN rollback or resubmit SQL from this reconciler. |
| Recovery proves committed / not committed | Under existing F2/F3 ownership constraints, append terminal evidence. Unverifiable owner/receipt stays pending. | Only that recovery proof resolves execution; authorization expiry does not resolve it. |

Every append can fail before commit, after commit, or after anchoring but before
acknowledgement. No caller treats an exception as a successful durable receipt.
Recovery validates existing evidence; it never erases an event to retry the same
nonce. There is no atomic transaction spanning gate storage, KMS and PostgreSQL.
Refusals must be durable before a normal refusal is returned; total storage
failure or a crash before the first append cannot be made traceable by that same
failed storage. Surface this limit instead of claiming every attempted request
is necessarily recoverable.

## 5. Reconciliation semantics

### 5.1 Inputs, coverage and settling

Read independent snapshots of verified gate history and signing history. Request
a half-open UTC interval `[start, end)` and pinned key scope. Complete gate
decisions must be available for every sign event, including decisions preceding
`start`; read lookback/history and verify references, not just timestamp-filtered
rows. Similarly, extend the source read to cover each selected decision's
possible signing interval. Inability to establish either side's completeness
is INDETERMINATE, including retention boundaries and legacy pre-F11 records.

Configuration pins `settle_seconds` (proposed default **900 seconds**, an
operator policy, not a cloud delivery guarantee), `max_clock_skew_seconds`,
bounded Sign attempt duration and record TTL. Durations must be finite,
non-boolean and non-negative; settling and the Sign deadline must be positive.
A production profile must supply a justified clock-skew bound; unknown clock
quality is INDETERMINATE. The model uses an explicit fake clock and bound.

The gate must start Sign only while the decision is unexpired. For absence
checks, use a conservative interval from issuance minus clock skew through
expiry plus the bounded Sign duration plus clock skew. A crash with no send
timestamp does not shrink this interval. It becomes settled only after its
upper bound plus `settle_seconds`. Visible events use their service timestamp;
`observed_at`/delivery time is separate. Signed-at times outside the permitted
interval do not acquire legitimacy just because a digest matches.

Inside settling, missing evidence is `INDETERMINATE / settling`, with
`retry_after`, not UNWITNESSED or clean. After settling, missing evidence can be
UNWITNESSED **only** if the source attests complete coverage of the required
interval with no gaps. An elapsed timer is not a completeness certificate.
Reported lag, missing pages, disabled logging, exclusions, unknown retention or
an unreadable source remain INDETERMINATE however long the operator waits.

An audit-source response must state scope, requested/covered intervals,
`complete_through`, gaps, observation time and capability (`digest_bound` or
`metadata_only`). A model may know completeness exactly; a real adapter must
explain its evidence for that assertion. Pagination exhaustion alone does not
prove that asynchronously delivered events have all arrived. Positive pairs
inside an incomplete requested range may be retained as evidence but the
range and affected records must not be reported MATCHED. An empty complete
range is reported as such with counts, not as a fabricated matched event.

### 5.2 Four outcomes and matching rules

| Outcome | Definition | Meaning |
|---|---|---|
| `MATCHED` | Valid authorised record plus successful, independently digest-bound signing event; scope/key/version, digest, caller, algorithm and admissible time agree, with required coverage established. | An explained Sign operation, not a claim about database execution or policy correctness. |
| `UNWITNESSED` | Mature valid authorised record has no corresponding successful Sign event in complete, readable, adequately scoped evidence. | Pre-Sign crash, unavailable/denied signing, missing witness or other anomaly. **Not the forgery signal.** Attach lifecycle reason when known. |
| `UNEXPLAINED` | Successful in-scope, digest-bound Sign event has no eligible authorised record in complete trusted gate history, or contradicts its bindings. | Suspected unauthorized signing / forgery signal; investigate, do not automatically retry or revoke. |
| `INDETERMINATE` | Read/verification error, insufficient correlation, immature interval, unknown/gapped scope or coverage, malformed evidence, conflicting identity mapping or missing legacy history. | Could not reconcile. Never silently clean or MATCHED. |

Recompute digests from disk. Matching on key, time proximity, an arbitrary
caller-provided alias, or a locally asserted digest is prohibited. Refused
decisions cannot explain successful signs. A mismatched digest yields an
UNEXPLAINED sign plus, when its own checks permit, an UNWITNESSED decision.
Do not substitute a corrupt gate record's stored hash for recomputation: corrupt
history makes the gate input INDETERMINATE and separately reports integrity
failure. Missing post-Sign result alone is **not** an unexplained signature,
because record-then-sign deliberately allows that crash window.

Use one-to-one event accounting. One gate decision does not explain unlimited
distinct successful Sign events for the same digest. Extra events are
UNEXPLAINED (`excess_sign_attempts`); exact repeated deliveries of the same source
event ID are one event. Conflicting payloads under one source ID make the source
INDETERMINATE. Where same-digest events are indistinguishable, report the excess
count without claiming which request was malicious. Nonce uniqueness and the
no-retry rule make this enforceable for normal operation.

Denied KMS attempts are retained as diagnostics (`outcome=denied`,
`forgery_signal=false`), with an optional exact gate link. They do not satisfy
MATCHED for a successful signature and are not called forged approvals. Unknown
KMS outcomes stay INDETERMINATE. A gate refusal is reported as a decision, not
forced into the four successful-sign comparison categories.

The implemented `promethyn-reconcile` CLI emits versioned JSON containing scope, intervals, coverage,
settling policy, gate/source verification evidence, per-record status/reason,
counts, denied attempts and limitations. Never emit signed envelopes or secrets.
Any incomplete coverage forces a non-clean top-level result even if other
intervals produced useful findings; retain those findings. Exit zero only for
a fully checked range with no discrepancies or indeterminate rows; nonzero
also for UNWITNESSED (not a forgery label), UNEXPLAINED and INDETERMINATE.

### 5.3 Implemented checkpoint 3 boundary

`reconcile_gate.read_gate` performs one read-only SQLite transaction and reuses
the 2a decoder only after raw chain/full anchor-history verification. The
independent auditor supplies `GateCheckpoint`: lineage, exact tip, complete
history interval, observation and evidence reference. This makes the design's
gate-completeness requirement explicit: a valid chain or recent timestamp is
not a coverage certificate. No authority journal writer/schema initializer is
used for the read. Missing legacy execution bindings, an unanchored tail,
conflicting mappings and corrupt records refuse. All history is loaded, including
the pre-start lookback and sign-result references.

`reconciliation.reconcile` consumes that snapshot and the 2b `SignAuditSource`.
Exact rational conversion of gate floats rounds nanosecond intervals outward;
selected decisions extend the source query. The gate checkpoint must cover the
extended start minus `(max TTL + Sign duration + skew)` through extended end plus
skew. Maturity checks cover the requested range and decision windows, followed
by explicit source attestation/frontier/gap checks. Unaffected findings survive
partial coverage, but the top level stays non-clean. Digest-indexed candidates
still undergo exact binding checks and one-to-one accounting; stored digests,
aliases and local asserted provenance never replace observed source evidence.

The CLI consumes **independently authenticated offline exports** plus auditor
pins. SHA-256 transfer hashes are not signatures or source-completeness proofs.
The API can consume a deployed read adapter, but no live adapter or SDK is bundled
or claimed validated. This is a faithful implementation of §5, not a change to
its detection claim. [Operator configuration, JSON schema, exit codes and
deployment procedure](reconciliation.md) specify the additional trust boundary.
No execution/issuance protocol, approval encoding, or F2 recovery state is changed.

## 6. Audit-source port and real-source feasibility

Checkpoint 2b implements the read-only `read_sign_records(scope, start,
end)` port, returning normalized immutable events plus the coverage descriptor
above. Minimum event fields: stable source/event ID, immutable key resource,
authenticated caller, signing timestamp, outcome (`success`, `denied`, or
`unknown`), algorithm, digest and digest provenance. A missing digest is an
explicit absent value with `metadata_only` capability, **not** an adapter error
silently converted to an empty event list. Responses are bounded and all pages
must be consumed or the read is incomplete. Readers cannot mutate history.

The faithful CI model has separate signer, audit reader and audit administrator
capabilities, durable gate storage, controllable delivery delay, retention,
coverage gaps, duplicate deliveries and late/lost replies after successful
signing. An administrator adversary can delete/replace source history and its
coverage assertions. A signing-only adversary cannot. Include both digest-bearing
and metadata-only profiles: do not call a digest-rich model “CloudTrail”.

### Implemented 2b surface and limits

`chokepoint/audit_source.py` defines `SignAuditSource`, `PagedSignAuditSource`,
`SignEvent`, `DigestEvidence`, `Coverage` and `SignRead`. The page collector is
shared by the offline adapter composition and model. No production signer,
authority, execution runner, ledger format or approval format changes in 2b.
Checkpoint 2b alone has no reconciliation decision, gate-history join or CLI.
Checkpoint 3 now supplies those in the separate consumer described in §5.3;
there is still no SDK or validated live adapter.

Time is **integer UTC epoch nanoseconds** with half-open `[start, end)` intervals;
boolean, floating/non-finite, negative, reversed and oversized values refuse.
RFC3339 UTC `Z` timestamps retain all nine fractional digits. Checkpoint 3
converts gate timestamps conservatively and accounts for pinned clock uncertainty;
the 2b source itself does not infer those comparison windows.

`AuditScope` pins provider, independent source ID, account/project/device domain,
region and immutable key resource/version. There is deliberately no caller
filter: unfamiliar principals using the scoped key must remain in the input.
Events include this scope, stable event ID, authenticated caller, signing time,
outcome, algorithm and algorithm provenance. Digest evidence is either exactly
32 observed bytes plus source-field provenance, or `None / absent` with
`metadata_only` event capability. Inferred provenance is rejected. Request IDs
and message type, where available, are diagnostic fields, not digest substitutes.

Coverage includes scope, requested/covered interval (covered may be unknown),
complete-through frontier (may be unknown), explicit gaps, observation time,
capability, `completeness_evidence`, and `pages_exhausted`. Source capability is
an ability, not a promise that every event contains every field: a redacted GCP
digest remains metadata-only on that event. A metadata-only source may never
return any digest-bearing event.

`SignRead.state` is input completeness only: `complete`, `incomplete`, or
`unusable` for conflicting payloads sharing a source event ID. Complete requires
all pages, source-attested coverage of the entire interval, an adequate frontier,
no gaps and no issues. It is **not** a clean reconciliation result. In particular,
an empty complete model interval is not a fabricated matched event; a complete
metadata-only read still supplies no cryptographic correlation.

The collector validates page ordinal, snapshot, query scope and unchanged
coverage; detects missing pages/token loops; deduplicates exact event IDs but
not repeated digests; and records malformed rows as issues while preserving the
valid prefix. Unknown schema fields/methods, conflicting identities, oversized
responses and errors never become an empty successful read. Known non-binding
provider containers (for example caller context and routing metadata) are not
projected into digest/caller/algorithm evidence. Unsupported/redacted binding
fields refuse except the explicit absent-digest and unknown-outcome cases.

Defaults: 64 pages, 10,000 deliveries, 4 MiB total raw events, 64 KiB per event,
3-second absolute monotonic deadline. Hard ceilings constrain configurable
counts and sizes. Late page and normalization replies are rejected. The injected
page adapter must itself bound I/O, parsing and allocations and honor the
deadline: this synchronous collector cannot preempt a blocked adapter. There is
no bundled transport or claim of a live cloud timeout proof. Adapter-maintained
page ordinals are sequencing diagnostics, **not** an independent source witness.

`audit_source_model.py::MemorySignAudit` is a trusted harness factory. Only its
`ModelSigner` is given to a signing adversary; it cannot select a different
authenticated principal. `ModelAuditReader` exposes only the read operation.
`ModelAuditAdministrator` can replace/delete deliveries and independently replace
retention/gaps/frontier assertions. Returned events, nested evidence, coverage
and history snapshots are immutable. These Python capability surfaces model
remote permissions, not protection against Python introspection in one process.

The `gcp_shaped` profile is `model-gcp / digest_bound`; `cloudtrail_shaped` is
`model-cloudtrail / metadata_only`. Both create real P-256 signatures and retain
denied attempts. The metadata-only medium never puts a digest or signature in
its history, including when a corresponding gate decision exists on disk.
Fault controls cover delivery delay, late read/sign replies, successful Sign
with a lost reply, unavailable readers and omitted pages. Administrator methods
model retention, exclusions, duplicates, conflicts and arbitrary malformed raw
deliveries. The model can know its pending deliveries exactly; native clouds
are not credited with that model-only knowledge.

The controls-both proof deletes Sign history and replaces its coverage assertions,
then obtains a complete, empty, gap-free read. No tombstone is manufactured.
The old `MemoryKms.sign_log` and set-based helpers remain legacy primitives;
they are not this port and are not an operational reconciler.

Provider normalizers live in `audit_normalization.py`. Fixtures are documented
provider-shaped examples with synthetic identities, **not captured deployment
evidence**. The [real-adapter acceptance checklist](audit-source-acceptance.md)
separates runnable offline tests from mandatory future deployment validation.

### AWS KMS and CloudTrail

- Signing: `GetPublicKey(KeyId)` pins SPKI; `Sign(KeyId=<resolved ARN>,
  Message=<32 digest bytes>, MessageType=DIGEST,
  SigningAlgorithm=ECDSA_SHA_256)` returns DER signature. The Sign request has
  **no EncryptionContext or arbitrary request-alias parameter**. Do not misuse
  grant tokens or invent a field. [AWS Sign API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)
- Reading: `LookupEvents(StartTime, EndTime, LookupAttributes=[EventName=Sign],
  NextToken)` then decode `CloudTrailEvent`, validate service/scope, and paginate;
  retained archive reads require their own complete listing and validation.
  LookupEvents is regional and limited to the recent 90-day history.
  [CloudTrail LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)
- Available in the documented event: key, caller, event time, algorithm,
  message type, request ID and event ID. **Message/digest and signature are
  absent.** Native Sign events therefore remain metadata-only for this design.
  [CloudTrail Sign example](https://docs.aws.amazon.com/kms/latest/developerguide/ct-sign.html)
- KMS events can be excluded; denied cross-account requests have different
  account coverage from successful requests. Verify trail selection and both
  account scopes instead of assuming every denied attempt is visible.
  [KMS logging scope](https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html)

Implemented: `normalize_aws_event` accepts supported CloudTrailEvent JSON,
validates account/region and the immutable `resources[].ARN`, retains caller ARN
plus principal ID, and always supplies absent digest evidence. It supports the
pinned 1.08/1.09 schema and IAMUser/AssumedRole identities; unfamiliar versions
or identities produce explicit malformed input, not silently filtered rows.
Unexpected digest-bearing request/response fields cannot upgrade the capability.
`native_coverage` applies LookupEvents' 90-day retention boundary and never
turns page exhaustion into a complete-through attestation. Archive readers are
not implemented. Request aliases are never the authoritative key identity.

Design consequence: an AWS adapter cannot advertise binding-complete
reconciliation from native CloudTrail alone. A post-response request-ID link
from the gate neither independently proves the signed digest nor survives every
lost-response crash. A caller-controlled context string, if another service
offers one, can be copied while signing a different digest. Supporting AWS with
equivalent assurances needs separately reviewed, independently trusted evidence
binding the actual digest to the actual Sign operation, including bypass calls
and crash semantics. A host-local logging wrapper is not such a witness. Until
that evidence is available, report INDETERMINATE, not approximate MATCHED.

### Google Cloud KMS and Cloud Audit Logs

- Signing: `cryptoKeyVersions.getPublicKey(name=<immutable version>)` pins the
  public key; `asymmetricSign(name, digest={sha256: <base64 32 bytes>})` signs it.
  Check the signature and any supplied CRC32C integrity fields; CRC32C is not a
  cryptographic audit binding. [AsymmetricSign API](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign)
- Reading: Logging `entries.list(resourceNames, filter, pageToken)` filters the
  time range, `cloudkms.googleapis.com`, and the validated AsymmetricSign method
  names; consume every page. Normalize key resource, authenticationInfo,
  timestamp, status and stable log/event identity without inventing absent data.
  [Logging entries.list](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list)
- Google explicitly documents correlation using
  `protoPayload.request.digest.sha256` in KMS signing logs. This is a real
  digest-bearing mapping, not an inference from the API accepting a digest.
  Verify its exact encoding, key version and availability in the deployment's
  actual successful and denied events before enabling `digest_bound`.
  [Google's signing-log correlation procedure](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/verify-identity-issuance-usage)
- AsymmetricSign uses Data Access / DATA_READ logging. Enable that logging and
  inspect exemptions/routing/retention. The method-name formats and metadata
  evolve; unknown formats fail closed. The documented caller-provided-context
  location is not a license to assume arbitrary context binds the signed bytes.
  [KMS audit logging](https://docs.cloud.google.com/kms/docs/audit-logging)

Implemented: `normalize_gcp_event` accepts the documented `AsymmetricSign`
method spelling, full immutable version and exact Data Access log scope. It
represents source event identity as timestamp plus insertId within that scope,
following the [LogEntry identity contract](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry), rather than assuming insertId alone suffices. It
decodes `request.digest.sha256` as canonical padded standard base64 to 32 bytes,
not hex. Unknown spellings, versions or encodings refuse. Absent digest remains
explicit metadata-only evidence. Explicit status 0 means success, 7 denied,
other recognized codes unknown; absent status remains unknown conservatively.

Implementation detail exposed by normalization: the signing request's SHA-256
field does not establish the asymmetric key algorithm. A separate trusted
`GetPublicKey` export must pin `EC_SIGN_P256_SHA256` and the same immutable key
version. `GcpKeyVersion` retains that export's hash, and the event marks the
algorithm as pinned key-version evidence, not an observed request field. This
is an explicit refinement, not a fabricated audit field. The export is not
authenticated by this offline code; deployment must establish its provenance.
GCP retention remains unknown until separately supplied; native page responses
never assert complete-through. Caller context/aliases never contribute a digest.

Signature bytes and an approval authorization ID are not required audit fields
here; the digest plus independently established identity/coverage supplies the
join. If the digest, caller, outcome or version is absent/redacted on an event,
keep it insufficiently correlated instead of synthesizing a successful match.

### PKCS#11 / HSM

`C_GetAttributeValue(CKA_EC_POINT, CKA_EC_PARAMS)` supplies public-key material;
`C_SignInit(CKM_ECDSA, key_handle)` followed by `C_Sign(<digest>)` produces a
signature (convert the mechanism's raw `r || s` to DER). The handle is session
state, not a durable key identity. Pin device identity, stable key object ID and
public-key fingerprint. [Cryptoki signing interface](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html)

There is **no portable PKCS#11 audit-history read call** in that interface.
Reading Sign events is a vendor-specific audit export/API: event IDs, caller,
time, operation outcome, digest, retention, deletion permissions and delivery
semantics must each be established for the chosen device. Do not equate
`C_Sign` returning success with a durable digest-bearing audit event. Without
that vendor evidence, capability is unavailable/metadata-only and reconciliation
is INDETERMINATE. No cloud SDK or speculative vendor adapter ships in F11.

### Real-adapter acceptance procedure

For a dedicated test key and independent audit reader: sign two different known
digests concurrently under the same caller/key; perform a direct invoke-only
sign outside the gate; attempt a denied call; repeat a digest; lose a successful
response. Capture exact service fields and independently verify returned
signatures. Document base64/hex conversion and one-to-one event identity. The
adapter must recover the correct digests without copying values from gate
records. Test an attacker copying a legitimate correlation alias with a different
digest; it must never match. If that cannot be demonstrated, do not claim binding.

Then measure delivery latency, deliberately omit a page, exclude a logging
interval, cross the retention boundary and deny the reader. Each must remain
incomplete/INDETERMINATE, not an empty clean result. Verify permissions using both
invoke-only and audit-administrator credentials in the test environment. Archive
the redacted fixtures, scope configuration and coverage rationale so CI can
exercise faithful semantics. Revalidate after a service schema or policy change.

## 7. Remaining checkpoints and proof plan

This table preserves the original design's proposed proof labels. The executed
2a tests are named in §8; 2b uses `tests/chokepoint/test_audit_source.py`; actual
checkpoint-3 proof names and deliberate guard reversions are in
`tests/chokepoint/test_reconciliation.py` and `scripts/f11_reconcile_revert_proofs.py`.
All three files are required by the per-file no-empty/no-skip CI gate. See the
[checkpoint-3 report](reviews/PROM-F11-checkpoint-3.md) for observed results,
not the historical proposed names below.

| Required proof | Proposed test / what must go red when removed |
|---|---|
| Real runtime writes decisions before Sign | `test_runtime_records_before_sign`: remove production authority wiring or move append after Sign. |
| Disk-only digest reconstruction after restart | `test_digest_recomputed_from_disk`: drop issuance/expiry, change float encoding or trust the stored digest. |
| Refusals have durable reasons | `test_runtime_persists_refusals`: remove refusal append; include FAIL, unavailable and non-authoritative cases. |
| Write/anchor failure: zero Sign calls, no approval, no executor/DB mutation | `test_record_failure_stops_real_runtime`: bypass append failure through runtime authority and runner composition. |
| Normal batch, zero false unexplained events | `test_normal_batch_matches`: break any binding join or one-to-one accounting; include restart and concurrent issuance. |
| Invoke-only forgery is detected | `test_invoke_only_sign_is_unexplained`: omit the source-to-gate direction or accept refused decisions as explanations. |
| Crash after record before Sign is not forgery | `test_record_then_crash_is_unwitnessed`: reverse ordering or require a signed-result row as the only explanation. |
| Lost Sign response still has an explanation | `test_lost_sign_reply_has_durable_decision`: erase the pre-Sign evidence or assume timeout means no Sign. |
| Coverage/read/verification failure is distinct | `test_source_gap_is_indeterminate`: treat failed reads, pages, retention or malformed history as an empty log. |
| Settling before and after boundary | `test_settling_defers_unwitnessed`: remove maturity checks; after maturity require complete coverage as well. |
| Binding mismatch is never a proximity match | `test_digest_or_principal_mismatch_is_unexplained`: join by key/time/alias alone. |
| Canonical bytes are unambiguous | `test_authorization_record_encoding_vectors`: remove length prefixes, field validation or stable order; test delimiter/Unicode/null/float edge cases. |
| Retries/duplicates do not launder extra signatures | `test_distinct_sign_events_are_not_deduplicated_by_digest`: use digest sets or enable automatic Sign retry. |
| Native metadata-only source cannot claim MATCHED | `test_missing_digest_is_indeterminate`: populate missing digest from gate data or accept a request-ID assertion. |
| F2 UNKNOWN remains pending even when signing matches | `test_matched_sign_does_not_resolve_execution`: derive a database outcome from KMS evidence. |
| Controls-both residual is demonstrably NOT detected | `test_invoke_and_audit_control_is_not_detected`: remove unauthorized Sign history under administrator capability without leaving a synthetic gap; assert no forgery signal and document why. |

Checkpoint 2 delivers persistence, production wiring, disk/fail-closed proofs,
the source port/model and mapping validation; then stops for review.
Checkpoint 3 delivers the operational read-only CLI/reconciler, all proof and
named-revert evidence, and updates `key-custody.md` / `threat-model.md` to claims
traceable to implementation. Only then remove F11 from the open list, retaining
the native-source limitations and controls-both residual. Full-suite and
voidguard results must distinguish passing, skipped, unavailable and existing
findings; neither report-only scanning nor unavailable infrastructure means
“green.” Checkpoint 2 is split at the persistence boundary: stop at 2a before
implementing 2b, then stop at 2b before implementing 3.

## 8. Implemented checkpoint 2a boundary

`runner.build_migration_runtime` now requires an explicit `AuthorizationContext`
and a private file-backed `SqliteLedger`. It returns `RecordedApprovalAuthority`;
its public `mint` refuses. `authorize` snapshots trusted metadata, validates the
request, writes the decision through `AuthorizationJournal`, confirms a bound
append receipt, checks time and signer identity again, and only then calls Sign.
It writes a separate sign-result before returning the approval. Refusals return
normally only after their record is durable. A sink/anchor error stops issuance;
it does not authorize fallback to an unrecorded signer or alternate store.

Decisions and results live in `audit_chain`, not the consumed-nonce table.
Each journal operation opens a fresh connection, uses `BEGIN IMMEDIATE` for
uniqueness/append, requires SQLite `synchronous=FULL`, confirms the committed
row and chain, fsyncs the parent directory, and requires acknowledgment from
any configured anchor. An append receipt's `ledger_id` is the first chain
entry's hash (lineage identity, not a deployment name). The existing anchor
requirement is the OR of `settings.require_ledger_anchor` and
`PROM_REQUIRE_LEDGER_ANCHOR`; an ordinary file anchor cannot satisfy it.

Create new storage with `SqliteLedger.private(path, tip_anchor=...)`. Its parent
must be gate-owned and private (no group/other permissions); the file must be
gate-owned, regular, singly linked and private. The factory uses 0700/0600 for
new storage and refuses existing insecure paths without chmoding them. Journal
operations recheck permissions and inode identity. Signed results contain a
bearer signature until expiry: do not expose this database, backups or raw
payloads to the agent. The demo prints only event headers and tampers with a
copy for illustration, not its durable journal.

`AuthorizationContext` is trusted entry-point configuration, **not** proof that
authentication or policy evaluation occurred. Callers supply pinned policy,
gate, requester and resolved signer identities. The authority checks the
signer's scheme, key ID, public-key fingerprint and (for `KmsSigner`) configured
caller against that snapshot. Provider scope/resource mapping remains the real
adapter/deployment's responsibility; no cloud adapter or live identity probe is
claimed here. The aggregate context is limited to 16 KiB in JSON to leave room
for a bounded refusal. An oversized request is refused without truncating its
target into a different identity; unavailable binding fields become null.
An authority is scoped to that requester: do not share one requester context
between differently authenticated callers. Creating or changing a context is
the trusted application's responsibility, not an option given to the agent.

Runner intent, refusal and outcome events now include the unsigned full
`approval_binding`, including exact float-hex issuance/expiry. They can also
describe externally presented approvals: the runner does not fabricate a gate
authorization record for them. Recovery carries the binding forward; malformed
binding stops recovery, and legacy missing binding remains null, not invented
evidence. Signing success still does not turn F2 `execution_unknown` into a
database commit.

`AuthorizationJournal.records()` checks chain/anchor integrity and reconstructs
immutable decisions from disk. It rejects duplicate IDs/nonces, orphan or
duplicate results, invalid result ordering, timestamps or envelope bindings.
The stored digest and preimage must agree with recomputation from structured
fields. This is a writer-side checked loader (opens SQLite with schema support),
**not** the future read-only reconciliation CLI. Result-envelope parsing is not
independent signature verification or an audit-source MATCHED verdict.

Load-bearing proofs in `tests/chokepoint/test_authorization_record.py`:

- `test_runtime_records_before_sign` opens the actual SQLite file inside the
  model KMS Sign call and checks that the durable decision explains its digest;
  runner intent/outcome bindings independently reproduce that digest.
- `test_digest_recomputed_from_disk` closes the runtime and ledger, spawns a
  fresh interpreter with only the database path, and compares its reconstructed
  digest against `approval_digest(live_approval)` calculated before shutdown.
- `test_record_failure_stops_real_runtime` covers failed writes, false/wrong
  receipts and failure after local commit: zero KMS invocations, no approval,
  no executor call. The separate database positive-control test proves zero
  rows changed on failure and an actual row insertion on successful execution.
- Refusal, unavailable-verifier, invalid-expiry, oversized-request, anchor
  failure, lost-Sign-reply and failed-result tests distinguish every partial
  boundary without treating inability to record as a recorded refusal.
- Real process termination after the decision, four-process issuance and
  threaded issuance check persistent history. Permission and signer-principal
  changes are refused. Encoding vectors pin the record's domain, order,
  prefixes, Unicode distinction and exact times; malformed records fail closed.

The CI matrix has a dedicated persistence step that requires at least one test
and zero skipped/failed/error cases; all new proofs are also in the full suite.
These tests use an explicit unverified-substrate opt-out on macOS only; Linux
uses the real probe. This proves persistence behavior, not macOS isolation or
multi-host correctness. Each operation currently verifies the full history:
cost grows with ledger size and may exhaust a short approval interval. Refuse
on expiry; do not bypass verification. Indexing/streaming, real-source coverage,
retention proof and reconciliation remain separate work. There is no atomic
transaction spanning SQLite, its anchor, KMS and PostgreSQL.

The fresh-connection guarantee covers issuance journal operations. The generic
caller-owned `SqliteLedger` passed to the execution runner retains SQLite's
thread affinity; construct execution runner/ledger pairs in their owning worker.
See [checkpoint 2a report](reviews/PROM-F11-checkpoint-2a.md) for observed tests,
mutation/revert evidence, remaining failures and publication status.
