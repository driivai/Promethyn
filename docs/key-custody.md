# Key custody — approval signing through an external KMS / HSM (PIH-2)

> **Conditional retrospective detection, not prevention.** Sign-invoke still
> obtains valid signatures. F11's operational reconciler detects unexplained
> signing only with independently trusted **digest-bound** history and adequate
> coverage on both sides. GCP-shaped digest evidence can supply that binding;
> native AWS CloudTrail is **metadata-only → INDETERMINATE, not detection**;
> PKCS#11 depends on vendor evidence. Control of signing and audit administration
> can erase an unauthorized event without detection. Nothing is uncrackable.

## The residual this answers

PROM-HARDEN-MAX proved the agent cannot reach the approval signing key
(`docs/threat-model.md` §1) and reduced what a partial host compromise yields
(§2). It left one residual standing in plain words: *root reads the signing
key out of the runner's memory and mints any approval it likes.* With an HMAC
key that is true and undetectable — the key is bytes in a process, and a copy
of bytes leaves no trace.

The insider-hardening doctrine is to convert that from "undetectable, silent"
to "detectable, witnessed" by introducing a witness the insider cannot
control. Here the proposed witness is the signing service's audit trail, subject
to the per-provider capability and coverage checks below. Custody alone is not
evidence that logging was enabled, delivered, retained or digest-bound.

## Options

| Signer | Where the private key is | Who can mint silently | Status |
|---|---|---|---|
| `LocalHmacSigner` (`signing_key` / `PROM_CHOKEPOINT_KEY`) | bytes in the runner process | anyone who can read the process: root, a debugger, a core dump | **Non-protecting against a host-level insider.** Development only. The runtime warns; `PROM_REQUIRE_EXTERNAL_SIGNER=1` refuses it. |
| `KmsSigner` over a `KmsPort` | inside the KMS / HSM; not returned through the port | invoke holders still sign; detection depends on independent digest-bound audit evidence | external-custody posture; deployment adapter must be validated |
| `PublicKeyVerifier` | nowhere on this host — it holds the public key only | nobody: this host cannot mint at all | the runner side of a split deployment |

`Config.require_external_signer` (`PROM_REQUIRE_EXTERNAL_SIGNER`) is on
`SECURITY_FIELDS`. It is the OR of its sources — the runner config, the
runtime `Config`, and the environment variable — and refuses a local key as a
requirement that "cannot be honoured". There is no path from a configured
`KmsSigner` to a local key: a KMS failure raises, it never falls back.

## The scheme

**ECDSA over NIST P-256 with SHA-256, DER-encoded signatures.** The message is
the approval's existing canonical bytes — the v2 binding of artifact, target,
nonce, issuance and expiry, length-prefixed and domain-separated — and what is
sent to the KMS is its SHA-256 digest (`MessageType=DIGEST`). The envelope
(`Approval` version 3) names the `scheme` and the `key_id` the signature was
made under; the verifier accepts only its own scheme and key before checking
anything else.

**Why this scheme.** It is the one every target offers: AWS KMS
`ECC_NIST_P256` with `ECDSA_SHA_256`, Google Cloud KMS `EC_SIGN_P256_SHA256`,
and PKCS#11 `CKM_ECDSA` over a P-256 key. Ed25519 would rule out AWS KMS and
older HSMs. RSA buys nothing here. Keeping HMAC inside the KMS
(`GenerateMac` / `VerifyMac`) was considered and rejected: it makes every
*verification* a KMS call, so the execute path fails whenever the KMS is
unreachable, and the verifying host still holds a KMS credential. With a
public key the verifier holds nothing a forger could use, needs no KMS
credential, and keeps working through a KMS outage — while minting, correctly,
does not.

**What did not change.** Artifact binding, target binding, expiry, single-use
nonces and the fail-closed `authorize` (only an authoritative PASS mints) are
untouched. `test_the_binding_is_the_v2_binding_unchanged` pins the SHA-256 of
the canonical bytes for a fixed input to the value computed before PIH-2, and
`test_every_binding_still_blocks_with_the_external_signer` re-proves each
refusal through the runner with a spy executor.

**Dependency.** The standard library has no asymmetric primitives, so
`cryptography` (OpenSSL-backed) is now a declared dependency. Implementing
ECDSA by hand in this repository would be the wrong kind of custody.

## The port, and its mapping to a real KMS

`KmsPort` is two operations. Neither can return key material; an adapter that
could is not an adapter for this port.

| Port | AWS KMS | Google Cloud KMS | PKCS#11 HSM |
|---|---|---|---|
| `sign(key_id, digest, principal=…)` → DER signature | `Sign(KeyId, Message=<digest>, MessageType=DIGEST, SigningAlgorithm=ECDSA_SHA_256)` → `Signature` (DER) | `asymmetricSign(name=<version>, digest={sha256: <digest>})` → `signature` (DER) | `C_SignInit(CKM_ECDSA)` + `C_Sign(<digest>)` → raw `r‖s`; re-encode as DER (`encode_dss_signature`) |
| `get_public_key(key_id)` → SubjectPublicKeyInfo DER | `GetPublicKey(KeyId)` → `PublicKey` (SPKI DER) | `getPublicKey(name)` → `pem`; decode to DER | `C_GetAttributeValue(CKA_EC_POINT, CKA_EC_PARAMS)`; assemble SPKI |
| `KmsAccessDenied` | `AccessDeniedException` | `PERMISSION_DENIED` | `CKR_USER_NOT_LOGGED_IN` / `CKR_KEY_FUNCTION_NOT_PERMITTED` |
| `KmsUnreachable` / `KmsTimeout` | endpoint / SDK timeout errors | `UNAVAILABLE` / `DEADLINE_EXCEEDED` | `CKR_DEVICE_ERROR` / `CKR_TOKEN_NOT_PRESENT` |
| the sign log | CloudTrail `kms:Sign` events (principal, key, time; no digest) | Cloud Audit Logs `AsymmetricSign` Data Access event (observed digest when present) | vendor-specific audit log; capability must be validated |

The `principal` argument names the credential the call is made under. A real
adapter ignores it — the credential is the client's — while the in-memory
model uses it to enforce and record who asked.

**No cloud SDK is bundled**, for the reason PIH-1 gave for buckets: a signer
adapter the CI cannot exercise against a real KMS is a guard nobody has seen
work. `MemoryKms` (`chokepoint/kms_model.py`) is the medium's semantics in
memory — unextractability, per-request logging including denied attempts,
separation of administration from invocation, a fault surface, and an
adversary surface — and it is what every test here runs against, on every CI
runner. A deployment writes its adapter against the table above and proves it
as described below.

### Unextractability, proven rather than asserted

The model generates each key inside `create_key` and keeps it only inside a
signing closure: no attribute of the model is a private key, the model cannot
be pickled, and `test_no_port_operation_returns_key_material` obtains the real
private scalar through that one closure (a positive control — its public
point is checked against the port's public key), calls every port operation,
and asserts the scalar appears in none of the results, attributes, or `repr`s
of the KMS, the signer, or the authority.

### Proving a real adapter

Before trusting an adapter against a production key:

1. **Create the key non-exportable.** AWS KMS asymmetric keys cannot be
   exported; on an HSM set `CKA_EXTRACTABLE=FALSE`, `CKA_SENSITIVE=TRUE`,
   `CKA_SIGN=TRUE`, and confirm `C_GetAttributeValue(CKA_VALUE)` fails and
   `C_WrapKey` is refused.
2. **Attempt every export path the SDK offers** with the most privileged
   credential you hold, and confirm each fails. An adapter that has not been
   seen to refuse is the void guard this document keeps naming.
3. **Sign once and find the record.** Make one signing request and locate it
   in the audit trail with the expected principal, key and time. Then make one
   with a credential that lacks the permission, and locate the denied event.
4. **Verify with the public key only**, on a host that holds no KMS
   credential (`PublicKeyVerifier`), and confirm an approval signed by any
   other key is refused.
5. **Reconcile.** Run `promethyn-reconcile` against the anchored gate snapshot
   and independently obtained source export, following [the operator procedure](reconciliation.md).
   A normal mature batch with complete digest-bound evidence must match without
   false UNEXPLAINED events; a direct invoke must be UNEXPLAINED. A metadata-only
   source must instead be INDETERMINATE. Do not print signed envelopes.

## The witness property — what is operational, and what is not

**F11: operational reconciliation implemented in checkpoint 3.**
`chokepoint/reconciliation.py::reconcile` consumes the actual 2a disk journal
and the 2b read-only `SignAuditSource`. `promethyn-reconcile` exposes it over
independent, pinned evidence exports. No cloud SDK or live adapter is bundled;
the deployed source and both completeness assertions must be validated separately.
The legacy set helpers in `kms_model.py` are not this control.

`reconcile_gate.read_gate` opens a read-only SQLite transaction, verifies the
raw chain against the entire external anchor history and an auditor-pinned
checkpoint, and only then reuses the 2a typed decoder. Preimage, approval digest
and record hash are recomputed from disk. The checkpoint must attest complete
gate history, including lookback; neither a recent tip nor a valid hash chain
establishes temporal completeness by itself.

| Outcome | Meaning |
|---|---|
| MATCHED | One authorised decision explains one successful independently observed digest-bound event with the pinned key/scope, caller, algorithm and admissible time. |
| UNWITNESSED | A mature valid decision has no successful witness in complete evidence. A pre-Sign crash or a denied attempt can cause this; **not the forgery signal**. |
| UNEXPLAINED | A successful digest-bound event has no eligible decision or exceeds the one-attempt allowance. **The forgery signal** under the stated trust assumptions. |
| INDETERMINATE | Verification/read error, incomplete/immature evidence, missing digest, legacy history, or conflicting identity mapping. Never a clean result. |

Denied attempts remain diagnostics, not forged approvals. A missing post-Sign
result does not invalidate a durable decision: lost replies and pre-result
crashes may still match. Exact repeated event IDs deduplicate; conflicting
payloads make the source indeterminate. Distinct excess Sign events do not
deduplicate by digest. Stable allocation does not identify which indistinguishable
attempt was malicious. Matching never resolves F2 UNKNOWN or releases a nonce.

The pinned policy defaults settling to **900 seconds**, and requires explicit
finite clock-skew, bounded Sign-attempt duration and maximum record TTL. Absence
checks cover issuance minus skew through expiry plus Sign duration plus skew;
missing send/result timestamps never shorten it. Before its upper bound plus
settling, return INDETERMINATE with retry time. Afterward, **attested complete
coverage is still required**; elapsed time and page exhaustion are not certificates.

- **GCP:** observed base64 SHA-256 plus pinned immutable version/algorithm can
  support detection, only with independently established complete source and
  gate coverage. Native pagination alone supplies no completeness frontier.
- **AWS CloudTrail:** digest absent, metadata-only, **INDETERMINATE, not detection**.
  Same key/caller/time or a copied request alias cannot upgrade it.
- **PKCS#11:** vendor-dependent; no portable audit-read API. Without validated
  independent digest and coverage evidence, INDETERMINATE.
- **Local HMAC:** INDETERMINATE / `no_independent_sign_source`.

`test_invoke_only_forgery_detected` and
`test_normal_concurrent_batch_across_restart_zero_false_positives` prove both
directions. `test_controls_both_residual_honestly_not_detected` deletes an
unauthorized event and replaces coverage assertions: it returns clean with no
synthetic gap. An attacker who can also append dishonest authorised gate
decisions can likewise make the histories agree. The auditor, pins, gate
checkpoint, anchor and source trust are deployment obligations, not facts
established by a model test. See [operator schema and limits](reconciliation.md)
and [real-source acceptance](audit-source-acceptance.md).

## Fail-closed

Couldn't-sign is not signed. Each failure is a distinct `SignerUnavailable`
subclass, no approval is minted, and — proven end to end through the chokepoint
runner with a spy executor — the database is untouched and the executor never
called.

| KMS behaviour | Raised | Approval | KMS log |
|---|---|---|---|
| unreachable | `SignerUnreachable` | none | no record (the request never arrived) |
| times out | `SignerTimeout` | none | unknown: a successful Sign reply may have been lost |
| denies the principal | `SignerDenied` | none | a `denied` record |
| answers with something that is not a signature under its own public key (garbage, or a signature by another key) | `SignerMalformed` | none | a `signed` record — the KMS did sign; the answer is refused here |
| unreachable or malformed at construction | the same classes | no signer is built | — |
| a verify-only host asked to mint | `SignerCapabilityAbsent` | none | — |

`test_no_silent_fallback_to_a_local_key` instruments `LocalHmacSigner` and
shows it is never called under a KMS configuration, and that no local signer
exists anywhere in the authority's object graph. A forged approval presented
under a KMS configuration is refused with `invalid_signature`; once the KMS is
back the same runtime mints and executes, so the refusals were not a dead path.

## The residual — the insider who holds Sign-invoke

**`KmsSigner` defeats silent key theft. It does not defeat an insider who
holds the Sign-invoke permission.** The KMS signs for an authorised caller;
that is what it is for. `test_an_insider_with_sign_invoke_gets_a_valid_signature_AND_is_logged`
grants an insider principal the permission, has them mint an approval for
hostile SQL, and shows the runner **executing it** — not prevented. It then
shows the legacy model log carrying the principal and digest. Checkpoint 3's
`test_invoke_only_forgery_detected` exercises the operational disk/source
reconciler and reports UNEXPLAINED. This detection requires the digest-bound
profile; AWS-shaped metadata-only evidence remains INDETERMINATE. An insider
without invoke permission is denied; that is a diagnostic, not a forgery signal.

Stopping that insider outright takes a second party: two-party control, where
no single principal can authorise alone (PIH-3, buyer-gated — the co-signer
protocol is shaped by a design partner's threat model, not guessed here).
Until then the boundary is exactly this: **who may invoke Sign**.

## The access policy — a deployment artifact for a security review

The witness is worth exactly the separation the deployment enforces. Three
principals, three permission sets, no overlap:

| Principal | May | Must not |
|---|---|---|
| **the runner / gate** (`KmsSigner`'s credential) | `kms:Sign` on the approval key; `kms:GetPublicKey` | administer the key, its policy, grants, or deletion; read or export it; write to the audit trail |
| **the key administrator** | create, rotate, set policy on, and schedule deletion of the key (`kms:PutKeyPolicy`, `kms:CreateGrant`, `kms:ScheduleKeyDeletion`; `roles/cloudkms.admin`; the HSM security-officer PIN) | `kms:Sign` — an administrator who can also invoke is the insider above with extra reach |
| **the auditor** | read the audit trail and the ledger | invoke or administer |

Concretely: on AWS, a key policy whose `kms:Sign` statement names only the
runner's role, whose administrative statements name only the key
administrator, and CloudTrail delivered to a bucket the runner's role cannot
write to — with Object Lock, which is the same medium PIH-1 anchors the ledger
to. On Google Cloud, `roles/cloudkms.signerVerifier` on the runner's service
account only, `roles/cloudkms.admin` elsewhere, and data-access audit logs
enabled for `cloudkms.googleapis.com`. On an HSM, the runner authenticates as a
user that can sign with this key and nothing else; the security officer role
is held by someone else.

`test_the_invoke_holder_cannot_administer_the_key` is the model's version of
the same separation: the signing principal cannot grant itself or anyone else
`Sign`, and cannot create keys.

## Settings

| Setting | Environment | Default | Effect |
|---|---|---|---|
| `MigrationRunnerConfig.signer` | programmatic | — | the external signer (`KmsSigner`, or `PublicKeyVerifier` on a verify-only host). Exactly one of `signer` and `signing_key` is given. |
| `MigrationRunnerConfig.signing_key` | `PROM_CHOKEPOINT_KEY` (the demo) | — | the local HMAC key. Non-protecting; warned about at build. |
| `require_external_signer` | `PROM_REQUIRE_EXTERNAL_SIGNER` | off | refuse a local key as "cannot be honoured". The OR of the runner config, the runtime `Config`, and the environment. |

**The one non-hardened default, stated:** `require_external_signer=False`. A
development install has no KMS to point at, and the in-memory model is a test
double, not a place to keep a production key. Production sets
`PROM_REQUIRE_EXTERNAL_SIGNER=1` (`docs/threat-model.md` §5.4).

## What this does NOT cover — the residual, in one place

- **An insider who holds the Sign-invoke permission** obtains valid signatures.
  Detected only with trustworthy digest-bound evidence and adequate coverage;
  native AWS metadata-only evidence is not that detection. Two-party prevention
  (PIH-3) is a separate design, not implemented here.
- **An insider who can administer the key** can grant themselves invoke, or
  rotate the key, which the log also records — if the deployment kept the
  roles separate. An administrator who is also the auditor, or who can delete
  the audit trail, collapses the witness. The access policy above is the
  boundary, and the code cannot check that a deployment set it.
- **The audit trail is the medium's.** If it is routed to a store the runner's
  principals can delete from, it is not a witness.
- **No KMS adapter is shipped.** The port and its mapping are; the adapter is
  the deployment's and must be proven as above.
- **The public key must be pinned honestly.** A verify-only host that fetches
  the public key from a place the insider controls verifies the insider's key.
  Fetch it once from the KMS under an auditor's credential, or pin it in
  configuration; a change to the pinned key is a config change (PIH-4a's
  subject).
- **Minting stops on a KMS signing failure.** A separate logging outage does
  not necessarily prevent Sign. Reconciliation then reports insufficient
  coverage, not a clean range. Verification needs only the public key.
- **Detection is conditional, not prevention.** The KMS signs what an invoke
  holder asks. An adversary who also controls audit administration can delete
  unauthorized signing and its coverage evidence without a detectable gap.
