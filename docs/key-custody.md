# Key custody — approval signing through an external KMS / HSM (PIH-2)

> **Detection, not prevention.** Nothing here stops a privileged insider from
> obtaining a signed approval. It stops them doing so *silently*: the private
> key no longer exists on the runner host, so a forgery must ask the KMS to
> sign, and every Sign request is recorded by the KMS, outside the insider's
> control. An insider who holds the Sign-invoke permission still gets a valid
> signature — and a log entry with their name on it. Nothing is called
> uncrackable.

## The residual this answers

PROM-HARDEN-MAX proved the agent cannot reach the approval signing key
(`docs/threat-model.md` §1) and reduced what a partial host compromise yields
(§2). It left one residual standing in plain words: *root reads the signing
key out of the runner's memory and mints any approval it likes.* With an HMAC
key that is true and undetectable — the key is bytes in a process, and a copy
of bytes leaves no trace.

The insider-hardening doctrine is to convert that from "undetectable, silent"
to "detectable, witnessed" by introducing a witness the insider cannot
control. Here the witness is the KMS's own audit trail.

## Options

| Signer | Where the private key is | Who can mint silently | Status |
|---|---|---|---|
| `LocalHmacSigner` (`signing_key` / `PROM_CHOKEPOINT_KEY`) | bytes in the runner process | anyone who can read the process: root, a debugger, a core dump | **Non-protecting against a host-level insider.** Development only. The runtime warns; `PROM_REQUIRE_EXTERNAL_SIGNER=1` refuses it. |
| `KmsSigner` over a `KmsPort` | inside the KMS / HSM; never returned by any operation | nobody: every signature is a logged request | the production posture |
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
| the sign log | CloudTrail `kms:Sign` events (principal, key, time) | Cloud Audit Logs `CryptoKeyVersions.AsymmetricSign` data-access log | the HSM's audit log |

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
5. **Reconcile.** Run the auditor's check below over a day's log and the
   approval envelopes you hold; it must come back empty. The ledger does not
   hold those envelopes or their digests today — see "The witness property"
   for exactly what that means.

## The witness property — what is operational, and what is not

Every approval minted through `KmsSigner` is exactly one Sign request, over
the SHA-256 of the approval's canonical bytes (`approval_digest`, in
`chokepoint/approval.py`: the hash over artifact hash, canonical target,
nonce, issuance time and expiry). The KMS records that digest per request
(`MemoryKms.sign_log` in the model; the audit trail of a real KMS). Two
helpers compare a set of approval digests with such a log:

- `unwitnessed_digests(approval_digests, sign_log)` — approvals with no Sign
  record. A valid approval that the KMS never signed means the key exists
  somewhere other than the KMS, or the log was tampered with. Both are alarms.
- `unexplained_records(sign_log, approval_digests)` — Sign records (and every
  denied attempt) that no authorised approval accounts for. **This is the
  forgery signal**: someone holding the invoke permission asked for a
  signature the gate never authorised.

**F11 checkpoint 2a: persistence exists; automated reconciliation does not.**
The earlier claim that the ledger could reconstruct the digest was false at
PROM-FIX-A. `build_migration_runtime` now requires a private durable ledger and
explicit authorization context. Its `RecordedApprovalAuthority` writes a full
decision **before Sign** and a separate result before delivering an approval.
The decision persists exact issuance/expiry and binding fields; runner events
also carry unsigned binding evidence. A fresh-process test reconstructs the
digest from disk alone. See [authorization record §8](authorization-record.md#8-implemented-checkpoint-2a-boundary)
for code, proof names, storage requirements and limits.

**F11 remains open.** Checkpoint 2b adds a read-only audit-source port, separate
signer/reader/administrator model capabilities and offline provider normalizers.
The coverage/settling-aware reconciler and operator CLI are still not implemented;
neither the port nor the set-based helpers above supplies that control.
AWS CloudTrail supplies metadata only, never a digest inferred from key/caller/time.
GCP's observed base64 digest can be retained; a missing digest stays absent and
the key algorithm requires separate pinned version evidence. PKCS#11 has no
portable audit-read capability; vendor evidence is required. Pagination is not
an asynchronous completeness attestation. See the [source mapping and limits](authorization-record.md#6-audit-source-port-and-real-source-feasibility).
No deployed cloud/HSM adapter has been validated by these local-model proofs.

The KMS log stands in for the real audit trail. What makes it a witness is
that the runner host cannot write to it: CloudTrail and Cloud Audit Logs are
written by the service, not the caller, and an HSM's audit log is inside the
device. That property is the medium's, and a deployment must keep it — route
the trail to a store the runner's principals cannot delete from.

## Fail-closed

Couldn't-sign is not signed. Each failure is a distinct `SignerUnavailable`
subclass, no approval is minted, and — proven end to end through the chokepoint
runner with a spy executor — the database is untouched and the executor never
called.

| KMS behaviour | Raised | Approval | KMS log |
|---|---|---|---|
| unreachable | `SignerUnreachable` | none | no record (the request never arrived) |
| times out | `SignerTimeout` | none | no record |
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
shows the KMS log carrying a `signed` record with the insider's principal and
the digest of exactly that approval, which `unexplained_records` flags against
the ledger — witnessed. An insider *without* the permission is denied, and the
attempt is a `denied` record.

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
  Witnessed by the log; stopped only by two-party control (PIH-3).
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
- **Minting stops when the KMS does.** That is the fail-closed choice, made on
  purpose: an outage of the witness is an outage of the gate, not a reason to
  sign without one. Verification does not stop, because it needs only the
  public key.
- **Detection, not prevention.** Everything here makes a forged approval
  *visible* after the fact. The KMS signs what an authorised caller asks.
