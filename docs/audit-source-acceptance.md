# F11 real-adapter acceptance checklist

**Status: offline normalization/model checks implemented; no real adapter has
passed deployment acceptance. No live cloud calls are made by this checkpoint.**
This procedure is for a separately authorized test environment, not production
keys. Checkpoint 3 now supplies the operational [reconciler](reconciliation.md);
these deployment checks remain mandatory and are not fulfilled by offline CI.

## Run the offline checks

From an installed development checkout:

```sh
python -m pytest -q tests/chokepoint/test_audit_source.py
python scripts/f11_source_revert_proofs.py
python -m pytest -q tests/chokepoint/test_reconciliation.py
python scripts/f11_reconcile_revert_proofs.py
```

The ordinary CI matrix runs all three 2a/2b/3 files, rejects skips/failures/errors
and requires each file to contribute test cases. The source tests include an
empty page with a next token, metadata-only self-certification attempts, a
copied correlation alias with a different digest, and the controls-both residual.
These are synthetic provider-shaped fixtures, not evidence of live service
configuration or completeness. Unknown formats fail closed until reviewed.

## Pin the deployment (all unchecked until evidence is archived)

- [ ] Record service/API version; account/project/device; region; immutable key
  resource/version; independent source identity and pinned public-key fingerprint.
  Resolve aliases before reading. Preserve old key versions for old history.
- [ ] Establish three distinct credentials/roles: Sign invoke, audit read, audit
  administer. The reader must not have mutation privileges. Do not filter the
  history to the expected caller: include unexpected principals on the scoped key.
- [ ] Record logging enablement, exclusions, routing, retention, clock quality and
  reader permissions. AWS LookupEvents is regional and covers 90 days; archives
  need their own listing/retention proof. GCP Data Access logging must be enabled.
- [ ] Pin the adapter's response byte/page limits and absolute deadline. Demonstrate
  that transport, parsing and allocation honor those bounds; the synchronous
  collector only rejects late replies and cannot terminate blocked external I/O.

## Capture operations using an independently observed test key

- [ ] Concurrently sign two different known 32-byte digests with the same key/caller.
  Independently verify each signature with the pinned public key. Record each
  unique service event ID, key version, authenticated principal and service time.
- [ ] Invoke Sign outside the gate using invoke-only credentials; confirm an event
  remains visible to the independent reader. With independently complete,
  digest-bound evidence, run the reconciler and require UNEXPLAINED. A
  metadata-only source must instead return INDETERMINATE, never MATCHED.
- [ ] Exercise denial, repeated digest with distinct Sign calls, and a successful
  Sign whose reply is lost. A lost caller reply must not erase a service event.
  Missing/redacted outcome or identity must remain unknown/malformed, not success.
- [ ] Copy a legitimate correlation alias/context label while signing a different
  digest. The normalized observed digest must remain the actual different bytes;
  **the alias must never be accepted as a match or used to fill a missing digest**.
  Run this through the checkpoint-3 matcher as well; it must reject this pair.
- [ ] Archive redacted raw events and exact byte conversions, not gate-derived
  substitutes. AWS Sign supplies no digest/signature in the supported native
  event; its result stays metadata-only regardless of `messageType=DIGEST`.
- [ ] For GCP, confirm actual `protoPayload.request.digest.sha256` representation.
  The implemented mapping requires padded standard base64, 32 decoded bytes,
  exact `AsymmetricSign`, full version and independent GetPublicKey export for
  the algorithm. Hex/unknown format is a failed acceptance, not a silent fallback.
- [ ] For PKCS#11, obtain device/vendor audit export documentation and captured
  examples for every required field. `C_Sign` success is not evidence that an
  audit-read API, retained history or observed digest exists. No generic adapter
  may be declared accepted in its absence.

## Prove incomplete coverage stays incomplete

- [ ] Read every page, including an empty page carrying a continuation token;
  deliberately omit a middle page. The latter must be incomplete, never a shorter
  clean list. Duplicate deliveries with identical source IDs collapse; conflicting
  payloads sharing one ID make the input unusable.
- [ ] Measure delayed delivery and repeat queries around the requested boundary.
  Keep `complete_through` unknown unless the source provides independently
  justified completeness evidence. Neither page exhaustion nor a settling timer
  proves all asynchronously delivered events have arrived.
- [ ] Cross retention, exclude a logging interval, deny the reader, interrupt a
  page read, corrupt a row, and exceed the response/deadline bound. Retain explicit
  gaps/issues or unreadable coverage, never an empty successful read.
- [ ] With audit-administrator authority in the isolated test environment, replace
  history **and** its coverage assertions. Document the clean-looking erased case.
  Do not manufacture a tombstone the adversary would remove. This is the known
  controls-both residual, not a passing security detection claim.

Archive raw fixture hashes, scope/configuration, credential-role evidence,
normalizer version, exact expected normalized records, completeness rationale,
observed delays and outstanding limitations. Independent reviewer approval is
required before claiming real-adapter acceptance. Repeat after provider schema,
key/version mapping, logging configuration or retention/permissions changes.

## Primary mapping references (checked 2026-09-08)

- [AWS native Sign event](https://docs.aws.amazon.com/kms/latest/developerguide/ct-sign.html)
  and [LookupEvents contract](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html).
- [GCP signing-log digest correlation](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/verify-identity-issuance-usage),
  [Digest bytes/base64 encoding](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign#Digest),
  [audited method names](https://docs.cloud.google.com/kms/docs/audit-logging),
  [entries.list pagination](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list).
- [PKCS#11 base interface](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html).
