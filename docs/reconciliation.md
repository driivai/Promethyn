# F11 operational signing reconciliation

## Limits first

This is retrospective evidence, not prevention. Sign-invoke still obtains valid
signatures. Detection requires independently trustworthy gate history, signing
history, coverage assertions and auditor pins. GCP's observed digest can support
detection **after deployment validation**. Native AWS CloudTrail lacks the
digest: **metadata-only → INDETERMINATE, not detection**. PKCS#11 requires vendor
evidence. Local HMAC has no independent Sign source. No live cloud/HSM adapter
or SDK ships here; passing CI does not validate a deployment.

An adversary controlling Sign and audit administration can erase an unauthorized
event and replace its coverage assertions, yielding a clean-looking result.
There is deliberately no synthetic tombstone. Dishonest authorised gate appends,
compromised auditor configuration, and simultaneous control of ledger and anchor
also defeat the relevant trust boundary. Nothing is claimed uncrackable.

## Run (read-only)

```sh
promethyn-reconcile \
  --config auditor-pins.json \
  --ledger gate-snapshot.db \
  --anchor-history independent-anchor.ndjson \
  --source-evidence independent-sign-history.ndjson
```

Equivalent without an installed console script:
`python -m prometheus_protocol.cli.reconcile` with the same arguments. JSON goes
to stdout; no files are created by the application, no signer/runner is built,
no SQL migration or recovery is attempted, and no anchor write is requested.
SQLite uses `mode=ro`, `query_only=ON`, and one read transaction. It may require
existing WAL/SHM access for a live WAL database; use a consistent, finalized
SQLite backup supplied by the trusted gate exporter for an offline read. Do not
copy a live main database without its committed WAL. Schema is never migrated.

1. Independently authenticate the gate lineage and its complete-history
   checkpoint. Pin `ledger_id` (first chain entry hash), exact tip, covered
   interval, observation time and evidence reference. **Do not derive coverage
   from the last row's timestamp, the current clock, or the chain being valid.**
   The exporter/operator must establish that all decisions in that interval are
   included at that tip, including pre-start lookback. If that cannot be
   established, do not fabricate a checkpoint: the CLI refuses missing evidence.
2. Obtain the **entire retained external anchor history** from the independent
   witness, not from the gate host's copy. Each NDJSON line is exactly
   `{"seq": <positive integer>, "entry_hash": "<64 lowercase hex>"}`. Pin its
   transfer SHA-256 in the auditor's configuration. A locally invented tip does
   not become external merely because its hash matches.
3. Read the 2b source port over a sufficiently extended interval. Preserve the
   returned capability, observation time, coverage/frontier, gaps, issues and
   provenance exactly. `encode_source_export(SignRead)` serializes that result;
   it does not authenticate it or promote pagination into completeness. Obtain
   it through the independently validated reader and pin its transfer SHA-256.
4. Pin the immutable key mapping, public-key fingerprint, expected authenticated
   caller, algorithm and observed digest field. This mapping is auditor-owned,
   never chosen from the gate record being checked. Preserve historical mappings.
5. Choose the requested half-open interval and justified policy bounds. Run the
   command, inspect **both** top-level problems and per-row outcomes. Incomplete
   evidence is not cured by waiting unless both source assertions actually advance.

File hashes protect transfer bytes relative to trusted configuration, **not**
origin or completeness. Putting all files under the suspect host's control
invalidates the independent-witness claim. The library accepts the existing
read-only source and an anchor reader programmatically; the CLI consumes their
offline exports, without loading arbitrary Python adapters or credentials.

## Input encoding v1

`auditor-pins.json` has exactly these fields; unknown/missing fields refuse:

| Field | Value |
|---|---|
| `version` | integer `1`, not boolean |
| `scope` | 2b `AuditScope`: provider, source_id, domain, region, key_resource |
| `key_pin` | approval_key_id, backend, gate_scope, public_key_sha256, caller_issuer, caller_subject, algorithm, digest_location, scheme |
| `policy` | max_clock_skew_seconds, sign_attempt_seconds, record_ttl_seconds, settle_seconds |
| `requested` | `{start, end}` UTC epoch integer nanoseconds |
| `gate_checkpoint` | ledger_id, tip `{seq, entry_hash}`, covered `{start,end}`, observed_at, evidence |
| `anchor_sha256`, `source_sha256` | lowercase hex SHA-256 of exact independent export bytes |

`record_ttl_seconds` is the maximum accepted gate TTL, not a replacement expiry.
Settling defaults to 900 seconds in the API; serialize the resolved value in CLI
configuration. Skew and TTL must be finite, non-boolean, non-negative. Settling
and Sign duration must additionally be positive. No production skew or Sign
deadline is guessed. Bounds must match the actual deployment's clock quality
and bounded Sign adapter; this retrospective code does not enforce that adapter's
I/O deadline. Configuring a claim does not prove it was true.

The source export is UTF-8 NDJSON: first line exactly
`{"version":1,"coverage":<2b Coverage>,"issues":[<2b SourceIssue>,...]}`;
each remaining line is exactly a 2b `SignEvent`. Dataclass fields and nested
structures are preserved; tuples become arrays and digest bytes become lowercase
64-character hex (`null` for absent). Digest provenance is `observed` or `absent`,
with the observed field location or null. No signed envelopes are included.
Duplicate JSON keys, blank/interrupted rows, unknown versions/fields and malformed
events refuse the **whole export**, never disappear during filtering.

Canonical native GCP location is `protoPayload.request.digest.sha256:base64`;
the source normalizer converts native base64 to bytes before export. The model
uses `model:service-observed-sign-input` and `model-gcp`, never masquerading as
a live provider. These known provider locations cannot be configured to a local
gate field; such a pin is indeterminate. A local asserted digest field does not
match a different pinned source location. Provenance labels are source assertions, not authentication;
the independent acquisition requirement still applies.

The CLI accepts a larger source export and intersects its coverage with the
required query; it does not extend coverage or hide identity conflicts outside
the subquery. A too-short export produces `export_does_not_cover_query`. The
result's `source_requested` tells the operator which interval must be re-read.

Bounds: 64 KiB config/individual NDJSON row, 4 MiB source export and 10,000
events, 16 MiB anchor export/100,000 tips; gate snapshot at most 100,000 rows,
64 MiB projected row content and 128 KiB per projected row. SQLite queries use a
3-second busy timeout and progress deadline. These are refusal limits, never
silent truncation. Anchor/source adapters must bound their own blocking I/O;
the synchronous API cannot preempt an arbitrary injected reader. There is no
claim of a hard whole-reconciler wall-clock deadline.

## Matching, coverage and settling

`reconcile_gate.read_gate` reads raw rows in insertion order, verifies the chain
against **all** anchor tips and the exact pinned snapshot tip, then reuses
`AuthorizationJournal._decisions`. That decoder verifies sign-result references,
unique decisions/requests/nonces, reconstructed preimage, approval digest and
authorization record hash. Corrupt input yields an integrity failure and no
eligible decisions. Unanchored/changed snapshots, missing legacy execution
bindings and unreadable input are indeterminate. All history is read, not a
timestamp-filtered set. An entirely unanchored empty ledger cannot be certified.

Select decisions whose possible signing windows overlap the request. Convert
binary64 gate times using exact rational arithmetic: floor the lower nanosecond
boundary and ceil the upper boundary, never round inward. For a decision:

`[issuance − skew, expiry + bounded Sign duration + skew)`.

Nonnegative epoch limits clip only a lower bound before epoch zero; negative
issuance and overflowing bounds refuse. A post-Sign result or send timestamp
does **not** shorten that window. Extend the source query to include every
selected window. Require independently attested gate history from the extended
start minus `(maximum TTL + Sign duration + skew)` through extended end plus
skew. A too-short checkpoint remains indeterminate, even when a nearby row exists.

Both the requested range and affected decision window must settle before a clean
conclusion: retry at their upper bound plus settling, whichever is later. After
settling, require all pages, source-attested coverage and adequate frontier with
no gap over the affected interval. Unknown outcomes/absent or wrong-location
digests cannot establish a witness's absence. An empty fully checked range can
be clean with zero matched rows; an empty immature, metadata-only or unreadable
range cannot. Any incomplete part keeps the top level non-clean while unaffected
findings are retained.

Digest equality is looked up only after recomputation from disk; candidate
matches also require authorised decision, pinned scope/key/version/public key
mapping, caller issuer+subject, algorithm and admissible service time. A copied
request alias is never consulted. One decision explains at most one distinct
successful event. Exact repeated IDs count once; conflicting payloads invalidate
the source. Excess same-digest events are UNEXPLAINED / `excess_sign_attempts`;
stable allocation does not identify which indistinguishable attempt was malicious.

## Output and exit codes

Versioned JSON (`schema_version: 1`) includes scope, requested/source-requested
intervals, policy, observation/retry times, gate chain/anchor/checkpoint evidence,
source coverage/issues, per-record/per-event status and stable reason, counts,
denied diagnostics, refused decisions, problems, limitations and `forgery_signal`.
`counts` aggregates both row sets; `record_counts` and `event_counts` disambiguate
them. One matched pair is one row in each set. Candidate IDs under incomplete
evidence are diagnostic links, not MATCHED claims. No raw payload, SQL, password,
nonce, preimage or signed envelope is projected. Errors never echo exception text.
Free-form completeness/checkpoint references are lookup SHA-256 fingerprints,
not echoed URLs; unknown source diagnostic/gap reasons become stable generic
codes. This prevents an adapter error or bearer URL in those fields leaking into
an otherwise routine report. Scope and event/caller identities are non-secret
identifiers under the port contract, not places to put credentials.

| Outcome | Interpretation |
|---|---|
| MATCHED | Successful independently digest-bound Sign explained by one eligible decision. Does not prove delivery, policy honesty, execution, or database commit. |
| UNWITNESSED | Mature valid decision without a successful witness under complete evidence. Non-clean, **not forgery**; pre-Sign crash and denial are possible. |
| UNEXPLAINED | Successful digest-bound Sign without eligible authority or excess attempts. **Forgery signal** under the stated trust assumptions. |
| INDETERMINATE | Could not reconcile; never MATCHED or clean. |

Denied events use `outcome=denied, forgery_signal=false`, outside the four success
comparison outcomes. Unknown events stay indeterminate. Refused gate decisions
are separately reported; they cannot explain successful signing.

- **0:** fully checked range, no discrepancy or indeterminate row (`clean=true`).
- **1:** valid request, non-clean reconciliation (including UNWITNESSED).
- **2:** invalid configuration/export or unavailable input before a report can be
  assembled; emits a minimal versioned INDETERMINATE JSON error. Argument syntax
  errors use argparse's stderr/exit 2. Never treat a missing detailed report as clean.

F2 execution recovery is a different operation. The reconciler never completes
an intent, retries SQL, releases a consumed nonce, revokes an approval, or mints
one. See `tests/chokepoint/test_reconciliation.py` and
`scripts/f11_reconcile_revert_proofs.py` for executed positive, negative and
controls-both proofs, including the read-only boundary and secret projection.
