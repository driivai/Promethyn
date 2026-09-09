# Ledger integrity — the tamper-evident audit chain

PROM-AUDIT found the experience ledger "append-only **by convention** only" — a
plain SQLite file with no hash chain, a record that claimed an integrity it did
not have. By this project's own thesis that is a void guard: a check present,
plausible, and void. This closes it with a **minimal, real** hash chain — tamper
*evidence*, not tamper-*proofing*. Implementation: `ledger/audit_chain.py` (the
pure hashing + the standalone `verify_rows` auditor) integrated into
`ledger/sqlite_ledger.py` (`record_chained` / `chained_events` / `verify_chain` /
`chain_tip`). The chokepoint's authorization decisions write to it.

## Design

Each entry commits to the hash of the prior entry, so altering any entry breaks
every link after it.

- **Hash:** SHA-256.
- **Genesis root** (a fixed, known constant so an auditor with no prior state can
  confirm the chain begins correctly):
  `GENESIS_ROOT = sha256("prom-audit-chain-v1/genesis")`. The first entry's
  `prev_hash` is this value.
- **Canonical preimage** (pinned — ambiguous serialization would let one history
  have two "valid" chains, itself a void guard):

  ```
  entry_hash = sha256(
      b"prom-audit-chain-v1\x00"
      || u64_be(seq)
      || lp(created_at) || lp(event) || lp(subject)
      || lp(canonical_json(payload))
      || lp(bytes.fromhex(prev_hash))
  )
  ```

  where `lp(x) = u64_be(len(x)) || x` **length-prefixes** every variable field, so
  no field boundary can be forged by embedding a delimiter in the data;
  `u64_be` is an 8-byte big-endian integer; and
  `canonical_json = json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)`
  is the one deterministic payload serialization used at write time. The hash
  commits to those **exact stored bytes** — verification recomputes over the
  stored payload verbatim, it does NOT re-canonicalize — so any byte-level edit
  (whitespace, key reorder, or a duplicate-key injection a JSON parser would
  normalize away) changes the hash and is caught. Decodability is still checked
  separately: a payload corrupted to non-JSON is reported `NOT_VERIFIABLE`.
- **Append is append-only in fact.** `record_chained` reads the current tip and
  chains onto it; the caller **cannot** pass `prev_hash`, so a forged-prior-hash
  append is impossible through the API. Direct-file forgery of a wrong `prev_hash`
  is caught at verify.

## The verifier

`verify_chain()` (and the standalone `verify_rows(rows)`) walk the chain in
insertion order from genesis and report the **first** failure with its index and
a specific reason — never a bare boolean:

```
clean 5-entry chain              : chain valid (5 entries)
dup-key edit (reparses equal)    : chain BROKEN at entry 3: content edited: stored hash a09e767d…, recomputed 947cba79…
delete interior entry 3          : chain BROKEN at entry 4: seq discontinuity: expected 3, found 4 (an interior entry was deleted or reordered)
honest append past anchor        : chain valid (7 entries)
full rewrite + extend (anchored) : chain BROKEN at entry 5: entry at the anchored seq does not match the anchored tip (chain rewritten)
truncate tail (no anchor)        : chain valid (3 entries)
truncate tail (anchored)         : chain TRUNCATED at entry 3: chain ends at seq 3 but the anchored tip is seq 5: 2 entrie(s) truncated
corrupt payload entry 2          : chain NOT_VERIFIABLE at entry 2: entry payload is not decodable JSON
forged anchor record (external)  : chain BROKEN at entry 3: the anchor history holds two different hashes for seq 3 (…): a record was written past the anchor's own guard …
```

(The "dup-key edit" case commits to exact stored bytes, so an edit that a JSON
parser would normalize back to the original is still caught; "honest append past
anchor" stays valid while "full rewrite + extend" is caught — the anchor pins the
entry at its seq regardless of later growth.)

It is callable independently — an auditor runs it over the rows; it is not only
an internal check. `verify_rows(rows, expected_tips=[…])` takes a whole anchor
history and pins every record in it (below).

## What this DOES and DOES NOT protect against

Stated precisely, because a tamper-evidence claim that oversells is exactly the
void guard being closed.

**DOES detect (an adversary who reached the ledger file):**
- a retroactive **edit** to any interior entry's content (the entry's recomputed
  hash no longer matches; caught at that entry);
- **deletion** of an interior entry (seq discontinuity / prev-hash break at the
  next entry);
- **reordering** of interior entries (prev-hash break);
- an **appended** entry with a fabricated `prev_hash` (prev-hash break);
- a **rewrite of the prefix up to an anchored point** — including a full rewrite
  from genesis, and a rewrite that then *extends* the chain past the anchor —
  **when an out-of-band tip anchor is supplied.** `verify_chain(expected_tip=…)`
  pins the entry at the anchored `seq`: because each entry commits to its
  predecessor, that one hash pins the whole prefix down to genesis, so any rewrite
  at or before the anchor is caught regardless of how far the chain has since
  grown (honest appends past the anchor stay valid);
- **the same, against a witness the ledger-writer cannot silence**, when the
  anchor is one of the external append-only targets below.

**Does NOT detect on its own — named limits, not silent gaps:**
- **Pure tail-truncation without an anchor.** Lopping entries off the end leaves a
  shorter but internally-valid chain; the chain alone cannot know entries once
  existed.
- **Deletion of the whole ledger without an anchor.** SQLite recreates a missing
  file and an empty chain is internally consistent, so the cheapest attack there
  is reads as `chain valid (0 entries)`.
- **A full rewrite from genesis without an anchor.** An adversary who can rewrite
  *every* row recomputes a wholly self-consistent chain, and a bare in-file chain
  with no external reference cannot tell the difference.
- **A rewrite by an adversary with authority over the anchor medium** — the
  residual of the external anchor, stated in its own section below.

## The tip anchor — operational, not merely available

All three of the first limits above are closed by an out-of-band anchor, and
PROM-HARDEN-MAX §3 made that anchor real rather than possible. `chain_tip()` and
`verify_chain(expected_tip=…)` had existed since this chain was written, and
**nothing in the codebase had ever stored a tip** — a capability present,
plausible, and never exercised, which is this project's own definition of the
thing it exists to name.

`ledger/tip_anchor.py` persists it. A `SqliteLedger` constructed with a
`tip_anchor` writes the new tip after every commit, and `verify_chain` consults
that anchor automatically, so an auditor cannot silently verify without it. The
anchor refuses to move backwards: a live tip below the anchored one, or a
different hash at the anchored seq, raises rather than being quietly recorded —
re-anchoring a shortened chain would destroy the only evidence there was.

**Never silently "valid".** If the verifier cannot actually check an entry — a
missing/None field, or a payload that is not decodable JSON — or cannot read a
configured anchor, it returns `NOT_VERIFIABLE`, distinct from `BROKEN` and
distinct from `VALID`. Couldn't-verify is not verified-clean; this is the EX-1
`Unavailable` distinction applied to the ledger's own integrity check.

## External anchor targets — the protecting deployment (PIH-1)

The Attacker-3 anchor wrote one file and rewrote it in place. Where that file
sat decided everything, and the placement most people reach for — beside the
ledger, on the same disk, owned by the same account — is worth nothing: whoever
rewrites the chain rewrites the anchor in the same breath. That case has always
been a passing test, `test_an_attacker_who_also_controls_the_anchor_is_NOT_detected`
in `tests/chokepoint/test_tip_anchor.py`, rather than a caveat in prose.

PIH-1 changes the **shape** of the anchor, not just its location. On the
external targets every anchored tip is its **own record, created once and never
overwritten or deleted by this code**, on a medium chosen because it refuses to
rewrite history — and the verifier pins **every record in that history**, not
just the newest. The doctrine: nothing here prevents a privileged insider from
rewriting the ledger. Each target introduces a witness the insider cannot
silence, converting the residual from "undetectable" to "detected out of band".

### The targets

Selected by `PROM_LEDGER_ANCHOR` (`Config.ledger_anchor`); built by
`runtime/factory.py::build_ledger`, which every production ledger goes through.

| Target | `PROM_LEDGER_ANCHOR` | What the code guarantees | What the medium must guarantee | Protecting? |
|---|---|---|---|---|
| **Local file** (`FileTipAnchor`) | `file:///path/tip.json` | one file, rewritten in place; no history | nothing can be asked of it | **No — non-protecting.** Development only. The runtime logs a warning naming it so. |
| **Object-lock / WORM directory** (`ObjectLockTipAnchor` over `DirectoryObjectStore`) | `worm:///directory` | one immutable record per tip, named by seq; exclusive create (`link` or `O_EXCL`, OS-enforced); never overwritten or deleted; whole history read | the directory is a write-once medium: a WORM volume, or an object-locked bucket mounted with retention in force | **Yes, while the medium refuses deletion.** On an ordinary filesystem it is as rewritable as the ledger, and the code cannot tell the difference. |
| **Object-lock bucket** (`ObjectLockTipAnchor` over an `ObjectStore` adapter) | programmatic | as above, through a three-operation port (`put_if_absent`, `versions`, `list_keys`) | compliance-mode retention | **Yes, while retention holds.** |
| **Remote append-only log** (`LogTipAnchor` over `HttpAppendOnlyLog`) | `https://host/path` (+ `PROM_LEDGER_ANCHOR_TOKEN`) | one record per tip appended over TLS; redirects refused; reads bounded; whole history read | the log is run by a party the ledger-host adversary is not, and only appends | **Yes, while the operator is a separate party.** |

`worm://` and `https://` are `append_only`; `file://` is not. The flag is on the
target class, the `Config` refuses to pair `PROM_REQUIRE_LEDGER_ANCHOR=1` with a
`file://` target ("cannot be honoured"), and
`test_external_targets_are_append_only_and_the_local_file_is_not` holds the
labels to account.

### What pinning the whole history buys

With one mutable anchor, an adversary holding the anchor's write credential
overwrites it to match the forged chain and wins. With an append-only history,
that credential can only **add** a record:

- a forged record at an already-anchored seq leaves the honest record in place.
  The verifier sees both, and reports `BROKEN` at that seq naming the conflict —
  *"the anchor history holds two different hashes for seq 3"* — because a
  record written past the anchor's own monotonic guard is itself the evidence
  (`test_a_forged_record_appended_with_the_write_credential_is_still_caught_on_object_lock`,
  `test_a_forged_record_appended_to_the_log_is_still_caught`);
- a forged record at a *higher* seq (anchor a longer forged chain) leaves the
  honest lower records pinned, and the rewritten prefix still mismatches them
  (`test_a_forged_record_at_a_higher_seq_does_not_mask_the_honest_history`).

So on an immutable medium the write credential is not enough. What the adversary
needs is authority over the medium itself, which is the trust boundary.

On a versioned, object-locked bucket, an *unconditional* `PutObject` by a
credential holder adds a version rather than replacing one. The port therefore
reads **every version** of every key (`ListObjectVersions`), not "latest":
reading latest is exactly the shortcut that would hand the forger the win.

### Continuous anchoring, and a write that fails

The tip is written to the target **after every `record_chained` commit** — not
on a schedule, not opt-in per call. `build_ledger` is the one place a production
ledger is opened, so every audit-chain append is anchored and every verify
consults the target's whole history (`test_every_append_anchors_the_new_tip`,
`test_the_production_builders_open_an_anchored_ledger`).

The write happens after the commit is durable
(`test_the_tip_is_anchored_after_the_commit_is_durable`), so an anchored tip
never names an entry the ledger does not have. The reverse order would make a
crash between the two read as truncation; this order makes it read as one
honest, un-anchored extra entry — the gap named in the residual.

**A failed anchor write is raised, never swallowed.** The chain entry is
committed, but `record_chained` raises `AnchorUnavailable`, so the caller learns
now that the entry has no witness rather than discovering it during an incident
(`test_a_failed_anchor_write_is_raised_from_the_append`). The chokepoint runner
treats any exception from the append as a failed append: a pre-execution intent
that cannot be anchored is a **hard refusal** — `reason=audit_unavailable`, the
database untouched, the executor never called
(`test_the_runner_refuses_to_execute_when_the_intent_cannot_be_anchored`). A
remote target that answers 500, hangs, or drips is surfaced within the deadline
(`test_a_failed_remote_append_is_raised_within_the_deadline`).

### The detection matrix

| Attack | No anchor | Local file, same medium | External append-only target |
|---|---|---|---|
| Edit / delete / reorder an interior entry | **detected** | detected | detected |
| Append with a forged `prev_hash` | **detected** | detected | detected |
| Truncate the tail | reads as valid | `TRUNCATED` ¹ | **`TRUNCATED`** |
| Delete the ledger (recreated empty) | reads as `valid (0 entries)` | `TRUNCATED` ¹ | **`TRUNCATED`** |
| Full rewrite from genesis | reads as valid | `BROKEN` ¹ | **`BROKEN` at the first anchored seq** |
| Rewrite, then extend the chain past the anchor | reads as valid | `BROKEN` ¹ | **`BROKEN`** |
| Rewrite **plus** a forged anchor record written with the anchor's write credential | reads as valid | **NOT detected** | **`BROKEN`** (conflicting history) |
| Rewrite **plus** authority over the anchor medium (retention lapsed or bypassed; the log's operator) | reads as valid | NOT detected | **NOT detected** |
| The anchor cannot be read | — | `NOT_VERIFIABLE` | `NOT_VERIFIABLE` |

¹ Only while the adversary has left the file alone — which, on the same medium,
nothing obliges them to do. The local-file column is the theatre case.

Every row of the external column is a test in
`tests/chokepoint/test_external_anchor.py`, parametrised over all four external
targets (the in-memory object-lock store, the WORM directory, the in-memory
log, and a real HTTP log server on loopback). None skips.

### The trust boundary, precisely

**The anchor is worth exactly as much as the separation between it and the
ledger-writer's authority, for exactly as long as that separation lasts.**

- **Object lock: the retention window is the boundary.** In compliance mode no
  principal — not the writing credential, not the bucket owner, not the account
  administrator — can delete or shorten a locked version before its
  retain-until date. Once the date passes, anyone with delete permission can.
  The window must therefore outlast the period over which you need a rewrite
  to be detectable. The default requested per record is **3650 days**
  (`PROM_LEDGER_ANCHOR_RETENTION_DAYS`); a shorter window is not a saving, it is
  the residual. Governance mode, which a privileged principal can bypass, does
  not give this property; use compliance mode.
- **WORM directory: the mount is the boundary.** The code creates exclusively
  and never deletes; whether anyone else can delete is the volume's property.
  On a plain filesystem `worm://` is a name, not a guarantee.
- **Remote log: the operator is the boundary.** The ledger host's credential
  may only append and read. The party running the log can replace its storage,
  so the log must be run by a party the ledger-host adversary is not — another
  account, another team, a transparency log. Transport is TLS-only to a remote
  host, with redirects refused and reads bounded, the same discipline as every
  credentialed endpoint (`docs/threat-model.md` §4).

**Detection holds when the anchor medium is genuinely outside the
ledger-writer's authority. It does not hold when the same adversary controls
both.** That is a pair of passing tests, so the claim cannot quietly grow:

- `test_an_adversary_with_authority_over_the_medium_is_NOT_detected_once_retention_lapses`
  — while retention holds the medium refuses the delete and the rewrite is
  `BROKEN`; the clock passes the retain-until date, the adversary deletes the
  honest records and writes matching forgeries, and the verifier reports
  `VALID`.
- `test_the_log_operator_is_NOT_detected` — the log's operator replaces the
  stored history (in memory, and on the real loopback server), and the verifier
  reports `VALID`.
- `test_an_attacker_who_also_controls_the_anchor_is_NOT_detected` (the local
  file) remains, as the control.

### Verifying

```
prometheus-protocol audit --verify-chain
```

prints the configured anchor (`append-only history` or `single file,
NON-PROTECTING`, or `(none)`) and the chain verdict, and exits **2 for anything
but `VALID`** — `BROKEN`, `TRUNCATED` and `NOT_VERIFIABLE` alike. Programmatic
auditors use `verify_ledger_file(path, tip_anchor=…)` or
`verify_rows(rows, expected_tips=history)` with a history obtained from the
target independently.

Run it from somewhere other than the ledger host where you can: the verdict is
only as trustworthy as the process computing it, and a verifier on a
compromised host can be lied to about what it read (that is the config-downgrade
class, PIH-4a's subject).

### The remote log's wire protocol

Three requests, small enough for a witness service to be a few dozen lines:

```
POST <url>              body {"version":1,"seq":N,"entry_hash":"…"}   → 201 {"index":k}
GET  <url>              → 200 {"entries":[record, …]}   (oldest first, the whole history)
GET  <url>/latest       → 200 {"entry": record | null}
```

F4/F5 tighten success without changing the index-only acknowledgement schema:

- POST must return **200 or 201**, with a non-boolean, non-negative integer
  `index`. GET must return **200**, not e.g. 202 or partial-content 206.
- An acknowledgement alone is insufficient. The HTTP adapter reads the whole
  history and requires the **exact canonical JSON record sent** at that index.
  Comparing `/latest` would be wrong if another writer appended in between.
  `LogTipAnchor` independently checks the log port's index and record, including
  custom adapters. Idempotent retries use confirmed history, never `/latest`.
- Responses and submitted objects reject duplicate JSON fields and non-finite
  numbers. Missing, malformed, unbound or unreadable confirmations raise
  `AnchorUnavailable`. A stored-but-unconfirmed write is not reported successful;
  a later retry can succeed once the matching record is visible in history.
- The service must provide **read-after-write consistency** and enforce its
  promised durability and append-only permissions. Read-back catches a faulty
  acknowledgement; it is **not a signed persistence receipt**, proof of fsync,
  or protection against an operator who lies on both POST and GET.

The shared transport validates HTTP framing before parsing JSON. It rejects
short bodies relative to Content-Length, duplicate lengths (even identical),
invalid lengths (only 1–20 ASCII decimal digits after outer whitespace), combined
Content-Length/Transfer-Encoding, and transfer encodings other than a single
`chunked`. Chunk sizes, separators and final trailer termination must be valid
CRLF-delimited framing. Metadata lines are capped at 8 KiB and trailers at
64 KiB. Valid chunk extensions and trailers remain supported. A complete JSON
prefix of an incomplete HTTP message is an error **only when the message's
framing was declared and parsed**. Raw header syntax is not validated: a
header line without a colon makes the permissive parser drop every later
header, `Content-Length` included, the message is then treated as
close-delimited, and a truncated body — a 57-byte body declared as 10000
bytes, carrying an empty `entries` list from a history that was not empty —
reads as a complete, verified history (independent review, finding 3,
reproduced; open). Close-delimited responses remain supported: EOF is their
HTTP boundary, so this cannot detect a server that intentionally sends a
semantically incomplete but correctly framed history.

F6 adds one **monotonic deadline per HTTP request**, beginning immediately before
network work: DNS, TCP address attempts, optional proxy CONNECT, TLS, request
writes, status/headers, framing and body all spend the same budget. The socket
reader applies the remaining timeout below buffering; header and chunk-metadata
drips cannot reset it. A DNS lookup runs in a short-lived isolated Python process
with an empty environment, host/port-only stdin and closed inherited descriptors.
On timeout it is killed and reaped; no resolver thread is left running. Failure
to launch or read the resolver refuses the request with no unbounded fallback.

The budget is **per request**, not per whole ledger operation: POST, read-back
and other history requests each get a budget. Process startup/cleanup and OS
scheduling add overhead; a stuck kernel is not bounded by this mechanism.
Request serialization and response JSON parsing are outside the network budget.
Timing out cannot undo a POST already accepted by the witness; confirmation
remains required and no automatic POST retry is introduced. Each DNS lookup
starts an isolated interpreter, adding process/latency overhead. Deployment must
allow that spawn and ship `core/_dns_worker.py`; ambient resolver overrides such
as `RES_OPTIONS` or `LOCALDOMAIN` are not inherited. System resolver configuration
still applies. F7's approval-at-execution expiry check is separate and unchanged.

`Authorization: Bearer <PROM_LEDGER_ANCHOR_TOKEN>` on every request when a token
is configured. The log must only ever append; the credential must not be able
to do anything else. Records returned by the log are validated field by field
and only ever *pinned against the chain* — nothing from the endpoint is trusted
for its meaning.

### The object-lock bucket port

No cloud SDK is bundled: a bucket client the CI cannot run against a real
bucket would be a guard nobody has seen work. `ObjectStore` is three operations,
and the mapping to an S3-style object-lock bucket is one call each —
`put_if_absent` → `PutObject` with `If-None-Match: *`,
`ObjectLockMode=COMPLIANCE`, `ObjectLockRetainUntilDate`; `versions` →
`ListObjectVersions` + `GetObject` per version; `list_keys` → `ListObjectsV2`.
`MemoryObjectLockStore` is that medium's semantics in memory and is what the
tests prove the anchor logic against, including the medium's refusals
(`test_the_object_lock_medium_refuses_to_overwrite_a_record`,
`test_the_object_lock_medium_refuses_to_delete_under_retention`).

A deployment that writes its own adapter should prove it against its own bucket
before trusting it: create a record, attempt an unconditional overwrite and a
delete with the writing credential and with the account's most privileged one,
and confirm the version listing shows the honest record still present. An
adapter that has not been seen to refuse is the void guard this document keeps
naming.

### Settings

| Setting | Environment | Default | Effect |
|---|---|---|---|
| `ledger_anchor` | `PROM_LEDGER_ANCHOR` | unset | the target; parsed and refused at load if malformed (`http://` to a remote host, a credential in the URL, a relative path, an unknown scheme) |
| `ledger_anchor_token` | `PROM_LEDGER_ANCHOR_TOKEN` | unset | bearer credential for the log; never logged |
| `ledger_anchor_retention_days` | `PROM_LEDGER_ANCHOR_RETENTION_DAYS` | `3650` | retention requested per object-lock record; `1`–`36500` |
| `require_ledger_anchor` | `PROM_REQUIRE_LEDGER_ANCHOR` | off | refuse to build any ledger without an append-only external anchor. The OR of its sources: the environment variable alone raises it, a programmatic `Config(False)` does not lower it. With no anchor, or a `file://` one, construction fails with a `ConfigError` naming the reason. |

A file-backed ledger opened with no anchor logs a warning on every open (*"a
rewrite of the audit chain from genesis, or its deletion, is undetectable"*); a
`file://` anchor logs one naming it non-protecting. Production sets
`PROM_REQUIRE_LEDGER_ANCHOR=1`, which turns both warnings into refusals.

### What this does NOT cover — the residual

- **An adversary with authority over the anchor medium is not detected.** The
  two passing tests above. Retention that has lapsed or was never compliance
  mode, an account that was deleted whole, a WORM mount that was not, a log run
  by the same party — each collapses the witness back onto the adversary's
  medium.
- **The retention window is a deployment choice** and the code cannot check
  that the medium honours it; `retain_for_s` is *requested*. The WORM
  directory target ignores it entirely, since retention there is the mount's.
- **The last entry before a crash may be un-anchored.** Anchoring after the
  commit means a crash between the two leaves one honest, un-witnessed entry,
  which reads as a valid chain one entry longer than the anchor knows. A crash
  during the anchor write itself raises on recovery only if the caller retries.
- **Anchoring is off by default.** In-memory and throwaway ledgers have nothing
  to anchor, and a development install has no witness to point at. The default
  is a warning; the production posture is `PROM_REQUIRE_LEDGER_ANCHOR=1`,
  which refuses instead. Stated in `docs/threat-model.md` §5.4.
- **The history grows by one record per append and is read whole on verify and
  log writes.** A new HTTP-backed log write performs three history reads: the
  monotonic/idempotence check, HTTP adapter confirmation, and log-port confirmation.
  The remote log's read ceiling is 64 MiB, room for several hundred thousand
  records; the directory and bucket targets list every key. Pruning old
  records is a log-operator decision that trades detection window for size,
  and nothing here does it.
- **A verifier pointed at the wrong anchor sees nothing.** Whoever can change
  `PROM_LEDGER_ANCHOR` on the verifying host can point it at an empty prefix.
  That is the silent-config-downgrade class, and the subject of PIH-4a (signed
  config digests), not of this document.
- **No bucket adapter is shipped.** The port is documented; the adapter is the
  deployment's, and must be proven against the real bucket as described above.
- **Detection, not prevention.** Everything here makes tampering *evident* after
  the fact. Nothing stops a writer with file access from making the change.

## Threat-model fit

For the chokepoint experiment (`docs/chokepoint-threat-model.md`), the relevant
adversary is a **sandboxed agent**, which by construction cannot reach the runner
zone where the ledger lives — so the realistic in-file tampering this chain makes
evident is a defense-in-depth property of the trusted zone, not the agent's
surface. The full-rewrite / truncation limits matter for an adversary who
already has runner-host write access — Attacker 3 and the privileged insider —
and the external anchor is what turns that adversary's rewrite from silent into
witnessed. See `docs/threat-model.md` §3.
