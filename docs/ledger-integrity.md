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
  is the one deterministic payload serialization. Verification re-canonicalizes
  the parsed payload, so a semantic edit changes the hash while incidental
  whitespace does not.
- **Append is append-only in fact.** `record_chained` reads the current tip and
  chains onto it; the caller **cannot** pass `prev_hash`, so a forged-prior-hash
  append is impossible through the API. Direct-file forgery of a wrong `prev_hash`
  is caught at verify.

## The verifier

`verify_chain()` (and the standalone `verify_rows(rows)`) walk the chain in
insertion order from genesis and report the **first** failure with its index and
a specific reason — never a bare boolean:

```
clean 5-entry chain      : chain valid (5 entries)
edit interior entry 3    : chain BROKEN at entry 3: content edited: stored hash a09e767d…, recomputed a19c4bc8…
delete interior entry 3  : chain BROKEN at entry 4: seq discontinuity: expected 3, found 4 (an interior entry was deleted or reordered)
truncate tail (no anchor): chain valid (3 entries)
truncate tail (anchored) : chain TRUNCATED at entry 3: chain ends at seq 3 but the anchored tip is seq 5: 2 entrie(s) truncated
corrupt payload entry 2  : chain NOT_VERIFIABLE at entry 2: entry payload is not decodable JSON
```

It is callable independently — an auditor runs it over the rows; it is not only
an internal check.

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
- a **rewritten tip**, when an out-of-band tip anchor is supplied (tip-hash
  mismatch).

**Does NOT detect on its own — named limits, not silent gaps:**
- **Pure tail-truncation.** Lopping entries off the end leaves a shorter but
  internally-valid chain; the chain alone cannot know entries once existed.
  *Mitigation, implemented:* `chain_tip()` returns the current `(seq, hash)`; an
  auditor holds it out-of-band and passes it as `expected_tip` to `verify_chain`,
  which then reports `TRUNCATED`. Without such an anchor, truncation reads as
  valid — and the verifier says "valid (N entries)", so the honest move is to
  anchor the tip.
- **A full rewrite from genesis.** An adversary who can rewrite *every* row can
  recompute a wholly self-consistent chain. A bare in-file chain cannot detect
  this; only an externally **anchored or signed** tip (the same `expected_tip`
  mechanism, or a signature over the tip held elsewhere) closes it. This is the
  boundary of "tamper-evidence in one file," and it is deliberately not
  overclaimed.

**Never silently "valid".** If the verifier cannot actually check an entry — a
missing/None field, or a payload that is not decodable JSON — it returns
`NOT_VERIFIABLE` for that entry, distinct from `BROKEN` and distinct from `VALID`.
Couldn't-verify is not verified-clean; this is the EX-1 `Unavailable` distinction
applied to the ledger's own integrity check.

## Threat-model fit

For the chokepoint experiment (`docs/chokepoint-threat-model.md`), the relevant
adversary is a **sandboxed agent**, which by construction cannot reach the runner
zone where the ledger lives — so the realistic in-file tampering this chain makes
evident is a defense-in-depth property of the trusted zone, not the agent's
surface. The full-rewrite / truncation limits matter only for an adversary who
already has runner-host write access (out of scope for the chokepoint sprint per
that model); anchoring the tip is the documented next step for that stronger
model.
