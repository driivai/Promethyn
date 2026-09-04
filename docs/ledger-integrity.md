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
```

(The "dup-key edit" case commits to exact stored bytes, so an edit that a JSON
parser would normalize back to the original is still caught; "honest append past
anchor" stays valid while "full rewrite + extend" is caught — the anchor pins the
entry at its seq regardless of later growth.)

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
- a **rewrite of the prefix up to an anchored point** — including a full rewrite
  from genesis, and a rewrite that then *extends* the chain past the anchor —
  **when an out-of-band tip anchor is supplied.** `verify_chain(expected_tip=…)`
  pins the entry at the anchored `seq`: because each entry commits to its
  predecessor, that one hash pins the whole prefix down to genesis, so any rewrite
  at or before the anchor is caught regardless of how far the chain has since
  grown (honest appends past the anchor stay valid).

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

## The tip anchor — now operational, not merely available

All three limits above are closed by an out-of-band anchor, and PROM-HARDEN-MAX
§3 made that anchor real rather than possible. `chain_tip()` and
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

**The anchor is worth exactly as much as its separation from the ledger.** An
anchor file beside the ledger, on the same disk, writable by the same account,
defends against nothing: whoever rewrites the chain rewrites the anchor with it.
That case is a passing test
(`test_an_attacker_who_also_controls_the_anchor_is_NOT_detected`) rather than a
caveat in prose, so the limit cannot quietly erode. For the anchor to mean
anything it must live in a trust domain the ledger-file adversary cannot write:
an append-only or write-once store, another host, a mount that is read-only from
the ledger host, or a signed digest recorded elsewhere. The code takes a path and
writes to it; **placement is a deployment property**, and it is the one that
decides whether any of this closed anything. See `docs/threat-model.md` §3.4.

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
