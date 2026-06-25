# ADR 0001: Baseline architecture for the open core

- Status: accepted
- Date: 2026-06-25

## Context

We are scaffolding the open core of a verifiable, reversible, self-improving
learning runtime. We need boundaries that keep the safety story enforceable in
code, keep the project vendor-neutral, and stay simple enough to review.

## Decision

1. **Five service interfaces in `core`** — Provider, Verifier, Registry, Gate,
   Ledger — each implemented in its own package depending only on `core`.
2. **The held-out firewall lives in the gate**, as a single guarded function
   (`assert_disjoint`) called on every promotion, plus a matching guard in the
   forge. The invariant is enforced at runtime, not just documented.
3. **The provider boundary is vendor-neutral and config-driven.** A remote
   provider speaks the chat-completions request shape over the standard library
   with no third-party dependency; a deterministic simulated provider is the
   default so the loop runs offline.
4. **The registry is a folder of markdown files.** Skills are meant to be read
   and reviewed by people and to diff cleanly; this also makes promotion
   trivially reversible.
5. **The ledger is append-only SQLite.** Auditability and reversibility follow
   from recording every attempt and promotion in order.
6. **The public API is one file** (`__init__.py`). It is the open-core line:
   what it exports is supported; everything else is internal.
7. **No third-party runtime dependencies.** The runtime uses only the standard
   library; test and build tooling are optional dev extras.

## Consequences

- The "model read the test" and "trained on the held-out set" failure modes
  are structurally prevented, not merely discouraged.
- Swapping models is a configuration change.
- The verifier is explicitly not a sandbox; containerisation is a documented,
  mandatory prerequisite for untrusted code (see `docs/security-model.md`).
- Keeping to the standard library constrains some conveniences (for example,
  hand-rolled markdown front-matter parsing) in exchange for a tiny dependency
  surface.
