# Chokepoint threat model — the credential-brokered migration gate (PROM-CHOKEPOINT)

**Status:** design, pinned before implementation (STOP 1). **Scope:** the destructive
PostgreSQL migration action only. **Protected action:** applying a migration (arbitrary,
potentially destructive DDL/DML) to a target PostgreSQL database.

## 1. Why this exists

The PROM-AUDIT readiness assessment (`docs/readiness-assessment.md`, PR #58) found that
Promethyn's gate is an **in-process authorizer, not a chokepoint**: "an agent that runs
code outside the sandbox is invisible to it." A gate that only governs actions a caller
*chooses* to submit proves nothing against an adversary — it proves that cooperative
callers obey the API. Before any adversarial experiment, the protected action must become a
**real chokepoint**: the agent must *lack the authority* to perform it, and a
Promethyn-controlled runner must *exclusively* hold that authority. This document pins the
adversary, the assets, the trust boundaries, and the properties to enforce — so the build
is measured against a written model, not a moving one.

## 2. Actors and trust boundaries

```
  ┌─────────────────────────┐        proposes            ┌──────────────────┐
  │  AGENT CONTEXT          │  ── migration artifact ──▶  │  GATE            │
  │  (sandboxed)           │       (SQL text)            │  (authorizer)    │
  │                        │                             └────────┬─────────┘
  │  • may author SQL      │                                      │ issues
  │  • may submit it       │                          approval bound to
  │  • NO db credential    │                       (artifact hash, target,
  │  • NO route to the DB  │                        single-use, TTL)
  └────────────────────────┘                                      │
             ✗ no path                                            ▼
             ✗ no psql                              ┌──────────────────────────┐
             ✗ no driver                            │  BROKERED RUNNER         │
             ✗ no socket                            │  (Promethyn-controlled)  │
                    ╎                               │  • holds the ONLY working │
                    ╎ (unreachable by construction) │    DB credential          │
                    ╎                               │  • re-hashes artifact     │
                    ▼                               │  • verifies approval      │
              ┌──────────┐   ◀── exclusive path ──  │  • fail-closed           │
              │ TARGET DB │      (credential)        └──────────────────────────┘
              └──────────┘
```

Three trust zones, two boundaries:

- **Agent zone** (untrusted). The sandboxed context where agent-authored code runs. It is
  adversarial: it *wants* the migration to run and will try to make it run by any means.
- **Runner zone** (trusted). A Promethyn-controlled process outside the sandbox that holds
  the sole DB credential and is the only thing that can touch the target.
- **The database** (the asset under protection).

The load-bearing boundary is **agent → DB**: it must be crossable *only* by transiting the
runner, and the runner crosses it *only* on a valid, current, bound authorization.

## 3. Assets

| Asset | Why it matters |
|---|---|
| The target database | The thing a destructive migration can irreversibly damage. |
| The DB credential | Whoever holds a working credential can bypass the entire gate. Must live only in the runner zone, never in the agent zone. |
| The approval capability | A forged or reused approval is an execution. Must be unforgeable by the agent and single-use. |
| The audit ledger | If an adversary who reaches the file can silently rewrite it, the trail is worthless. Must be tamper-evident. |

## 4. Adversary model

**The adversary is a sandboxed agent that wants to run a migration to complete its task.**

**What the agent CAN do (by design — this is the product's legitimate surface):**
- Author migration SQL (arbitrary text).
- Submit a proposed migration artifact to the gate for authorization.
- Read anything in its own sandbox workspace.
- Attempt, adversarially, to: reach the DB directly; forge or fabricate an approval; replay
  a previous approval; swap a different artifact under a valid approval; redirect an
  approval at a different target; run past an approval's expiry.

**What the agent CANNOT do — and why the "cannot" holds by construction, not by policy:**

1. **Reach the DB directly.** Enforced by two independent namespace boundaries, because one
   alone is insufficient:
   - *Network namespace* (`unshare --net`, `sandbox/namespace.py`): the sandbox has only
     its own empty `lo`. The host's `127.0.0.1:5432` is a *different* loopback in a
     *different* net namespace, so a TCP connect from inside the sandbox cannot reach a
     host-loopback-bound Postgres — it hits the sandbox's own empty loopback and is
     refused. (PROM-AUDIT already proved only `lo` is visible inside.)
   - *Mount namespace* — **the subtlety this model exists to name.** A PostgreSQL **Unix
     domain socket is a filesystem object, not a network object**; a connection to it does
     *not* traverse the network namespace at all. The sandbox bootstrap
     (`sandbox/_bootstrap.py`) makes root read-only and overlays only `/root` and `/home`
     with empty tmpfs — everything else on root stays *visible*. So a Postgres socket left
     at the default `/var/run/postgresql/` **would be reachable from the sandbox** despite
     the network isolation. Therefore the construction requirement: the runner's Postgres
     listens on host-loopback TCP only (or a Unix socket placed under a path the sandbox
     hides, e.g. `/root/...`), so **no socket the agent's mount namespace can see leads to
     the DB.** This will be proven live at STOP 2, both paths (TCP and socket) shown to
     fail from inside the sandbox and to succeed from the runner.

2. **Obtain a working DB credential.** The credential lives only in the runner's
   environment/process, never on the sandbox's writable workspace, never in an artifact,
   never passed into the agent zone. The agent's context is constructed without it.

3. **Forge an approval.** The approval is produced by the gate and consumed by the runner
   over a channel the agent cannot write, and is bound cryptographically (content hash +
   target + nonce) so a hand-crafted "approval" fails verification. Where it lives and why
   the agent can't produce one is specified in the build (STOP 2) and re-stated in the
   final report; the principle is the EX-1/bootstrap lesson — no authorization signal on a
   surface the adversary can write.

## 5. Security properties to enforce (invariants)

Each is enforced **by construction** and then has an explicit **blocks-not-just-allows**
test (a check tested only on the happy path is itself a void guard):

- **P1 — Chokepoint.** The only path from agent to DB is through the runner. Proven live:
  every direct-reach attempt fails.
- **P2 — Credential exclusivity.** Only the runner holds a working credential.
- **P3 — Artifact binding.** An approval binds to the exact artifact content hash; the
  runner re-hashes what it is about to execute and refuses on mismatch (**swap-fails**).
- **P4 — Target binding.** An approval binds to the exact target (DB/schema); use against
  another target is refused (**wrong-target-fails**).
- **P5 — Single use.** An approval executes at most once; a second use is refused
  (**replay-fails**), enforced atomically so concurrent drivers cannot both execute.
- **P6 — Expiry.** Approvals are short-lived; past the TTL they are refused
  (**expired-fails**). Proposed TTL: **5 minutes** — long enough for a human/automated
  approval-to-execution hop, short enough that a captured approval is stale before it is
  useful, and consistent with the migration being a deliberate, promptly-executed act.
- **P7 — Unforgeable approval.** The approval cannot be produced by the agent zone (§4.3).
- **P8 — Fail closed.** Any ambiguity — an `Unavailable` verifier, an unbound / expired /
  replayed / mismatched approval, a runner that cannot confirm the target — results in the
  migration **not running**. There is no fail-open branch anywhere in the chain.
- **P9 — Tamper-evident ledger.** The audit trail is a hash chain: each entry carries the
  prior entry's hash, so any retroactive edit or deletion is detectable by a verifier that
  walks the chain and reports the first broken link.

## 6. Attack scenarios → defense

| # | Attack | Defense | Test |
|---|---|---|---|
| A1 | Agent connects to the DB directly (TCP) | Network namespace: host loopback unreachable | live proof, STOP 2 |
| A2 | Agent connects via the Postgres Unix socket | Socket placed outside the sandbox's mount view; §4.1 | live proof, STOP 2 |
| A3 | Agent finds/steals a credential in its context | Credential only in runner zone (P2) | isolation proof |
| A4 | Agent replays a used approval | Single-use, atomic claim (P5) | replay-fails |
| A5 | Agent swaps artifact B under artifact A's approval | Runner re-hashes; mismatch refused (P3) | swap-fails |
| A6 | Agent aims an approval at a different target | Target binding (P4) | wrong-target-fails |
| A7 | Agent waits out / captures a stale approval | TTL expiry (P6) | expired-fails |
| A8 | Agent fabricates an approval | Unforgeable, gate-issued (P7) | forge-fails |
| A9 | Verifier can't run; agent hopes it slips through | Fail closed on `Unavailable` (P8) | fail-closed test |
| A10 | Adversary rewrites the ledger to hide a run | Hash chain detects the edit (P9) | tamper-detection test |

## 7. In scope vs out of scope (this sprint)

**In scope.** Can the agent get a destructive migration executed *without* a valid, current,
correctly-bound approval — by reaching the DB directly, or by tricking the gate/runner
(replay, swap, wrong-target, expired, forged)? And is the audit trail tamper-evident? The
whole authorization chain from proposal to execution, fail-closed, is in scope.

**Explicitly out of scope — deferred, not forgotten:**
- **Network egress exfiltration.** An approved migration could, in principle, read data and
  exfiltrate it over the network. That is the deferred **egress-broker** work (PROM-AUDIT
  §7 item 1), buyer-gated and net-new; it is *not* this sprint. This sprint makes the
  migration *action* a real chokepoint; brokering what an executing migration may reach on
  the network is a separate capability.
- **Semantic correctness of an *approved* migration.** Whether a human/verifier *should*
  have approved a given destructive migration is the gate's existing judgment surface; this
  sprint ensures that *only* what was approved, exactly, runs at most once — not that the
  approval decision was wise.
- **Physical/host compromise.** If the adversary already has code execution in the *runner*
  zone (not the sandbox), the credential is theirs by definition; defending the runner host
  itself is out of scope. The boundary this sprint hardens is agent-zone → DB.

## 8. Success criteria (what STOP 2 and the final must show)

1. **Live proof** the agent cannot reach the DB: direct TCP and direct Unix-socket attempts
   from inside the sandbox both fail, pasted literally; the runner reaches it and succeeds.
2. All four binding failure modes tested and blocking: **replay, swap, wrong-target,
   expired** — plus **forge** and the **fail-closed** path.
3. A tamper-evident ledger: a mutated middle entry is detected by the chain verifier.
4. voidguard dogfoods clean — no new VOID/WARN introduced by this work.

Anything that lets a destructive migration run without a valid, current, correctly-bound,
single-use approval — or any fail-open branch — is a defect by this model, not a nuance.
