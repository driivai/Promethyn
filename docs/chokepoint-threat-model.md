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
| The PostgreSQL execution receipt | Proves whether an intent committed when the runner dies before recording its audit outcome. It must commit atomically with the migration. |

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

     > **Update (PROM-HARDEN-MAX, attacker 1).** The gap named here is no longer
     > discharged by a deployment requirement. The bootstrap now hides `/tmp`,
     > `/var/tmp`, `/dev/shm`, `/run` and `/var/run` as well, so a socket at either
     > stock PostgreSQL location is unreachable by construction rather than by the
     > operator remembering. The overlay is also unconditional: it previously skipped
     > any directory containing the workspace, and since workspaces come from
     > `tempfile`, `/tmp` was routinely left exposed. See `docs/threat-model.md` §1.

2. **Obtain a working DB credential.** The credential lives only in the runner's
   environment/process, never on the sandbox's writable workspace, never in an artifact,
   never passed into the agent zone. The agent's context is constructed without it.

   > **Correction (PROM-HARDEN-MAX, attacker 1).** This was written as an achieved
   > property and was not one. The namespace sandbox launched the candidate with
   > `subprocess.run(...)` and no `env=` argument, so Python passed the runner's entire
   > environment through — including `PGPASSWORD` and `PROM_CHOKEPOINT_KEY`, the approval
   > signing key. An agent holding that key mints its own approvals, so this was a total
   > bypass that required no connection at all. The agent's environment is now *built*
   > from six fixed non-secret values rather than inherited, and
   > `tests/chokepoint/test_agent_zone_containment.py` proves it (and fails when the fix
   > is removed). See `docs/threat-model.md` §1.

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
- **P4 — Target binding.** An approval binds to a canonical target object containing
  host, port, database, database user, and schema. A credential rotation does not change
  that identity, but a principal/privilege or schema change does; use against any different
  target is refused (**wrong-target-fails**).
- **P5 — Single use.** An approval executes at most once; a second use is refused
  (**replay-fails**). The runner requires a durable filesystem-backed spent-nonce store;
  SQLite's unique claim is serialized within a process and atomic across processes, so
  concurrent drivers cannot both execute and a restart cannot forget a spent approval.
  Spent nonces are intentionally retained rather than pruned: deleting one could revive a
  replay if the host wall clock later moved backward into that approval's validity window.
- **P6 — Expiry.** Approvals are short-lived; past the TTL they are refused
  (**expired-fails**). Default TTL: **90 seconds** — the clock starts after human or
  automated authorization, so it covers only the approval-to-execution hop. Exact-boundary,
  non-finite-time, and serialization tests keep the deadline fail-closed.
- **P7 — Unforgeable approval.** The approval cannot be produced by the agent zone (§4.3).
- **P8 — Fail closed.** Any ambiguity — an `Unavailable` verifier, an unbound / expired /
  replayed / mismatched approval, a runner that cannot confirm the target — results in the
  migration **not running**. There is no fail-open branch anywhere in the chain.
- **P9 — Tamper-evident ledger.** The audit trail is a hash chain: each entry carries the
  prior entry's hash, so any retroactive edit or deletion is detectable by a verifier that
  walks the chain and reports the first broken link. The runner must commit an execution
  intent before database contact; an unavailable intent append blocks execution. The
  outcome links back to that intent, so a post-execution audit outage leaves a durable,
  explicitly unresolved record rather than making the run disappear.
- **P10 — Crash-reconcilable execution.** Each intent carries a stable execution ID bound
  to the approval nonce, artifact hash, and canonical target. The executor holds a
  PostgreSQL advisory lock for that ID and inserts a matching row in
  `promethyn_internal.migration_receipts` in the same transaction as the migration. After
  restart, a matching receipt proves commit. An absent receipt proves non-commit only
  after acquiring **both** the trusted cross-process execution/recovery guard and the
  PostgreSQL receipt lock: the earlier owner cannot resume and no transaction is active.
  An active, unavailable, malformed, or conflicting receipt blocks
  every later migration for that canonical target. Artifact-level transaction-control statements are rejected before
  connection so SQL cannot commit separately from its receipt. The runner role therefore
  requires permission to create the reserved receipt schema/table when absent; a
  pre-provisioned deployment instead needs `USAGE` on the schema and `SELECT`/`INSERT` on
  the table.

### Recovery follow-up: F2/F3

An executor exception or negative boolean is not proof of rollback: COMMIT may
have reached PostgreSQL while its response was lost. The executor now reports
`committed`, `not_committed`, or `execution_unknown`. The latter creates an
`execute_unknown` event and leaves the intent pending. Only an acknowledged
commit, acknowledged rollback, pre-execution refusal, or successful receipt
reconciliation produces a terminal outcome. A rollback attempted after losing
a COMMIT response cannot resolve the uncertainty. Callers must inspect
`MigrationResult.execution_state`, not infer rollback from `executed=False`.

Recovery revisits historical false outcomes without an explicit execution state;
old `migration_error` events could represent committed transactions. An old
acknowledged success remains terminal. Reconciliation does not execute SQL again.

The guard is a nonblocking `flock` on the approval store's own inode (a
descriptor opened once at construction and held for the store's lifetime;
PROM-FIX-B), held from before reconciliation through nonce claim, intent
append, execution, and outcome append. It also gates standalone
reconciliation. Contention refuses the new migration without consuming its
approval. Process suspension retains ownership; process death releases it. A
surviving PostgreSQL transaction is separately protected by its session
advisory lock. No age-based takeover is used.

**Deployment boundary — partly checked (PROM-FIX-A), lock identity enforced
(PROM-FIX-B).** The guard is an OS file lock, which is mutual exclusion only
where one kernel grants every lock *and every runner locks the same object*:
a local filesystem on one host, one lock per store. Until PROM-FIX-A that
requirement was the previous version of this paragraph — a sentence an
operator had to remember, with nothing in the process to notice a deployment
that broke it, and in such a deployment the F3 race was live. PROM-FIX-A added
two checks; the independent review found each narrower than this paragraph
then claimed ("checked, not assumed"), and its meta-finding — "local
filesystem recognised" is not "every runner holds the same exclusive execution
guard" — is what PROM-FIX-B answers for the lock itself. The 1A/1B follow-up
adds opened-object substrate inspection and topology-aware parent preflight.

- **Substrate (1A/1B).** `ConsumedApprovals` retains a conservative parent
  preflight before creation, including SQLite sidecar placement, then inspects
  the actual opened store descriptor before SQLite initialization. That same
  descriptor is PROM-FIX-B's lock object; its device/inode identifies the lock,
  while its Linux `fdinfo` mount ID selects exactly one `mountinfo` entry whose
  device must agree with `fstat`. An alias's mount ID may differ without
  changing the lock's device/inode identity. The held descriptor is reinspected
  before every guard acquisition, including after a fork reopens it.
  The preflight retains mount IDs and parent IDs and follows visible children:
  overmounting `/srv` hides the lower mount's `/srv/private` descendant, even
  though the latter has a longer pathname. Duplicate identities, cycles,
  disconnected covering mounts and competing visible children are refused as
  unverified, not resolved by line order. Neither device-only matching nor a
  pathname fallback can establish an opened object's identity.
  Mount roots are not always pathnames, and the shapes recognized here were
  **measured before they were recognized** — `scripts/mountinfo_diagnostic.py`
  reports the per-row distribution (driver, root format class, whether the
  parser reads it) on every Linux CI job. Recognized today: an absolute
  normalized pathname (an ordinary mount, a bind mount of a subdirectory, a
  btrfs subvolume root); the same with a trailing `//deleted`, which the
  generic dentry path printer appends for an unlinked source — not scoped to a
  driver, because no driver emits it, and produced from a real mount by the
  Linux integration suite rather than asserted from a fixture; and
  `name:[inode]` for `nsfs` only, which `nsfs_show_path` writes for namespace
  files. Recognition decides only whether a row is *read*: the driver is what
  is classified, no driver is added to a safe list by recognizing its root
  shape, and mount points still require absolute normalized paths for every
  shape. An `nsfs` row remains unverified if it is the target.
- **Relevance scoping (SUBSTRATE-ROBUST).** A row this parser cannot read no
  longer fails the whole table. Each row is read on its own terms; a row that
  is not readable is retained as an `UnparsedEntry` carrying whatever *was*
  readable — its mount id, parent id and above all its mount point — plus the
  raw line and the reason. A row is **never dropped**: a dropped row is a
  mount that is not there to be reasoned about, which is the hiding case.
  Each resolution then decides whether an unread row could affect *it*. The
  rule, deliberately conservative — a row is set aside only where it is
  established that it cannot matter:
  - its mount point is an ancestor of the target, or the target itself (an
    overmount can hide the mount that would otherwise answer, and a row at the
    same pathname is a member of that pathname's mount stack) → **relevant**;
  - its mount point is at or below the target (any row inside the subtree the
    store lives in could shadow a component that resolution or the store's own
    creation traverses; no attempt is made to prove a particular descendant
    harmless) → **relevant**;
  - its mount point is not readable at all, so none of the above can be ruled
    out → **relevant**. An entry whose location is unknown is never set aside.
  - anything else — a row on a wholly unrelated subtree — is **recorded and
    set aside**, and does not affect the verdict.

  For the opened-object join the same rule is keyed to identity rather than
  location: the descriptor's mount is the one `fdinfo` named, so a row that was
  readable enough to name a *different* mount id cannot be it, while a row
  whose mount id is unreadable might be. Topology anomalies — a parent that
  does not contain its child, a parent cycle, a self-parent away from `/`, a
  duplicated mount id — are the same kind of finding as an unreadable row: the
  row is demoted to an unread row (keeping its location, so relevance can still
  rule it out) instead of poisoning rows that are coherent. What was set aside
  is carried on `SubstrateReport.set_aside`, named in every refusal and warning
  `enforce_substrate` emits, logged at debug on every classification, and
  printed by `scripts/mountinfo_diagnostic.py`. Setting a row aside silently
  would be the void-guard version of this fix.

  The verdicts are unchanged in kind: a clean resolution answers safe/unsafe;
  a relevant unread row, or a topology the resolver cannot settle, is
  `unknown` and refuses. This sprint reduces false refusals; it relaxes
  nothing. **The set of recognized mount-root formats is empirical, not
  exhaustive**, and an unrecognized format on the resolution path refuses
  startup — an availability property an operator will meet, and the deliberate
  trade for not guessing: refuse on surprise, never bypass on surprise.
  Where the inspected object or preflight identifies a known
  network or host-shared filesystem — NFS, CIFS/SMB, 9p, virtiofs, vboxsf,
  Ceph, GFS2, OCFS2, Lustre, AFS, sshfs/glusterfs/s3fs and the like — the
  store is **refused** with `ConfigError`, and there is no opt-out. A filesystem the probe cannot identify — an overlay
  (its lower layers are not visible from inside it, and copy-up gives one path
  two inodes), a generic FUSE mount, a driver the probe does not know, or a
  platform without a mount table — is refused by default: couldn't-verify is
  not verified-safe. `allow_unverified_substrate`
  (`PROM_ALLOW_UNVERIFIED_SUBSTRATE`) is the explicit opt-out for that case
  only, logged as a warning at every accepted inspection; `require_verified_substrate`
  (`PROM_REQUIRE_VERIFIED_SUBSTRATE`, the OR of its sources) withdraws it, and
  the pair set together is refused as incoherent. Environment sources use the
  strict parser from PROM-FIX-B; programmatic values and direct policy fields
  must be actual booleans, and a true earlier source does not suppress
  validation of later sources. A recognized local filesystem — ext4,
  xfs, btrfs, tmpfs, f2fs, zfs, and the other names in
  `substrate.SAFE_FILESYSTEMS` — proceeds. Parent-preflight refusal creates
  nothing. An opened-object refusal can leave an empty newly created file,
  but happens before the store's SQLite initialization. `AuthorizationJournal`
  inspects its separately existing file through `O_PATH` before issuance and
  around operation opens, enforcing the same policy and checked inode identity.
- **Lock identity (PROM-FIX-B, finding 2).** The guard used to be an `flock`
  on a companion file named after the store's path. The independent review
  reproduced, with real subprocesses, hard links, SQLite and OS locks, what
  that means: two hard links to one store inode gave two runners two lock
  files, both acquired, and recovery recorded `reconciled_not_committed` for
  an owner that was still running — the lock proved exclusion over a *path*,
  not over *the store*. The guard is now an `flock` on a descriptor of the
  store's own inode, opened once at construction and held for the store's
  lifetime, released with `LOCK_UN`. The kernel evaluates `flock` conflicts
  per inode, across processes, so every alias of the store — a hard link, a
  file bind mount, a symlink — contends for one lock object by construction.
  Two threads of one process contend through an in-process mutex (a second
  `flock` on the same open file description would merely convert the lock);
  a forked child contends with a descriptor of its own. Before every
  acquisition the descriptor is re-checked to still be the inode at the
  store's path, private, owned, and singly linked; a store with a second
  name is refused at construction and refused before use if the name was
  added later (`_MultiplyLinkedStore` → `approval_store_unavailable`). The
  descriptor is never closed while the SQLite connection is open, because
  closing any descriptor of a file drops the process's POSIX locks on that
  file — the locks SQLite holds inside a transaction; `flock` locks are
  independent of those on Linux, which is the platform the guard is
  specified for, and elsewhere it refuses (`_PlatformUnsupported`) rather
  than risk the interaction. Rejected as insufficient, as the review
  pre-empted: `realpath()` (hard links survive it), refusing symlinks (both
  lock files were valid regular files), comparing the store's inode to its
  own saved inode (both aliases pass), and checking the link count only at
  startup (aliases can appear later, and a file bind mount does not raise
  the link count at all — only an inode-keyed lock excludes it).
- **Owner identity.** Every `execute_intent` records the owner's hostname,
  kernel boot id, machine id, pid, and the identity of the lock it held
  (`owner_lock_id`, the store inode's `dev:ino`; `chokepoint/ownership.py`).
  A recovering runner compares that record with itself before it may read
  "no receipt" as "not committed": the same boot id *and* the same lock
  identity means the owner locked the inode this runner now holds
  exclusively, so the owner is gone; the same boot id with a different or
  unrecorded lock identity means a held lock proves nothing about it
  (`lock_mismatch`); the same machine id *and* hostname under another boot
  id means this machine rebooted and the owner did not survive it, whatever
  lock it held; anything else means the owner may be alive on another host
  (`foreign`); an intent with no identity at all establishes nothing
  (`legacy`). Everything not established is reported `owner_unverifiable`
  and left pending — its receipt is not even consulted. It is never recorded as
  `reconciled_not_committed` by a runner that could not place its owner, and
  the runner's own execution path (`execute`) never asserts otherwise: new
  approvals for that target are refused `reconciliation_required`, unspent.
  An operator who has established by other means that the owner is dead
  reconciles with `reconcile_unfinished(assume_owner_dead=True)`; the outcome
  event then records `owner_override: true`, `owner_basis` and
  `reconciled_by_host`, and the runner logs the assertion.

Multi-host execution is still **not supported**. What changed is that the
unsupported case fails closed — refused at construction, or left pending with
its reason — instead of producing false recovery evidence.

**Still undetectable, stated plainly:**

- A filesystem that is local *here* and exported from here to other hosts.
  This host sees ext4 and proceeds; the other hosts see NFS and refuse, so the
  case is closed from their side, not this one.
- Two hosts with the same hostname *and* the same machine id (cloned images
  that kept `/etc/machine-id`) sharing a store on a substrate that passed the
  probe or was opted out of: the second host's recovery reads the first as
  "this machine, rebooted". Both conditions must hold at once, behind the
  substrate check.
- A kernel that reports no boot id and no machine id (some sandboxed
  runtimes; non-Linux hosts): every recorded owner other than this exact
  machine is unplaceable, so recovery stays pending until an operator asserts
  otherwise. Fail closed and noisy — a wedge, not a race.
- Intents written before ownership identity existed (`owner_basis: legacy`),
  and intents written by PROM-FIX-A runners that recorded a host but no lock
  identity (`lock_mismatch`), establish nothing about their owner and stay
  pending until an operator who has established it by other means reconciles
  with `assume_owner_dead=True`. The window is the upgrade itself, and it
  fails closed: a wedge an operator resolves on the record, not a race.
- **The recognized mount-root formats are empirical, not exhaustive.** They
  were added from formats actually observed on the hosts this runs on, not
  from a reading of the kernel's `show_path` implementations, and the next
  kernel or driver may write a shape this parser has not seen. On the
  resolution path that shape refuses startup; off it, it is recorded and set
  aside. So the residual an operator meets is availability, not a silent
  bypass — and `scripts/mountinfo_diagnostic.py`, which runs on every Linux CI
  job, is how the distribution keeps being measured rather than guessed.
- Relevance is decided from mount points as canonical pathnames. A row whose
  location the kernel wrote in a form this parser cannot compare is treated as
  relevant everywhere (it refuses), never as unrelated.
- The kernel, proc metadata, parent directories and mount namespace remain
  trusted. Linux metadata absent from this namespace, malformed topology or
  disagreement between descriptor and mount device is unverified, not guessed.
  Concurrent privileged mount replacement and path replacement are outside
  this guarantee: Python SQLite opens by pathname, not by our inspected
  descriptor, so the inspection and SQLite open are not one atomic VFS action.
  Do not remount or replace storage while runners exist.
- A recognized filesystem driver establishes the supported single-kernel
  locking assumption, not storage-controller behavior, truthful fsync, shared
  block-device exclusivity or survival across power loss. tmpfs/ramfs remain
  recognized for locking but are volatile; use persistent local storage for
  replay protection across reboot. Overlay layers and unrecognized drivers
  remain unverified. The opt-out does not prove any of these properties.
- Issuance through `AuthorizationJournal` checks the audit file's substrate;
  a bare `SqliteLedger` or a custom runner audit sink does not gain this check
  automatically. Independent stores sharing one ledger do not become one
  execution lock: recovery still depends on the recorded owner/lock identity.
- The guard is specified for Linux. On any other platform `execution_guard`
  refuses, so `execute` and `reconcile_unfinished` report
  `approval_store_unavailable` there even under the substrate opt-out.
- As before: do not replace or unlink the store while runners exist, or mix
  old unguarded runners with new ones during upgrade (stop the old processes
  first). Missing OS locking support refuses execution. Asynchronously
  detached custom executors are outside this ownership model; custom
  executors must stop all execution activity before returning, and persist
  receipts atomically with approved SQL.

`tests/chokepoint/test_execution_recovery.py` exercises unknown/legacy outcomes,
commit-vs-rollback acknowledgment, threads, and suspended/killed processes.
`test_substrate.py` drives the probe with synthetic mount tables (a refusal for
each named network filesystem, the default refusal of an unidentified one, the
opt-out and its logged warning, the requirement withdrawing it, the incoherent
pair, and the local-filesystem positive control under every policy — plus the
real probe against the CI checkout). `test_opened_substrate.py` covers hidden
descendants independent of table order, exact descriptor identity, unavailable
metadata and journal reinspection. `test_substrate_linux.py` requires five real
namespace cases: separately mounted store and journal files, a bind-mounted
store/lock alias with subprocess contention, a hidden descendant and preservation
of a live SQLite POSIX lock during journal inspection. A sixth case adds a
real namespace-file bind mount, checks that it stays unverified and confirms
that an ordinary local store still works beside it. Missing Linux or mount
support fails these tests rather than skipping them.
`test_mount_relevance.py` pins the relevance rule from both directions: the
regression (an unrelated `nsfs` row leaves the store safe) and, with
recognition switched off so the row is genuinely unreadable, that relevance —
not recognition — is what carries it; every ancestor, same-path stack member,
descendant and unreadable-location case still refusing; every row accounted
for as read or recorded-unread; the set-aside listing appearing in the report,
the refusal and the warning; the hidden-descendant topology unchanged; and a
real `ConsumedApprovals` building and locking beside an unread row while still
refusing one on its path. The guard mutations in
`scripts/substrate_revert_proofs.py` pin both the number of reverts and the
resulting call-phase failures; shortfall and excess both fail.
`test_owner_identity.py` plays a second
host against a shared ledger and store: the foreign owner's intent is left
`owner_unverifiable` with no receipt lookup and no outcome recorded, a runner on
the owner's kernel holding the same lock and the same machine after a reboot
reconcile it, the operator override is recorded, and a legacy intent stays
pending until asserted. `test_lock_identity.py` reproduces the review's
finding 2 exactly — a live subprocess owner on `original.db`, a real hard
link `alias.db`, a recovering runner given the alias — and shows it BUSY with
its executor never called and no outcome recorded for the live owner; that
aliased stores resolve to one lock object (hard link, two processes, two
threads, and under a private mount namespace a real file bind mount, which
leaves the link count at 1); that a second name added after construction is
caught before use; that a same-kernel runner on a *copy* of the store is
`owner_unverifiable`; and the positive controls for a single-linked store and
its own dead owner. `test_migration_live.py`
adds real PostgreSQL tests for a dropped COMMIT response, suspension immediately
after intent append, and an active database transaction surviving client death.
The existing `PROM_REQUIRE_PG=1` CI step includes them; a local skip is not
evidence of database correctness.

## 6. Attack scenarios → defense

| # | Attack | Defense | Test |
|---|---|---|---|
| A1 | Agent connects to the DB directly (TCP) | Network namespace: host loopback unreachable | live proof, STOP 2 |
| A2 | Agent connects via the Postgres Unix socket | Socket placed outside the sandbox's mount view; §4.1 | live proof, STOP 2 |
| A3 | Agent finds/steals a credential in its context | Credential only in runner zone (P2) | isolation proof |
| A4 | Agent replays a used approval, including after restart | Durable single-use, atomic claim (P5) | replay-fails + restart/thread/process races |
| A5 | Agent swaps artifact B under artifact A's approval | Runner re-hashes; mismatch refused (P3) | swap-fails |
| A6 | Agent changes DB, host, port, user/privilege, or schema | Canonical target binding (P4) | wrong-target + privilege-change tests |
| A7 | Agent waits out / captures a stale approval | TTL expiry (P6) | expired-fails |
| A8 | Agent fabricates an approval | Unforgeable, gate-issued (P7) | forge-fails |
| A9 | Verifier can't run; agent hopes it slips through | Fail closed on `Unavailable` (P8) | fail-closed test |
| A10 | Adversary rewrites the ledger to hide a run | Hash chain detects the edit (P9) | tamper-detection test |
| A11 | Runner dies after DB commit but before outcome audit | Atomic DB receipt reconstructs commit/rollback and blocks on ambiguity (P10) | restart + mandatory live PostgreSQL tests |
| A12 | A second runner on another host, or a store on a network filesystem, recovers a live owner's intent as "not committed" | Store substrate probed: network filesystem refused, unidentified one refused unless opted out (logged); owner identity in every intent; an unplaceable owner left `owner_unverifiable`, receipt not consulted | `test_substrate.py`, `test_owner_identity.py` |

## 7. In scope vs out of scope (this sprint)

**In scope.** Can the agent get a destructive migration executed *without* a valid, current,
correctly-bound approval — by reaching the DB directly, or by tricking the gate/runner
(replay, swap, wrong-target, expired, forged)? Is the audit trail tamper-evident, and can
the runner recover an execution outcome after termination without guessing? The whole
authorization chain from proposal through crash reconciliation, fail-closed, is in scope.

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
