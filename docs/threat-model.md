# Threat model — what is proven, and what is left standing

This is the consolidated adversarial assessment for Promethyn's enforcement path.
It is organised by **attacker class**, and each class states three things without
softening any of them:

1. what the attacker can do,
2. what is now **proven** closed — by a test that fails when the defence is
   removed, not by a claim in prose, and
3. what **remains open**, named plainly.

Nothing here is described as uncrackable, unhackable, or unbreakable. Every
defence below has a boundary, and the boundary is written down. A gap that is
named is a gap that is being managed; a gap that is hidden is a vulnerability
with better marketing — and by this project's own thesis, a check that is
present, plausible, and void is the failure mode we exist to name.

> **Status.** Attackers 1, 2 and 3 are complete. Attackers 4 and 5 are listed
> with their scope so the shape of the work is visible, and are explicitly
> **not yet assessed** — they are not claimed as closed, and the absence of
> findings under them means nobody has looked yet.

---

## Attacker 1 — the sandboxed agent

**Capability.** Arbitrary code execution inside the sandbox, full knowledge of
this repository (it is public), and unlimited attempts. It wants to run SQL
against the production database — either by reaching the database directly, or
by producing an approval the runner will honour.

This is the primary threat and the one the whole chokepoint exists to stop, so
it was pushed hardest.

### 1.1 What was found

Four reachable paths, each demonstrated by running a probe inside the real
sandbox and reading the result. Two were load-bearing.

| # | Path | Severity | Status before |
|---|---|---|---|
| A1-1 | The **approval signing key** (`PROM_CHOKEPOINT_KEY`) and `PGPASSWORD` reached the agent through the inherited process environment | **Critical** | Open |
| A1-2 | A Unix socket at either **stock PostgreSQL location** (`/tmp`, `/run/postgresql`) was connectable from the sandbox | **High** | Open by default; mitigated only by a deployment requirement |
| A1-3 | The **host procfs** was mounted in the sandbox: host PIDs, and the command lines of runner-zone processes | **Medium** | Open |
| A1-4 | The six-path isolation proof **never ran in CI** — it gated on a variable the workflow sets nowhere | **High (assurance)** | Open |

**A1-1 is a total bypass, and it is worth being precise about why.** The
chokepoint's unforgeability property rests entirely on the agent not holding the
HMAC key. `demo/README.md` documents deployment as
`export PROM_CHOKEPOINT_KEY=...` — into the runner's environment. The namespace
sandbox then launched the candidate with `subprocess.run(...)` and **no `env=`
argument**, so Python passed the parent environment through by default. The agent
could read the signing key out of `os.environ` and mint approvals for any
artifact against any target. No connection needed to be made and no namespace
was involved: the leak travelled in the process image. Every other defence in the
chokepoint — artifact binding, target binding, expiry, single-use nonces — is
downstream of a key the attacker already had.

`docs/chokepoint-threat-model.md` §4.2 stated the opposite as settled fact: *"the
credential lives only in the runner's environment/process … never passed into
the agent zone. The agent's context is constructed without it."* It was not. The
sentence described an intention as an achievement, which is the exact failure
this project names.

**A1-2 was documented but not enforced.** §4.1 of that same document names the
gap correctly — a Unix socket is a filesystem object and does not traverse the
network namespace, so `--net` never touched it — and then discharges it with a
*deployment requirement*: run PostgreSQL on loopback TCP, or put its socket under
a path the sandbox hides. That is a real mitigation, but it lives in an
operator's head. A stock PostgreSQL puts its socket in `/tmp` (source builds) or
`/run/postgresql` (Debian/Ubuntu packages), and neither was hidden. Hardening it
means moving the property from *documented constraint* to *enforced by
construction*.

**A1-4 is why the other three survived.** `tests/chokepoint/test_isolation.py`
skipped unless `PROM_CHOKEPOINT_PG_SOCKDIR` was set. `.github/workflows/ci.yml`
sets that variable in no step, and a containerised CI database cannot provide one
(its socket lives inside its own container). The repository's central proof was
therefore green-by-skipping on every run.

### 1.2 What is now proven closed

Measured by running the same probes before and after. Literal output:

```
                                          BEFORE                     AFTER
env  PROM_CHOKEPOINT_KEY              LEAKED:SECRET-SIGNING-KEY…     <absent>
env  PGPASSWORD                       LEAKED:SECRET-DB-PASSWORD      <absent>
env  variable count                   136                            6
unix /tmp/.s.PGSQL.*                  REACHED (read back "PGDATA")   BLOCKED FileNotFoundError
unix /run/postgresql/.s.PGSQL.*       REACHED (read back "PGDATA")   BLOCKED FileNotFoundError
unix abstract namespace               BLOCKED ConnectionRefused      BLOCKED ConnectionRefused
proc visible PIDs                     76  (max host pid 1812)        1  (max 1)
proc runner-zone cmdline              LEAKED "--password=…"          clean
proc /proc/self/environ               135 vars                       6 vars
proc /proc/<other>/environ            BLOCKED PermissionError        BLOCKED
proc /proc/<other>/mem                BLOCKED PermissionError        BLOCKED
net  DNS resolution                   BLOCKED gaierror               BLOCKED gaierror
net  UDP / TCP egress                 BLOCKED OSError                BLOCKED OSError
```

The three changes behind that:

- **The candidate's environment is built, not inherited**
  (`sandbox/namespace.py`). `subprocess.run` receives an explicit `env=` holding
  six fixed, non-secret values (`PATH`, `HOME`, `TMPDIR`, `PWD`, `LANG`,
  `LC_ALL`), with `HOME`/`TMPDIR` pointed at the workspace. Deliberately not an
  allowlist: an allowlist is a denylist wearing a disguise, and the next secret
  to leak is the one whose name nobody thought to ban.
- **The runtime-socket directories are hidden** (`sandbox/_bootstrap.py`).
  `/tmp`, `/var/tmp`, `/dev/shm`, `/run` and `/var/run` join `/root` and `/home`
  under empty tmpfs. Two details matter. The overlay is now **unconditional**:
  the old code skipped hiding any directory that contained the workspace, and
  since callers build workspaces with `tempfile`, that meant `/tmp` was
  routinely not hidden — a guard present, plausible, and void. The workspace is
  instead parked on a staging mountpoint, the overlay applied, and the workspace
  bound back at its own path, so hiding never has to be given up to keep it. And
  a mount that fails now **fails the run** rather than being shrugged past, since
  a silently-skipped overlay is the same void guard again.
- **A private `/proc` for the PID namespace** (`sandbox/_bootstrap.py`). The
  sandbox already unshared PIDs but kept the host's procfs mounted, so host
  processes and their command lines stayed readable — and a credential passed as
  a command-line argument is readable to anything that can open `/proc`.

### 1.3 How it is proven

`tests/chokepoint/test_agent_zone_containment.py` (9 tests) probes each property
inside the real sandbox. Two rules make its green mean something:

- **Every negative has a positive control.** "Blocked" is worthless if the target
  was never reachable. Each test first proves the socket IS reachable from
  outside, or that the canary IS in the parent environment, or that the
  filesystem sweep DOES find the key when nothing isolates it.
- **The probe is proven to have run.** A harness fault that produced no output
  would otherwise read as "nothing was reachable", so the candidate's start and
  exit status are asserted and empty output is a failure.

The final test sweeps for the signing key by *every* inspected path at once —
environment values, `/proc/self/environ`, `/proc/self/cmdline`, every other
process's `environ` and `cmdline`, and a bounded filesystem walk of everything
the agent can see — and requires zero hits with a non-zero scan count. Its needle
is assembled from two halves at runtime so the probe file cannot match itself.

These tests need **no database**, so they run on every CI run rather than
gating on a configured PostgreSQL.

Each fix was verified to have teeth by reverting it and confirming the specific
tests go red:

```
env fix reverted            -> 3 failed (key present in environ and /proc/self/environ)
socket-dir hiding reverted  -> 2 failed (stock locations REACHED and visible)
private /proc reverted      -> 2 failed (runner-zone cmdline leaked)
all restored                -> 9 passed
```

`test_isolation.py` (the real-database proof) now gates **per path** instead of
all-or-nothing, so the TCP paths run against the real database whenever one is
configured, and it asserts a positive control — the database is reachable from
outside — so the run cannot pass because the database is simply down. CI runs it
in the PostgreSQL step with `-rs`, so a proof that stops running is visible
rather than invisible.

### 1.4 What remains open

- **Kernel-level escape.** Everything above rests on Linux namespaces. A user- or
  mount-namespace escape, or a kernel 0-day, defeats all of it. Unprivileged user
  namespaces are themselves a meaningful kernel attack surface. For hostile
  multi-tenant workloads a microVM boundary (gVisor, Firecracker, Kata) is the
  right answer, and this adapter is not a substitute for one.
- **Anything the agent is legitimately given.** Containment is about what the
  agent can reach on its own. Whatever a caller deliberately writes into the
  workspace, the agent has.
- **Side channels.** Timing, cache and speculative-execution attacks are not
  addressed and are not claimed to be.
- **A compromised runner zone.** If the attacker is already executing in the
  runner zone, they hold the signing key and the credential directly, and the
  chokepoint has nothing left to say. That is attacker 2's subject (§2).
- **`unsafe` and `container` adapters.** The environment-construction fix is
  applied to the namespace adapter. The `unsafe` adapter is explicitly not a
  sandbox and is opt-in behind `PROM_ALLOW_UNSAFE_EXEC=1`; the container adapter
  gets a clean environment from the container runtime rather than from this code
  path, which is a different mechanism and has not been re-proven here.
- **Denial of service against itself.** An agent can burn its own CPU and wall
  clock. Bounded by cgroups/rlimits, not eliminated.

---

## Attacker 2 — the runner host, and standing privilege in the runner zone

**Capability.** A local account on the runner host, or a partial compromise of
the runner zone — a readable log, a crash report, an exception rendered
somewhere it should not have been. **Full host compromise is explicitly out of
scope**, and stays out: root on this machine holds the signing key, the database
credential and the ledger file, so it can mint any approval and write any
history. Nothing below changes that, and §2.5 says so plainly rather than
implying a defence that does not exist. What *is* in scope is the blast radius
before that point, and the standing authority the runner keeps while idle.

### 2.1 What was found

| # | Finding | Severity | Status before |
|---|---|---|---|
| B2-1 | The sandbox workspace was `chmod 0777` — world-readable and world-writable, including the window between an artifact being written and being hashed | **High** | Open |
| B2-2 | The same line re-permissioned any directory it was handed. The repository's own tests passed `workspace="/tmp"`, so **every suite run stripped the sticky bit off the machine's `/tmp`** | **High** | Open, and running in CI |
| B2-3 | `DbTarget.password` and `MigrationRunnerConfig.signing_key` rendered verbatim in `repr` — so any log line, f-string or traceback carrying them published the credential and the key | **High** | Open |
| B2-4 | `UnsafeLocalSandbox` spawned candidate code with the inherited environment — the A1-1 defect at a **second** call site | **High** | Open |
| B2-5 | The runner holds the database credential for the whole process lifetime; nothing existed to hold it for less | Medium | Open |

**B2-2 was measured, not deduced.** Running the pre-fix provenance tests changes
`/tmp` from `drwxrwxrwt` to `drwxrwxrwx`. Losing the sticky bit means any local
user can delete or rename any other user's files there — a machine-wide
downgrade performed by the test suite itself, on every CI run.

**B2-4 is the A1-1 lesson generalised.** Fixing one spawn site fixed one spawn
site. A second adapter had the same defect, and "it is dev-only and isolates
nothing anyway" is not an answer: it still executes candidate code with
`PROM_CHOKEPOINT_KEY` in its environment whenever that key is exported in the
same shell, which is precisely what `demo/README.md` tells an operator to do.

### 2.2 What is now enforced

- **The workspace is owner-only.** `prepare_workspace` sets `0700` and never
  widens. Access without widening comes from ownership: a privileged runner
  `chown`s the directory to the unprivileged container user (`65534`) and the
  candidate runs as it; an unprivileged runner instead runs the container as its
  own uid/gid, which already traverses its own `0700` directory. If neither
  works the run is **refused** — a workspace nobody can reach is a failed run,
  while a workspace everybody can reach is a silent downgrade.
- **Shared directories are refused, not re-permissioned.** The sticky bit is the
  kernel's own marker for a communal drop-box, so a sticky directory is rejected
  as a workspace outright.
- **Secrets do not render.** `password` and `signing_key` are `repr=False`;
  `DbTarget.__str__` returns the credential-free canonical identity, so logging a
  target still tells an operator which database was touched.
- **No adapter inherits the runner environment.** `candidate_env` moved to the
  sandbox port (`base.py`) and every spawning adapter uses it, so the fix is not
  one adapter away from being wrong again.
- **A deployment can hold no standing credential.** `DbTarget.password_provider`
  is consulted per connection, so an idle runner holds nothing worth stealing.

### 2.3 The swap-after-hash question

Between hashing an artifact and executing it, can a local adversary change what
runs? **No — by construction rather than by check.** `MigrationArtifact` holds
the SQL string it was built from and hashes that same string, so the executed
artifact is the hashed artifact with no window in between. There is no path
carried to the executor that could be made to mean something else.

`MigrationArtifact.from_path` is the safe ingestion point for the ordinary case
where a migration starts life as a file: one descriptor, opened `O_NOFOLLOW` so
a symlink swapped in cannot redirect the read and `O_NONBLOCK` so a FIFO cannot
block the runner indefinitely, checked to be a regular file, then `fstat`-ed and
read through that same descriptor.

The tests perform the attack rather than describing it: the approved file is
rewritten in place and replaced by rename, and the benign SQL still reaches the
executor. One test deliberately simulates the **naive path-carrying design** and
shows the hostile SQL landing under a still-valid approval — without it, every
other assertion could be passing because the swap never worked.
`source_still_matches()` reports tampering as evidence; execution never depends
on it, because the content is already held.

### 2.4 Every spawn in the runner path

The A1-1 lesson applied exhaustively rather than to the one site that was found:

| Site | Environment | Verdict |
|---|---|---|
| `sandbox/namespace.py` — candidate | explicit `candidate_env` | clean |
| `sandbox/unsafe.py` — candidate | explicit `candidate_env` (**fixed here**) | clean |
| `sandbox/container.py` — `docker run` | container receives only `PYTHONDONTWRITEBYTECODE`; the runtime does not forward the host environment | clean for the candidate |
| `sandbox/container.py` — `docker info` probe | inherited | **accepted**: runs the host's own CLI, which needs `DOCKER_HOST`/`PATH`, and passes it no candidate code |
| `sandbox/_bootstrap.py` — `execv` | inherits the already-constructed environment | clean |
| `sandbox/_container_bootstrap.py` — `execvp` | inherits the container's environment | clean |
| `tools/stale_branch_demo.py` — `git` ×4 | inherited | **accepted**: a fixture builder that runs `git` against a throwaway local repository, never candidate code |
| `demo/run_demo.py` — `psql` | inherited plus `PGPASSWORD` | **accepted, and named**: a demonstration script, not the runner. `PGPASSWORD` in a child environment is readable by same-uid processes; the runner itself never spawns `psql`, connecting over the wire protocol instead |

The chokepoint runner spawns **no** subprocesses at all — it talks to PostgreSQL
through the driver — so no credential crosses a process boundary in the
production path.

### 2.5 Residual — what is not covered

- **Full host or root compromise defeats all of it.** Root reads the signing key
  out of the runner's memory, reads or replaces the credential, rewrites the
  ledger from genesis (`docs/ledger-integrity.md`: undetectable without an
  out-of-band anchor), and mints any approval it likes. Every item in §2.2
  reduces what a *partial* compromise yields. None of them survives root, and no
  arrangement of them would.
- **Memory is not scrubbed.** A `password_provider` narrows the credential's
  window from process-lifetime to call-scope. It does not erase anything: Python
  strings are immutable and the interpreter may copy them, so the value can
  persist until garbage collection. A test asserting a wipe would be a void
  guard.
- **The provider is opt-in.** The default still holds the credential in the
  config for the runner's lifetime, because making it mandatory would break
  every existing caller. Supported and tested, not enforced.
- **Escape lands as the runner user on an unprivileged host.** Where the runner
  cannot `chown`, the container runs as the runner's own uid, so a container
  escape lands there rather than as `nobody`. This is a deliberate trade: an
  escape past `--cap-drop ALL --security-opt no-new-privileges --read-only
  --network none` requires a runtime vulnerability, while a world-writable
  workspace required only a local shell. A privileged runner takes the stronger
  path automatically.
- **`0644` files inside the workspace.** Files written there keep the creating
  process's default mode. They are protected by the `0700` directory, not by
  their own bits — so a workspace moved somewhere world-traversable would expose
  them again.
- **Cross-user denial is proven only where privilege can be dropped.** The mode
  assertions run everywhere; the test that actually becomes another local user
  and is refused requires root to drop privilege, so it skips on an unprivileged
  runner. **Verification procedure there:** as a second local account, attempt
  `ls`, `cat` and file creation inside a live workspace; all three must fail with
  `EACCES`.
- **The runner's own filesystem and network reach are unbounded.** It is an
  ordinary process: nothing stops it opening other files or hosts. Confining it
  (systemd hardening, a dedicated service account, a network policy) remains a
  **deployment recommendation**, not something this code enforces.
- **`unsafe` remains unsafe.** It now withholds the environment, which is not the
  same as isolating. It is opt-in behind `PROM_ALLOW_UNSAFE_EXEC=1` and warns on
  every run.

---

## Attacker 3 — an adversary who reaches the ledger file

**Capability.** Read and write access to the ledger file, without owning the
host: a backup agent, a misconfigured shared mount, a lower-privileged service
account, a stale snapshot with wide permissions. They want the record of what
was authorised and executed to say something other than what happened.

The chain already stopped the easy versions — an edit, a deletion or a reorder of
any interior entry breaks every link after it. This class is about the two things
it could not stop, and about the verifier's own honesty when it cannot run.

### 3.1 What was found

| # | Finding | Severity |
|---|---|---|
| C3-1 | The tip anchor was **available but never operational** — `chain_tip()` and `verify_chain(expected_tip=…)` existed, and nothing in the codebase ever stored or supplied a tip. A full genesis rewrite was therefore undetectable in practice | **High** |
| C3-2 | **Deleting the ledger read as valid.** SQLite recreates a missing file, and an empty chain is internally consistent, so the cheapest possible attack reported `chain valid (0 entries)` | **High** |
| C3-3 | **22 numeric settings accepted NaN, infinity, negatives and out-of-range values** across `Limits`, `Config`, `VerifierBank`, `SubprocessVerifier`, `SqlVerifier` and `PendingActionService` | **High** |

C3-1 is the shape this project keeps finding in its own work: a capability that
is present, plausible and never exercised. The anchor was documented, tested as a
primitive, and load-bearing for the one attack the chain cannot see — and no
caller had ever written one down.

C3-3 matters because these values do not fail loudly. `confidence < nan` is
**always False**, so `PROM_ESCALATE_BELOW=nan` leaves the human-escalation gate
in place and permanently non-escalating. `timeout=inf` never fires. A negative
TTL lands in the `<= 0` branch that means "expiry disabled". Each one reads as a
working configuration, and each is reachable from a typo in a deployment
variable.

### 3.2 What is now enforced

- **The anchor is written on every append** (`ledger/tip_anchor.py`,
  `SqliteLedger(tip_anchor=…)`), after the commit, so an anchored tip never names
  an entry the ledger does not have. An anchor write that fails is **not**
  swallowed: an un-anchored append is one a later rewrite could hide.
- **`verify_chain` consults the configured anchor without being asked**, so an
  auditor cannot silently verify without it — the difference between operational
  and available.
- **The anchor refuses to move backwards.** A live tip below the anchored one, or
  a different hash at the anchored seq, raises rather than being recorded.
  Quietly re-anchoring a shortened chain would erase the only evidence there was.
- **Numeric settings are validated at construction** (`core/validation.py`),
  rejecting NaN, infinities, wrong signs and out-of-range values — never
  clamping, because a clamp hides the misconfiguration the operator needs to see.

### 3.3 What the anchor does and does not detect

| Attack | Without an anchor | With an anchor out of reach |
|---|---|---|
| Edit / delete / reorder an interior entry | **detected** (chain break) | detected |
| Append with a forged `prev_hash` | **detected** | detected |
| Truncate the tail | reads as valid | **detected** (`TRUNCATED`) |
| Delete the ledger entirely | reads as `valid (0 entries)` | **detected** (`TRUNCATED`) |
| Full rewrite from genesis | reads as valid | **detected** (`BROKEN` at the anchored seq) |
| Full rewrite **plus** rewriting the anchor | reads as valid | **NOT detected** |

The last row is the residual, and it is a *passing test* in
`tests/chokepoint/test_tip_anchor.py` rather than a sentence in a document —
`test_an_attacker_who_also_controls_the_anchor_is_NOT_detected` performs the
rewrite, rewrites the anchor to match, and asserts the result comes back
**valid**. Recording it that way keeps the limit from quietly eroding.

### 3.4 The trust boundary — the whole value of the anchor

**The anchor is worth exactly as much as the separation between it and the
ledger, and nothing more.** An anchor file in the same directory, on the same
disk, writable by the same account, defends against nothing: an attacker who can
rewrite the chain can rewrite the anchor in the same breath. It would look like
protection and be theatre.

For it to mean anything, the anchor must live in a trust domain the ledger-file
adversary cannot write. In rough order of strength:

1. an append-only or write-once store — object storage with object-lock or a WORM
   volume, where even a valid credential cannot overwrite history;
2. a different host the ledger's account cannot reach, pulling or receiving the
   tip;
3. a mount that is read-only from the ledger host's perspective;
4. a periodic out-of-band record — a signed digest posted somewhere durable, or
   simply written down.

The code cannot verify any of this and does not pretend to: `FileTipAnchor` takes
a path and writes to it. **Placement is a deployment property**, and it is the
one that decides whether §3 closed anything at all.

### 3.5 Residual — what is not covered

- **An attacker who controls both the ledger and the anchor is not detected.**
  This is the §2.5 root case in another guise, and it is stated here rather than
  buried: root, or any compromise spanning both stores, defeats the whole scheme.
- **The anchor is opt-in.** A `SqliteLedger` built without one behaves exactly as
  before. Making it mandatory would break in-memory and throwaway ledgers, which
  have nothing meaningful to anchor. Supported, wired and tested — not enforced.
- **Detection, not prevention.** Everything here makes tampering *evident* after
  the fact. Nothing stops a writer with file access from making the change.
- **A gap between the last append and a crash** is not covered by a cadence the
  code controls: the anchor is written per-append, so a crash *between* the
  commit and the anchor write leaves the anchor one entry behind. That reads as a
  valid chain with one honest extra entry, not as tampering.
- **Numeric validation covers the fields enumerated in §3.1.** It is a fixed list,
  not a mechanism that catches a numeric field added later — a new unvalidated
  setting would be a new hole. The helpers exist to make adding validation cheap;
  nothing forces a future field through them.
- **`0` still means "disabled"** for the cpu, memory, process and TTL settings.
  That is pre-existing documented behaviour and was deliberately preserved; only
  negatives, which reached the same branch by accident, are now refused. An
  operator can still switch those caps off on purpose.

---

## Attackers 4–5 — scope stated, not yet assessed

Listed so the remaining surface is visible. **No claim is made that either of
these is closed.** Findings will be added as each class is worked.

- **Attacker 4 — the network.** Requiring TLS on credentialed endpoints, and
  bounding provider responses.
- **Attacker 5 — misconfiguration.** Structurally enforced security
  configuration, so an insecure deployment is refused rather than merely
  discouraged (`require_digest_pin` is the model).

---

## Related documents

- `docs/chokepoint-threat-model.md` — the chokepoint's own model and invariants.
- `docs/sandbox.md` — the sandbox adapters and their guarantees.
- `docs/ledger-integrity.md` — what the audit hash chain does and does not detect.
- `docs/pre-disclosure-audit.md` — the external-reviewer readiness audit.
