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

> **Status.** All five attacker classes are complete; this document is the
> final state of PROM-HARDEN-MAX and the one to hand to a design partner's
> security team or to an independent auditor. Each class states what is
> enforced, what is a deployment recommendation, which test proves each claim,
> and what remains open. Nothing is closed by assertion.

> **Insider hardening (PIH).** PROM-HARDEN-MAX modelled adversaries short of a
> privileged insider. The PIH sprints that follow it do not claim to prevent
> one. Each introduces a **witness the insider cannot control**, converting a
> residual from "undetectable, silent" to "detectable, witnessed". PIH-1 (§3)
> made the ledger anchor external, append-only and continuous. PIH-2 (§2.6,
> `docs/key-custody.md`) moved approval signing to an external KMS / HSM whose
> key is not returned through the port. F11 adds retrospective detection only
> with independently trusted digest-bound history and complete coverage: GCP
> can supply the digest, native AWS CloudTrail cannot (INDETERMINATE), and
> PKCS#11 depends on vendor evidence. This is not prevention. Every "what it does not cover"
> survives here as a passing test, because an overclaim is the exact defect
> this program exists to catch.

## Design principles the whole model rests on

**Execution recovery follow-up (F2/F3):** negative executor results and lost
COMMIT responses no longer establish rollback. Unknown events leave an intent
pending until receipt reconciliation proves its outcome. A cross-process guard
covers the interval before the executor connects. Until PROM-FIX-B that guard
was an OS file lock keyed to the store's *pathname*, so it excluded only
runners that named the store by the same path: two aliases of one store — a
hard link, a file bind mount — gave two runners two locks, both acquired, and
a runner recovering through an alias read the live owner's missing receipt as
"not committed" (independent review, finding 2, reproduced with real
subprocesses, hard links, SQLite and OS locks). The guard is now an `flock`
on the store's own inode, held for the store's lifetime, so every alias of
the store contends for one lock object across processes; a multiply linked
store is refused at construction and before every use; and every intent
records the identity of the lock its owner held, so "same kernel" establishes
a dead owner only when it is provably the same lock (`chokepoint/runner.py`,
`chokepoint/ownership.py`; `tests/chokepoint/test_lock_identity.py`
reproduces the review's scenario and shows it failing closed). The substrate
check from PROM-FIX-A is narrower than its earlier wording here claimed: it
classifies, from the mount table, the filesystem *type* at the pathname of
the store's parent directory (`chokepoint/substrate.py`) and refuses the known
network types; it does not examine the opened store or lock objects and uses
no mount identity, so "local filesystem recognised" is not "every runner holds
the same exclusive guard" (findings 1A/1B, open). A filesystem the probe
cannot identify is refused unless explicitly opted out of
(`allow_unverified_substrate`, logged; withdrawn by
`require_verified_substrate`). Every execution intent records its owner's
host identity and lock identity (`chokepoint/ownership.py`), and a recovering
runner that cannot place the recorded owner — on its own kernel holding the
same lock object, or on its own rebooted machine — leaves the intent pending
as `owner_unverifiable`; intents with no identity, or with a host but no lock
identity, stay pending until the operator's recorded assertion. Multi-host
execution is unsupported. See `docs/chokepoint-threat-model.md`, "Recovery
follow-up: F2/F3", for what is detected, what is not, and the regression
coverage.

1. **Couldn't-verify is never verified-clean.** A check that could not run
   returns `Unavailable` — no verdict at all — at every tier. It is never a
   PASS, and never an ABSTAIN that reads as an opinion (EX-1; §4 extends it to
   the transport layer; §3 to the ledger's own verifier).
2. **A requested security property that cannot be honoured is refused, never
   degraded.** Asking for digest pinning with an adapter that runs no image,
   asking for isolation when only the unsafe runner exists for a remote model,
   asking for plaintext to a remote host: each is a `ConfigError` at
   construction, not a quietly weaker object (§5).
3. **A security requirement is the OR of its sources.** A `Config` value and an
   environment variable can each raise a requirement; neither lowers the other.
4. **Every negative has a positive control.** "Blocked" means nothing if the
   target was never reachable; every containment test first proves the thing it
   then proves refused.
5. **A named gap is managed; a hidden gap is a vulnerability.** Every section
   ends with what is *not* covered, and the honest limits are recorded as
   passing tests where they can be (§3's attacker-controls-the-anchor case).

## The model on one page

| # | Attacker | Surface | Enforced by construction | Deployment recommendation | Proven by | Residual (headline) |
|---|---|---|---|---|---|---|
| 1 | The sandboxed agent | env, filesystem, sockets, `/proc`, network | constructed environment; socket dirs hidden; private `/proc`; no interfaces | microVM for hostile multi-tenant work | `test_agent_zone_containment.py`, `test_isolation.py` | kernel / namespace escape |
| 2 | The runner host (and, with PIH-2, the insider who reads its memory) | workspace mode, secrets in `repr`, spawn env, artifact bytes, the signing key | `0700` workspace; redacted secrets; every spawn env-clean; bytes-not-paths; approval signing through an external KMS whose key never exists on the host; a KMS failure mints nothing | service account, filesystem/network confinement; the KMS access policy (invoke ≠ administer ≠ audit); KMS audit logging enabled, delivered and retained — a Sign is logged only where the deployment made the KMS log it, which this code cannot enforce (`docs/key-custody.md`); `PROM_REQUIRE_EXTERNAL_SIGNER=1` | `test_sandbox_privilege.py`, `test_credential_hygiene.py`, `test_artifact_integrity.py`, `test_key_custody.py` | an insider holding Sign-invoke gets a valid signature (witnessed, not prevented); root still holds the database credential |
| 3 | The ledger file (and, with PIH-1, the insider who rewrites it) | chain rewrite, deletion, numeric settings | tip anchored to an external append-only target after every append; the whole anchor history pinned on verify; refuses to rewind; a failed anchor write raised, the runner refuses; NaN/inf/range refused | object-lock retention that outlasts the audit horizon, or a log run by another party; `PROM_REQUIRE_LEDGER_ANCHOR=1` | `test_external_anchor.py`, `test_tip_anchor.py`, `test_ledger_verify_failure_modes.py`, `test_numeric_config_validation.py` | authority over the anchor medium: retention lapsed or bypassed, the log's operator |
| 4 | The network | credentialed HTTP | `https://` required; redirects refused; bounded reads under a deadline; failures typed and `Unavailable` | certificate pinning per deployment | `test_transport_hardening.py` | system trust store; proxy env is host-controlled |
| 5 | Misconfiguration | every security flag and combination | requirement honoured or refused; dead-flag mechanism; coherent combinations; hardened defaults | pin the sandbox image | `test_security_posture.py` | `require_digest_pin` and `require_ledger_anchor` off by default |

---

## Attacker 1 — the sandboxed agent

### P0 follow-up — candidate-controlled verification harness

The independent review found a separate trust-boundary defect in the Python
verifier: the candidate shared a process and writable workspace with the
comparison harness. It could write `result.json` containing forged pass counts
and exit successfully without running any cases. Sandbox isolation did not
authenticate those counts. The previous claim that keeping verdicts off stdout
prevented forgery was incorrect.

`verifier/runner.py` now keeps expected answers, comparison and verdict aggregation
in the trusted parent. The sandbox receives arguments and returns bounded,
data-only values through `verifier/_value_codec.py`; it never supplies authoritative
counts. The parent does not read candidate-written result files or reconstruct
candidate Python objects. See `docs/security-model.md` for supported types,
limits and failure classification.

`tests/unit/test_verifier_boundary.py` covers the original attack, harness
monkeypatching, custom equality objects, forged responses, malformed payloads,
resource/start-signal precedence and checks that expectations are absent from
the sandbox port and staged files. These local subprocess fixtures prove the
protocol boundary, **not isolation**. `test_sandbox_verifier_boundary.py` runs
positive and adversarial controls through real namespaces and containers;
CI requires the relevant runtime rather than accepting skips. A local skip is
not evidence of containment.

**Residual:** this verifies outputs, not execution of a particular algorithm.
A candidate that knows the correct answers can return them directly. Inputs
are necessarily visible, public fixtures are not secrets, and the explicit
unsafe adapter cannot protect parent memory or files. The design still depends
on isolation from the trusted parent; it does not protect against a sandbox
escape or a compromised host.

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
somewhere it should not have been. **Full host compromise was explicitly out of
scope** for PROM-HARDEN-MAX: root on this machine held the signing key, the
database credential and the ledger file, so it could mint any approval and
write any history, and §2.5 said so plainly rather than implying a defence that
did not exist. What *was* in scope is the blast radius before that point, and
the standing authority the runner keeps while idle.

The insider-hardening sprints take root on as a *witnessed* adversary rather
than an out-of-scope one. PIH-1 (§3) put the ledger's tip on a medium root
cannot rewrite. PIH-2 (§2.6) put the signing key in a KMS root cannot read, so
minting an approval means asking the KMS, and the KMS records the request.
Root still holds the database credential and can still run SQL with it; that
path is not the chokepoint's to stop, and nothing here claims to.

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
- **A deployment can hold no signing key at all** (PIH-2, §2.6). With
  `MigrationRunnerConfig(signer=KmsSigner(…))` the private key exists only in
  the KMS; a verify-only host holds the public key and cannot mint.

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
| `core/_deadline.py` — `resolve`, the DNS worker `core/_dns_worker.py` (added by #77) | **`env={}`**, `close_fds=True`, interpreter in `-I` mode; stdin is exactly `[host, port]`, stdout the address list; killed and reaped on the deadline | clean: one process per HTTP request under a deadline, so on the chokepoint path one per request an `https://` ledger anchor makes |

The chokepoint runner spawns no subprocess to reach PostgreSQL: it talks to
the database through the driver, so the database credential never crosses a
process boundary. It does spawn one kind of subprocess, on one path. When its
audit ledger is anchored to an `https://` log (§3.2), every anchored audit
append — one per refusal, intent and outcome the runner records — makes four
HTTP requests (`ledger/anchor_targets.py`, `LogTipAnchor.write`: a read of the
log's history for the idempotence check, the `POST`, and the two read-backs in
`anchor_http.py`'s `append` and in `write` itself that confirm the record at
its returned index, §3.2), and each request opens its own connection and
resolves the log's hostname in a disposable interpreter
(`core/_deadline.py:resolve`, running `core/_dns_worker.py`), because a
resolver stalled inside the C library cannot otherwise be cancelled under the
request deadline (§4.5, "The resolver adds a process boundary"). What that child
receives is the A1-1 discipline applied again: an **empty environment**
(`env={}`), no inherited descriptors (`close_fds=True`), isolated mode (`-I`),
and a stdin of exactly `[host, port]` — never the URL, the bearer token or any
credential. On the deadline it is killed and reaped, never abandoned. With a
`file://` or `worm://` anchor, or no anchor, the runner spawns nothing.
`tests/conformance/test_transport_deadline.py::test_resolver_has_no_ambient_credentials_or_inheritable_descriptor`
proves the child's environment and descriptors, and
`test_stalled_dns_is_killed_reaped_and_cannot_continue` the kill and reap.

**Why this paragraph was false, and for how long.** Until #77 it read "the
chokepoint runner spawns **no** subprocesses at all", and that was true. #77 —
a hardening fix, the whole-request deadline — added the resolver child and
described it in §4, and this sentence was not revisited: from #77 until this
change the document contradicted itself, with the false version as the
headline claim in the section whose whole point is to enumerate every spawn. The standing
lesson: **new security code can falsify an existing claim.** A spawn table
that is not re-swept when a spawn site is added is the void guard this
document keeps naming, and the independent shakedown that found it is the
witness this repository would not otherwise have had. Corrected in
PROM-FIX-A.

### 2.5 Residual — what is not covered

- **Full host or root compromise still defeats the confidentiality items.**
  Root can read/replace the database credential and run SQL directly. External
  signing removes the private key from the port's host, not Sign-invoke access.
  Independent immutable anchors can reveal ledger rewrites (§3); independently
  trustworthy digest-bound Sign history can reveal unauthorized signing (§2.6).
  These are conditional witnesses, not blanket visibility of root's actions.
  Native AWS metadata-only evidence cannot provide F11 digest-bound detection;
  control of signing plus audit administration can erase the witness entirely.
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

### 2.6 PIH-2 — key custody: the signing key leaves the host

**The finding.** Every approval was sealed by an HMAC over a key held as bytes
in the runner process. The agent could not reach it (§1). Root could: a memory
read, a core dump, a debugger — and a copy of bytes leaves no trace, so a
forged approval was indistinguishable from a real one and nobody was told.
`docs/key-custody.md` is the full statement; the essentials:

- **The signer is a port** (`chokepoint/signer.py`). `LocalHmacSigner` keeps the
  key in the process and is **non-protecting against a host-level insider** —
  development only, warned about at build, refused under the requirement.
  `KmsSigner` signs through a two-operation `KmsPort` (`sign`,
  `get_public_key`) neither of which can return key material; the private key
  exists only in the KMS / HSM. `PublicKeyVerifier` is a host that can check
  approvals and never mint one.
- **The scheme** is ECDSA over P-256 with SHA-256, DER signatures, over the
  approval's *unchanged* canonical bytes — the one scheme AWS KMS, Google
  Cloud KMS and PKCS#11 HSMs all offer. Verification uses the public key, so
  the verify side holds nothing a forger could use, needs no KMS credential,
  and keeps working through a KMS outage while minting, correctly, does not.
  Artifact and target binding, expiry, single use and the fail-closed
  `authorize` are untouched; a test pins the canonical bytes to their pre-PIH-2
  digest.
- **F11: operational reconciliation.** `chokepoint/reconciliation.py` and the
  read-only `promethyn-reconcile` CLI consume the durable 2a journal and 2b
  source. The gate's chain and full external anchor history are verified before
  decoding/recomputing records. An independent pinned checkpoint attests gate
  history coverage; the read includes pre-start decisions and extends source
  coverage through each selected decision's possible Sign interval.
  MATCHED requires a successful independently observed digest, exact key/scope,
  caller, algorithm, admissible time and complete coverage. UNWITNESSED is a
  mature decision without a witness, **not forgery**. UNEXPLAINED is a successful
  digest-bound Sign without an eligible decision (including excess distinct
  attempts): the forgery signal. Errors, unknown/metadata-only evidence and
  incomplete/immature ranges are INDETERMINATE, never clean. Denied attempts
  remain diagnostics. One decision explains one event; exact deliveries
  deduplicate by event ID, conflicting IDs invalidate the source.
  Absence uses issuance − skew through expiry + bounded Sign duration + skew,
  then settling (default 900 seconds). TTL/skew/deadline are pinned and strictly
  validated. A timer is not a completeness certificate; logging exclusions,
  unavailable readers, retention gaps and unattested pages stay indeterminate.
  **GCP digest-bound evidence can support real detection once the deployed
  adapter and coverage are validated. AWS CloudTrail metadata-only evidence
  cannot: INDETERMINATE, not detection. PKCS#11 is vendor-dependent; local HMAC
  has no independent Sign source.** No live cloud/HSM adapter ships here.
  `test_invoke_only_forgery_detected` proves the bypass signal;
  `test_normal_concurrent_batch_across_restart_zero_false_positives` proves the
  normal case. `test_matched_sign_never_resolves_unknown_or_releases_nonce`
  preserves F2 UNKNOWN and spent nonces. The passing
  `test_controls_both_residual_honestly_not_detected` deletes history and replaces
  its coverage under audit administration, with **no** manufactured gap/alert.
  Dishonest authorised gate appends and compromised auditor pins are also
  outside this comparison's trust boundary. See [operator contract](reconciliation.md).
- **No whole-reconciler wall-clock deadline — an open residual, and a
  requirement on any adapter.** The reconciler's API is synchronous: it cannot
  preempt an injected anchor or source reader that blocks, stalls or answers
  slowly, so no hard wall-clock bound on a whole reconciliation is claimed,
  and none is proven against a live cloud or HSM. What is bounded refuses
  rather than truncates: the gate snapshot size
  (`test_gate_size_bound_refuses_without_truncation`), export and page limits
  (`test_response_limits_preserve_incompleteness`), and a normalizer that
  finishes after its deadline does not pass
  (`test_normalizer_finishing_after_deadline_does_not_pass`). A real adapter
  must enforce its own I/O and size deadlines before it is accepted
  (`docs/audit-source-acceptance.md`, "Pin the adapter's response byte/page
  limits and absolute deadline"); `docs/reconciliation.md` states the same
  limit to the operator. Recorded here from the checkpoint-3 report
  (`docs/reviews/PROM-F11-checkpoint-3.md` §2) so that it lives in the threat
  model, not only in a report.
- **Fail-closed.** A KMS that is unreachable, denies the call, times out, or
  answers with something that is not a signature under its own public key
  raises a distinct `SignerUnavailable` subclass and mints nothing — proven end
  to end through the chokepoint runner: database untouched, executor never
  called. There is no path from a configured `KmsSigner` to a local key.
- **The requirement.** `require_external_signer` (`PROM_REQUIRE_EXTERNAL_SIGNER`,
  on `SECURITY_FIELDS`) is the OR of its sources and refuses a local key as
  "cannot be honoured".
- **No KMS SDK is bundled.** `MemoryKms` carries the medium's semantics —
  unextractability proven by walking the surface against the real scalar,
  per-request logging including denied attempts, separation of administration
  from invocation, a fault surface — and the port's mapping to each real KMS is
  documented call by call with the procedure for proving an adapter.

**Residual.** An insider who holds the Sign-invoke permission obtains valid
signatures — `test_an_insider_with_sign_invoke_gets_a_valid_signature_AND_is_logged`
has the runner execute their hostile SQL — and is caught only by the log entry
they leave. Stopping them takes two-party control (PIH-3, buyer-gated). The
witness is worth exactly the separation the deployment enforces between who
may invoke Sign, who administers the key, and who reads the trail; the access
policy that does so is a documented deployment artifact, and the code cannot
check that it was set.

---

## Attacker 3 — an adversary who reaches the ledger file

**Capability.** Read and write access to the ledger file, without owning the
host: a backup agent, a misconfigured shared mount, a lower-privileged service
account, a stale snapshot with wide permissions. They want the record of what
was authorised and executed to say something other than what happened.

The chain already stopped the easy versions — an edit, a deletion or a reorder of
any interior entry breaks every link after it. This class is about the two things
it could not stop, and about the verifier's own honesty when it cannot run.

**PIH-1 extends this class to the privileged insider** — root on the ledger
host, who rewrites the ledger from genesis. The Attacker-3 anchor made that
detectable only if its one file sat somewhere root could not write, which on the
same host is nowhere. PIH-1 makes the anchor external, append-only and
continuous, so the witness is a medium or a party outside the host's authority
(§3.2–§3.5; `docs/ledger-integrity.md`, "External anchor targets").

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

**Added by PIH-1** (`ledger/anchor_targets.py`, `ledger/anchor_http.py`,
`runtime/factory.py::build_ledger`; proven in `tests/chokepoint/test_external_anchor.py`,
no test of which skips):

- **The anchor is external and append-only.** Two target families keep every
  anchored tip as its **own record, created once and never overwritten or
  deleted by this code**: an object-lock / WORM target (one immutable record
  per tip, exclusive create, on a write-once medium — a directory on a WORM
  mount via `worm://`, or an object-locked bucket through a three-operation
  port) and a remote append-only log over TLS (`https://`). The single-file
  target remains for development, is flagged `append_only = False`, is called
  **non-protecting** in the docs and by a runtime warning, and is refused when
  the anchor is required.
- **The verifier pins the whole anchor history**, not the newest record. A
  forged record appended with the anchor's write credential does not mask the
  honest records before it: the verifier reports `BROKEN` naming the conflict
  in the anchor history itself. What the adversary needs is authority over the
  medium, which is the boundary (§3.4).
- **Anchoring is continuous and in the production path.** Every production
  ledger is opened through `build_ledger`, so every audit-chain append writes
  the tip to the configured target after the commit is durable, and every
  verify consults the target. A file-backed ledger with no anchor is warned
  about on every open; `PROM_REQUIRE_LEDGER_ANCHOR=1` refuses it instead, and
  refuses a `file://` target as one that "cannot be honoured". The requirement
  is the OR of its sources.
- **A failed anchor write is raised, never swallowed, and the runner fails
  closed.** `record_chained` raises `AnchorUnavailable`; the chokepoint runner
  treats a pre-execution intent that cannot be anchored as a hard refusal — the
  database untouched, the executor never called. F4/F5 additionally require a
  valid append index and read-back of the exact submitted record there; a 2xx
  empty acknowledgement or a no-op write cannot authorize execution. Idempotence
  uses history evidence, not `/latest`. F6 bounds each network request with one
  monotonic budget; multiple requests in a ledger operation have separate budgets.
- **The operator's entry point:** `prometheus-protocol audit --verify-chain`,
  exit 2 for anything but `VALID`.

### 3.3 What the anchor does and does not detect

| Attack | Without an anchor | Local file on the same medium | External append-only target |
|---|---|---|---|
| Edit / delete / reorder an interior entry | **detected** (chain break) | detected | detected |
| Append with a forged `prev_hash` | **detected** | detected | detected |
| Truncate the tail | reads as valid | `TRUNCATED` ¹ | **`TRUNCATED`** |
| Delete the ledger entirely | reads as `valid (0 entries)` | `TRUNCATED` ¹ | **`TRUNCATED`** |
| Full rewrite from genesis | reads as valid | `BROKEN` ¹ | **`BROKEN` at the first anchored seq** |
| Full rewrite **plus** a forged anchor record written with the anchor's write credential | reads as valid | **NOT detected** | **`BROKEN`** (conflicting history) |
| Full rewrite **plus** authority over the anchor medium (retention lapsed or bypassed; the log's operator) | reads as valid | NOT detected | **NOT detected** |

¹ Only while the adversary has left the file alone, which on the same medium
nothing obliges them to do. The local file is the theatre case.

The last row is the residual, and it is a set of *passing tests* rather than a
sentence in a document — `test_an_attacker_who_also_controls_the_anchor_is_NOT_detected`
(the local file, `test_tip_anchor.py`),
`test_an_adversary_with_authority_over_the_medium_is_NOT_detected_once_retention_lapses`
and `test_the_log_operator_is_NOT_detected` (`test_external_anchor.py`) each
perform the rewrite, exercise the authority, and assert the result comes back
**valid**. Recording it that way keeps the limit from quietly eroding. Every
rewrite in those files is real: the forged chain is asserted `VALID` on its own
terms before the anchor is consulted.

### 3.4 The trust boundary — the whole value of the anchor

**The anchor is worth exactly as much as the separation between it and the
ledger-writer's authority, for exactly as long as that separation lasts.** An
anchor file in the same directory, on the same disk, writable by the same
account, defends against nothing: an attacker who can rewrite the chain can
rewrite the anchor in the same breath. It would look like protection and be
theatre.

For the external targets the boundary is stated precisely, because it is what
a deployment must actually provide:

1. **Object lock: the retention window.** In compliance mode no principal — the
   writing credential, the bucket owner, the account administrator — can delete
   or shorten a locked version before its retain-until date; after it, anyone
   with delete permission can. The window must outlast the period over which a
   rewrite must stay detectable. The default requested per record is 3650 days
   (`PROM_LEDGER_ANCHOR_RETENTION_DAYS`); shorter is the residual, not a saving.
   Governance mode, which a privileged principal can bypass, does not give this
   property.
2. **WORM directory: the mount.** The code creates exclusively and never
   deletes; whether anyone else can is the volume's property. On a plain
   filesystem `worm://` is a name, not a guarantee, and the code cannot tell.
3. **Remote log: the operator.** The ledger host's credential may only append
   and read; the party running the log can replace its storage. The log must be
   run by a party the ledger-host adversary is not.

The code verifies none of this and does not pretend to. **Placement is a
deployment property**, and it is the one that decides whether §3 closed
anything at all. Detection holds when the anchor medium is genuinely outside
the ledger-writer's authority; it does not hold when the same adversary
controls both.

### 3.5 Residual — what is not covered

- **An adversary with authority over the anchor medium is not detected.** This
  is the §2.5 root case in another guise: root who also holds the bucket after
  retention lapsed, or who runs the log, defeats the whole scheme. The passing
  tests in §3.3 record it. Root on the ledger host *alone*, with the witness
  outside their authority, is now detected — that is what PIH-1 changed.
- **The retention window is a deployment choice**, and the code only *requests*
  it; the WORM directory target ignores it, since retention there is the
  mount's. An adapter for a real bucket is the deployment's and must be proven
  against the real bucket (`docs/ledger-integrity.md` gives the procedure); no
  cloud SDK is bundled, because an adapter the CI cannot exercise is a guard
  nobody has seen work.
- **Anchoring is off by default** (§5.4). In-memory and throwaway ledgers have
  nothing to anchor and a development install has no witness to point at. The
  default is a warning on every unanchored file-backed open; the production
  posture is `PROM_REQUIRE_LEDGER_ANCHOR=1`, which refuses.
- **Detection, not prevention.** Everything here makes tampering *evident* after
  the fact. Nothing stops a writer with file access from making the change.
- **A gap between the last append and a crash** is not covered by a cadence the
  code controls: the anchor is written per-append, after the commit, so a crash
  *between* the two leaves the anchor one entry behind. That reads as a valid
  chain with one honest extra entry, not as tampering.
- **The anchor history grows by one record per append** and is read whole on
  verify and log writes (including read-back confirmation). The remote log's
  read ceiling is 64 MiB — room for several hundred
  thousand records — and pruning is a log-operator decision that trades the
  detection window for size; nothing here does it.
- **A verifier pointed at the wrong anchor sees nothing.** Whoever can change
  `PROM_LEDGER_ANCHOR` on the verifying host can point it at an empty prefix.
  That is the silent-config-downgrade class, PIH-4a's subject, not this one's.
- **Numeric validation covers the fields enumerated in §3.1.** It is a fixed list,
  not a mechanism that catches a numeric field added later — a new unvalidated
  setting would be a new hole. The helpers exist to make adding validation cheap;
  nothing forces a future field through them.
- **`0` still means "disabled"** for the cpu, memory, process and TTL settings.
  That is pre-existing documented behaviour and was deliberately preserved; only
  negatives, which reached the same branch by accident, are now refused. An
  operator can still switch those caps off on purpose.

---

## Attacker 4 — the network between Promethyn and its endpoints

**Capability.** A position on the path between Promethyn and any remote endpoint
it calls: a hostile network, a compromised proxy, a poisoned resolver, or the
endpoint itself gone bad. They can read plaintext, inject responses, redirect,
stall, and send as many bytes as they like.

### 4.0 The sweep — how many places talk to the network

One. `RemoteModelProvider._post` in `provider/remote.py` is the only code in the
repository that opens a network connection; the proposer, the model judge, the
grounding judge, the swarm roles and the calibration benchmarks all reach the
network through it. The hits a grep turns up elsewhere are dataclasses named
`VerificationRequest`, not HTTP. So the class is closed at one chokepoint, and a
second call site would have to be *written*, not found.

| Outbound call | Carries | Path | TLS required | Body read |
|---|---|---|---|---|
| `propose_solution` | `Authorization: Bearer` | `_post` | yes | bounded |
| `assess` (model judge, grounding judge, calibration eval) | `Authorization: Bearer` | `_post` | yes | bounded |
| `generate` (swarm roles) | `Authorization: Bearer` | `_post` | yes | bounded |
| HTTP error bodies (quoted into messages) | — | `_post` | — | bounded, 64 KiB |

### 4.1 What was found

Each measured on the pre-fix code against a local server, not inferred.

| # | Finding | Severity |
|---|---|---|
| D4-1 | `http://` with an API key was accepted at construction; a typo in `PROM_API_BASE` sent the bearer token in cleartext | **High** |
| D4-2 | **The bearer token followed a `302` to another origin** — `urllib` copies request headers onto the redirected request, so a scheme check on the configured URL alone closes nothing | **High** |
| D4-3 | Response bodies were read whole: a response bomb reached **262 MB read, 525 MB peak** in three seconds and escaped as a raw `http.client.IncompleteRead` | **High** |
| D4-4 | `timeout=` bounded each socket read, not the exchange: a server sending one byte every half second ran **6.0 s against `timeout_s=1.0`**, and would run forever | **High** |
| D4-5 | A judge whose provider could not be reached returned an `ABSTAIN` verdict — the EX-1 defect at the transport layer: a dead or hostile endpoint read as a working judge with nothing to say | **Medium** |

### 4.2 What is now enforced

- **Every endpoint must be `https://`, refused at construction and at
  `Config` load** (`core/endpoint.py`). Not only credentialed ones: an
  unauthenticated plaintext judge lets the network *answer* the judge, which is
  a different attack on the same trust, so it is one rule. `file://`, embedded
  URL credentials (they would be logged with the URL) and query strings on a
  base are refused too.
- **Plaintext to loopback only, only with `PROM_ALLOW_INSECURE_LOOPBACK=1`,
  and it logs a WARNING at construction.** Loopback is decided from the URL
  literal — `127/8`, `::1`, or the name `localhost` — never by resolving
  anything. There is **no opt-out for a remote plaintext endpoint.**
- **Redirects are refused outright.** An API base that redirects a credentialed
  request is a leak, whatever it points at. The refusal names the target's
  origin only; an attacker-chosen `Location` is never echoed in full.
- **Certificates are verified through an explicit default context**, exposed on
  the provider so a test asserts `CERT_REQUIRED` and hostname checking rather
  than trusting a library default.
- **Every body is read in bounded chunks with deadline checks between reads**,
  using `read1` (one body receive per call — `read(n)` on a chunked body
  loops until *n* bytes or EOF, which is exactly how a drip defeated the first
  version of this fix). A body over the ceiling is **refused, never
  truncated**: a truncated body that happens to parse — a complete answer
  followed by padding — would be reported as a normal answer, and that test
  exists. A declared `Content-Length` over the ceiling is refused before a byte
  is read. HTTP error bodies are read under the same bounds.
- **F5 checks raw header syntax, then declared framing, before JSON parsing**
  in both the provider and anchor. A short Content-Length body,
  contradictory/unsupported framing, missing final chunk terminator or
  malformed chunk boundary raises a typed transport failure. Since
  PROM-FIX-B (independent review, finding 3): a header line without a colon
  used to make the permissive parser drop every later header,
  `Content-Length` included, after which the framing check saw a
  close-delimited body and accepted EOF as its end — a 57-byte body declared
  as 10000 bytes read clean, an empty anchor history verified `VALID`, a
  provider reply verified `PASS`. Every status line and header line is now
  matched against its grammar *before* the parser sees it, the header block
  must end with its blank line, and any parser defect that remains is
  refused as a second, independent check; the refusal is the client's
  `malformed` error (`ProviderMalformedResponse`, `AnchorUnavailable`) and
  an anchor history behind it is `NOT_VERIFIABLE`, never `VALID`. Honest
  scope: this closes the demonstrated case and the parser's defect list; it
  is not proof of complete strict-header validation. Real-socket cases for
  both clients are in `tests/conformance/test_header_integrity.py` and
  `test_response_integrity.py`. Supported framing and its intentional
  strictness are specified in `docs/ledger-integrity.md`.
- **F6 carries one monotonic budget across the network request**, starting
  immediately before network work: DNS, all connection attempts, proxy CONNECT,
  TLS, request writes, status/headers, chunk framing and response body (including
  errors). Every receive below buffering gets the remaining time, rather than
  a fresh inactivity timeout. DNS runs in a disposable isolated interpreter:
  host/port-only stdin, empty environment, closed inherited FDs. Timeout kills
  and reaps that process; there is no thread that continues resolving afterward
  and no fallback to unbounded DNS. Concurrent requests do not share deadline
  state. Tests in `tests/conformance/test_transport_deadline.py` cover slow
  headers, chunk sizes/trailers, TLS, proxy CONNECT, shared phase budgets,
  blocked writes, resolver cleanup and absence of inherited credentials/FDs.
- **Every transport failure is a distinct `ProviderError` subclass** —
  `ProviderTimeout`, `ProviderTLSError`, `ProviderRedirectRefused`,
  `ProviderResponseTooLarge`, `ProviderHTTPError`, `ProviderMalformedResponse`,
  `ProviderTransportError` — and nothing else leaves `_post`.
- **A judge that cannot run returns `Unavailable(INFRA_FAULT)`**, not an
  `ABSTAIN` Evidence, from both `ModelJudgeVerifier` and `GroundingVerifier`.
  It carries no verdict, creates no calibration sample, and the bank never lets
  it stand in for an authoritative check. A model that *ran* and said
  `ABSTAIN` is still an `ABSTAIN` — the distinction cuts both ways.

### 4.3 Transport failure modes — each fails closed, each distinctly

| Failure | Provider raises | Judge returns | Through the bank |
|---|---|---|---|
| connection refused | `ProviderTransportError` | `Unavailable` | never `PASS` |
| no answer within the deadline | `ProviderTimeout` | `Unavailable` | never `PASS` |
| slow drip past the deadline | `ProviderTimeout` | `Unavailable` | never `PASS` |
| self-signed / untrusted certificate | `ProviderTLSError` | `Unavailable` | never `PASS` |
| `https://` to a plaintext server | `ProviderTLSError` | `Unavailable` | never `PASS` |
| redirect, to anywhere | `ProviderRedirectRefused` | `Unavailable` | never `PASS` |
| body over the ceiling / declared oversize | `ProviderResponseTooLarge` | `Unavailable` | never `PASS` |
| HTTP 5xx (bomb-sized error body included) | `ProviderHTTPError` | `Unavailable` | never `PASS` |
| non-JSON, non-UTF-8, non-object, wrong shape | `ProviderMalformedResponse` | `Unavailable` | never `PASS` |
| a working endpoint | — | `Evidence` with the model's verdict | as before |

The judge row is the load-bearing one. Alone, an unavailable soft judge yields a
non-authoritative abstention from the bank — nothing to go on, never a pass.
Beside an authoritative `PASS`, the hard verdict decides and the judge that
never ran contributes **no** calibration sample: it did not abstain, it did not
run.

### 4.4 The frozen default-judge path

`verifier/model_judge.py` and `verifier/grounding.py` are on the repository's
frozen list (`tests/conformance/test_soft_levers.py`), which fails on any
unsanctioned change to them. D4-5 changes both. The sanction follows EX-1's
precedent exactly: the two files are named in a `_HARDEN4_CHANGED` block with
the reason, so the guard still fails on any *other* protected change. That
block is the one thing in this class that needs an explicit ruling rather than
a review — it is called out at the top of the pull request.

### 4.5 Residual — what is not covered

- **The trust root is the system certificate store.** A CA compromise, or a
  rogue CA installed on the host, passes verification. There is no certificate
  pinning; pinning a vendor-neutral gateway would need a pin per deployment, and
  that is a deployment decision, not one this code can make.
- **Proxy environment variables are honoured.** `HTTPS_PROXY` and friends route
  every call through whatever they name — required for real deployments, and
  the way this repository's own CI egresses. A host that can set them can
  redirect the connection; that is the runner-host adversary (§2), not the
  network's.
- **`localhost` trusts `/etc/hosts`.** The loopback literal is not resolved, but
  the name `localhost` is whatever the host's resolver says it is. Same
  boundary as above.
- **Deadlines are not hard real-time guarantees.** F6 bounds network waits with
  a shared monotonic budget; process creation/reaping and OS scheduling add
  overhead and cannot bound a stalled kernel. Serialization and response JSON
  parsing are outside that budget. One ledger operation can perform several
  separately budgeted requests. Cancellation cannot retract bytes already sent
  or undo a remote POST. This is not an exactly-once transport or F7's approval
  expiry enforcement.
- **The resolver adds a process boundary and overhead.** Each lookup launches
  an isolated interpreter — the one subprocess on the chokepoint runner's
  path; §2.4 enumerates exactly what it receives and when it is spawned.
  Missing worker code, denied process creation or
  invalid resolver output fails closed, not over to an unbounded resolver.
  The child uses system DNS configuration but does not inherit environment
  overrides (e.g. `LOCALDOMAIN`, `RES_OPTIONS`) or credentials. Proxy environment
  configuration remains in the parent; the child receives only the selected
  host and port. Deployments need process capacity for concurrent lookups.
- **A soft-tier `Unavailable` is not carried on the fused Judgment.** The bank
  carries *authoritative* unavailability (HARD/HUMAN) downstream; an advisory
  judge that could not run is visible as its own result and in logs, and yields
  a non-authoritative abstention from the bank. Widening the Judgment is a
  Hearth change and was not made here.
- **Swarm proposal generation degrades silently.** `swarm/roles.py` turns any
  provider failure into "no proposal". That is fail-closed — nothing is
  promoted from nothing — but it is not *distinct*: a dead endpoint and a model
  that produced nothing look the same to the swarm. Named, not fixed: it is not
  a verification path, and the transport failure underneath it is now a typed
  error a future change can act on.
- **The error body is quoted.** Up to 500 characters of an endpoint's error
  response are repeated in the exception message. That is attacker-influenced
  text in a log line, bounded and not parsed for meaning.

---

## Attacker 5 — misconfiguration

**Capability.** Not an intruder: the operator, or the deployment, getting a
setting wrong — and, more precisely, a control that is *set* and not *honoured*,
or that can be silently downgraded. This is the last class because it decides
whether the first four mean anything: a defence that can be switched off by a
typo, or asked for and quietly not provided, protects nothing.

### 5.1 What was found

| # | Finding | Severity |
|---|---|---|
| E5-1 | `Config.require_digest_pin` was **read by nothing**. `build_sandbox` took only a name and built `ContainerSandbox()` bare; only the environment variable path worked. `Config(require_digest_pin=True)` produced a container sandbox reporting `False` — measured | **High** |
| E5-2 | With the requirement set and an adapter that cannot pin (namespace, unsafe, or `auto` with no container runtime), nothing refused: the sandbox was built without the property | **High** |
| E5-3 | `Limits.deny_network` was read by no adapter. `True` (the default) changed nothing on the isolating adapters (they deny unconditionally) and was not honoured by the unsafe one; `False` was silently ignored | Medium |
| E5-4 | `provider=remote` with `sandbox=unsafe` — a remote model's output executed with no isolation — was accepted, at load and via `auto`'s opt-in fallback | **High** |
| E5-5 | An unknown sandbox name was accepted at `Config` load and failed only at the first run | Low |

E5-1 is the shape this project keeps finding in its own work, and it is the
reason this class exists: the setting was documented, tested as an environment
variable, and wired to nothing as a field. The audit that named it was right.

### 5.2 What is now enforced

- **The requirement reaches the sandbox, or construction refuses.**
  `build_sandbox` takes `require_digest_pin`; every builder in
  `runtime/factory.py` obtains its sandbox through `build_sandbox_for(config)`,
  the single place the property is honoured. With the container adapter it is
  passed through. With any adapter that runs no image, or under `auto` with no
  container runtime, it is a `ConfigError` — never a sandbox that lacks it.
  Under `auto`, the requirement *decides* the adapter: the container adapter is
  selected even where namespace would ordinarily be preferred.
- **The requirement is the OR of its sources.** `Config.require_digest_pin` and
  `PROM_REQUIRE_DIGEST_PIN` can each raise it; a programmatic `Config(False)`
  beside the environment variable does not switch pinning off.
- **Boolean settings are parsed strictly, by one parser (F9, PROM-FIX-B).**
  Every boolean security setting used to be read by a truth-set test copied
  into seven modules and twenty-one test files, with two fail-open shapes the
  independent review reproduced: a present but misspelled value
  (`PROM_REQUIRE_VERIFIED_SUBSTRATE=tru`) was silently `False`, and a
  programmatic string (`allow_unverified_substrate="false"`) was coerced with
  `bool()` and *enabled* the opt-out. `core/booleans.py` is now the single
  parser at every entry point — `Config` and `Config.from_env`,
  `MigrationRunnerConfig`, `resolve_substrate_policy` and the substrate
  variables, `PROM_REQUIRE_EXTERNAL_SIGNER`, `PROM_REQUIRE_LEDGER_ANCHOR`,
  `PROM_ALLOW_UNSAFE_EXEC`, `PROM_REQUIRE_DIGEST_PIN` (factory and container
  adapter), and the CI gate flags `PROM_REQUIRE_SANDBOX`, `PROM_REQUIRE_PG`,
  `PROM_REQUIRE_PRIVILEGED` and `PROM_REQUIRE_CONTAINER` in the test tree.
  Unset takes the default; a set value must be one of `1/true/yes/on` or
  `0/false/no/off` (surrounding whitespace ignored, case-insensitive) and
  anything else — `tru`, `y`, `t`, `enabled`, an empty string — is refused
  with `ConfigError`, never read as `False`. A programmatic value must be an
  actual `bool`; a string, number or `None` is refused, not coerced.
  `tests/conformance/test_strict_booleans.py` runs the same value matrix
  against every entry point and sweeps the source and test trees so the old
  pattern cannot reappear at another site.
- **Incoherent combinations are refused at load**, with the reason:
  `require_digest_pin=True` with `sandbox=namespace|unsafe`; `provider=remote`
  with `sandbox=unsafe`; an unknown sandbox name. The runtime half of the
  remote rule is enforced too: `auto` may fall back to the unsafe adapter for
  the mock provider under the opt-in, and refuses to for a remote one.
- **A knob that cannot grant what it names is refused.** `Limits(deny_network=False)`
  raises: no isolating adapter grants network access, so the field states the
  invariant rather than pretending to switch it.
- **High-risk routing is not a Config field.** `build_execution_controller`
  hardcodes `route_high_risk=True`; the most permissive `escalate_below` a
  Config can express (`0.0`) still routes high-risk actions to a human.
- **The class, as a mechanism.** `Config.SECURITY_FIELDS` declares every
  security-relevant field. A conformance test parses the source tree and fails
  if any declared field is read nowhere outside `config.py`; a second fails if a
  field whose *name* looks like a security flag is not declared. The next dead
  flag fails CI instead of shipping.

### 5.3 The sweep — every security setting, and what happens when it cannot be met

| Setting | Source | Honoured by | If it cannot be honoured | Status |
|---|---|---|---|---|
| `require_digest_pin` | Config, env | `build_sandbox` → container adapter refuses bare tags | **refused at construction** | fixed (E5-1, E5-2) |
| `sandbox` | Config, env | `build_sandbox` | unknown name refused at load; `unsafe` needs the env opt-in | fixed (E5-5) |
| `PROM_ALLOW_UNSAFE_EXEC` | env only | `build_sandbox` | without it, `unsafe` is refused and `auto` falls to `NullSandbox` (refuses to run) | enforced |
| `allow_insecure_loopback` | Config, env | `validate_endpoint` at load and construction | plaintext to a remote host is refused regardless | enforced (§4) |
| `api_base` / `judge_api_base` scheme | Config, env | `validate_endpoint` | refused at load | enforced (§4) |
| `provider_max_response_bytes`, `request_timeout_s` | Config, env | `RemoteModelProvider` | out of range refused at load; exceeded at runtime → typed error, `Unavailable` | enforced (§3, §4) |
| `verifier_*` caps, `Limits` | Config, env | sandbox adapters | NaN/inf/negative refused at load; `0` documented as "no cap" | enforced (§3) |
| `Limits.deny_network` | code | invariant on isolating adapters | `False` refused | fixed (E5-3) |
| `escalate_below`, `gate_threshold` | Config, env | `ActionGate`, `PromotionGate` | out of `[0,1]` refused at load | enforced (§3) |
| `route_high_risk` | hardcoded | `ActionGate` | not configurable | enforced |
| `pending_ttl_seconds` | Config, env | `PendingActionService` | negative refused; `0` documented as "no expiry" | enforced (§3) |
| `enable_model_judge` | Config, env | `build_orchestrator` | a provider without `assess` → every verify is `Unavailable`, visibly; not refused (advisory feature, not a security requirement) | honoured |
| `MigrationRunnerConfig` | code | chokepoint runner | key under 32 bytes, no durable store, or neither/both of `signing_key` and `signer` → refused at construction | enforced (§1, §2.6) |
| `require_external_signer` | Config, env, runner config (OR of sources) | `resolve_signer` at build | a local HMAC key → **refused at construction** ("cannot be honoured"); a KMS failure at build → no signer | enforced (§2.6, PIH-2) |
| `ledger_anchor` | Config, env | `build_ledger` → the anchor target; written after every append, pinned on every verify | malformed or plaintext-to-remote refused at load; a target that cannot be read → `NOT_VERIFIABLE`; a target that cannot be written → `AnchorUnavailable` raised, the runner refuses | enforced when set (§3, PIH-1) |
| `require_ledger_anchor` | Config, env (OR of sources) | `build_ledger` | no anchor, or a `file://` one → **refused at construction** ("cannot be honoured") | enforced (§3, PIH-1) |
| `ledger_anchor_retention_days` | Config, env | object-lock targets (requested per record) | out of `[1, 36500]` refused at load; the medium's honouring of it is a deployment property | enforced at load (§3.4) |
| `require_verified_substrate` | Config, env, runner config (OR of sources) | `resolve_substrate_policy` → `ConsumedApprovals` at construction | an approval store on a filesystem the probe cannot identify → **refused at construction** ("cannot be honoured"), the opt-out below withdrawn; a known network or host-shared filesystem is refused regardless of any setting | enforced (§2, PROM-FIX-A) |
| `allow_unverified_substrate` | Config, env, runner config (honoured from any source) | `ConsumedApprovals` at construction | the opt-out for an *unidentified* substrate only, logged as a warning at every construction; no effect on a known network filesystem; refused at load, at runner-config construction and at resolution beside `require_verified_substrate` | enforced (§2, PROM-FIX-A) |
| every boolean setting above, and the CI gate flags | Config, env, runner config, test tree | `core/booleans.py` at every read | a set value outside `1/true/yes/on` and `0/false/no/off` → **refused at load** (`ConfigError`), never read as false; a programmatic non-`bool` → refused, never coerced; unset → the default | enforced (F9, PROM-FIX-B) |

### 5.4 Default posture

A `Config()` with nothing set: mock provider (no network), `sandbox=auto`
(isolating adapters only; with nothing isolating available and no opt-in it
builds a `NullSandbox` that refuses to run code), plaintext loopback off, model
judge off, human holds expire, escalation floor `0.75` with high-risk routing
hardcoded on, every cap finite and positive, and an approval store accepted
only on a filesystem identified as local (`allow_unverified_substrate` off).
Asserted by `test_defaults_are_the_hardened_posture` and
`test_an_unknown_substrate_is_refused_by_default`.

**Three defaults are not the hardened posture, stated rather than hidden:**

- **`require_digest_pin=False`.** Digest pinning is a property of a container
  image, and the shipped default image is a floating tag by design so the code
  stays vendor- and architecture-neutral; a pinned digest is a per-deployment
  value that would go stale in the repository. `auto` prefers the namespace
  adapter, which runs no image to substitute, and the container adapter warns
  on every unpinned construction. Turning the default on would make every
  deployment with a container runtime and no pinned image refuse to run — the
  right posture for production, and a production deployment sets it. It is the
  recommended production setting and the one flag this model asks an operator
  to remember.
- **`require_ledger_anchor=False`** (§3.5). A file-backed ledger with no anchor
  opens with a warning that a rewrite from genesis is undetectable; in-memory
  and throwaway ledgers have nothing to anchor and a development install has no
  witness to point at. Production sets `PROM_REQUIRE_LEDGER_ANCHOR=1`, which
  refuses an unanchored ledger and a `file://` anchor alike.
- **`require_external_signer=False`** (§2.6). A development install has no KMS
  to point at, and the in-memory KMS is a test double, not a place for a
  production key; the local key is warned about at build as non-protecting.
  Production sets `PROM_REQUIRE_EXTERNAL_SIGNER=1`, which refuses it.

### 5.5 Residual — what is not covered

- **Three of the defaults above are permissive**, for the stated reasons. An
  operator who forgets `require_digest_pin` on a container-only host runs an
  unpinned image, with a warning; one who forgets `require_ledger_anchor` runs
  an unwitnessed ledger, with a warning on every open; one who forgets
  `require_external_signer` signs with a key root can read, with a warning at
  build.
- **The dead-flag mechanism sees attribute reads, not enforcement.** It proves
  a field is *consumed* somewhere; whether the consumer honours it correctly is
  what the per-flag tests in §5.3 are for. A field read only to be logged would
  pass the mechanism and fail nothing else — a limit of static reading, named.
- **Environment-only settings bypass `Config`.** `PROM_SANDBOX_IMAGE` and
  `PROM_ALLOW_UNSAFE_EXEC` are read from the environment directly. They are
  validated where they are read, but they are not on `SECURITY_FIELDS` because
  they are not fields; a future one is not caught by the mechanism.
- **`enable_model_judge` with a provider that cannot assess is not refused.**
  Every verify is a visible `Unavailable` rather than a silent abstention (§4),
  and the judge is advisory; refusing at load was judged more disruptive than
  the failure it would prevent.
- **Coherence rules are a fixed list.** The six combinations checked are the
  ones found; a new setting introduces new combinations that nothing enumerates
  automatically.

---

## Related documents

- `docs/chokepoint-threat-model.md` — the chokepoint's own model and invariants.
- `docs/sandbox.md` — the sandbox adapters and their guarantees.
- `docs/ledger-integrity.md` — what the audit hash chain does and does not detect.
- `docs/pre-disclosure-audit.md` — the external-reviewer readiness audit.
