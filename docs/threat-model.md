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

> **Status.** Attacker 1 is complete. Attackers 2–5 are listed with their scope
> so the shape of the work is visible, and are explicitly **not yet assessed** —
> they are not claimed as closed, and the absence of findings under them means
> nobody has looked yet.

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
  chokepoint has nothing left to say. That is attacker 2's subject.
- **`unsafe` and `container` adapters.** The environment-construction fix is
  applied to the namespace adapter. The `unsafe` adapter is explicitly not a
  sandbox and is opt-in behind `PROM_ALLOW_UNSAFE_EXEC=1`; the container adapter
  gets a clean environment from the container runtime rather than from this code
  path, which is a different mechanism and has not been re-proven here.
- **Denial of service against itself.** An agent can burn its own CPU and wall
  clock. Bounded by cgroups/rlimits, not eliminated.

---

## Attackers 2–5 — scope stated, not yet assessed

Listed so the remaining surface is visible. **No claim is made that any of these
is closed.** Findings will be added as each class is worked.

- **Attacker 2 — the runner host.** Privilege minimisation for the runner
  process, including the world-writable (`0777`) container workspace; what an
  attacker with runner-host write access can do to the ledger, given that a full
  rewrite from genesis is undetectable without an out-of-band anchor
  (`docs/ledger-integrity.md` states this limit).
- **Attacker 3 — the ledger.** Making the tip anchor operational rather than
  available, and finite-range validation for numeric configuration.
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
