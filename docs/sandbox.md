# Sandbox: isolating untrusted candidate code

The verifier runs untrusted, model-generated code: candidate solutions and the
swarm Skeptic's executable falsification cases. This document describes the
isolation layer that contains that code — what it defends against, what it does
not, and the adapters that provide it.

## The guarantee (and what it is not)

The trusted-core guarantee is small and provable: **untrusted candidate code
runs only under isolation.** It is expressed as the `Sandbox` port and the
INV-SANDBOX invariants (`spec/invariants.md`), and proven by adversarial tests
that run hostile code and assert containment (`tests/conformance/test_sandbox.py`).

This layer closes an existing hole — the verifier already executed candidate
code — without opening a new capability. **Live execution is still disabled**:
the swarm executor remains a no-op `RecordingExecutor`. The sandbox is designed
so a future live executor can reuse it, but this sprint wires it only into the
verifier.

## Threat model

**Defended against** (a malicious or buggy candidate cannot):

- **Reach the network** — no interfaces / `--network none` (INV-SANDBOX-1).
- **Touch the host filesystem** — it sees a read-only root with a single
  writable workspace; it cannot write outside the workspace, modify read-only
  paths, or read sensitive host directories (INV-SANDBOX-2).
- **Exhaust host resources** — address space, CPU time, process count, and wall
  clock are bounded (by a cgroup where available, otherwise POSIX rlimits — see
  *Process/resource limiting* below), and the whole process tree is reaped on
  exit (INV-SANDBOX-3).
- **Escalate privilege** — it runs unprivileged with `no_new_privs` set and
  capabilities dropped, so setuid/`mknod`/mount escalation fails (INV-SANDBOX-4).

**Explicitly NOT defended against** (out of scope for this layer):

- Kernel or container-runtime 0-days, side-channels (Spectre-class), or hardware
  attacks. Use a microVM (gVisor, Firecracker, Kata) for hostile multi-tenant
  workloads.
- A compromised host, image, or supply chain — see image pinning below.
- Covert resource use within the granted limits, or wall-clock starvation of
  other tenants beyond the per-run bound.
- Anything the unsafe opt-in path (`PROM_ALLOW_UNSAFE_EXEC=1`) disables; that
  path is dev-only and is not a sandbox.

## Adapters

Selected by `Config.sandbox` / `PROM_SANDBOX`; the default `auto` picks the best
*functioning* isolating adapter and never the unsafe runner.

### Container (`container`) — most robust for production

Runs the candidate in Docker or Podman with `--network none`, a read-only root
plus a writable workspace bind, `--memory` / CPU quota / `--pids-limit`
(cgroup-backed resource bounds), `--cap-drop ALL`,
`--security-opt no-new-privileges`, a non-root user, and the runtime's default
seccomp profile. Requires a container daemon.

**Pin the image by digest** in production via `PROM_SANDBOX_IMAGE` (e.g.
`python:3.12-slim@sha256:…`). By default a bare tag is accepted but logged as a
supply-chain risk. Set **`PROM_REQUIRE_DIGEST_PIN=1`** to make that posture
enforceable: the adapter then *refuses* to run a bare-tag image — a
could-not-verify (`started_ok=False` → the verifier ABSTAINs), checked before
the container is created so it is deterministic. A bare tag can be silently
repointed at a different image after it was vetted; the flag closes that
substitution window. It is off by default for dev convenience and is the
recommended production setting.

### Namespace (`namespace`) — daemonless default where no runtime exists

Runs the candidate under `unshare` in fresh user + mount + network + PID
namespaces, then makes the root filesystem read-only with a writable workspace,
hides sensitive paths, drops all capabilities, sets no-new-privileges, and
applies POSIX rlimits. No daemon or root required — only a Linux kernel with
unprivileged user namespaces enabled (`kernel.unprivileged_userns_clone=1` /
`user.max_user_namespaces > 0`). This is the adapter the bundled conformance
tests exercise.

### Unsafe (`unsafe`) — dev-only, opt-in, NOT a sandbox

The historical child-interpreter-with-timeout path. No network, filesystem, or
privilege isolation. Selectable only with `PROM_ALLOW_UNSAFE_EXEC=1`; logs a
warning on every run. For offline development against trusted/mock examples.

### Null backstop

When no isolating adapter is available and the unsafe path was not opted into,
the default returns a `NullSandbox` whose runs report `started_ok=False`, so the
verifier ABSTAINs (could-not-verify) rather than executing untrusted code in the
clear. The sandbox is mandatory by construction (INV-SANDBOX-5).

## Process/resource limiting

The namespace adapter bounds the candidate tree with the **strongest lever the
host offers, and never a weaker one silently**:

- **Primary — cgroup.** Where a writable cgroup is available (the cgroup v2
  unified hierarchy with the `pids` controller delegated, or the v1 `pids`
  controller) the adapter creates a scoped cgroup, caps it (`pids.max`, and on
  v2 also `memory.max` and `cpu.max`), and moves the candidate tree into it
  before it runs. A cgroup `pids.max` is a per-cgroup cap that even a privileged
  nested process cannot bypass, and its `pids.events` counter is an unforgeable
  record that the cap was enforced.
- **Floor — POSIX rlimits.** The bootstrap *always* applies `RLIMIT_AS`,
  `RLIMIT_CPU`, `RLIMIT_NPROC`, and `RLIMIT_FSIZE` regardless. So the cgroup can
  only *add* containment; it never replaces the floor and never breaks a run.

This is best-effort and fail-safe by construction: any cgroup step that fails
returns to the rlimit floor. Which lever was used is reported on every result as
`SandboxResult.limiter` (`"cgroup"` or `"rlimit"`) — never silently weaker, a
caller can always tell. The container adapter's `--pids-limit` / `--memory` are
cgroup-backed by the runtime, so it reports `"cgroup"`.

The INV-SANDBOX-3 conformance test asserts the **stronger** property where the
cgroup lever is present (the cgroup itself denied the fork, via `pids.events`)
*and* the universally-true property everywhere (the bomb was bounded and its tree
reaped, the host unaffected).

## Classification

The verdict mapping is unchanged. A candidate that cleanly fails its cases is
`FAIL`; a sandbox/infrastructure failure (`started_ok=False`) is `ABSTAIN` (no
calibration sample), consistent with existing ABSTAIN handling. Timeouts and OOM
remain `ABSTAIN` for now; the sandbox makes a cleaner candidate-fault vs
harness-fault distinction possible as a separate, deliberate follow-up.

## CI

The conformance tests skip when the isolation runtime is absent locally. In CI
they must not silently skip: with `PROM_REQUIRE_SANDBOX=1` (set in the workflow)
an otherwise-skipped sandbox test fails instead, so a CI without the runtime
cannot pass with isolation untested. GitHub's Ubuntu runners provide
unprivileged user namespaces and run non-root, so the namespace adapter runs
there.
