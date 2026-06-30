# Security Policy

## The untrusted-code requirement

Promethyn executes proposed code in its verifier — model-generated candidate
solutions, and the swarm Skeptic's executable cases the verifier runs. That
untrusted code now runs **inside an isolating sandbox** (`sandbox/`): the
default verifier executes every candidate through an adapter that denies the
network, constrains the filesystem to a writable workspace over a read-only
root, drops capabilities and sets no-new-privileges, and bounds resources
(memory, CPU time, processes, wall clock). The isolation is proven by
adversarial conformance tests (INV-SANDBOX-1…5 in `spec/invariants.md`,
`tests/conformance/test_sandbox.py`) that run hostile code and assert
containment.

The historical no-isolation path (a child interpreter with only a timeout and
rlimits) survives as the explicitly-named `UnsafeLocalSandbox`. It is **not a
sandbox** and is selectable only with `PROM_ALLOW_UNSAFE_EXEC=1`; it is for
offline development against trusted/mock examples, never for untrusted code, and
it logs a warning whenever it runs.

> Choose the isolating adapter that matches your platform (`PROM_SANDBOX`): the
> container adapter (Docker/Podman, the most robust — pin the image by digest)
> or the daemonless namespace adapter. Where no isolating runtime is available
> the default refuses to run candidate code (it abstains) rather than running it
> unsandboxed. See `docs/sandbox.md` for the threat model and requirements, and
> `docs/security-model.md` for the full model.

**Live execution (tool side-effects) is still NOT enabled**: the swarm executor
remains a no-op recorder. This layer sandboxes the code the verifier already
runs; it does not grant any new execution capability.

## Supported versions

During the v0.x series, only the latest released minor version receives
security fixes.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do **not** open a public
issue for a security report.

- Email: `security@driivai.com`
- Include: affected version or commit, a description, and reproduction steps or
  a proof of concept if available.

We aim to acknowledge a report within three business days and to agree on a
coordinated disclosure timeline. Please give us reasonable time to release a
fix before any public disclosure. We are happy to credit reporters who wish to
be named.
