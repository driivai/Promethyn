# Security Policy

## The untrusted-code requirement

Prometheus Protocol executes proposed code in its verifier. The reference
verifier (`src/prometheus_protocol/verifier/runner.py`) applies a wall-clock
timeout and POSIX resource limits and runs each candidate in an isolated
interpreter — but **it is not a sandbox**. Those measures bound accidental
runaway code; they do not contain hostile code.

> Before running untrusted code, you MUST run the verifier inside a real
> isolation boundary — a locked-down container, microVM, or seccomp/namespace
> jail — with no network access and a read-only, disposable filesystem.

Treat the built-in limits as defence in depth only. See
`docs/security-model.md` for the full model.

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
