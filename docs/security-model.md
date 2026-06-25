# Security Model

## Threat: executing proposed code

The verifier runs code it did not write. In the reference implementation that
code comes from a simulated or configured proposer, but the protocol is built
to learn from *arbitrary* proposals, so the verifier must be treated as an
executor of untrusted code.

### What the reference verifier does

`verifier/runner.py` runs each candidate in a separate Python process with:

- a **wall-clock timeout** (terminates hung code),
- **POSIX resource limits** — CPU time (`RLIMIT_CPU`), address space
  (`RLIMIT_AS`, opt-in), and file size (`RLIMIT_FSIZE`),
- **isolated interpreter mode** (`-I`), and
- a result file kept off stdout so candidate output cannot forge a verdict.

### What it does NOT do — and the hard requirement

This is **not** a real sandbox. The limits above bound *accidental* runaway
code; they do not contain *hostile* code. A determined payload can still read
the filesystem, open network sockets, or exhaust shared resources.

> Before running untrusted code, you MUST place the verifier inside a real
> isolation boundary — a locked-down container, microVM, or
> seccomp/namespace jail — with no network and a read-only, disposable
> filesystem. Treat the in-process limits as defence in depth, never as the
> only line of defence.

This requirement is repeated prominently in the verifier source and in
`SECURITY.md`.

## Threat: evaluation leakage

If the proposer could see hidden cases, or if skills were promoted on the same
tasks they were mined from, measured improvement would be an illusion. Two
structural controls prevent this:

- The provider contract excludes hidden cases by construction.
- The held-out firewall (invariant I1) keeps the forge's training ids and the
  gate's scoring ids disjoint, enforced in code.

## Threat: silent or irreversible change

Every attempt and promotion is appended to the ledger, and every promoted
skill is a removable markdown file. Changes are therefore auditable (I3) and
reversible (I2): a bad promotion can be identified from the ledger and undone.

## Reporting

See `SECURITY.md` for the coordinated disclosure process.
