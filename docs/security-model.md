# Security Model

> The adversarial assessment — five attacker classes, what is proven by which
> test, and what remains open — is `docs/threat-model.md`. This page describes
> the verifier's execution boundary; the threat model is the document to hand
> to a reviewer.

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
- a data-only response channel: the child supplies return values, while the
  trusted parent retains expected answers and computes comparisons, counts and
  the verdict. No candidate-written verdict file is read.

The child harness is **not trusted**, even inside an isolating sandbox. A
candidate can alter its harness or fabricate its entire response; it still has
to supply values that match the parent's expectations. This checks observable
outputs, not whether a particular function body or algorithm executed. Inputs
are visible to the candidate; expected answers are not staged in its workspace
or passed over the sandbox port.

The wire format accepts only built-in `None`, booleans, integers, floats,
strings, bytes, lists, tuples and dictionaries, with type-preserving tags.
Custom objects (including subclasses), sets and other unsupported task values
cause `Unavailable` before execution; unsupported candidate returns fail the
case. There is no pickle, eval, or candidate-defined comparison in the parent.
Messages are limited to 1,000,000 bytes of ASCII-encoded JSON,
nesting depth 32 (root depth 0) and 20,000 value nodes; the parent rejects non-ASCII wire text,
oversized responses, malformed envelopes, wrong case counts and duplicate
mapping keys. Normal candidate prints go to evidence stderr; stdout is reserved
for the value protocol. Truncation, abnormal exits and resource-limit flags
cannot produce a pass. Missing start confirmation is `Unavailable`, and a
confirmed-start timeout remains `ABSTAIN`, never `PASS`.

### What it does NOT do — and the hard requirement

Process limits and `-I` alone are **not** a real sandbox. The default adapter
requires namespace or container isolation and refuses execution if unavailable.
The explicitly opted-in `UnsafeLocalSandbox` does not contain hostile code and
is only for trusted development fixtures. It provides no protection for the
parent's expected answers, credentials or memory against a hostile candidate.

> Before running untrusted code, you MUST use a real isolation boundary for the
> candidate, separate from the trusted verdict process — a locked-down container,
> microVM, or seccomp/namespace jail — with no network and a disposable writable
> workspace. Treat process limits as defence in depth, not the only boundary.

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
