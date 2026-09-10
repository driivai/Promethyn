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

## Threat: a secret reaching a diagnostic

An independent review took one canary token, put it in the configured API key,
and found it in roughly twenty-five distinct public strings: `repr(Config)`,
`asdict(Config)` serialised to JSON, a provider exception message reading
`endpoint returned HTTP 401: Bearer <CANARY>`, that exception's `__cause__`, a
judge `Unavailable.detail`, a **successful** judge result's `Evidence.detail`, a
redirect diagnostic naming an attacker-chosen hostname, and the ledger rows
written from all of the above.

The tempting reading is twenty-five bugs. The correct reading is one: **raw
upstream text and unredacted configuration were allowed into public strings at
all**, and every enumerated sink was a place that permission had been exercised.
Patching the enumerated sinks is the denylist trap — the sink nobody listed
leaks the next secret. So the fix is two things that hold without an inventory.

### 1. A secret cannot render, by any path

`prometheus_protocol.core.secrets.Secret` wraps the value. `__repr__`,
`__str__` and `__format__` return `Secret(<redacted>)`; `__deepcopy__` returns
`self`, so `dataclasses.asdict` copies the *wrapper* rather than unwrapping it;
and the type is not JSON-serialisable, so `json.dumps` fails closed instead of
emitting anything. `reveal()` is the single exit, and it is greppable.

**`repr=False` was tried and is not sufficient — this is measured, not
theoretical.** `DbTarget.password` carried `repr=False` *and* a credential-free
`__str__`, and `asdict(target)` still returned the password in clear: `asdict`
never consults `field.repr`. Two correct per-path opt-outs, one uncovered path,
credential out. A per-field opt-out also fails in the direction that matters
most — a field added next year is unprotected by default. A wrapper type is
protected by default, and the discovery sweep below catches a new field that
forgets to use one.

### 2. A diagnostic is drawn from a closed vocabulary

`prometheus_protocol.core.diagnostics` defines a frozen set of reason codes and
an **allowlist** of context keys with their types. A `Diagnostic` refuses at
construction: an unknown reason, an unlisted key, a wrong type, an `endpoint`
that is not a bare configured origin, an unlisted `operation`. Upstream bytes
have nowhere to go — not because a scrubber removed them, but because no field
accepts them.

**No public diagnostic in this codebase carries raw upstream text, and there is
no location where such text is retained instead.** The response body is read
under a byte ceiling, counted, and discarded; what survives is the count.

Diagnostics stay actionable: a rejected credential (`http_unauthorized
status=401`) is distinguishable from a timeout (`timeout elapsed_ms=30000`),
from an oversized response (`response_too_large bytes_read=… limit_bytes=…`),
and from a malformed body (`body_not_json position=17 document_bytes=900`);
`LOCAL_REASONS` answers "ours or theirs" structurally.
`test_secret_sink_regressions.py` asserts each of those distinctions.

### Three consequences worth stating plainly

**A TLS failure keeps OpenSSL's symbolic reason.** The first version of this
work returned a bare `tls_failure` for every TLS error, and that is a different
failure mode rather than a fix: an expired certificate, a hostname mismatch, a
self-signed chain and a plaintext server answering `https` demand different
actions. The diagnostic carries `tls_reason` (OpenSSL's symbolic constant) and
`verify_code` (its X509 table), both closed vocabularies the peer does not
compose; `str(exc)` and `verify_message` are dropped, because they are prose and
for a hostname mismatch the message names the identities the *peer presented* —
attacker-chosen content of exactly the kind the redirect rule refuses.

**A redirect refusal does not name where it was sent.** The attacker controls
the hostname, so stripping path and query is not enough and a hash of the target
is still derived from attacker-chosen content. The refusal reports the status
and the *configured* endpoint: `redirect_refused status=302
endpoint=https://api.example`. An operator diagnoses it from their own side —
the endpoint is known, and where it redirects to is a property of that endpoint,
observable with one `curl` against infrastructure they control.

**A successful judgement records a classification, not the model's words.** The
`Evidence.detail` of a passing judge call is `judge_verdict verdict=PASS
response_chars=412 confidence=0.9` — verdict, length, and the parsed confidence.
Success was a leak channel as much as failure: the model is a remote endpoint
being fed candidate text, and its reply was written verbatim into a permanent,
signed, replicated record. A digest of the reply was considered and rejected:
for short or templated replies it is brute-forcible, so it is still derived from
content that may be attacker-chosen.

### Proof, and what it does not cover

`tests/conformance/test_secret_canary_sweep.py` drives a unique canary through
every credential field and a reflecting HTTP endpoint that echoes the bearer
token in a 4xx body, a 5xx body, a 200 body, a response header and a redirect
`Location` hostname, then asserts its absence from exception strings and
`args`, formatted traceback chains, every public result object's
repr/str/asdict/JSON, `Evidence.detail` and `Unavailable.detail`, ledger rows
read back from disk, and captured log output at every level. Surfaces are found
by **discovery** — dataclasses via `pkgutil.walk_packages`, CLI subcommands from
the real argparse parser — so a new dataclass or a new subcommand is covered the
day it is added, without editing a list.

The residual, stated because a hidden gap is worth less than a named one:

- **`reveal()` is the boundary, and the plaintext is real on the other side.**
  It sits in the frame and in the outbound request header, and travels to the
  configured endpoint under TLS. That is the credential being used.
- **A `Secret` still pickles**, deliberately, because `multiprocessing` carries
  configuration between processes. A pickled config on disk is a credential at
  rest and must be treated as one.
- **Process memory is not scrubbed.** Trust boundary 2 in the threat model —
  an insider reading the runner's memory — is unchanged by any of this.
- **Discovery matches credential-shaped field NAMES.** A credential in a field
  called `handle` is not found. Two fields are sanctioned as deliberate
  non-credentials (`AuditPage.next_token`, a pagination cursor;
  `ModelSigner._public_key`, a public key), and a test fails if a sanction
  outlives the field it excuses.
- **The canary sweep proves absence for the surfaces it drives.** A code path
  no test reaches is untested, not proven clean.

## Threat: silent or irreversible change

Every attempt and promotion is appended to the ledger, and every promoted
skill is a removable markdown file. Changes are therefore auditable (I3) and
reversible (I2): a bad promotion can be identified from the ledger and undone.

## Reporting

See `SECURITY.md` for the coordinated disclosure process.
