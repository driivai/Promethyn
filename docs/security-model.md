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

## Threat: an action authorized without the verification it required

Two fail-opens were reproduced, neither caused by a broken verifier. The swarm's
aggregation substituted *everything that ran passed* for *everything REQUIRED
passed*: a missing verifier, a raising verifier or an ABSTAIN was discarded, a
passing structural check then yielded a synthetic HARD PASS, and the gate
approved. Separately the bank accepted a HARD PASS alongside a HARD Unavailable
and returned an authoritative PASS — which is CORRECT for two redundant HARD
verifiers where either suffices, and a fail-open when the unavailable one was
the only thing covering a requirement. The bank could not tell those apart
because nothing told it.

Every producer implements "couldn't-verify is never verified-clean". The
aggregate did not. The missing thing was not a fix to either aggregator; it was
a trusted notion of a REQUIRED CHECK, which no layer had.

### The invariant

> An action is authorizable only when every requirement derived from the trusted
> policy has a valid, satisfactory result bound to that action and verification
> attempt. Untrusted inputs may request additional checks but cannot weaken those
> requirements. Missing policy, missing evidence, uncertainty, or an unavailable
> required verifier cannot produce an authorization-capable result.

No clause is added to that and none is excepted. In particular, permitting more
than one implementation for a requirement does not add one: the requirement is
satisfied by a RESULT, never by the permitted set's size.

### How it is made true

**A requirement is keyed by CHECK IDENTITY, not by verifier or tier.**
`BoundRequirement` carries `check_id` and the implementations permitted to
satisfy it, and deliberately has **no tier field**. HARD means authoritative
evidence; it never means "this check covers every requirement". The consequence
that has to hold is that a missing executable check cannot ERASE a requirement —
and it cannot, because the requirement is derived from the policy and the action
class alone, never from what the plan turned out to contain.

**The resolver is trusted; the plan is not.** An untrusted proposal may request
additional checks and they are recorded. It cannot remove, replace, downgrade or
omit-into-nonexistence a policy requirement. If policy requires executable
verification for a code action, an empty entry point means **verification cannot
proceed** — not "this action needs only structural checks". Adding a
`required=True` field to the plan would not fix this, because the attack is
omission, not mislabeling.

**Coverage is validated before fusion.** `VerifierBank.judge_covered` decides
coverage against the resolved snapshot first and fuses only what survives.
Fusion answers "how confident are we in the verdict we have"; it was never able
to answer "is there a verdict we are missing".

**Interchangeable redundancy is not quorum.** Two permitted implementations
means the requirement was never keyed to one. It is satisfied when at least one
produced a valid, satisfactory, correctly bound result; unavailable results from
the others are recorded and irrelevant. Both unavailable **refuses** — absence
never satisfies, however many were permitted. Quorum, substitution and fallback
are deferred as distinct concepts needing their own specification and threat
model, and nothing here leaves a hook for them.

### Where policy lives, and why that is temporary

Profiles are committed data under the content-based Hearth sanction, selected by
`Config.verification_profile`, with the profile's content digest bound into every
snapshot so a decision is bound to the policy that produced it.

**That is right for this version and wrong for the product.** A licensed
component whose customers cannot supply their own digest-pinned policy without a
code change is a bad product shape — their policy is their risk decision, not
ours. The resolver therefore takes a policy VALUE and nothing downstream reaches
for the profile table, so a customer-supplied supplier is a later addition
beside `load_profile`, not a rewrite.


### The unbound-judgment route, and how it was closed (PHASE-1.2b)

Checkpoint 2 enforced requirement coverage and then named its own exposure: a raw
authoritative `Judgment` still authorized. Four surfaces took one and asked it a
single question — is this an authoritative PASS — which a `Judgment` can answer
with no policy ever resolved:

| surface | what it authorized |
|---|---|
| `ActionGate.decide` | any executable action |
| `ExecutionController.submit` | the same, plus the human-hold path |
| `ActionGateway.route_action` | a workflow step's action |
| `ApprovalAuthority.authorize` / `RecordedApprovalAuthority.authorize` | a signed, single-use capability against a privileged database principal |

The fourth was not named in the sprint brief and was found while migrating. It is
the most consequential of them, and `RecordedApprovalAuthority` — not the base
class — is what `build_migration_runtime` constructs.

**The change is a type, not a check.** None of those surfaces has a parameter
that accepts a `Judgment` any more. They accept a `PolicyAssessment`, which
carries the resolved snapshot digest the decision is bound to and the outcome
coverage validation produced. `VerifierBank.assess` is the only thing that mints
one, and it mints only what `judge_covered` returned.

**How structural that is, precisely.** At the INTERFACE it is a construction: no
caller can hand over a verdict, and no amount of forgetting a check reopens the
route. At the CONSTRUCTOR it is a guard: `PolicyAssessment` refuses to be built
except by minting, and it CONSUMES its minting token, so `dataclasses.replace`
inherits a spent one and is refused. That last part was measured — `replace`
forged a valid-looking assessment before the token was consumed.

**What still varies.** Anything able to run arbitrary code in this process:
`object.__setattr__` reaches through `frozen=True`, and
`policy.assessment._MINT` is an importable module global. The mint guard makes an
accidental assessment impossible and a deliberate one a visible, greppable act
that `test_no_second_aggregator.py` sweeps for. It is not a security boundary,
and the control against arbitrary in-process code remains the process boundary.

**A Checkpoint-2 claim withdrawn.** Checkpoint 2 said `build_orchestrator`,
`build_execution_controller` and `build_migration_runtime` "reach the same
`judge_covered` once their callers pass a snapshot", asserted as
`assert build_migration_runtime is not None`. Two thirds of that was wrong:
`build_migration_runtime` never reaches `VerifierBank` at all, and
`build_orchestrator` has a `PromotionGate` and no executor, so it cannot
authorize an action and had nothing to reach. Both are now asserted
behaviourally, including the absence.

### The residuals, named

- **The operator asserts that permitted implementations are equivalent; nothing
  verifies it.** The policy names them and the record shows WHICH one answered,
  so a reviewer can see that A was down and B answered. Managed, not hidden.
- **An attacker who can make the stronger permitted implementation unavailable
  may get the weaker one to answer.** Inherent to permitting more than one; the
  policy naming them is the auditable control. It does not extend to satisfying
  a requirement with no answer.
- **~~A raw authoritative `Judgment` still authorizes.~~ CLOSED in PHASE-1.2b.**
  See *The unbound-judgment route, and how it was closed* below. The residual
  that replaces it is narrower and is stated there.
- **`frozen=True` is not protection against hostile Python in the process.**
  `object.__setattr__` reaches through it. It prevents accidental mutation and
  guarantees a policy value cannot drift between being digested and being
  enforced; the control against arbitrary code is the process boundary.
- **Coverage validates the evidence it is GIVEN.** A trusted caller that never
  constructs a result for a check it ran looks identical to a check that never
  ran, and coverage refuses — the safe direction, but caller completeness stays
  the caller's contract.

## Threat: silent or irreversible change

Every attempt and promotion is appended to the ledger, and every promoted
skill is a removable markdown file. Changes are therefore auditable (I3) and
reversible (I2): a bad promotion can be identified from the ledger and undone.

## Reporting

See `SECURITY.md` for the coordinated disclosure process.
