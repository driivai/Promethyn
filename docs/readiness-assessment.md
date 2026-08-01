# Promethyn readiness assessment (PROM-AUDIT)

**Date:** 2026-07-30 · **Scope:** `driivai/Promethyn` @ `59569af` (main) · **Mode:** read-only.
**Question:** can Promethyn serve as a live authorization gate against an adversarial
agent — specifically the planned Hugging-Face-pattern experiment (an agent escaping
containment via unauthorized **network egress**)?

Every claim below is backed by a file reference or a command I ran in this environment.
Where I could execute the thing rather than read it, I did.

---

## 1. Executive verdict

**NOT READY for the egress experiment — the load-bearing capability does not exist.**

Promethyn is a genuinely well-built authorization gate for a *narrow, code-shaped* action
set: it verifies candidate code in real isolation, blocks or routes by construction, and
fails **closed** when verification cannot run. That machinery is real, tested, and (for the
sandbox) empirically verified here. But it has **zero network-egress interception**: the
action model has exactly two kinds — `python_code` and `git_delete_branch`
(`core/models.py:250-252`) — and neither is a network operation. The gate authorizes
*actions submitted to it*; it is an in-process authorizer, not a network chokepoint. The
sandbox *does* deny egress — verified, only `lo` is visible inside it — but by **total
interface removal**, all-or-nothing, which cannot model "allow the agent its legitimate
API calls, block the exfiltration." For the HF experiment the needed capability is
**NOT-BUILT** (§3). Two secondary gaps compound it: the ledger is append-only *by
convention only*, not tamper-evident (§5), and the whole model assumes the agent *proposes*
and Promethyn *executes* — an agent that acts directly is invisible to the gate (§5).

---

## 2. Capability inventory

| Pillar | State | Evidence |
|---|---|---|
| **VERIFY** | **Implemented (real)** | `verifier/runner.py` `SubprocessVerifier` runs candidate code against hidden cases in the sandbox and returns PASS/FAIL/ABSTAIN — a real HARD check, not always-pass. SOFT verifiers (`model_judge.py`, `grounding.py`) are advisory (non-authoritative) by tier construction (`core/models.py:73-74`). The conformance suite has **teeth**: `tests/conformance/test_extension_surface.py` *rejects* a guessing verifier and a lying-SOFT verifier. |
| **GATE** | **Implemented (real, enforced by construction)** | `gate/authorization.py` `ActionGate.decide`; `execution/executor.py:55-56` raises on any decision that is `not approved`. A blocked/routed/unavailable decision is always `approved=False` and cannot reach execution. **Caveat:** it governs only `ExecutableAction`s handed to `ExecutionController.submit` — it is not a runtime chokepoint (§5). |
| **RECORD** | **Partial** | `ledger/sqlite_ledger.py` is append-only **by convention** (its own docstring, line 3). Real audit columns, backfill, and queries exist — but there is **no** hash chain, HMAC, or signature (grep for `hashlib\|hmac\|sha256\|chain\|signature` in `ledger/` → none), and `resolve_pending_action` uses `UPDATE`. Not tamper-evident. |
| **ROUTE-TO-HUMAN** | **Implemented (real)** | `execution/controller.py` + `execution/pending.py`: TTL expiry, approve/reject/retry, an atomic at-most-once execution claim (`claim_pending_execution`), and — load-bearing — an UNAVAILABLE outcome that is recorded distinctly and is *never* an approvable hold (`controller.py:128-147`). Genuinely solid. |
| **SANDBOX / EXECUTION** | **Implemented (real; namespace verified live, container unverified here)** | `sandbox/namespace.py` (`unshare --net`, default) and `sandbox/container.py` (`--network none`, `--cap-drop ALL`, non-root, read-only root). Egress denial **empirically confirmed** below. Fail-closed: `sandbox/factory.py` never returns the unsafe runner without `PROM_ALLOW_UNSAFE_EXEC=1`, and falls to a `NullSandbox` (ABSTAIN) otherwise. Container backend could not be exercised here (no daemon: `ContainerSandbox.available()` → False). |

---

## 3. The egress answer (highest-priority finding)

**Verdict: NOT-BUILT. This must be built before the experiment is meaningful.**

**Does Promethyn intercept, broker, or authorize network egress? No — not anywhere.**
- The executor's entire action vocabulary is two kinds, `python_code` and
  `git_delete_branch` (`core/models.py:250-252`, `EXECUTABLE_ACTION_KINDS`). Neither is a
  network operation. `execution/executor.py:10` states it outright: "no network or external
  connectors this sprint (the sandbox denies the network regardless)."
- The gate reasons over a `Judgment` about an action; it has **no concept of an outbound
  connection**. There is no allowlist, no proxy, no per-connection decision, nothing that
  sees a destination host or port.

**Does the sandbox enforce egress restrictions, and is that VERIFIED (the exact thing the
incident got wrong)?** Yes, verified — but by *total denial*, not brokering. I ran a
candidate through `NamespaceSandbox` that attempts real outbound connections:

```
started_ok: True | exit: 0
CANDIDATE OUTPUT: TCP blocked: OSError | DNS blocked: gaierror | HTTP blocked: URLError | interfaces: ['lo']
--- host (no sandbox), same probes ---
host interfaces: ['lo', 'eth0']
```

Inside the sandbox only loopback exists; `eth0` is gone, and TCP/DNS/HTTP all fail. This is
enforcement by **interface removal** — genuine and verified, but **all-or-nothing**. You
cannot express "allow egress to the model API, deny everything else." The setting is
"nothing," and the only lever is on/off.

**If we ran the experiment today, what would Promethyn gate, and what would it be blind
to?**
- If the adversarial agent **is** the sandboxed candidate: egress is already 100% denied —
  but so is *all* network, so you cannot run a realistic agent that legitimately needs some
  network and then measure whether Promethyn blocks the *unauthorized* part. There is
  nothing to broker, so nothing to measure.
- If the agent runs **outside** the sandbox (the more faithful model of the HF incident):
  Promethyn is **entirely blind** to its network activity. The gate never sees a socket;
  the ledger never records a connection. Note the runtime itself already makes ungated
  egress — `provider/remote.py:143-145` calls `urllib.request.urlopen` to the model API —
  which is treated as infrastructure, not a gated action.

**Conclusion:** the capability does not exist and is not a wiring-up job. It requires a new
**egress broker** — a network chokepoint (transparent proxy / egress allowlist enforced in
the sandbox's network namespace) that turns each outbound connection into a gate decision
recorded in the ledger. That is net-new construction (§7, item 1).

---

## 4. Test quality (not count)

- **Count:** the "~634 tests" figure could **not** be reproduced. `pytest --collect-only`
  reports **472 collected**; a full run here: **470 passed, 2 skipped, 0 failed** in 96s.
  The 2 skips are the opt-in real-container run (`PROM_REQUIRE_CONTAINER=1`); the namespace
  sandbox tests *did* run (namespaces work in this environment).
- **voidguard dogfood** (the tool run on the runtime it came from):
  **0 VOID, 0 WARN, 2 UNKNOWN.** Both UNKNOWNs are pre-existing and honest: (a) four
  conformance Hearth-diff tests gated on `origin/main` being fetchable — the "in-PR
  tripwire" shape — and (b) the `container-sandbox.yml` nightly schedule, whose run history
  isn't statically decidable. **Caveat, stated loudly:** voidguard v0 detects 4 of the 7
  taxonomy classes, so "0 VOID" means "no void guards of the *detectable* shapes," **not**
  "no hollow tests." I did not find hollow tests by hand either, but this is not a
  certificate of their absence.
- **Gate/ledger negative paths — well covered.** `tests/conformance/test_execution*.py`
  assert BLOCK/refuse/raise, not just allow; `test_extension_surface.py` proves the suite
  rejects a verdict-guessing verifier. The gate has tests proving it **blocks**.
- **EX-1 recurrence check (skips gated on unset flags):** the sandbox tests skip when
  isolation is unavailable **but fail hard under `PROM_REQUIRE_SANDBOX=1`** (which CI sets)
  — `tests/conformance/test_sandbox.py:36-40`. That is a correctly-toothed gate, not a void
  guard. The origin/main-gated conformance skips (voidguard's UNKNOWN) are the known,
  documented in-PR-tripwire and remain the one soft spot.
- **Integration/e2e:** present — `tests/integration/test_live_execution.py` and
  `test_swarm_end_to_end.py` drive the full verify→gate→record loop, not just units.

---

## 5. Adversarial posture

- **Gate bypass paths.** The gate is an **in-process API authorizer**, not a chokepoint.
  Every consequential action reaches execution *only* through
  `ExecutionController.submit → executor.execute`, and the executor refuses anything not
  `approved` — I confirmed there are no other `executor.execute` call sites. So within the
  intended model (agent *proposes*, Promethyn *executes* in the sandbox) the wall holds.
  **But** anything that can run code outside the sandbox does not need the gate's
  permission — it simply acts. The **sandbox**, not the gate, is the real containment
  boundary; the gate governs only what the sandbox is asked to run. For an adversary with
  out-of-sandbox code execution, the gate is not a barrier.
- **Forgeable signals — strong posture (EX-1 hardened).** The candidate-start signal is a
  per-run nonce delivered over stdin/a pipe the candidate cannot read back
  (`sandbox/namespace.py:112-113`, `container.py:206-231`); authorization lives in an
  in-process `GateDecision` object, **not** on the agent-writable workspace mount. A
  sandboxed candidate cannot forge an approval or a start. No marker-file authorization on
  a writable surface — the specific EX-1 lesson is respected.
- **Ledger tamper-evidence — absent.** The ledger is a plain SQLite file with no
  cryptographic chain (§2). An actor that gained write access to the file could alter or
  erase its own trail undetected. Mitigating fact: the ledger is written by the controller,
  *outside* the sandbox — the sandboxed candidate has no path to it — so this matters for
  an out-of-sandbox adversary, which is exactly the experiment's model.
- **Fail-open vs fail-closed on UNAVAILABLE — proven CLOSED.** When an authoritative
  verifier cannot run, `controller.submit` takes the `OUTCOME_UNAVAILABLE` branch
  (`controller.py:128-147`): recorded distinctly, **never executed, never an approvable
  hold.** `gate/authorization.py:81-95` returns `approved=False` for any `Unavailable`. The
  `Unavailable` type has no `.verdict` attribute by construction (`core/models.py:166-192`),
  so "could not verify" cannot degrade into "abstained/passed" even by accident. This is the
  strongest part of the system.

---

## 6. Code state

- **Does it run?** Yes. Fresh `pip install -e ".[dev]"`, clean import, **470 passed / 2
  skipped / 0 failed** in 96s.
- **Dead code / half-built features:** none material. Every `NotImplementedError` is an
  abstract-interface stub (`core/interfaces.py` ABCs, `swarm/executor.py`, `roles.py`,
  `sandbox/base.py`) or the mock provider deliberately emitting a not-implemented candidate.
  No `TODO`/`FIXME`/`XXX`/`HACK` on load-bearing paths.
- **Hygiene / secrets:** `scripts/check_hygiene.py` passes (213 files, no banned tokens). No
  key/token patterns in `src/` or `tests/`. (A deeper full-history secret audit was done
  separately and was clean.)
- **Internal codenames / PII:** none. No hits for ARMADA, EdgeNexis, CarHeroes, AgentStig,
  Plegma, ZooLo, LifeOS, "project emma", or "driivai-internal" in `src/`, `docs/`, `tests/`.
- **Discrepancy to correct:** the "~634 tests" figure is not reproducible — the suite
  collects 472. Wherever 634 is published, fix it.

---

## 7. Prioritized gap list

### Blocks the experiment (build before it means anything)
1. **No egress interception — build an egress broker.** A network chokepoint in the
   sandbox's net namespace (transparent proxy / egress allowlist) that turns each outbound
   connection into a gate decision recorded in the ledger. This is *the* finding: without
   it the experiment has nothing to measure. Net-new capability, not a wiring-up.
2. **Brokered (not all-or-nothing) egress.** To model "agent needs its legitimate API,
   exfiltration must be blocked," the sandbox needs a per-destination allowlist, not total
   interface removal. Extends #1.
3. **Pin the threat model first.** Is the adversarial agent the *sandboxed candidate*
   (egress already fully denied, but no realistic networked agent) or an *out-of-sandbox*
   actor (gate and ledger both blind)? Promethyn supports neither egress-brokering case
   today; the experiment design has to choose, and the build in #1–#2 must target that
   choice.

### Would improve it
4. **Ledger tamper-evidence** — a hash chain or append-only enforcement, so the trail is
   defensible against an adversary who reaches the file. (Partially overlaps the filed
   follow-up to persist `Judgment.unavailable` onto the execution row.)
5. **Verify the container backend end-to-end on the experiment host.** Only the namespace
   adapter was exercisable here; the experiment likely wants container isolation, whose
   `--network none` egress denial should be proven live (the two opt-in container tests are
   currently skipped).

### Unrelated cleanup
6. **Correct the test-count claim** (634 → 472 measured) wherever it is published.
7. **The origin/main-gated conformance skips** (voidguard UNKNOWN ×1) remain the one
   in-PR-tripwire soft spot from the repo audit; convert to a standing check when convenient.

---

*Read-only assessment. No code was changed and no fix was applied; every item in §7 is a
proposal, not an action taken.*
