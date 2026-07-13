"""The verifier extension contract, and the checks that mechanically enforce it.

This module is the platform trust primitive: it turns the seam the three
built-in domains (code, SQL, grounding) already share into a *named, checkable*
contract. It is a contract AROUND the Hearth, not a change to it — it imports
the bank, the tiers, and the firewall and uses them as a client would; it
never modifies any of them, and it grants no verifier any authority.

An extender describes their verifier with a :class:`VerifierCase` and runs
:func:`check_verifier`; the returned :class:`ConformanceReport` says, check by
check, whether the verifier is well-behaved. The three built-in verifiers each
ship a case (see ``cases.py``) and pass unchanged, which is what proves this
contract describes reality rather than an aspiration.

The REQUIRED GUARANTEES, each mapped to a mechanical check below:

* **tier honesty** — the verifier declares a real tier, tags every Evidence
  with it, and cannot smuggle a higher tier past the bank (the bank pins a
  verifier's tier and rejects contradicting Evidence). A SOFT verifier's
  judgment is therefore non-authoritative no matter how confident it sounds;
  a HARD/HUMAN verifier's is authoritative. Authority is a property of the
  tier the platform assigns, never something the verifier can assert.
* **fault distinction** — a candidate at fault yields FAIL; a run whose fault
  cannot be pinned on the candidate yields ABSTAIN. Never a guessed verdict.
* **fail-closed** — if the verifier cannot obtain isolation or ground truth,
  it ABSTAINs rather than guessing. This is checked by injecting a
  ground-truth source that refuses to start and asserting ABSTAIN.
* **adversarial soundness** (verifier-appropriate, optional) — a candidate
  crafted to pass by coincidence or by exploiting the comparison is caught or
  correctly ABSTAINed. The extender supplies the probe; the contract cannot
  know a domain's exploit shapes for it.

The honest limit of the suite is stated plainly in the extension guide: it
proves a verifier is well-behaved *at its declared tier on the examples the
extender provides*; it cannot certify that a HARD verifier's ground truth is
actually sound, nor that a SOFT verifier's error rate is low — that is what
the admissions measurement (``benchmarks/*_eval``) is for.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from prometheus_protocol.core.interfaces import Verifier
from prometheus_protocol.core.models import (
    AUTHORITATIVE_TIERS,
    SPLIT_HELDOUT,
    SPLIT_TRAIN,
    Attempt,
    Evidence,
    Tier,
    Unavailable,
    Verdict,
)
from prometheus_protocol.forge.miner import LessonForge
from prometheus_protocol.gate.promotion import FirewallError, assert_disjoint
from prometheus_protocol.verifier.bank import VerifierBank

#: A (candidate, task) pair the suite runs through a verifier. ``task`` is
#: whatever domain task type the verifier consumes (code ``Task``, ``SqlTask``,
#: ``GroundingTask``, ...); the suite only ever hands it back to ``verify``.
Example = tuple[str, object]

#: A verifier-appropriate adversarial probe: returns (sound, detail). ``sound``
#: is True when the crafted exploit was caught or correctly ABSTAINed.
AdversarialProbe = Callable[[], "tuple[bool, str]"]


@dataclass(frozen=True)
class VerifierCase:
    """Everything the conformance suite needs to exercise one verifier.

    The extender fills this in for their verifier. Only ``verifier``,
    ``tier``, and ``failclosed`` are strictly required; the behavioural
    examples make the report stronger and should be supplied whenever the
    domain has ground truth to run.
    """

    name: str
    #: The verifier under test, ready to run.
    verifier: Verifier
    #: The tier it claims. Must equal ``verifier.tier`` and be a real Tier.
    tier: Tier
    #: A verifier whose ground-truth source is broken (isolation refuses to
    #: start, or the provider raises) paired with an example it is asked to
    #: judge. Running it MUST yield ABSTAIN — the fail-closed guarantee. This
    #: is the one behavioural check that needs no real runtime, so it is
    #: required.
    failclosed: "tuple[Verifier, Example]"
    #: A (candidate, task) the verifier must PASS. Optional: HARD verifiers
    #: need the isolation runtime to run these, so a caller without it skips
    #: the behavioural checks rather than failing them.
    passing: Example | None = None
    #: A (candidate, task) the verifier must FAIL (candidate fault).
    failing: Example | None = None
    #: An optional domain-appropriate adversarial soundness probe.
    adversarial: AdversarialProbe | None = None


@dataclass(frozen=True)
class CheckResult:
    """One check's outcome: name, pass/fail, and a human-readable reason."""

    name: str
    ok: bool
    detail: str
    skipped: bool = False


@dataclass(frozen=True)
class ConformanceReport:
    """The full result of checking one verifier."""

    case_name: str
    checks: tuple[CheckResult, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    @property
    def failures(self) -> tuple[CheckResult, ...]:
        return tuple(c for c in self.checks if not c.ok)

    def render(self) -> str:
        lines = [f"conformance report: {self.case_name}"]
        for c in self.checks:
            mark = "SKIP" if c.skipped else ("PASS" if c.ok else "FAIL")
            lines.append(f"  [{mark}] {c.name}: {c.detail}")
        verdict = "WELL-BEHAVED" if self.ok else "REJECTED"
        lines.append(f"  => {verdict}")
        return "\n".join(lines)


def _bank_with(verifier_id: str, tier: Tier) -> VerifierBank:
    bank = VerifierBank()
    bank.register(verifier_id, tier)
    return bank


def check_verifier(
    case: VerifierCase, *, run_behavioural: bool = True
) -> ConformanceReport:
    """Mechanically check a verifier against the extension contract.

    ``run_behavioural`` runs the PASS/FAIL examples, which for a HARD verifier
    need the isolation runtime; a caller without it passes ``False`` and those
    checks are reported as skipped (never as failures). The tier-honesty and
    fail-closed checks always run — they need no runtime.
    """

    checks: list[CheckResult] = []

    # -- tier honesty (static) --------------------------------------------
    tier_ok = isinstance(case.tier, Tier) and case.verifier.tier == case.tier
    checks.append(CheckResult(
        "tier-declared",
        tier_ok and bool(case.verifier.verifier_id),
        f"verifier {case.verifier.verifier_id!r} declares tier "
        f"{case.tier.value!r}" if tier_ok else
        f"verifier.tier ({getattr(case.verifier, 'tier', None)}) does not match "
        f"the declared tier ({case.tier})",
    ))

    # -- tier honesty (the bank pins the tier; forged HARD is rejected) ----
    forged_tier = Tier.SOFT if case.tier in AUTHORITATIVE_TIERS else Tier.HARD
    forged = Evidence(
        passed=True, total=1, passed_count=1,
        verifier_id=case.verifier.verifier_id,
        verdict=Verdict.PASS, tier=forged_tier,
    )
    bank = _bank_with(case.verifier.verifier_id, case.tier)
    try:
        bank.judge([forged])
        forged_rejected, forged_detail = False, (
            f"the bank accepted Evidence claiming tier {forged_tier.value!r} "
            f"for a {case.tier.value!r} verifier — tier is not pinned"
        )
    except ValueError as exc:
        forged_rejected, forged_detail = True, (
            f"the bank rejects forged {forged_tier.value!r} Evidence ({exc})"
        )
    checks.append(CheckResult("tier-pinned", forged_rejected, forged_detail))

    # -- authority follows the tier, not the verifier's say-so -------------
    honest = Evidence(
        passed=True, total=1, passed_count=1,
        verifier_id=case.verifier.verifier_id,
        verdict=Verdict.PASS, tier=case.tier,
    )
    judgment = _bank_with(case.verifier.verifier_id, case.tier).judge([honest])
    expect_auth = case.tier in AUTHORITATIVE_TIERS
    checks.append(CheckResult(
        "authority-matches-tier",
        judgment.authoritative == expect_auth,
        f"a {case.tier.value!r} PASS is "
        f"{'authoritative' if judgment.authoritative else 'advisory'} "
        f"(expected {'authoritative' if expect_auth else 'advisory'})",
    ))

    # -- fail-closed (always runnable: the injected source refuses to run) --
    # The contract is tier-dependent and by-construction:
    #   * an AUTHORITATIVE (executable) verifier that could not run must return a
    #     could-not-execute OUTCOME (Unavailable) — a non-verdict carrying no
    #     ``verdict`` at all. It may NOT return an ABSTAIN: an authoritative check
    #     that could not execute must never degrade into an abstention (EX-1). A
    #     type-level distinction, not a convention.
    #   * an ADVISORY judge that cannot form an opinion abstains (Evidence,
    #     ABSTAIN) — a genuine "no opinion", which is its correct fail-closed.
    fc_verifier, (fc_code, fc_task) = case.failclosed
    fc_evidence = fc_verifier.verify(code=fc_code, task=fc_task)
    if case.tier in AUTHORITATIVE_TIERS:
        fc_ok = isinstance(fc_evidence, Unavailable)
        fc_detail = (
            "with ground truth unavailable the executable verifier returned "
            + (
                "an Unavailable (could-not-execute — no verdict to guess or abstain)"
                if fc_ok
                else f"{getattr(fc_evidence, 'verdict', fc_evidence)!r} "
                "(an authoritative check that could not run must return Unavailable, "
                "never a verdict or an abstention)"
            )
        )
    else:
        fc_ok = isinstance(fc_evidence, Evidence) and fc_evidence.verdict == Verdict.ABSTAIN
        fc_detail = (
            "with no opinion the advisory judge returned "
            + (
                "ABSTAIN (refuses to guess)"
                if fc_ok
                else f"{getattr(fc_evidence, 'verdict', fc_evidence)!r} "
                "(an advisory judge with no opinion must ABSTAIN)"
            )
        )
    checks.append(CheckResult("fail-closed", fc_ok, fc_detail))

    # -- emits its declared tier (catches a soft process stamping HARD) -----
    # A well-behaved verifier tags EVERY outcome — an Evidence (even an ABSTAIN)
    # or an Unavailable — with its declared tier. A soft verifier that stamps HARD
    # on its output is caught here directly, on a real outcome it emitted, before
    # the bank is even consulted.
    emitted_tier = fc_evidence.tier
    checks.append(CheckResult(
        "emits-declared-tier",
        emitted_tier == case.tier,
        f"the verifier tagged its Evidence tier "
        f"{emitted_tier.value if emitted_tier else None!r} "
        + ("(matches its declared tier)" if emitted_tier == case.tier
           else f"but declares {case.tier.value!r} — a verifier cannot emit a "
                "tier it does not hold"),
    ))

    # -- behavioural: candidate fault -> FAIL, correct -> PASS -------------
    if case.passing is not None:
        if run_behavioural:
            code, task = case.passing
            ev = case.verifier.verify(code=code, task=task)
            checks.append(CheckResult(
                "passes-a-correct-candidate",
                ev.verdict == Verdict.PASS and ev.tier == case.tier,
                f"a known-correct candidate verified "
                f"{ev.verdict.value!r} at tier {ev.tier.value if ev.tier else None!r}",
            ))
        else:
            checks.append(CheckResult(
                "passes-a-correct-candidate", True,
                "skipped (no isolation runtime; run under PROM_REQUIRE_SANDBOX=1)",
                skipped=True,
            ))
    if case.failing is not None:
        if run_behavioural:
            code, task = case.failing
            ev = case.verifier.verify(code=code, task=task)
            checks.append(CheckResult(
                "fails-a-faulty-candidate",
                ev.verdict == Verdict.FAIL,
                f"a known-faulty candidate verified {ev.verdict.value!r} "
                "(candidate fault must be FAIL, not ABSTAIN or PASS)",
            ))
        else:
            checks.append(CheckResult(
                "fails-a-faulty-candidate", True,
                "skipped (no isolation runtime; run under PROM_REQUIRE_SANDBOX=1)",
                skipped=True,
            ))

    # -- adversarial soundness (verifier-appropriate, optional) ------------
    if case.adversarial is not None:
        sound, detail = case.adversarial()
        checks.append(CheckResult("adversarial-soundness", sound, detail))

    return ConformanceReport(case.name, tuple(checks))


def check_firewall_is_domain_general() -> CheckResult:
    """The held-out firewall is id-set arithmetic — it governs any domain.

    Not a per-verifier check: it is a property of the learn loop that every
    domain inherits unchanged (proven for code and SQL). Re-proven here over a
    minimal ``LearnableTask``-shaped stand-in so the extension guide can point
    at a runnable guarantee: an id that appears in both splits is a breach the
    unmodified gate refuses, and the unmodified forge refuses a non-train
    attempt. Neither depends on the domain of the task.
    """

    class _Task:  # a minimal LearnableTask: the loop needs only these fields
        def __init__(self, task_id: str, split: str) -> None:
            self.id = task_id
            self.prompt = "x"
            self.split = split
            self.cluster = "c"

    # Gate side: an overlapping id set raises before anything is scored.
    gate_ok = False
    try:
        assert_disjoint(["d/train"], ["d/train"])  # deliberate overlap
    except FirewallError:
        gate_ok = True

    # Forge side: a held-out attempt is refused regardless of domain.
    forge_ok = False
    held = Attempt(
        task_id="d/heldout", split=SPLIT_HELDOUT, entry_point="",
        code="", evidence=Evidence(passed=False, total=1, passed_count=0),
    )
    try:
        LessonForge().mine([held], tasks_by_id={"d/heldout": _Task("d/heldout", SPLIT_HELDOUT)})
    except ValueError:
        forge_ok = True

    # And the disjoint case does not raise (a well-formed split is accepted).
    disjoint_ok = True
    try:
        assert_disjoint(["d/train"], ["d/heldout"])
    except FirewallError:
        disjoint_ok = False

    ok = gate_ok and forge_ok and disjoint_ok
    _ = SPLIT_TRAIN  # (documented: train is what the forge is allowed to see)
    return CheckResult(
        "held-out-firewall-domain-general",
        ok,
        "the unmodified gate refuses an overlapping id set and the unmodified "
        "forge refuses a held-out attempt (id-set arithmetic, domain-general)"
        if ok else
        f"firewall check failed (gate={gate_ok}, forge={forge_ok}, disjoint={disjoint_ok})",
    )
