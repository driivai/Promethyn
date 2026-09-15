"""One behavioural proof per outcome-affecting security field (G17, part 2b).

WHY THIS EXISTS. ``test_security_posture.py`` has a SPELLING check: it proves a
declared field's name appears as an attribute somewhere outside ``config.py``.
Measured (G17, reproduction C4), that is compatible with the field being wired
to nothing — every genuine consumption of ``require_ledger_anchor`` removed from
``src/`` and one dead store left under ``if False:`` still reported 26 passed.

This file is the other half. For each field whose absence changes whether
something is authorized, refused or executed, it drives the field through the
runtime and observes the outcome it names. Neutralize the consumption and a
NAMED test here goes red; the reproduction that survived the spelling check does
not survive this one.

THE SHAPE, and it is the same for all fourteen (doctrine #4):

    the field set to its enforcing value   -> the outcome it names
    the field withdrawn, everything else identical -> that outcome does NOT occur

The second line is not decoration. Without it every test here is equally
consistent with code that refuses unconditionally, which is a different defect
and one this project has shipped before.

WHAT THESE TESTS ARE, stated rather than implied. They prove the field reaches
its consumer and that the consumer's decision moves with it. They do not prove
the decision is the RIGHT one, they do not prove there is no second path around
the consumer, and a field can be honoured here and bypassed elsewhere. A proof
that a control is wired is worth more than a proof that its name is spelled, and
less than a proof that it cannot be evaded.

THE OTHER EIGHT of the twenty-two declared fields are not here, and the partition
is enforced below rather than described:

* six RESOURCE BOUNDS are proven in ``test_resource_bound_outcomes.py`` under a
  DIFFERENT shape — neutralizing one does not produce a refusal, it produces a
  different VERDICT, so no refusal test can catch it. Keeping them out of this
  file is what stops that difference being read as the same guarantee.
* two are SPELLING-CHECKED ONLY and say so (G17 2c): proving that neutralizing
  them changes nothing is a claim about the absence of an effect, which is not
  provable by a test.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

from prometheus_protocol.attestation.runtime import attestation_target_for
from prometheus_protocol.chokepoint.runner import resolve_signer
from prometheus_protocol.chokepoint.substrate import resolve_substrate_policy
from prometheus_protocol.core.config import (
    PROVIDER_REMOTE,
    SECURITY_FIELDS,
    Config,
)
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.core.models import Judgment, Verdict
from prometheus_protocol.core.secrets import Secret
from prometheus_protocol.gate.authorization import ActionGate
from prometheus_protocol.runtime.factory import (
    build_execution_controller,
    build_sandbox_for,
    build_tip_anchor_for,
    build_verification_policy,
)

# ===========================================================================
# The partition, as executable structure rather than a table in a document
# ===========================================================================

#: Neutralizing one of these changes whether something is authorized, refused
#: or executed. Every name here must have a test in THIS module naming it.
OUTCOME_AFFECTING = (
    "require_ledger_anchor",
    "ledger_anchor",
    "sandbox",
    "require_digest_pin",
    "allow_insecure_loopback",
    "escalate_below",
    "gate_threshold",
    "pending_ttl_seconds",
    "require_external_signer",
    "require_verified_substrate",
    "allow_unverified_substrate",
    "require_config_attestation",
    "config_attestation_target",
    "verification_profile",
)

#: Proven in ``test_resource_bound_outcomes.py``, by VERDICT FLIP rather than by
#: refusal. Named here so the partition is total, not so the shapes are equated.
RESOURCE_BOUND = (
    "verifier_timeout_s",
    "verifier_memory_mb",
    "verifier_cpu_seconds",
    "verifier_max_processes",
    "request_timeout_s",
    "provider_max_response_bytes",
)

#: Spelling-checked only, deliberately and permanently (G17 2c). Neither reaches
#: a decision: one is a retention window on a record, the other bounds how much
#: work happens. If either grows a consumer that decides something it moves into
#: ``OUTCOME_AFFECTING`` and the guard below fails until it has a proof.
SPELLING_ONLY = (
    "ledger_anchor_retention_days",
    "max_role_calls",
)

#: field -> the tests in THIS module that prove it. Written out rather than
#: scraped from test names: a substring match would let
#: ``test_require_ledger_anchor_…`` stand in as the proof for ``ledger_anchor``,
#: which is the kind of accidental coverage G17 is about. Both guards below run
#: against this mapping, so a renamed or deleted test fails rather than silently
#: leaving a field unproven.
PROOFS: dict[str, tuple[str, ...]] = {
    "require_ledger_anchor": (
        "test_require_ledger_anchor_refuses_a_configuration_it_cannot_honour",
        "test_require_ledger_anchor_is_honoured_from_the_environment_too",
    ),
    "ledger_anchor": ("test_ledger_anchor_selects_the_witness_and_its_absence_means_unanchored",),
    "sandbox": (
        "test_sandbox_selects_the_adapter_that_executes_candidate_code",
        "test_sandbox_refuses_a_non_isolating_adapter_beside_a_remote_provider",
    ),
    "require_digest_pin": ("test_require_digest_pin_reaches_the_adapter_that_honours_it",),
    "allow_insecure_loopback": (
        "test_allow_insecure_loopback_is_what_permits_a_plaintext_loopback_endpoint",
        "test_allow_insecure_loopback_does_not_permit_a_remote_plaintext_endpoint",
    ),
    "escalate_below": (
        "test_escalate_below_decides_whether_a_confident_pass_halts_for_a_human",
        "test_escalate_below_is_the_gate_bar_not_a_constant",
    ),
    "gate_threshold": (
        "test_gate_threshold_decides_whether_an_improvement_is_promoted",
        "test_gate_threshold_reaches_the_promotion_gate_from_config",
    ),
    "pending_ttl_seconds": ("test_pending_ttl_seconds_reaches_the_service_that_expires_holds",),
    "require_external_signer": ("test_require_external_signer_refuses_a_local_key_it_cannot_honour",),
    "require_verified_substrate": ("test_require_verified_substrate_raises_the_bar_from_the_runtime_config",),
    "allow_unverified_substrate": ("test_allow_unverified_substrate_lowers_the_bar_and_the_pair_is_refused",),
    "require_config_attestation": (
        "test_require_config_attestation_refuses_a_configuration_it_cannot_honour",
        "test_require_config_attestation_is_honoured_from_the_environment_too",
    ),
    "config_attestation_target": ("test_config_attestation_target_selects_the_witness",),
    "verification_profile": ("test_verification_profile_selects_the_policy_and_a_typo_refuses_startup",),
}

_THIS_FILE = Path(__file__)


def _test_names_in_this_module() -> set[str]:
    tree = ast.parse(_THIS_FILE.read_text(encoding="utf-8"))
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    }


def test_the_partition_covers_every_declared_security_field_exactly_once():
    """The ratchet. A field added to ``SECURITY_FIELDS`` must be classified, and
    a field removed must not leave a stale claim behind.

    Without this the partition is a paragraph in a document that the code can
    drift away from — which is what G4 records happening to F10's text.
    """

    partition = OUTCOME_AFFECTING + RESOURCE_BOUND + SPELLING_ONLY
    assert len(partition) == len(set(partition)), "a field is in two classes"

    declared = set(SECURITY_FIELDS)
    assert set(partition) == declared, {
        "classified but not declared": sorted(set(partition) - declared),
        "declared but unclassified": sorted(declared - set(partition)),
    }


def test_every_outcome_affecting_field_has_a_proof_that_exists():
    """A field cannot be listed as outcome-affecting and left unproven, and a
    proof cannot be named and then renamed away: the claim and the tests are
    checked against each other, not just written down."""

    assert sorted(PROOFS) == sorted(OUTCOME_AFFECTING), {
        "mapped but not classified": sorted(set(PROOFS) - set(OUTCOME_AFFECTING)),
        "classified but unmapped": sorted(set(OUTCOME_AFFECTING) - set(PROOFS)),
    }

    names = _test_names_in_this_module()
    missing = sorted(
        {test for tests in PROOFS.values() for test in tests} - names
    )
    assert missing == [], f"PROOFS names tests that do not exist here: {missing}"


def test_the_coverage_guard_is_not_universally_true():
    """The positive control for the guard above: it must be able to say no.

    An instrument that returns an empty set reads downstream as a pass
    (doctrine #8), and ``_test_names_in_this_module`` returning nothing would
    make the previous test vacuous for every field at once — every name would
    be "missing" only if the assertion ran, and an empty PROOFS would make the
    subtraction empty and the test green.
    """

    names = _test_names_in_this_module()
    assert len(names) > len(OUTCOME_AFFECTING), "the collector found too little"
    assert "test_the_coverage_guard_is_not_universally_true" in names
    assert "test_a_name_that_is_not_defined_here_xyz" not in names


# ===========================================================================
# 1. require_ledger_anchor — the field C4 proved was wired to nothing
# ===========================================================================


def test_require_ledger_anchor_refuses_a_configuration_it_cannot_honour(tmp_path):
    """THE ONE THAT CLOSES C4, and it refuses at LOAD.

    MEASURED, because I assumed otherwise first: the enforcing consumer is the
    coherence block in ``core/config.py``, not ``build_tip_anchor_for``. Both
    of these are refused before a Config object exists —

      * the requirement with no anchor at all;
      * the requirement with a ``file://`` anchor, which is rewritten by whoever
        rewrites the ledger and so witnesses nothing.

    — and the same two configurations load cleanly with the requirement
    withdrawn. So the field decides whether the runtime starts.

    That the enforcing site is inside ``config.py`` is exactly why the spelling
    check could not see it: the collector skips that file. C4 removed every
    genuine consumption of this field from ``src/``, config.py included, and
    ``test_security_posture.py`` still reported 26 passed. This goes red.
    """

    spec = f"file://{tmp_path / 'tip'}"
    for kwargs in ({}, {"ledger_anchor": spec}):
        with pytest.raises(ConfigError):
            Config(ledger_path=":memory:", require_ledger_anchor=True, **kwargs)
        # The positive control: identical but for the requirement.
        assert Config(ledger_path=":memory:", **kwargs) is not None


def test_require_ledger_anchor_is_honoured_from_the_environment_too():
    """The second enforcing site, which the load check cannot reach: the
    requirement is the OR of the field and ``PROM_REQUIRE_LEDGER_ANCHOR``, and
    ``build_tip_anchor_for`` refuses an unanchored runtime under either.

    Kept separate from the load proof on purpose. A mutation that removes only
    the runtime read leaves the load check standing, and only this test would
    catch it; a mutation that removes only the load check leaves this standing.
    One test covering both would redden for either and distinguish neither.
    """

    unanchored = Config(ledger_path=":memory:")
    with pytest.raises(ConfigError):
        build_tip_anchor_for(unanchored, env={"PROM_REQUIRE_LEDGER_ANCHOR": "1"})
    assert build_tip_anchor_for(unanchored, env={}) is None


# ===========================================================================
# 2. ledger_anchor — the target itself
# ===========================================================================


def test_ledger_anchor_selects_the_witness_and_its_absence_means_unanchored(tmp_path):
    """The field names WHERE the tip is written. Neutralize it and every
    configuration is unanchored, including the ones that asked not to be."""

    anchored = build_tip_anchor_for(
        Config(ledger_path=":memory:", ledger_anchor=f"file://{tmp_path / 'tip'}"),
        env={},
    )
    assert anchored is not None

    assert build_tip_anchor_for(Config(ledger_path=":memory:"), env={}) is None


# ===========================================================================
# 3-4. sandbox and require_digest_pin — the adapter, and its provenance rule
# ===========================================================================


def test_sandbox_selects_the_adapter_that_executes_candidate_code():
    """The field decides WHAT runs untrusted output. A neutralized selector
    returns the same adapter for every configuration, which this catches by
    asking for two different ones."""

    namespace = build_sandbox_for(Config(sandbox="namespace"), env={})
    assert namespace.name == "namespace"

    container = build_sandbox_for(Config(sandbox="container"), env={})
    assert container.name != namespace.name


def test_sandbox_refuses_a_non_isolating_adapter_beside_a_remote_provider():
    """The combination the sandbox exists for. Refused with a typed reason, and
    the same adapter is permitted with the mock provider — so this cannot pass
    by refusing the adapter unconditionally."""

    env = {"PROM_ALLOW_UNSAFE_EXEC": "1"}
    with pytest.raises(ConfigError) as refusal:
        build_sandbox_for(
            Config(provider=PROVIDER_REMOTE, sandbox="unsafe",
                   api_base="https://example.invalid", model="m"),
            env=env,
        )
    assert refusal.value.reason == "unsafe_with_remote"

    permitted = build_sandbox_for(Config(sandbox="unsafe"), env=env)
    assert permitted.isolating is False


def test_require_digest_pin_reaches_the_adapter_that_honours_it():
    """The original defect this whole area is named for: the operator could set
    the flag and ``build_sandbox`` never received it, so a deployment asking for
    digest pinning got a sandbox reporting ``False``."""

    pinned = build_sandbox_for(Config(sandbox="container", require_digest_pin=True), env={})
    assert getattr(pinned, "require_digest_pin", None) is True

    unpinned = build_sandbox_for(Config(sandbox="container"), env={})
    assert getattr(unpinned, "require_digest_pin", None) is False


# ===========================================================================
# 5. allow_insecure_loopback — refused at load, before the header is built
# ===========================================================================


def test_allow_insecure_loopback_is_what_permits_a_plaintext_loopback_endpoint():
    """Refused at LOAD rather than at the first request: by then the
    Authorization header has been built and is about to leave."""

    with pytest.raises(ValueError):
        Config(api_base="http://127.0.0.1:9/v1")

    permitted = Config(api_base="http://127.0.0.1:9/v1", allow_insecure_loopback=True)
    assert permitted.api_base == "http://127.0.0.1:9/v1"


def test_allow_insecure_loopback_does_not_permit_a_remote_plaintext_endpoint():
    """The opt-out is scoped to loopback and there is no opt-out for a remote
    plaintext endpoint — a credential sent there crosses the network in clear.
    Stated because an opt-out that silently widened would be the real defect."""

    with pytest.raises(ValueError):
        Config(api_base="http://example.invalid/v1", allow_insecure_loopback=True)


# ===========================================================================
# 6. escalate_below — the confidence bar that halts for a human
# ===========================================================================


def _judgment(confidence: float) -> Judgment:
    return Judgment(verdict=Verdict.PASS, confidence=confidence, authoritative=True)


def test_escalate_below_decides_whether_a_confident_pass_halts_for_a_human():
    """Driven through the gate's own outcome function rather than read off an
    attribute: the same authoritative PASS is APPROVED under one bar and ROUTED
    to a human under the other."""

    strict = build_execution_controller(
        Config(ledger_path=":memory:", escalate_below=0.9)
    )._gate
    lenient = build_execution_controller(
        Config(ledger_path=":memory:", escalate_below=0.1)
    )._gate

    judgment = _judgment(0.5)
    routed = strict._outcome(judgment, risk_class="low", floor=0.0)
    approved = lenient._outcome(judgment, risk_class="low", floor=0.0)
    assert routed != approved, (routed, approved)
    assert routed == "route", routed
    assert approved == "approve", approved


def test_escalate_below_is_the_gate_bar_not_a_constant():
    """A gate constructed with no bar at all must not route on confidence, or
    the assertion above would hold for a gate that ignores the field."""

    gate = ActionGate(
        escalate_below=None, route_high_risk=False, target_canonical="sandbox://probe"
    )
    assert gate._outcome(_judgment(0.01), risk_class="low", floor=0.0) == "approve"


# ===========================================================================
# 7. gate_threshold — the promotion bar
# ===========================================================================


@dataclass(frozen=True)
class _Candidate:
    id: str = "skill/probe"


def test_gate_threshold_decides_whether_an_improvement_is_promoted():
    """A measured +0.2 improvement is promoted under a 0.0 bar and refused under
    a 0.5 bar, with the same candidate and the same scores."""

    from prometheus_protocol.gate.promotion import PromotionGate

    def score(_tasks, _candidate):
        return 0.7

    kwargs = dict(candidate=_Candidate(), train_ids=[], heldout_tasks=[],
                  score_fn=score, rate_before=0.5)
    assert PromotionGate(threshold=0.0).evaluate(**kwargs).approved is True
    assert PromotionGate(threshold=0.5).evaluate(**kwargs).approved is False


def test_gate_threshold_reaches_the_promotion_gate_from_config():
    """The wiring half, stated as wiring: the orchestrator's gate carries the
    configured bar rather than the class default."""

    from prometheus_protocol import build_orchestrator

    orchestrator = build_orchestrator(Config(ledger_path=":memory:", gate_threshold=0.5))
    assert orchestrator.gate.threshold == 0.5


# ===========================================================================
# 8. pending_ttl_seconds — a hold that has lapsed can never execute
# ===========================================================================


def test_pending_ttl_seconds_reaches_the_service_that_expires_holds():
    """WIRING, named as wiring rather than dressed up as enforcement.

    The expiry BEHAVIOUR — a lapsed hold refusing approval at decision time — is
    proven in ``test_execution_expiry.py`` and is not restated here. What this
    adds is the half C4 defeated: that the number the operator configured is the
    number the pending service enforces, rather than the class default.
    """

    short = build_execution_controller(Config(ledger_path=":memory:", pending_ttl_seconds=1))
    long = build_execution_controller(Config(ledger_path=":memory:", pending_ttl_seconds=7))
    assert short._pending._ttl_seconds == 1
    assert long._pending._ttl_seconds == 7


# ===========================================================================
# 9. require_external_signer — key custody
# ===========================================================================


@dataclass(frozen=True)
class _SignerRequest:
    """A minimal ``SignerRequest``: the protocol is three read-only members."""

    signer: object | None = None
    signing_key: Secret | bytes | None = None
    require_external_signer: bool = False


def test_require_external_signer_refuses_a_local_key_it_cannot_honour():
    """A key root on the host can read and use a local HMAC key silently. Under
    the requirement that is refused; without it the same key is accepted and
    warned about, so this cannot pass by refusing local keys outright."""

    request = _SignerRequest(signing_key=b"k" * 32)

    with pytest.raises(ConfigError):
        resolve_signer(request, settings=Config(require_external_signer=True), env={})

    allowed = resolve_signer(request, settings=Config(require_external_signer=False), env={})
    assert allowed is not None


# ===========================================================================
# 10-11. require_verified_substrate / allow_unverified_substrate
# ===========================================================================


def test_require_verified_substrate_raises_the_bar_from_the_runtime_config():
    """The requirement is the OR of its sources, and ``Config`` is one of them —
    the source C4's mutation would have silenced."""

    assert resolve_substrate_policy(
        None, settings=Config(require_verified_substrate=True), env={}
    ).require_verified is True

    assert resolve_substrate_policy(
        None, settings=Config(), env={}
    ).require_verified is False


def test_allow_unverified_substrate_lowers_the_bar_and_the_pair_is_refused():
    """It is on this list because it LOWERS the bar: a field that weakens a
    control is outcome-affecting in the same way one that raises it is. Set
    together with the requirement the pair is incoherent and refused, rather
    than resolved by a quiet precedence."""

    assert resolve_substrate_policy(
        None, settings=Config(allow_unverified_substrate=True), env={}
    ).allow_unverified is True

    with pytest.raises(ConfigError):
        resolve_substrate_policy(
            None,
            settings=Config(
                require_verified_substrate=True, allow_unverified_substrate=True
            ),
            env={},
        )


# ===========================================================================
# 12-13. require_config_attestation / config_attestation_target
# ===========================================================================


def test_require_config_attestation_refuses_a_configuration_it_cannot_honour(tmp_path):
    """The same two-site arrangement as the ledger anchor, and measured the same
    way: required with nothing to attest to, and required against a ``file://``
    witness the config-changing adversary rewrites in the same breath, are both
    refused at LOAD. Withdraw the requirement and both load."""

    spec = f"file://{tmp_path / 'attest'}"
    for kwargs in ({}, {"config_attestation_target": spec}):
        with pytest.raises(ConfigError):
            Config(ledger_path=":memory:", require_config_attestation=True, **kwargs)
        assert Config(ledger_path=":memory:", **kwargs) is not None


def test_require_config_attestation_is_honoured_from_the_environment_too():
    """The runtime half, reachable only through the environment variable — the
    site a mutation could remove without the load check noticing."""

    unattested = Config(ledger_path=":memory:")
    with pytest.raises(ConfigError):
        attestation_target_for(unattested, env={"PROM_REQUIRE_CONFIG_ATTESTATION": "1"})
    assert attestation_target_for(unattested, env={}) is None


def test_config_attestation_target_selects_the_witness(tmp_path):
    """The target names WHERE the running configuration is witnessed.
    Neutralize it and every runtime is unattested, including the ones that
    configured a witness."""

    spec = f"file://{tmp_path / 'attest'}"
    assert attestation_target_for(Config(config_attestation_target=spec), env={}) is not None
    assert attestation_target_for(Config(), env={}) is None


# ===========================================================================
# 14. verification_profile — which requirements must be satisfied at all
# ===========================================================================


def test_verification_profile_selects_the_policy_and_a_typo_refuses_startup():
    """A typo in the selected profile must never silently authorize under a
    policy nobody chose — that is the omission attack wearing a configuration
    error. The named profile loads; an unknown one raises."""

    assert build_verification_policy(Config(verification_profile="baseline")) is not None

    with pytest.raises(Exception):
        build_verification_policy(Config(verification_profile="baselinee"))
