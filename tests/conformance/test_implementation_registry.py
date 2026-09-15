"""OPEN-GAPS G26: a policy may only permit implementations that EXIST.

WHAT THIS PROVES, and its scope. That ``PolicyRequirement`` refuses, at
construction and with a typed reason, a permitted name that no implementation
has declared; that the refusal is distinct from an implementation that exists
but could not answer (doctrine #1's ``Unavailable``, which is a COVERAGE outcome
at assessment time, not a construction error); that an EMPTY registry refuses
distinctly rather than reading as permissive (doctrine #8); and that the
registry's declarations and the package's implementation sites agree IN BOTH
DIRECTIONS, by a sweep that refuses when it cannot see the whole package.

BOTH ATTACK CLASSES, applied to the new instrument (G25's lesson):

* DELETION — the registry check removed; a declaration removed; a site's
  reference replaced by a bare re-spelled literal. Each reddens a named test
  here; the executed mutations are recorded beside G26 in the tracker.
* CROSS-CONTEXT SUBSTITUTION — a site's reference swapped for a DIFFERENT
  declaration (``VERIFIER_ID = SWARM_CHECKS`` inside the subprocess verifier),
  or two sites claiming one identity. The value check and the reverse sweep
  catch the first; the registry's own conflict refusal catches the second.

TWO CHECKS. Construction checks that a permitted name is DECLARED. A
declaration is a claim — "this identity is reported at this site" — and the
claim is tested when the policy is put to use: ``load_profile`` and the resolver
resolve the declared site and require it to report the identity (PR #111, P2:
before this, ``declare_implementation("custom", implemented_by="missing.module.Verifier")``
let a policy construct and fail forever as incomplete coverage — G26 one layer
up). A declaration made with the class in hand is verified at the declaration.

WHAT IT DOES NOT PROVE, stated so it is not read as proved. That a registered
implementation does what the check means: a stub reporting a real identity
satisfies this registry, and the control against it is implementation identity
at coverage plus the trust store's fixed tier (G26's residual, unchanged). And a
registered-for-registered swap PRESENT WHEN A POLICY IS AUTHORED is caught by
nothing — not by this registry, not by the digest, not by coverage (PR #111,
P2, corrected here; OPEN-GAPS G27). The proof of that is a named limit, and it
says what the stale-evidence refusal it used to lean on actually proves.
"""

from __future__ import annotations

import ast
import importlib
import pathlib
import pkgutil

import pytest

from prometheus_protocol.core.models import (
    Evidence,
    Tier,
    Unavailability,
    Unavailable,
    Verdict,
)
from prometheus_protocol.policy import implementations
from prometheus_protocol.policy.coverage import (
    REFUSAL_REASONS,
    REFUSED_INCOMPLETE,
    REFUSED_INVALID_EVIDENCE,
    BoundResult,
    CoverageRefused,
    CoverageSatisfied,
    validate_coverage,
)
from prometheus_protocol.policy.implementations import (
    SUBPROCESS_TESTS,
    SWARM_CHECKS,
    ImplementationConflict,
    ImplementationSiteUnresolved,
    declarations,
    declare_implementation,
    implemented_by,
    is_registered,
    is_verified,
    registered_implementations,
)
from prometheus_protocol.policy.profile import (
    CHECK_EXECUTABLE_CASES,
    IMPL_SUBPROCESS,
    POLICY_REFUSAL_REASONS,
    PROFILES,
    PolicyError,
    PolicyRequirement,
    VerificationPolicy,
    load_profile,
    policy_digest,
)
from prometheus_protocol.policy.resolver import ResolutionRefused, resolve
from prometheus_protocol.policy.snapshot import (
    ACTION_SANDBOX_EXECUTE,
    BoundRequirement,
    snapshot_digest,
)
from tests.support.positional_sweep import SweepIncomplete

PACKAGE_PREFIX = "prometheus_protocol."

#: One character off the shipped identity: the misspelling G26 is about.
TYPO = "subprocess-test"
ARTIFACT = "a" * 64
TARGET = "sandbox://registry"
ATTEMPT = "attempt-1"


# ---------------------------------------------------------------------------
# fixtures, built the way the coverage suite builds them
# ---------------------------------------------------------------------------


def _requirement(*permitted: str) -> PolicyRequirement:
    return PolicyRequirement(
        check_id=CHECK_EXECUTABLE_CASES,
        permitted=permitted,
        applies_to=(ACTION_SANDBOX_EXECUTE,),
    )


def _policy(*permitted: str) -> VerificationPolicy:
    return VerificationPolicy(
        policy_id="registry-test",
        version=1,
        requirements=(_requirement(*permitted),),
        require_verification=(ACTION_SANDBOX_EXECUTE,),
    )


def _snapshot(policy: VerificationPolicy):
    return resolve(
        policy,
        artifact_sha256=ARTIFACT,
        target_canonical=TARGET,
        action_class=ACTION_SANDBOX_EXECUTE,
        attempt_id=ATTEMPT,
    )


def _passing(verifier_id: str) -> Evidence:
    return Evidence(
        passed=True,
        total=1,
        passed_count=1,
        failures=(),
        verifier_id=verifier_id,
        verdict=Verdict.PASS,
        tier=Tier.HARD,
    )


def _unavailable(verifier_id: str) -> Unavailable:
    return Unavailable(
        verifier_id=verifier_id,
        tier=Tier.HARD,
        reason=Unavailability.INFRA_FAULT,
        detail="sandbox unavailable",
    )


def _bound(snapshot, outcome, *, implementation: str) -> BoundResult:
    return BoundResult(
        check_id=CHECK_EXECUTABLE_CASES,
        snapshot_digest=snapshot_digest(snapshot),
        implementation=implementation,
        outcome=outcome,
    )


# ---------------------------------------------------------------------------
# the sweep: declarations against the package, in both directions
# ---------------------------------------------------------------------------


def _site_parts(site: str) -> tuple[str, str]:
    module_name, _, attribute = site.rpartition(".")
    return module_name, attribute


def _reported_at(site: str) -> str:
    """The identity the object at ``site`` REPORTS, read off the live object.

    A class reports its OWN ``VERIFIER_ID`` (own ``__dict__``, so an inherited
    one — another class's identity — does not count); a module constant reports
    itself.
    """

    module_name, attribute = _site_parts(site)
    obj = getattr(importlib.import_module(module_name), attribute)
    if isinstance(obj, type):
        return str(vars(obj)["VERIFIER_ID"])
    assert isinstance(obj, str), (site, type(obj).__name__)
    return obj


def _source_of(module_name: str) -> ast.Module:
    module = importlib.import_module(module_name)
    return ast.parse(pathlib.Path(str(module.__file__)).read_text(encoding="utf-8"))


def _assignment_value(site: str) -> ast.expr:
    """The AST value of the assignment that binds the identity at ``site``."""

    module_name, attribute = _site_parts(site)
    module = importlib.import_module(module_name)
    tree = _source_of(module_name)
    if isinstance(getattr(module, attribute), type):
        classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == attribute]
        assert len(classes) == 1, (site, len(classes))
        body: list[ast.stmt] = classes[0].body
        wanted = "VERIFIER_ID"
    else:
        body, wanted = tree.body, attribute
    for node in body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == wanted for target in node.targets
        ):
            return node.value
    raise AssertionError(f"{site}: no assignment to {wanted} in {module_name}")


def _is_by_reference(value: ast.expr) -> bool:
    """A Name (the imported declaration) or the declaring call itself.

    A string literal is a RE-SPELLING: the copy that agrees by hand, which is
    the shape this registry exists to remove, and which a value comparison
    alone cannot tell from a reference because the strings are equal."""

    if isinstance(value, ast.Name):
        return True
    if isinstance(value, ast.Call):
        func = value.func
        if isinstance(func, ast.Name):
            return func.id == "declare_implementation"
        if isinstance(func, ast.Attribute):
            return func.attr == "declare_implementation"
    return False


def _shipped_declarations() -> dict[str, str]:
    """identity -> site, for declarations whose site is inside the package."""

    return {
        identity: site
        for identity, site in declarations().items()
        if site.startswith(PACKAGE_PREFIX)
    }


def _reported_identities() -> dict[str, str]:
    """``{site: identity}`` for every implementation-identity DEFINITION in the
    shipped package: a class carrying its own ``VERIFIER_ID``, or a module-level
    ``*_VERIFIER_ID`` constant ASSIGNED in that module (a re-export by import is
    not a definition and is not collected).

    Raises :class:`SweepIncomplete`, naming every module, if any module cannot
    be imported. A narrowed population is not a measurement of the package.
    """

    import prometheus_protocol

    found: dict[str, str] = {}
    unreadable: list[str] = []
    for info in pkgutil.walk_packages(prometheus_protocol.__path__, prefix=PACKAGE_PREFIX):
        try:
            module = importlib.import_module(info.name)
        except Exception as exc:  # noqa: BLE001 - recorded and refused below
            unreadable.append(f"{info.name}: {type(exc).__name__}: {exc}")
            continue
        for obj in vars(module).values():
            if (
                isinstance(obj, type)
                and obj.__module__ == info.name
                and "VERIFIER_ID" in vars(obj)
            ):
                found[f"{info.name}.{obj.__qualname__}"] = str(vars(obj)["VERIFIER_ID"])
        for node in _source_of(info.name).body:
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.endswith("_VERIFIER_ID"):
                    found[f"{info.name}.{target.id}"] = str(getattr(module, target.id))
    if unreadable:
        raise SweepIncomplete(
            "the implementation sweep could not import "
            f"{len(unreadable)} module(s), so its population is narrower than "
            "the package and its answer is not a measurement of it:\n  "
            + "\n  ".join(sorted(unreadable))
        )
    return found


# ---------------------------------------------------------------------------
# the refusal, its positive control, and what it is NOT
# ---------------------------------------------------------------------------


def test_a_misspelled_implementation_is_refused_at_construction_with_the_typed_reason():
    """G26's headline. Before this, ``subprocess-test`` constructed cleanly and
    every assessment for the action class refused as ``coverage.incomplete`` —
    a configuration error presenting as a runtime outage."""

    assert not is_registered(TYPO)
    with pytest.raises(PolicyError) as refusal:
        _requirement(TYPO)
    assert refusal.value.reason == "implementation_not_registered"
    assert refusal.value.reason in POLICY_REFUSAL_REASONS
    assert refusal.value.implementation == TYPO
    assert refusal.value.check_id == CHECK_EXECUTABLE_CASES
    assert TYPO in str(refusal.value)


def test_the_correct_identifier_constructs_and_its_requirement_is_satisfiable():
    """The paired positive control (doctrine #4), registered in
    ``positive_controls.json`` beside its three negatives. Without it, the
    refusal above is consistent with a registry that refuses everything."""

    policy = _policy(IMPL_SUBPROCESS)
    snapshot = _snapshot(policy)
    outcome = validate_coverage(
        snapshot,
        [_bound(snapshot, _passing(IMPL_SUBPROCESS), implementation=IMPL_SUBPROCESS)],
    )
    assert isinstance(outcome, CoverageSatisfied)
    assert outcome.answered_by == {CHECK_EXECUTABLE_CASES: IMPL_SUBPROCESS}


def test_no_such_implementation_and_implementation_unavailable_are_different_refusals():
    """The distinction the brief required. "No such implementation" is a
    configuration error, refused before a policy exists. "Exists but cannot
    answer right now" is doctrine #1's ``Unavailable``: the policy constructs,
    the snapshot resolves, and COVERAGE refuses as incomplete at assessment.
    Collapsing them would put a permanent misconfiguration behind a
    transient-sounding outcome."""

    with pytest.raises(PolicyError) as refusal:
        _requirement(TYPO)
    assert refusal.value.reason == "implementation_not_registered"

    policy = _policy(SUBPROCESS_TESTS)
    snapshot = _snapshot(policy)
    outcome = validate_coverage(
        snapshot,
        [_bound(snapshot, _unavailable(SUBPROCESS_TESTS), implementation=SUBPROCESS_TESTS)],
    )
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_INCOMPLETE
    assert outcome.check_id == CHECK_EXECUTABLE_CASES

    # Different types, different vocabularies, different moments. Structurally
    # disjoint, so neither can ever be spelled as the other.
    assert not isinstance(outcome, PolicyError)
    assert POLICY_REFUSAL_REASONS.isdisjoint(REFUSAL_REASONS)


def test_an_empty_registry_refuses_distinctly_rather_than_reading_as_permissive(monkeypatch):
    """Doctrine #8, driven directly. With nothing declared, "not registered"
    would be true of every name and would read as N misspellings; the fault is
    that nothing was declared, and the refusal says so under its own reason."""

    with monkeypatch.context() as patched:
        patched.setattr(implementations, "_DECLARED", {})
        assert registered_implementations() == frozenset()
        with pytest.raises(PolicyError) as refusal:
            _requirement(SUBPROCESS_TESTS)
        assert refusal.value.reason == "implementation_registry_empty"
        assert refusal.value.reason != "implementation_not_registered"
        assert refusal.value.check_id == CHECK_EXECUTABLE_CASES
    # Positive control: with the declarations back, the same construction holds.
    assert _requirement(SUBPROCESS_TESTS).permitted == (SUBPROCESS_TESTS,)


def test_the_typed_reasons_are_a_closed_set():
    with pytest.raises(ValueError, match="not a known policy refusal reason"):
        PolicyError("x", reason="made_up_reason")
    assert PolicyError("plain").reason is None
    assert PolicyError("typed", reason="implementation_registry_empty").reason == (
        "implementation_registry_empty"
    )


# ---------------------------------------------------------------------------
# the shipped profiles, and the registry against the package
# ---------------------------------------------------------------------------


def test_every_shipped_profile_names_only_implementations_the_package_reports_under():
    """The measurement the brief asked for, kept as a permanent test: does any
    shipped requirement name an implementation that does not exist? Every
    permitted name must be declared AND its declared site must, live, report
    that identity."""

    assert PROFILES, "no committed profiles at all"
    for profile_id, profile in PROFILES.items():
        assert load_profile(profile_id) is profile
        for requirement in profile.requirements:
            for name in requirement.permitted:
                assert is_registered(name), (profile_id, requirement.check_id, name)
                site = declarations()[name]
                assert site.startswith(PACKAGE_PREFIX), (name, site)
                assert _reported_at(site) == name, (name, site)


def test_every_declared_site_reports_its_identity_by_reference():
    """FORWARD. Every declaration inside the package resolves to a site that
    reports exactly that identity (a swapped reference reports another's), and
    the assignment at the site is a REFERENCE to the declaration, never a
    re-spelled literal (which a value check alone cannot distinguish)."""

    shipped = _shipped_declarations()
    assert len(shipped) >= 6, shipped
    for identity, site in sorted(shipped.items()):
        assert _reported_at(site) == identity, (
            f"{site} is declared to report {identity!r} but reports "
            f"{_reported_at(site)!r}: the reference at the site was swapped"
        )
        value = _assignment_value(site)
        assert _is_by_reference(value), (
            f"{site} binds its identity to {ast.dump(value)}: a re-spelled "
            "literal, not a reference to the declaration. This is the copy that "
            "agrees by hand, back again."
        )


def test_every_identity_the_package_reports_is_declared_at_that_site():
    """REVERSE. Walk the whole package: every class carrying its own
    ``VERIFIER_ID`` and every module-level ``*_VERIFIER_ID`` definition must be
    a declared identity whose declared site is THAT site. An undeclared
    implementation, or one declared as living elsewhere, fails here.

    Non-vacuity is pinned structurally: the collected sites must equal the
    declared sites of that shape, so a walk that collected nothing fails."""

    reported = _reported_identities()
    declared_sites = {site: identity for identity, site in _shipped_declarations().items()}

    wrong = {
        site: (identity, declared_sites.get(site))
        for site, identity in reported.items()
        if declared_sites.get(site) != identity
    }
    assert wrong == {}, (
        "sites reporting an identity the registry does not declare for them "
        f"(site: (reported, declared-for-site)): {wrong}"
    )

    expected = {
        site
        for site in declared_sites
        if site.endswith("_VERIFIER_ID")
        or isinstance(getattr(importlib.import_module(_site_parts(site)[0]), _site_parts(site)[1]), type)
    }
    assert set(reported) == expected, (
        f"the walk collected {sorted(reported)}, the registry declares "
        f"{sorted(expected)} of that shape"
    )


def test_the_sweep_refuses_a_module_it_cannot_import(monkeypatch):
    """The instrument must REFUSE a narrowed population, not report the rest
    (G2's lesson, applied to this sweep). Probed by making one real module
    raise on import."""

    real = importlib.import_module

    def _raise_for_one(name, *args, **kwargs):
        if name == "prometheus_protocol.core.bounds":
            raise ImportError("probe: this module cannot be imported")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(
        "tests.conformance.test_implementation_registry.importlib.import_module",
        _raise_for_one,
    )
    with pytest.raises(SweepIncomplete) as refusal:
        _reported_identities()
    assert "prometheus_protocol.core.bounds" in str(refusal.value)


# ---------------------------------------------------------------------------
# substitution, order, and the named limits
# ---------------------------------------------------------------------------


def test_two_sites_cannot_claim_one_identity_and_one_site_may_repeat_itself():
    """Cross-context substitution at the registry: a second implementation
    claiming a shipped identity is refused, and the refused claim changes
    nothing. The same site declaring again is idempotent."""

    site = declarations()[SUBPROCESS_TESTS]
    assert declare_implementation(SUBPROCESS_TESTS, implemented_by=site) == SUBPROCESS_TESTS
    with pytest.raises(ImplementationConflict):
        declare_implementation(SUBPROCESS_TESTS, implemented_by="somewhere.else.Stub")
    assert declarations()[SUBPROCESS_TESTS] == site


def test_a_swap_between_registered_implementations_present_at_authoring_is_caught_by_NOTHING():
    """G27, as a passing test (doctrine #5). Registration cannot catch a policy
    that permits ``swarm-checks`` where it meant ``subprocess-tests``: both
    exist. The first version of this test then claimed the policy digest and
    coverage catch it. Review (PR #111, P2) showed that claim covered only a
    swap made AFTER authoring, judged against evidence for the ORIGINAL policy.
    A swap PRESENT at authoring is self-consistent: the digest faithfully binds
    the swapped policy, and coverage accepts an authoritative ``swarm-checks``
    result bound to ``executable.cases`` because ``implementation`` and the
    evidence's ``verifier_id`` agree. Nothing binds an implementation to the
    checks it may answer. The stale-evidence refusal below proves MISMATCH
    REJECTION, not swap detection, and is kept labelled as exactly that."""

    swapped = _policy(SWARM_CHECKS)  # constructs: the registry has no objection
    original = _policy(SUBPROCESS_TESTS)
    # Distinguishable is not detected: two different policies have two digests,
    # and nothing compares the swapped one with what the author meant.
    assert policy_digest(swapped) != policy_digest(original)

    snapshot = _snapshot(swapped)
    # THE LIMIT. The swapped policy's own implementation satisfies its own
    # requirement, authoritatively. This is the CoverageSatisfied the review
    # described, and no instrument in this tree objects to it.
    accepted = validate_coverage(
        snapshot,
        [_bound(snapshot, _passing(SWARM_CHECKS), implementation=SWARM_CHECKS)],
    )
    assert isinstance(accepted, CoverageSatisfied)
    assert accepted.answered_by == {CHECK_EXECUTABLE_CASES: SWARM_CHECKS}

    # What the withdrawn claim actually proved: evidence for the ORIGINAL
    # policy's implementation is refused under the swapped one. Mismatch
    # rejection — useful, and not the same property.
    stale = validate_coverage(
        snapshot,
        [_bound(snapshot, _passing(SUBPROCESS_TESTS), implementation=SUBPROCESS_TESTS)],
    )
    assert isinstance(stale, CoverageRefused)
    assert stale.reason == REFUSED_INVALID_EVIDENCE


def test_a_declaration_must_precede_the_policy_that_names_it():
    """The ORDER limit, as a passing test (doctrine #5). A policy constructed
    before its implementation declares is refused, not deferred; declaring
    afterwards makes a fresh construction succeed. There is no un-declare."""

    late = "declared-after-first-use"
    assert not is_registered(late)
    with pytest.raises(PolicyError) as refusal:
        _requirement(late)
    assert refusal.value.reason == "implementation_not_registered"
    declare_implementation(
        late, implemented_by="tests.conformance.test_implementation_registry"
    )
    assert _requirement(late).permitted == (late,)


def test_requested_checks_are_not_validated_here_and_that_is_a_named_limit():
    """An untrusted request may only ADD requirements (resolver docstring). An
    added requirement naming an implementation nobody reports under is NOT
    refused by the registry — and can only hurt the requester: the added
    requirement has no result, so coverage refuses the whole action. Recorded
    as the scope boundary rather than left to be discovered."""

    snapshot = resolve(
        load_profile("baseline"),
        artifact_sha256=ARTIFACT,
        target_canonical=TARGET,
        action_class=ACTION_SANDBOX_EXECUTE,
        attempt_id=ATTEMPT,
        requested_checks=(
            BoundRequirement(check_id="extra.lint", permitted=("linter-nobody-implements",)),
        ),
    )
    assert "extra.lint" in snapshot.check_ids
    outcome = validate_coverage(
        snapshot,
        [_bound(snapshot, _passing(SUBPROCESS_TESTS), implementation=SUBPROCESS_TESTS)],
    )
    assert isinstance(outcome, CoverageRefused)
    assert outcome.reason == REFUSED_INCOMPLETE
    assert outcome.check_id == "extra.lint"


# ---------------------------------------------------------------------------
# the second check: a declaration is a claim, and the claim is tested at use
# ---------------------------------------------------------------------------


class CustomExtensionVerifier:
    """A deployment's own implementation, declared WITH THE CLASS IN HAND."""

    VERIFIER_ID = "custom-extension"


class MisreportingExtension:
    """Declared for one identity, reports another."""

    VERIFIER_ID = "something-else"


#: A module constant that does NOT report the identity a declaration will
#: claim for it — the path form of the misreporting class.
LIAR_CONSTANT = "not-custom-liar"


def test_an_extension_declared_with_its_class_is_verified_on_the_spot_and_works():
    """The positive control for the second check (doctrine #4). A deployment
    declares its own implementation by class; the registry verifies, right
    there, that the class reports the identity; a policy naming it constructs,
    resolves, and is satisfied by that implementation's evidence."""

    identity = declare_implementation("custom-extension", implemented_by=CustomExtensionVerifier)
    assert is_registered(identity)
    assert is_verified(identity)
    # The site is read OFF THE CLASS (pytest imports this module under its bare
    # name, so a hard-coded dotted path would pin the import mode, not the site).
    assert implemented_by(identity) == (
        f"{CustomExtensionVerifier.__module__}.{CustomExtensionVerifier.__qualname__}"
    )
    policy = _policy(identity)
    snapshot = _snapshot(policy)  # resolution runs the second check; it passes
    outcome = validate_coverage(
        snapshot, [_bound(snapshot, _passing(identity), implementation=identity)]
    )
    assert isinstance(outcome, CoverageSatisfied)
    assert outcome.answered_by == {CHECK_EXECUTABLE_CASES: identity}


def test_an_extension_class_reporting_another_identity_is_refused_at_declaration():
    """Substitution at the declaration itself, with the class in hand: refused
    before anything is recorded, so a refused declaration declares nothing."""

    with pytest.raises(ImplementationSiteUnresolved) as refusal:
        declare_implementation("custom-mismatch", implemented_by=MisreportingExtension)
    assert refusal.value.identity == "custom-mismatch"
    assert "something-else" in str(refusal.value)
    assert not is_registered("custom-mismatch")


def test_a_declaration_pointing_nowhere_is_refused_when_the_policy_is_resolved():
    """THE REVIEW'S EXAMPLE (PR #111, P2), as a test. Before the second check,
    ``declare_implementation("custom", implemented_by="missing.module.Verifier")``
    made a policy permitting it construct and then fail forever as incomplete
    coverage. Now: it still constructs — the name IS declared — and the first
    use, resolution, refuses with a typed reason that names the site, before any
    assessment runs. Configuration error, not runtime outage."""

    identity = declare_implementation("custom-nowhere", implemented_by="missing.module.Verifier")
    assert is_registered(identity)
    assert not is_verified(identity)
    policy = _policy(identity)  # constructs: declared
    with pytest.raises(ResolutionRefused) as refusal:
        _snapshot(policy)
    assert refusal.value.reason == "implementation_site_unresolved"
    assert refusal.value.implementation == identity
    assert refusal.value.check_id == CHECK_EXECUTABLE_CASES
    assert "missing.module.Verifier" in str(refusal.value)
    assert not is_verified(identity)


def test_a_declaration_whose_site_reports_a_different_identity_is_refused_at_resolution():
    """The path form of substitution: the site exists and resolves, and reports
    something else. Refused at resolution, naming both identities."""

    identity = declare_implementation(
        "custom-liar",
        implemented_by="tests.conformance.test_implementation_registry.LIAR_CONSTANT",
    )
    policy = _policy(identity)
    with pytest.raises(ResolutionRefused) as refusal:
        _snapshot(policy)
    assert refusal.value.reason == "implementation_site_unresolved"
    assert refusal.value.implementation == identity
    assert LIAR_CONSTANT in str(refusal.value)


def test_the_committed_profiles_verify_every_declared_site_at_load(monkeypatch):
    """``load_profile`` runs the second check over the whole profile. Positive:
    both committed profiles load, and every permitted name is verified after.
    Negative: a shipped declaration re-pointed at a missing site is refused at
    load, typed, naming the implementation — and the tree is put back."""

    for profile_id in PROFILES:
        profile = load_profile(profile_id)
        for requirement in profile.requirements:
            for name in requirement.permitted:
                assert is_verified(name), (profile_id, name)

    with monkeypatch.context() as patched:
        patched.setitem(
            implementations._DECLARED, SUBPROCESS_TESTS, "missing.module.SubprocessVerifier"
        )
        patched.setattr(
            implementations, "_VERIFIED", set(implementations._VERIFIED) - {SUBPROCESS_TESTS}
        )
        with pytest.raises(PolicyError) as refusal:
            load_profile("baseline")
        assert refusal.value.reason == "implementation_site_unresolved"
        assert refusal.value.implementation == SUBPROCESS_TESTS
        assert refusal.value.check_id == CHECK_EXECUTABLE_CASES
    assert load_profile("baseline") is PROFILES["baseline"]
