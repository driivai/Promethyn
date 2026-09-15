"""The implementation registry: which verifier identities EXIST, declared once.

WHY (OPEN-GAPS G26). ``PolicyRequirement.permitted`` names the implementations
allowed to satisfy a check. Until this module existed nothing checked that a
name in it was the identity of anything. ``IMPL_SUBPROCESS = "subprocess-tests"``
in ``policy/profile.py`` was a literal a person had copied off
``SubprocessVerifier.VERIFIER_ID`` — correct because it was copied correctly,
not because anything compared them at construction. A typo constructed cleanly
and failed later, on every assessment, as ``coverage.incomplete``: a
configuration error presenting as a runtime outage, permanent for that action
class, and worst for a customer-supplied policy, which has no shipped constants
beside it at all.

WHAT IT IS. One declaration per identity, HERE, consumed BY REFERENCE at the
implementation's definition site (``VERIFIER_ID = SUBPROCESS_TESTS``) and by the
policy module (``IMPL_SUBPROCESS = SUBPROCESS_TESTS``). There is one spelling,
and both consumers are the same object as the declaration, so the three copies
that used to agree by hand are one declaration and two references.
``PolicyRequirement`` refuses, at construction and with a typed reason, any
permitted name the registry has not declared — and refuses an EMPTY registry
outright rather than validating against nothing (doctrine #8).

WHAT "DERIVED" MEANS HERE, stated honestly. The registry is not computed from
the package at runtime. Python has no reflection over "every implementation that
will ever be defined", and the derivation cannot run from the implementations
into the policy module: ``swarm/runtime.py`` imports ``policy/profile.py``, and
the verifier modules would drag the sandbox adapters into every policy load. So
it runs the other way — each implementation imports its identity FROM here —
and what is derived is the CHECK. ``tests/conformance/test_implementation_registry.py``
walks the whole package and requires, in both directions, that every identity an
implementation reports is declared here naming that site, and that every
declaration here resolves to a site that reports it by reference rather than by
a re-spelled literal. A declaration nobody implements, an implementation that
re-spells its identity, a site whose reference was swapped for another
declaration, and two sites claiming one identity are each refused there. A
package that cannot be fully imported is refused as an incomplete sweep, not
measured in part.

WHAT CAN VARY OUTSIDE THE DERIVATION:

* **Identities composed at construction.** ``verifier/soft_levers.py`` builds
  ``"<base>:threshold@0.8"`` and ``"<base>:k3-majority"`` per instance, and
  ``GroundingVerifier`` / ``ModelJudgeVerifier`` accept a caller-chosen
  ``verifier_id``. None of those is registered here, so a policy naming one is
  refused at construction. Every wrapper emits ``Tier.SOFT`` evidence, which
  cannot satisfy a requirement regardless (``policy/coverage.py``), so nothing
  that could have authorized is lost. A deployment that trusts an identity of
  its own declares it with :func:`declare_implementation` at the definition
  site, before any policy names it.
* **Order.** A declaration must run before a policy names it. The shipped
  identities are declared by importing THIS module, which the policy module does
  before it constructs a profile, so a shipped profile can never observe an
  empty registry. A deployment's own implementation must be imported (declared)
  before its policy is constructed; a policy constructed earlier is refused, not
  deferred, and there is no API to un-declare.
* **Existence is not correctness.** Registered means "some code reports this
  identity", not that the code does what the check means. A stub reporting a
  real identity satisfies this registry. The control against that is
  implementation identity at coverage (``coverage.invalid_evidence`` when the
  result and the evidence name different implementations) and the trust
  store's fixed tier, not this module — G26's residual, kept as stated.
"""

from __future__ import annotations

from prometheus_protocol.policy.snapshot import _identity


class ImplementationConflict(ValueError):
    """One identity, two implementation sites.

    Refused rather than merged: two implementations reporting under one name
    is exactly the substitution coverage keys on, and a registry that let the
    second claim stand would make the first one's identity mean nothing.
    """


#: identity -> the site that reports under it. Module-private; read through the
#: functions below so the mapping cannot be reassigned from outside by accident.
_DECLARED: dict[str, str] = {}


def declare_implementation(identity: str, *, implemented_by: str) -> str:
    """Declare that ``identity`` is reported by the implementation at ``implemented_by``.

    Returns the identity so the declaration can BE the constant that everything
    else references. Idempotent for the same site; a different site claiming an
    already-declared identity raises :class:`ImplementationConflict`.

    ``implemented_by`` is a dotted path to the object that carries the identity
    — a class with a ``VERIFIER_ID`` attribute, or a module-level constant. The
    package sweep resolves it and checks it, so a declaration pointing nowhere,
    or at a site that reports something else, fails in the suite.
    """

    name = _identity(identity, what="implementation")
    site = _identity(implemented_by, what="implemented_by")
    previous = _DECLARED.get(name)
    if previous is not None and previous != site:
        raise ImplementationConflict(
            f"implementation {name!r} is already declared as implemented by "
            f"{previous!r}; {site!r} cannot claim it as well. Two sites reporting "
            "under one identity is the substitution coverage keys on, so the "
            "second declaration is refused rather than merged."
        )
    _DECLARED[name] = site
    return name


def registered_implementations() -> frozenset[str]:
    """Every identity declared so far, as an immutable snapshot."""

    return frozenset(_DECLARED)


def is_registered(identity: str) -> bool:
    return identity in _DECLARED


def implemented_by(identity: str) -> str | None:
    """The declared site for ``identity``, or ``None`` when undeclared."""

    return _DECLARED.get(identity)


def declarations() -> dict[str, str]:
    """A copy of the whole mapping, identity -> site, for the sweep and for
    diagnostics. A copy, so a caller cannot edit the registry through it."""

    return dict(_DECLARED)


# ---------------------------------------------------------------------------
# The shipped identities. Declared here, referenced at the site each names.
# ---------------------------------------------------------------------------

#: ``SubprocessVerifier`` — the sandboxed test run, HARD tier.
SUBPROCESS_TESTS = declare_implementation(
    "subprocess-tests",
    implemented_by="prometheus_protocol.verifier.runner.SubprocessVerifier",
)

#: ``SqlVerifier`` — sandboxed SQL execution plus result equivalence, HARD tier.
SQL_RESULT_EQUIVALENCE = declare_implementation(
    "sql-result-equivalence",
    implemented_by="prometheus_protocol.verifier.sql.SqlVerifier",
)

#: ``GroundingVerifier`` — the claim-vs-source judge, SOFT tier.
GROUNDING_JUDGE = declare_implementation(
    "grounding-judge",
    implemented_by="prometheus_protocol.verifier.grounding.GroundingVerifier",
)

#: ``ModelJudgeVerifier`` — the model-graded outcome judge, SOFT tier.
MODEL_JUDGE = declare_implementation(
    "model-judge",
    implemented_by="prometheus_protocol.verifier.model_judge.ModelJudgeVerifier",
)

#: The swarm's deterministic check runner, reported under a module constant.
SWARM_CHECKS = declare_implementation(
    "swarm-checks",
    implemented_by="prometheus_protocol.swarm.runtime.CHECK_VERIFIER_ID",
)

#: The git merge check, reported under a module constant.
GIT_MERGE_CHECK = declare_implementation(
    "git-merge-check",
    implemented_by="prometheus_protocol.tools.git.MERGE_CHECK_VERIFIER_ID",
)
