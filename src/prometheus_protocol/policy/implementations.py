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

TWO CHECKS, TWO MOMENTS — the second added after review (PR #111, P2). A
declaration is a CLAIM: "this identity is reported by the code at this site".
Construction checks the NAME is declared. Whether the claim is TRUE — the site
exists and reports that identity — is checked when the policy is put to use:
:func:`verify_implementation` resolves the declared site and requires it to
report the identity, and ``load_profile`` and the trusted resolver call it for
every permitted name (``policy/profile.py``, ``policy/resolver.py``), refusing
with ``implementation_site_unresolved``. Without that second check a deployment
could declare ``"custom"`` as implemented by ``missing.module.Verifier``, and a
policy permitting ``custom`` would construct and then fail forever as incomplete
coverage — G26's failure moved up one layer, from the permitted name to the
declaration. A declaration made WITH THE CLASS IN HAND
(``declare_implementation("custom", implemented_by=MyVerifier)``) is verified at
the declaration itself, because nothing has to be imported to check it.

WHY THE SECOND CHECK IS NOT AT DECLARATION FOR A PATH. The shipped declarations
below name sites inside this package, and this module cannot import them:
``verifier/runner.py`` imports this module for its identity, ``swarm/runtime.py``
imports ``policy/profile.py`` which imports this module, so resolving a path
here, during this module's own import, is a cycle. A deployment's own module has
the same shape when it declares itself by path while being imported. So a path
is recorded and verified at first use, when everything is importable; a class
is verified on the spot. Both refuse; only the moment differs, and it is typed.

WHAT "DERIVED" MEANS HERE, stated honestly. The registry is not computed from
the package at runtime. Python has no reflection over "every implementation that
will ever be defined", and the derivation cannot run from the implementations
into the policy module (the cycle above). So it runs the other way — each
implementation imports its identity FROM here — and what is derived is the
CHECK. ``tests/conformance/test_implementation_registry.py`` walks the whole
package and requires, in both directions, that every identity an implementation
reports is declared here naming that site, and that every declaration here
resolves to a site that reports it by reference rather than by a re-spelled
literal. A declaration nobody implements, an implementation that re-spells its
identity, a site whose reference was swapped for another declaration, and two
sites claiming one identity are each refused there. A package that cannot be
fully imported is refused as an incomplete sweep, not measured in part.

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
* **A class-level identity.** Site verification reads the identity OFF THE
  CLASS (its own ``VERIFIER_ID`` or ``verifier_id``) or off a module constant.
  An implementation that only sets ``self.verifier_id`` in ``__init__`` cannot
  be verified without constructing it, which this module will not do; such a
  site is refused as reporting nothing. The seam declares the identity at class
  level (``core/interfaces.py``) and every shipped verifier sets it there.
* **Existence is not correctness.** Registered and verified means "the code at
  this site reports this identity", not that the code does what the check
  means. A stub reporting a real identity satisfies this registry, and a policy
  that permits the wrong registered implementation for a check is caught by
  nothing here (OPEN-GAPS G27: there is no implementation-to-check binding).
  The control against a stub is implementation identity at coverage and the
  trust store's fixed tier, not this module.
"""

from __future__ import annotations

import importlib

from prometheus_protocol.policy.snapshot import _identity


class ImplementationConflict(ValueError):
    """One identity, two implementation sites.

    Refused rather than merged: two implementations reporting under one name
    is exactly the substitution coverage keys on, and a registry that let the
    second claim stand would make the first one's identity mean nothing.
    """


class ImplementationSiteUnresolved(ValueError):
    """A declared site cannot be resolved, or does not report its identity.

    The declaration was a claim; this is the claim being false. Carries the
    identity and the site so the refusal that wraps it can name both without
    parsing this message.
    """

    def __init__(self, message: str, *, identity: str, site: str | None) -> None:
        super().__init__(message)
        self.identity = identity
        self.site = site


#: identity -> the site that reports under it. Module-private; read through the
#: functions below so the mapping cannot be reassigned from outside by accident.
_DECLARED: dict[str, str] = {}

#: Identities whose declared site has been resolved and found to report them.
#: Sites do not change at runtime, so a verified identity stays verified.
_VERIFIED: set[str] = set()


def _site_of(cls: type) -> str:
    return f"{cls.__module__}.{cls.__qualname__}"


def _reported_by(obj: object) -> str | None:
    """The identity ``obj`` reports, or ``None`` when it reports nothing.

    A class reports its OWN class-level ``VERIFIER_ID`` or ``verifier_id`` (own
    ``__dict__``: an inherited value is another class's identity, and the seam's
    default is the empty string, which reports nothing). A module constant
    reports itself. Anything else reports nothing — an instance in particular,
    because reading an instance identity means constructing a verifier, which
    the registry will not do.
    """

    if isinstance(obj, type):
        own = vars(obj)
        for attribute in ("VERIFIER_ID", "verifier_id"):
            value = own.get(attribute)
            if isinstance(value, str) and value:
                return value
        return None
    if isinstance(obj, str):
        return obj
    return None


def declare_implementation(identity: str, *, implemented_by: str | type) -> str:
    """Declare that ``identity`` is reported by the implementation at ``implemented_by``.

    Returns the identity so the declaration can BE the constant that everything
    else references. Idempotent for the same site; a different site claiming an
    already-declared identity raises :class:`ImplementationConflict`.

    ``implemented_by`` is either the implementing CLASS — verified here and
    now: it must report ``identity`` at class level, or the declaration is
    refused — or a dotted path to the object that carries the identity (a class,
    or a module-level constant), recorded now and verified by
    :func:`verify_implementation` when a policy that names it is loaded or
    resolved. See the module docstring for why a path cannot be verified at
    declaration time.
    """

    name = _identity(identity, what="implementation")
    if isinstance(implemented_by, type):
        site = _site_of(implemented_by)
        reported = _reported_by(implemented_by)
        if reported != name:
            raise ImplementationSiteUnresolved(
                f"{site} is declared to implement {name!r} but reports "
                f"{reported!r} at class level. A declaration whose site does not "
                "report its identity would let a policy name something no result "
                "ever carries — the misspelling G26 refuses, one layer up.",
                identity=name,
                site=site,
            )
        verified = True
    elif isinstance(implemented_by, str):
        site = _identity(implemented_by, what="implemented_by")
        verified = False
    else:
        raise TypeError(
            "implemented_by must be the implementing class or a dotted path to "
            f"the class or constant that reports the identity, not "
            f"{type(implemented_by).__name__}"
        )
    previous = _DECLARED.get(name)
    if previous is not None and previous != site:
        raise ImplementationConflict(
            f"implementation {name!r} is already declared as implemented by "
            f"{previous!r}; {site!r} cannot claim it as well. Two sites reporting "
            "under one identity is the substitution coverage keys on, so the "
            "second declaration is refused rather than merged."
        )
    _DECLARED[name] = site
    if verified:
        _VERIFIED.add(name)
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


def is_verified(identity: str) -> bool:
    """Whether the declared site for ``identity`` has been resolved and found to
    report it. ``False`` for an undeclared identity and for a path declaration
    that nothing has used yet."""

    return identity in _VERIFIED


def _resolve_site(site: str) -> object:
    module_name, _, attribute = site.rpartition(".")
    if not module_name or not attribute:
        raise ImportError(f"{site!r} is not a dotted module.attribute path")
    module = importlib.import_module(module_name)
    return getattr(module, attribute)


def verify_implementation(identity: str) -> str:
    """Resolve the declared site for ``identity`` and require that it REPORTS
    the identity. Returns the site.

    Raises :class:`ImplementationSiteUnresolved` when the identity is not
    declared, when the site cannot be imported or has no such attribute, or when
    the object there reports a different identity (or none). A verified identity
    is remembered, so the import happens once per process.
    """

    site = _DECLARED.get(identity)
    if site is None:
        raise ImplementationSiteUnresolved(
            f"{identity!r} is not a declared implementation",
            identity=identity,
            site=None,
        )
    if identity in _VERIFIED:
        return site
    try:
        obj = _resolve_site(site)
    except (ImportError, AttributeError) as exc:
        raise ImplementationSiteUnresolved(
            f"implementation {identity!r} is declared as implemented by {site!r}, "
            f"which cannot be resolved ({type(exc).__name__}: {exc}). A declaration "
            "pointing nowhere is the misspelling G26 refuses, one layer up: a "
            "policy naming this identity would construct and then fail on every "
            "assessment as incomplete coverage.",
            identity=identity,
            site=site,
        ) from exc
    reported = _reported_by(obj)
    if reported != identity:
        raise ImplementationSiteUnresolved(
            f"implementation {identity!r} is declared as implemented by {site!r}, "
            f"which resolves but reports {reported!r} rather than {identity!r}. "
            "The declaration is a claim, and the claim is false.",
            identity=identity,
            site=site,
        )
    _VERIFIED.add(identity)
    return site


# ---------------------------------------------------------------------------
# The shipped identities. Declared here by path (this module cannot import the
# sites — see the docstring), referenced at the site each names, and verified
# at first use and by the package sweep in the suite.
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
