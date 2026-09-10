"""The stated SBOM model is the one the files actually follow.

``docs/DEPENDENCY-LICENSES.md`` declares ``docs/sbom.cdx.json`` to be a
single-platform installed snapshot (CPython 3.11, Linux x86-64) and
``constraints.txt`` to be a resolution input spanning 3.10-3.12. A model that
only lives in prose drifts, and the drift is invisible: an independent review
counted 23 constraints against 22 components and could not tell which reading
was intended, because both were on the page at once.

So the security-relevant direction of the model is asserted here: **everything
the snapshot installed is pinned**. A package that arrives in the environment
without a version pin — a transitive dependency picked up by a resolver change,
a build backend that started vendoring something — fails the build instead of
shipping unrecorded.

The reverse direction is NOT asserted, deliberately: ``constraints.txt`` naming
packages a Linux/3.11 snapshot does not install (``colorama`` on Windows,
``exceptiongroup`` and ``tomli`` on 3.10) is the stated model working, not a
discrepancy, and a test that demanded equality would be enforcing the model this
document explicitly rejected.
"""

from __future__ import annotations

import json
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[2]
SBOM = REPO / "docs" / "sbom.cdx.json"
CONSTRAINTS = REPO / "constraints.txt"
LICENSES = REPO / "docs" / "DEPENDENCY-LICENSES.md"

#: The environment's own installer and build backend. They are in the snapshot
#: because they are really there; they are not in ``constraints.txt`` because
#: they are not resolved dependencies of this project — pip supplies them. This
#: is a closed set of two and the only exemption; anything else that appears in
#: the snapshot must be pinned.
_ENVIRONMENT_TOOLING = frozenset({"pip", "setuptools"})


def _normalize(name: str) -> str:
    """PEP 503 normalization: ``types-PyYAML`` and ``types_pyyaml`` are one
    package, and comparing raw names would invent differences."""

    return re.sub(r"[-_.]+", "-", name).lower()


def _constraint_pins() -> dict[str, str]:
    pins = {}
    for line in CONSTRAINTS.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name, _, version = line.partition("==")
        assert version, f"constraints.txt line is not an exact pin: {line!r}"
        pins[_normalize(name)] = version.strip()
    return pins


def _sbom_components() -> dict[str, str]:
    document = json.loads(SBOM.read_text(encoding="utf-8"))
    return {
        _normalize(component["name"]): component["version"]
        for component in document["components"]
    }


def test_every_installed_component_is_pinned_at_the_same_version():
    """The direction that matters: nothing installs unrecorded or unpinned."""

    pins = _constraint_pins()
    unpinned, mismatched = [], []
    for name, version in sorted(_sbom_components().items()):
        if name in _ENVIRONMENT_TOOLING:
            continue
        if name not in pins:
            unpinned.append(f"{name}=={version}")
        elif pins[name] != version:
            mismatched.append(f"{name}: snapshot {version}, pinned {pins[name]}")

    assert unpinned == [], (
        f"the SBOM snapshot contains unpinned package(s) {unpinned}. Every "
        "package that actually installs must be in constraints.txt, or the "
        "build is not reproducible and the licence review has a hole in it."
    )
    assert mismatched == [], f"snapshot and pins disagree: {mismatched}"


def test_the_declared_model_is_still_the_one_documented():
    """The prose and the assertion above have to stay the same claim."""

    text = LICENSES.read_text(encoding="utf-8")
    for claim in (
        "single-platform INSTALLED SNAPSHOT",
        "CPython 3.11, Linux x86-64",
        "resolution input spanning CPython",
        "everything the snapshot installed is pinned",
    ):
        assert claim in text, f"DEPENDENCY-LICENSES.md no longer states: {claim!r}"


def test_the_tooling_exemption_is_exactly_the_installer_and_build_backend():
    """A widening exemption is how "everything is pinned" quietly becomes
    "everything we felt like pinning". Two names, both justified in the doc."""

    assert _ENVIRONMENT_TOOLING == {"pip", "setuptools"}
    installed = _sbom_components()
    assert _ENVIRONMENT_TOOLING <= set(installed), (
        "the exemption names package(s) that are not even in the snapshot — "
        "remove it rather than carrying a permission for nothing"
    )


def test_the_sbom_is_a_cyclonedx_document_with_components():
    document = json.loads(SBOM.read_text(encoding="utf-8"))
    assert document.get("bomFormat") == "CycloneDX", document.get("bomFormat")
    assert len(document["components"]) >= 20, len(document["components"])
