"""The Hearth content ledger is complete, live, and cannot be quietly narrowed.

``hearth_ledger.py`` replaced four path-based ``git diff origin/main`` guards
with digests of the sanctioned CONTENT. That closes the two defects those guards
had — a path sanctioned once was sanctioned forever, and on main the comparison
was empty so the guard asserted nothing — but it introduces two obligations of
its own, and this module discharges both:

* **completeness** — a digest is only a guard over files it covers, so the union
  of the four guards' file tuples is pinned against the ledger's key set AND
  against a count. Deleting a file from a guard's tuple to unfreeze it fails
  here; so does adding a file to a tuple without adding its digest.
* **non-vacuity** — the previous guards passed on main because there was nothing
  to compare, and nothing in the suite noticed. So this one is proved to FIRE:
  the comparison is run against a synthetic tree holding a modified copy of a
  protected file, and it must report it.
"""

from __future__ import annotations

import pathlib
import shutil

import pytest

from hearth_ledger import (
    COMPOSITION_FILES,
    DIGESTS,
    EXPECTED_PROTECTED_FILES,
    EXTENSION_SURFACE_FILES,
    ORCHESTRATION_FILES,
    PROTECTED_FILES,
    REPO,
    SOFT_LEVER_FILES,
    digest_of,
    unsanctioned_changes,
)

_GUARD_SETS = {
    "test_composition.py": COMPOSITION_FILES,
    "test_extension_surface.py": EXTENSION_SURFACE_FILES,
    "test_orchestration.py": ORCHESTRATION_FILES,
    "test_soft_levers.py": SOFT_LEVER_FILES,
}


def test_the_hearth_ledger_covers_exactly_the_protected_files():
    """Every protected file has a digest, and the ledger has no orphans.

    A digest for a file no longer in any guard's tuple is the tell that the tuple
    was narrowed — which is how a frozen file gets unfrozen without touching a
    single digest.
    """

    assert set(DIGESTS) == set(PROTECTED_FILES), (
        "ledger drift: "
        f"in the ledger but unprotected {sorted(set(DIGESTS) - set(PROTECTED_FILES))}; "
        f"protected but unsanctioned {sorted(set(PROTECTED_FILES) - set(DIGESTS))}"
    )
    assert len(PROTECTED_FILES) == EXPECTED_PROTECTED_FILES, (
        f"{len(PROTECTED_FILES)} protected file(s); pinned at "
        f"{EXPECTED_PROTECTED_FILES}. Shrinking a guard's tuple unfreezes a file "
        "without changing any digest — raise this pin only when the Hearth "
        "genuinely grows."
    )


@pytest.mark.parametrize("guard", sorted(_GUARD_SETS))
def test_every_guards_file_tuple_is_non_empty_and_fully_sanctioned(guard):
    """A guard whose tuple emptied would pass while freezing nothing."""

    files = _GUARD_SETS[guard]
    assert files, f"{guard} freezes no files at all"
    assert set(files) <= set(DIGESTS), (
        f"{guard} freezes file(s) with no sanctioned digest: "
        f"{sorted(set(files) - set(DIGESTS))}"
    )


def test_every_protected_file_exists_and_matches_its_digest():
    """The whole ledger, in one place, so a drifted digest is one failure and not
    four."""

    assert unsanctioned_changes(PROTECTED_FILES) == []


def test_the_ledger_actually_detects_a_changed_file(tmp_path):
    """NON-VACUITY, proved rather than assumed.

    The guards this replaced were vacuous on main — ``git diff origin/main`` is
    empty once the remote points at the same commit — and passed for that reason
    with nothing in the suite able to tell the difference. So the comparison is
    exercised here against a tree that DOES differ: a copy of the repository's
    protected files with one byte appended to the authorization gate, the file
    the old path-based guards had stopped watching entirely since PR #52.
    """

    target = "src/prometheus_protocol/gate/authorization.py"
    assert target in DIGESTS, "the authorization gate must be in the ledger"

    for relative in PROTECTED_FILES:
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / relative, destination)

    # The unmodified copy is clean, so the fixture itself is not the thing under
    # test — otherwise a broken copy would look like a working guard.
    assert unsanctioned_changes(PROTECTED_FILES, root=tmp_path) == []

    modified = tmp_path / target
    modified.write_bytes(modified.read_bytes() + b"\n# an unsanctioned edit\n")
    findings = unsanctioned_changes(PROTECTED_FILES, root=tmp_path)
    assert len(findings) == 1 and target in findings[0], findings
    assert digest_of(target, tmp_path) != DIGESTS[target]


def test_the_guards_do_not_depend_on_a_branch_being_resolvable(tmp_path):
    """No git, therefore no skip.

    The four guards used to carry ``skipif`` on ``git rev-parse origin/main``.
    Under a shallow checkout that predicate was TRUE and all four silently
    skipped — the failure mode CI now spends a whole step ("Hearth content
    guards must EXECUTE, not skip") watching for. With the ledger there is
    nothing to resolve, so the assertion holds in a directory that is not a git
    repository at all.
    """

    for relative in PROTECTED_FILES:
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO / relative, destination)
    assert not (tmp_path / ".git").exists()
    assert unsanctioned_changes(PROTECTED_FILES, root=tmp_path) == []


def test_the_ledger_states_the_limit_of_what_a_digest_proves():
    """A digest is an IDENTITY guard, not a QUALITY guard, and the module must
    say so where the assurance is described — the same discipline the revert
    runners are held to."""

    import hearth_ledger

    doc = hearth_ledger.__doc__ or ""
    for claim in (
        "proves the bytes are unchanged, not that they are",
        "Whoever can edit the Hearth can edit these digests",
        "The file list",
    ):
        assert claim in doc, f"the ledger no longer states: {claim!r}"


def test_no_protected_file_is_a_directory_or_missing():
    missing = [p for p in PROTECTED_FILES if not (REPO / p).is_file()]
    assert missing == [], f"protected path(s) are not files: {missing}"


def test_digests_are_sha256_hex():
    bad = sorted(
        path for path, digest in DIGESTS.items()
        if len(digest) != 64 or set(digest) - set("0123456789abcdef")
    )
    assert bad == [], f"not SHA-256 hex: {bad}"


def test_the_protected_set_is_a_pathlib_safe_relative_set():
    for relative in PROTECTED_FILES:
        assert not pathlib.PurePosixPath(relative).is_absolute()
        assert ".." not in pathlib.PurePosixPath(relative).parts
