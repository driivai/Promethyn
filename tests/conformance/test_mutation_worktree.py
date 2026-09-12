"""The mutation worktree runs the WORKTREE'S code, proven by a planted mutation.

Measured on 2026-09-12: the runner as merged in #100 ran the worktree's tests
against the PRIMARY checkout's package, because the editable install's finder
resolved ``prometheus_protocol`` to the primary ``src`` — a mutation applied
to ``verifier/bank.py`` in the worktree reddened nothing while the same
mutation in memory reddened ten tests. A mutation runner whose mutations never
reach the code under test reports GREEN for every one of them, which is a
proof of nothing presented as a proof of safety. This plants a mutation the
Checkpoint-B proofs must catch and requires the red; the positive control
requires the unmutated worktree to be green.

Runs against the committed tree (HEAD), so it needs a git checkout with
history — which CI has (``fetch-depth: 0``) and a source checkout always has.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

from mutation_worktree import MutationWorktree, MutationWorktreeError  # noqa: E402

TARGET = "tests/conformance/test_execution_descriptor.py"
SELECTION = "honestly_redigested_weakened"
SEAM = "src/prometheus_protocol/verifier/bank.py"
# The bank's re-resolution comparison that closes R1 at minting — the same
# join the Checkpoint-B runner's first mutation removes in memory. Removing it
# lets a weakened snapshot mint; the named proof goes red.
OLD = "        if snapshot_digest(expected) != snapshot_digest(snapshot):"
NEW = "        if False:"


def _git_available() -> bool:
    try:
        subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError):
        return False
    return True


pytestmark = pytest.mark.skipif(not _git_available(), reason="needs a git checkout with HEAD")


def test_the_unmutated_worktree_is_green_for_the_selected_proof():
    """Positive control: the selection collects and passes on HEAD."""

    with MutationWorktree() as tree:
        red, summary = tree.pytest([TARGET], "-k", SELECTION)
    assert red == [], (red, summary)
    assert " passed" in summary, summary


def test_a_mutation_applied_in_the_worktree_is_what_the_run_sees():
    """The planted mutation must redden the proof — which it can only do if the
    run imports the worktree's package rather than the editable install's."""

    primary_before = (REPO / SEAM).read_bytes()
    with MutationWorktree() as tree:
        try:
            tree.apply(SEAM, OLD, NEW)
        except MutationWorktreeError as exc:  # pragma: no cover - drift is a finding
            pytest.fail(f"the planted mutation no longer matches the seam: {exc}")
        imported = tree.imported_package_file()
        assert imported.startswith(str(tree.path)), (
            f"a run in the worktree imports {imported}, not the worktree's package"
        )
        red, summary = tree.pytest([TARGET], "-k", SELECTION)
    assert red, (
        "the mutation reddened nothing: the worktree run is importing the "
        f"primary tree's package, not the worktree's ({summary}; imported {imported})"
    )
    assert any(SELECTION in test_id for test_id in red), red
    # And the primary tree was never written to — compared by content, since a
    # developer's checkout may legitimately be dirty for other reasons.
    assert (REPO / SEAM).read_bytes() == primary_before, (
        "the mutation leaked into the primary checkout"
    )
