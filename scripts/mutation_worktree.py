"""Run executed-mutation proofs in a throwaway git worktree.

WHY THIS EXISTS. Every mutation runner in this repository has worked the same
way: edit a source file in place, run the suite, restore in a ``finally``, and
assert the restore was byte-identical. That restore is correct and has never
failed. The gap is not the restore — it is the WINDOW.

While a run is in flight the primary checkout holds a deliberately disabled
security comparison. Anything that reads the tree in that window sees it: a
concurrent test run, a stray ``git add -A``, a commit hook, a reviewer's editor.
During this sprint a repository stop-hook twice reported "uncommitted changes,
please commit and push" while a mutation was applied, and the only thing between
that prompt and a pushed commit disabling an authorization check was the
operator noticing. That is vigilance where construction is available.

A worktree removes the window. Mutations are applied to a separate checkout of
the same commit, the suite runs there, and the primary tree is never written to
at all — so there is no moment at which committing from it is dangerous.

USAGE, as a library::

    from mutation_worktree import MutationWorktree

    with MutationWorktree() as tree:
        tree.apply("src/prometheus_protocol/policy/execution.py", old, new)
        red, summary = tree.pytest(["tests/conformance"])

The worktree is created from HEAD, so uncommitted work in the primary tree is
deliberately NOT carried over: a mutation proof should describe a commit, not a
desk. ``include_dirty=True`` opts into copying tracked modifications when a
proof is genuinely about work in progress.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


class MutationWorktreeError(RuntimeError):
    """The worktree could not be created, used, or removed."""


class MutationWorktree:
    """A disposable checkout of HEAD that mutations are applied to."""

    def __init__(self, *, include_dirty: bool = False) -> None:
        self._include_dirty = include_dirty
        self._path: Path | None = None
        self._originals: dict[Path, str] = {}

    # -- lifecycle ------------------------------------------------------
    def __enter__(self) -> "MutationWorktree":
        self._path = Path(tempfile.mkdtemp(prefix="prom-mutation-"))
        # `--detach` so the worktree holds no branch: nothing here can be
        # pushed, and the primary branch cannot be moved out from under it.
        self._git("worktree", "add", "--detach", str(self._path), "HEAD")
        if self._include_dirty:
            diff = self._git("diff", "HEAD", capture=True)
            if diff.strip():
                subprocess.run(
                    ["git", "apply", "-"], cwd=self._path, input=diff,
                    text=True, check=True,
                )
            # Untracked, not-ignored files too: a proof about work in progress
            # that omits its new modules fails at import, with no summary,
            # which reads as "nothing red" to a careless caller. Measured.
            untracked = self._git(
                "ls-files", "--others", "--exclude-standard", capture=True
            ).split("\n")
            for relative in untracked:
                relative = relative.strip()
                if not relative:
                    continue
                source = REPO / relative
                if source.is_file():
                    destination = self._path / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, destination)
        return self

    def __exit__(self, *exc) -> None:
        if self._path is None:
            return
        try:
            self._git("worktree", "remove", "--force", str(self._path))
        except Exception:  # pragma: no cover - best effort, then force
            shutil.rmtree(self._path, ignore_errors=True)
            self._git("worktree", "prune")
        self._path = None

    # -- operations -----------------------------------------------------
    @property
    def path(self) -> Path:
        if self._path is None:
            raise MutationWorktreeError("worktree is not active")
        return self._path

    def apply(self, relative: str, old: str, new: str) -> None:
        """Replace ``old`` with ``new`` once in ``relative``, inside the worktree.

        Refuses when ``old`` is absent. A mutation string that no longer matches
        is a mutation that did not happen, and a run that reports GREEN for a
        mutation it never applied is worse than no run at all — it is a proof
        of nothing, presented as a proof of safety.
        """

        target = self.path / relative
        text = target.read_text(encoding="utf-8")
        if old not in text:
            raise MutationWorktreeError(
                f"mutation target not found in {relative}: the string has drifted, "
                "so this mutation would silently not apply"
            )
        self._originals.setdefault(target, text)
        target.write_text(text.replace(old, new, 1), encoding="utf-8")

    def environment(self) -> dict[str, str]:
        """The environment a run in this worktree gets: its own ``src`` first."""

        env = dict(os.environ)
        inherited = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = str(self.path / "src") + (
            os.pathsep + inherited if inherited else ""
        )
        return env

    def imported_package_file(self) -> str:
        """Where ``import prometheus_protocol`` resolves for a run in this
        worktree — the check that the worktree's own code is what runs."""

        proc = subprocess.run(
            [sys.executable, "-c", "import prometheus_protocol; print(prometheus_protocol.__file__)"],
            cwd=self.path, capture_output=True, text=True, env=self.environment(),
        )
        return proc.stdout.strip() or proc.stderr.strip()

    def revert(self) -> None:
        """Undo every applied mutation. Cheap, since the worktree is disposable."""

        for target, text in self._originals.items():
            target.write_text(text, encoding="utf-8")
        self._originals.clear()

    def pytest(self, targets: list[str], *extra: str) -> tuple[list[str], str]:
        """Run pytest IN THE WORKTREE; return (failed test ids, summary line).

        THE WORKTREE'S OWN ``src`` MUST WIN, and until this line it did not.
        The package is installed editable, so ``import prometheus_protocol``
        resolves through the site-packages finder to the PRIMARY checkout's
        ``src`` — the one tree this runner exists to keep unmutated. Measured
        on 2026-09-12: a mutation applied to ``verifier/bank.py`` in the
        worktree reddened nothing (``11 passed``) while the same mutation
        applied in memory reddened ten tests. The worktree was running the
        worktree's TESTS against the primary tree's CODE, and a runner that
        reports GREEN for a mutation the code under test never received is
        the void guard this repository keeps naming — here, in the tool built
        to prevent a different one. ``PYTHONPATH`` is prepended with the
        worktree's ``src`` so its package shadows the editable install;
        ``tests/conformance/test_mutation_worktree.py`` plants a mutation and
        requires the red.
        """

        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--tb=no",
             "-p", "no:cacheprovider", *targets, *extra],
            cwd=self.path, capture_output=True, text=True, env=self.environment(),
        )
        # ``FAILED <nodeid> - <message>``: split on the separator, not on the
        # first space, or a parametrised id containing a space ("returns FAIL")
        # is truncated to a prefix that names several rows at once.
        red = sorted({
            line[len("FAILED "):].split(" - ", 1)[0].strip()
            for line in proc.stdout.splitlines() if line.startswith("FAILED ")
        })
        summary = [
            line for line in proc.stdout.strip().splitlines()
            if " passed" in line or " failed" in line
        ]
        return red, (summary[-1] if summary else "(no summary)")

    # -- internals ------------------------------------------------------
    def _git(self, *args: str, capture: bool = False) -> str:
        proc = subprocess.run(
            ["git", *args], cwd=REPO, capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise MutationWorktreeError(
                f"git {' '.join(args)} failed: {proc.stderr.strip()}"
            )
        return proc.stdout if capture else ""


if __name__ == "__main__":  # pragma: no cover - smoke check
    with MutationWorktree() as tree:
        print("worktree:", tree.path)
        print("primary tree stays clean while this runs")
