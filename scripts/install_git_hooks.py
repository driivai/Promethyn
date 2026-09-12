#!/usr/bin/env python3
"""Point this clone's git at the repository's hooks (scripts/git-hooks).

Git does not clone hooks, so a guard that lives only in .git/hooks is a guard
the next clone does not have. The hooks are committed under scripts/git-hooks
and this sets ``core.hooksPath`` to that directory — one command, per clone,
recorded in CONTRIBUTING.md. A clone that never runs it is still refused by
the same checkers in CI; the hooks only move the refusal earlier.

Named limit: this is per-clone opt-in. Nothing in a repository can force a
hook onto a clone, which is why CI runs the same checks.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOKS = REPO_ROOT / "scripts" / "git-hooks"


def main() -> int:
    if not HOOKS.is_dir():
        print(f"no hooks directory at {HOOKS}")
        return 1
    for hook in sorted(HOOKS.iterdir()):
        if hook.is_file():
            mode = hook.stat().st_mode
            hook.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    relative = os.path.relpath(HOOKS, REPO_ROOT)
    subprocess.run(
        ["git", "config", "core.hooksPath", relative], cwd=REPO_ROOT, check=True
    )
    configured = subprocess.run(
        ["git", "config", "--get", "core.hooksPath"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout.strip()
    print(f"core.hooksPath = {configured} ({len(list(HOOKS.iterdir()))} hook(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
