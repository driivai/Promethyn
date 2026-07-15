"""Optional API mode: the one question static analysis cannot answer.

Only used when a token and repo are supplied; failures degrade to None so the
verdict stays UNKNOWN instead of guessing.
"""

from __future__ import annotations

import json
import os
import urllib.request


def make_schedule_probe(repo_slug: str, token: str | None = None):
    """Return probe(workflow_basename) -> int|None scheduled runs on record."""

    token = token or os.environ.get("GITHUB_TOKEN", "")

    def probe(basename: str) -> int | None:
        url = (
            f"https://api.github.com/repos/{repo_slug}/actions/workflows/"
            f"{basename}/runs?event=schedule&per_page=1"
        )
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "voidguard",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        })
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return int(data.get("total_count", 0))
        except Exception:
            return None  # stays UNKNOWN; never guess

    return probe
