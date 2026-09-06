#!/usr/bin/env python3
"""IP consistency gate: every artifact a reviewer cross-checks names one owner
and one license, and nothing still declares the old one.

What a prime's counsel verifies by hand, verified in CI instead:

* ``LICENSE``, ``NOTICE``, ``pyproject.toml``, ``README.md`` and
  ``site/index.html`` all name the canonical owner and the proprietary
  license;
* no tracked file declares Apache-2.0 as the *current* license — the license
  may be named only in the historical documents listed in ``HISTORICAL``,
  which state it as a past or superseded fact;
* no source file carries an SPDX header for any other license;
* with ``--history``, every commit reachable from the checked-out branch is
  authored and committed by the canonical identity (the check that keeps the
  squash-merge identity from creeping back after the provenance rewrite —
  ``docs/repository-identity.md``).

Exit status is non-zero on the first inconsistency, with every finding printed.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # Python 3.10: the dev closure ships tomli
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]  # regex fallback below

REPO_ROOT = Path(__file__).resolve().parent.parent

OWNER = "DriivAIDev"
OWNER_EMAIL = "will@driivai.com"
CANONICAL_IDENTITY = f"{OWNER} <{OWNER_EMAIL}>"
LICENSE_EXPRESSION = "LicenseRef-Proprietary"

#: Documents that may name the former license, as history. Everything else
#: that names it is a stray declaration.
HISTORICAL = {
    "docs/LICENSE-HISTORY.md",
    "docs/IP-READINESS.md",
    "docs/DEPENDENCY-LICENSES.md",
    "docs/pre-disclosure-audit.md",
    "docs/readiness-assessment.md",
    "docs/open-core-boundary.md",
    "CHANGELOG.md",
    "scripts/check_ip_consistency.py",
}
_FORMER_LICENSE = re.compile(r"Apache[- ]2\.0|Apache License", re.IGNORECASE)
_SPDX = re.compile(r"SPDX-License-Identifier:\s*(\S+)")
_TEXT_SUFFIXES = {".py", ".md", ".txt", ".toml", ".yml", ".yaml", ".html", ".cfg", ".ini", ""}


def _tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [line for line in out.splitlines() if line]


def _read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")


def _project_table(pyproject: str) -> dict:
    """The ``[project]`` table, via a TOML parser where one exists and a narrow
    regex otherwise — the three fields this gate reads are single-line."""

    if tomllib is not None:
        return tomllib.loads(pyproject)["project"]
    table: dict = {}
    match = re.search(r'^license\s*=\s*"([^"]*)"', pyproject, re.M)
    table["license"] = match.group(1) if match else None
    table["authors"] = [
        {"name": m.group(1), "email": m.group(2)}
        for m in re.finditer(r'\{\s*name\s*=\s*"([^"]*)"\s*,\s*email\s*=\s*"([^"]*)"\s*\}', pyproject)
    ]
    classifiers = re.search(r"^classifiers\s*=\s*\[(.*?)\]", pyproject, re.M | re.S)
    table["classifiers"] = re.findall(r'"([^"]*)"', classifiers.group(1)) if classifiers else []
    return table


def check_declarations() -> list[str]:
    findings: list[str] = []

    license_text = _read("LICENSE")
    if OWNER not in license_text or "All rights reserved" not in license_text:
        findings.append("LICENSE does not name the owner with all rights reserved")
    if _FORMER_LICENSE.search(license_text.split("License history:")[0]):
        findings.append("LICENSE still carries the former license text")

    notice = _read("NOTICE")
    if OWNER not in notice or "proprietary" not in notice.lower():
        findings.append("NOTICE does not name the owner as proprietary")

    project = _project_table(_read("pyproject.toml"))
    if project.get("license") != LICENSE_EXPRESSION:
        findings.append(f"pyproject.toml license is {project.get('license')!r}, not {LICENSE_EXPRESSION!r}")
    authors = project.get("authors") or []
    if not any(a.get("name") == OWNER and a.get("email") == OWNER_EMAIL for a in authors):
        findings.append(f"pyproject.toml authors do not name {CANONICAL_IDENTITY}")
    if any("License ::" in c for c in project.get("classifiers", [])):
        findings.append("pyproject.toml carries a license classifier alongside the expression")

    readme = _read("README.md")
    if "## License" not in readme or OWNER not in readme.split("## License", 1)[1]:
        findings.append("README.md License section does not name the owner")

    site = _read("site/index.html")
    if OWNER not in site or "proprietary" not in site.lower():
        findings.append("site/index.html does not state the proprietary license")

    return findings


def check_no_stray_former_license() -> list[str]:
    findings: list[str] = []
    for rel in _tracked_files():
        path = REPO_ROOT / rel
        if path.suffix not in _TEXT_SUFFIXES or not path.is_file():
            continue
        if rel in HISTORICAL:
            continue
        text = _read(rel)
        if rel == "LICENSE":
            text = text.split("License history:")[0]
        for match in _FORMER_LICENSE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            context = text[max(0, match.start() - 40): match.end() + 40].replace("\n", " ")
            findings.append(f"{rel}:{line}: names the former license outside a historical document: …{context}…")
        for match in _SPDX.finditer(text):
            if match.group(1) != LICENSE_EXPRESSION:
                findings.append(f"{rel}: SPDX header declares {match.group(1)}")
    return findings


def check_history(ref: str) -> list[str]:
    out = subprocess.run(
        ["git", "log", ref, "--format=%H %an <%ae>|%cn <%ce>"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout
    findings: list[str] = []
    for line in out.splitlines():
        sha, _, identities = line.partition(" ")
        author, _, committer = identities.partition("|")
        for role, identity in (("author", author), ("committer", committer)):
            if identity != CANONICAL_IDENTITY:
                findings.append(f"{sha[:10]} {role} is {identity!r}, not {CANONICAL_IDENTITY!r}")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--history", metavar="REF", nargs="?", const="HEAD",
                        help="also require the canonical identity on every commit reachable from REF (default HEAD)")
    args = parser.parse_args(argv)

    findings = check_declarations() + check_no_stray_former_license()
    if args.history:
        findings += check_history(args.history)
    for finding in findings:
        print(f"  {finding}")
    if findings:
        print(f"IP consistency check FAILED: {len(findings)} finding(s)")
        return 1
    scope = f"declarations, stray-license scan" + (f", history of {args.history}" if args.history else "")
    print(f"IP consistency check passed ({scope}): owner {CANONICAL_IDENTITY}, license {LICENSE_EXPRESSION}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
