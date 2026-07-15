"""Class 3 — settings that are silently discarded.

Exactly three provable shapes, no general config-effectiveness analysis:
  R3a  PYTHON* env vars handed to `python -I` / `python -E` (both drop them)
  R3b  workflow env set-and-never-read (conservative; WARN only)
  R3c  Dockerfile ARG consumed after FROM without re-declaration
"""

from __future__ import annotations

import re

from .model import VOID, WARN, Evidence, Finding
from .repo import Repo

_Q3 = ("does this setting reach the process it configures? — the interpreter is "
       "invoked with -I/-E, which drops every PYTHON* variable before startup.")

#: python invocation whose flag clusters include -I or -E (isolated / no-env mode).
_PY_ISOLATED = re.compile(
    r"\bpython(?:[0-9](?:\.[0-9]+)?)?((?:\s+-[A-Za-z]+)+)"
)


def _has_isolated_flag(clusters: str) -> bool:
    for cluster in clusters.split():
        body = cluster.lstrip("-")
        # a cluster like -I, -IB, -Es; long options (--version) are not clusters
        if cluster.startswith("--"):
            continue
        if len(body) <= 4 and ("I" in body or "E" in body):
            return True
    return False


def _isolated_invocations(text: str) -> list[str]:
    out = []
    for m in _PY_ISOLATED.finditer(text):
        if _has_isolated_flag(m.group(1)):
            out.append(m.group(0).strip())
    return out


# -- R3a ------------------------------------------------------------------------------


def scan_python_isolated(repo: Repo) -> list[Finding]:
    findings: list[Finding] = []

    # workflows: any env level (workflow/job/step) + a run line with python -I/-E
    for wf in repo.workflows():
        env_vars = re.findall(r"^\s*(PYTHON\w+)\s*:", wf.text, re.M)
        if not env_vars:
            continue
        isolated = _isolated_invocations(wf.text)
        if not isolated:
            continue
        for var in sorted(set(env_vars)):
            findings.append(Finding(
                rule="R3a", vg_class=3, verdict=VOID,
                guard=f"{wf.rel}: env {var}",
                mechanism=f"{var} set in workflow env; run step invokes `{isolated[0]}`",
                evidence=Evidence(
                    summary=f"{var} is set in {wf.rel} and a run step invokes the "
                            f"interpreter in isolated/no-env mode ({isolated[0]!r}); "
                            "-I implies -E and -E ignores every PYTHON* variable",
                    searched=[wf.rel],
                    found=isolated[:3],
                ),
                question=_Q3,
                fix="use the command-line flag the env var stands for (e.g. -B for "
                    "PYTHONDONTWRITEBYTECODE), or drop -I/-E if the env must apply",
            ))

    # Dockerfiles: ENV PYTHON* then a later python -I/-E
    for p in repo.glob("Dockerfile*", "**/Dockerfile*", "docker/**"):
        rel = repo.rel(p)
        text = repo.read(p)
        env_vars = re.findall(r"^\s*ENV\s+(PYTHON\w+)", text, re.M)
        if not env_vars:
            continue
        isolated = _isolated_invocations(text)
        if not isolated:
            continue
        for var in sorted(set(env_vars)):
            findings.append(Finding(
                rule="R3a", vg_class=3, verdict=VOID,
                guard=f"{rel}: ENV {var}",
                mechanism=f"ENV {var} + `{isolated[0]}` in the same image",
                evidence=Evidence(
                    summary=f"{rel} sets ENV {var} and invokes the interpreter in "
                            f"isolated/no-env mode ({isolated[0]!r})",
                    searched=[rel], found=isolated[:3],
                ),
                question=_Q3,
                fix="use the equivalent command-line flag, or drop -I/-E",
            ))

    # code (same-file, narrow): a PYTHON* env assignment AND an argv flag literal
    # "-I"/"-E" in the same file. Cross-file flows are out of v0 scope (README).
    flag_lit = re.compile(r"[\"'](-[A-Za-z]{1,3})[\"']")
    env_set = re.compile(
        r"environ\[\s*[\"']PYTHON\w+[\"']\s*\]\s*="
        r"|setenv\(\s*[\"']PYTHON\w+[\"']"
        r"|[\"']PYTHON\w+=[^\"']*[\"']",
    )
    for p in repo.files():
        if p.suffix != ".py":
            continue
        rel = repo.rel(p)
        if rel.startswith("tests/") or "/tests/" in rel:
            continue  # test fixtures legitimately construct such argv
        text = repo.read(p)
        env_m = env_set.search(text)
        if not env_m:
            continue
        iso_flags = [
            m.group(1) for m in flag_lit.finditer(text)
            if ("I" in m.group(1) or "E" in m.group(1)) and m.group(1) not in {"-e"}
        ]
        if iso_flags and re.search(r"sys\.executable|[\"']python", text):
            findings.append(Finding(
                rule="R3a", vg_class=3, verdict=WARN,
                guard=f"{rel}",
                mechanism=f"PYTHON* env set and interpreter flag {iso_flags[0]!r} "
                          "constructed in the same file",
                evidence=Evidence(
                    summary=f"{rel} sets a PYTHON* variable ({env_m.group(0)[:60]!r}) "
                            f"and builds an argv containing {iso_flags[0]!r}; if that "
                            "argv reaches an interpreter run with the env, the setting "
                            "is dropped. Same-file heuristic — data flow not proven, "
                            "so WARN, not VOID.",
                    searched=[rel],
                ),
                question="does this setting reach the process it configures? — "
                         "possibly not; -I/-E would drop it.",
                fix="verify the flow; prefer the command-line flag over the env var",
            ))
    return findings


# -- R3b: set-and-never-read (conservative WARN) ------------------------------------------

_CONSUMED_PREFIXES = (
    "PYTHON", "PIP_", "PATH", "LD_", "CC", "CXX", "CFLAGS", "CXXFLAGS", "GITHUB_",
    "ACTIONS_", "RUNNER_", "CI", "FORCE_COLOR", "NO_COLOR", "LANG", "LC_", "TZ",
    "HOME", "VIRTUAL_ENV", "UV_", "POETRY_", "NPM_", "NODE_", "YARN_", "CARGO_",
    "RUST", "GO", "JAVA_", "MAVEN_", "GRADLE_", "DOCKER_", "COMPOSE_", "TERM",
    "SOURCE_DATE_EPOCH", "PRE_COMMIT", "TOX_", "NOX_", "PYTEST_", "COVERAGE_",
    "SETUPTOOLS_", "HATCH_", "DEBIAN_", "MAKEFLAGS", "AWS_", "GCP_", "AZURE_",
    "SSH_", "GPG_", "TWINE_", "PKG_CONFIG",
    # consumed implicitly by tools the job invokes (measured on real repos:
    # gh reads GH_TOKEN, build backends read PYO3_/CIBW_/MATURIN_ knobs)
    "GH_TOKEN", "GH_", "PYO3_", "MATURIN_", "CIBW_", "SCCACHE_", "CMAKE_",
    "MACOSX_DEPLOYMENT_TARGET", "FLIT_", "PDM_", "RYE_", "CONDA_", "MAMBA_",
)


def scan_env_unread(repo: Repo) -> list[Finding]:
    findings = []
    # cache a lowercase-insensitive source corpus once
    source_blob: list[tuple[str, str]] = []
    for p in repo.files():
        if p.suffix in {".py", ".sh", ".go", ".rs", ".js", ".ts", ".rb", ".mk",
                        ".cfg", ".ini", ".toml"} or p.name in {"Makefile", "Dockerfile"}:
            source_blob.append((repo.rel(p), repo.read(p)))

    for wf in repo.workflows():
        env_keys = set(re.findall(r"^\s*([A-Z][A-Z0-9_]{2,})\s*:", wf.text, re.M))
        env_keys = {
            k for k in env_keys
            if not any(k.startswith(pref) for pref in _CONSUMED_PREFIXES)
            and k not in {"TRUE", "FALSE"}
        }
        for var in sorted(env_keys):
            # read inside the same workflow's run text?
            runs = "\n".join(
                ln for ln in wf.text.splitlines() if not re.match(rf"^\s*{var}\s*:", ln)
            )
            if re.search(rf"\$(?:{var}\b|\{{{var}\}})|\benv\.{var}\b|\${{{{\s*env\.{var}", runs):
                continue
            # read anywhere in repo source?
            readers = [rel for rel, text in source_blob if var in text]
            if readers:
                continue
            findings.append(Finding(
                rule="R3b", vg_class=3, verdict=WARN,
                guard=f"{wf.rel}: env {var}",
                mechanism="workflow env var set and read nowhere",
                evidence=Evidence(
                    summary=f"{var} is set in {wf.rel}, is not referenced by any run "
                            f"step in that workflow, and appears in none of "
                            f"{len(source_blob)} source/config files searched",
                    searched=[wf.rel, f"{len(source_blob)} source files (name match)"],
                ),
                question="who reads this setting? — nothing in this repo does.",
                fix="delete the env line, or point it at whatever was meant to read it",
            ))
    return findings


# -- R3c: Dockerfile ARG after FROM ----------------------------------------------------------


def scan_dockerfile_args(repo: Repo) -> list[Finding]:
    findings = []
    for p in repo.glob("Dockerfile*", "**/Dockerfile*"):
        rel = repo.rel(p)
        global_args: set[str] = set()
        stage_args: set[str] = set()
        seen_from = False
        for i, raw in enumerate(repo.read(p).splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"(?i)^ARG\s+(\w+)", line)
            if m:
                (stage_args if seen_from else global_args).add(m.group(1))
                continue
            if re.match(r"(?i)^FROM\b", line):
                seen_from = True
                stage_args = set()
                continue  # FROM lines may legally use global ARGs
            if not seen_from:
                continue
            for used in re.findall(r"\$\{?(\w+)\}?", line):
                if used in global_args and used not in stage_args:
                    findings.append(Finding(
                        rule="R3c", vg_class=3, verdict=VOID,
                        guard=f"{rel}:{i}: ${used}",
                        mechanism="ARG declared before FROM, consumed after FROM "
                                  "without re-declaration",
                        evidence=Evidence(
                            summary=f"ARG {used} is declared before the first FROM and "
                                    f"used on line {i}; an ARG is out of scope after "
                                    f"FROM unless re-declared, so ${used} expands empty",
                            searched=[rel],
                            found=[f"line {i}: {line[:80]}"],
                        ),
                        question="does this ARG reach the stage that uses it? — an ARG "
                                 "is not visible after FROM unless re-declared.",
                        fix=f"add `ARG {used}` after the FROM of the stage that uses it",
                    ))
                    stage_args.add(used)  # one finding per (file, arg)
    return findings


def scan(repo: Repo) -> list[Finding]:
    out = []
    out.extend(scan_python_isolated(repo))
    out.extend(scan_env_unread(repo))
    out.extend(scan_dockerfile_args(repo))
    return out
