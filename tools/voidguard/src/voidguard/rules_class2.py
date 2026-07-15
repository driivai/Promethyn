"""Class 2 — type gates that check nothing.

Only configs that some CI workflow actually invokes are assessed: a lax config
nothing runs is not a *gate* (it guards nothing, so there is nothing to void).
"""

from __future__ import annotations

import re

from .model import UNKNOWN, VOID, WARN, Evidence, Finding
from .repo import Repo

_TRUE = {"true", "1", "yes", "on"}

_VALUE_FLAGS = {
    "--config-file", "--python-version", "--cache-dir", "--python-executable",
    "-p", "--package", "-m", "--module", "--exclude", "--follow-imports",
    "--shadow-file", "--junit-xml", "--any-exprs-report", "--platform",
}


def _typecheck_lines(repo: Repo) -> list[tuple[str, str, str]]:
    """(workflow_rel, tool, line) for mypy/pyright invocations in CI."""

    out = []
    for wf in repo.workflows():
        for line in wf.text.splitlines():
            s = line.strip()
            if s.startswith("#"):
                continue
            if re.search(r"\bmypy\b", s):
                out.append((wf.rel, "mypy", s))
            elif re.search(r"\bpyright\b", s):
                out.append((wf.rel, "pyright", s))
    return out


# -- R2a: the vacuous-resolution trap (the EX-1 shape, byte for byte) -----------------


def scan_vacuous_mypy(repo: Repo) -> list[Finding]:
    cfg = repo.mypy_config()
    if cfg is None:
        return []
    invocations = [x for x in _typecheck_lines(repo) if x[1] == "mypy"]
    if not invocations:
        return []  # config exists but no CI gate runs it: nothing to void
    cfg_path, glob, per = cfg

    ignore_missing = glob.get("ignore_missing_imports", "").lower() in _TRUE
    mypy_path = glob.get("mypy_path", "")
    explicit_bases = glob.get("explicit_package_bases", "").lower() in _TRUE

    pkgs = repo.first_party_packages()
    src_pkgs = [name for name, layout in pkgs.items() if layout == "src"]
    flat_pkgs = [name for name, layout in pkgs.items() if layout == "flat"]

    searched = [
        cfg_path,
        f"first-party packages: src-layout={src_pkgs or 'none'}, flat={flat_pkgs or 'none'}",
        f"CI invocations: {[f'{w}: {ln[:80]}' for w, ln, in [(w, l) for w, _, l in invocations]]}",
    ]

    findings: list[Finding] = []
    if ignore_missing and src_pkgs and not mypy_path and not explicit_bases:
        # src-layout package not importable from the repo root, no resolution
        # config: first-party imports are "missing" and silenced to Any.
        unresolvable = [p for p in src_pkgs if not repo.exists(f"{p}/__init__.py")]
        if unresolvable:
            typed = [p for p in unresolvable if repo.exists(f"src/{p}/py.typed")]
            verdict = UNKNOWN if typed else VOID
            summary = (
                f"{cfg_path}: ignore_missing_imports=true; mypy_path unset; "
                f"explicit_package_bases unset; src-layout package(s) "
                f"{unresolvable} not importable from the repo root — first-party "
                "imports resolve as missing and are silenced to Any"
            )
            if typed:
                summary += (
                    f"; {typed} ship py.typed, so resolution via an installed copy "
                    "is environment-dependent — not statically decidable"
                )
            findings.append(Finding(
                rule="R2a", vg_class=2, verdict=verdict,
                guard=f"CI type gate running mypy ({invocations[0][0]})",
                mechanism=f"{cfg_path}: ignore_missing_imports without first-party resolution",
                evidence=Evidence(summary=summary, searched=searched),
                question="does this type gate see the code it claims to check? — "
                         "first-party imports degrade to Any, so a type error in the "
                         "package cannot be caught.",
                fix="set mypy_path (e.g. mypy_path = src) and explicit_package_bases = "
                    "true so first-party types resolve; then prove the gate with a "
                    "deliberate type error it must catch",
            ))

    # -- R2b: scope silencers -----------------------------------------------------
    if glob.get("follow_imports", "") == "skip":
        findings.append(Finding(
            rule="R2b", vg_class=2, verdict=VOID,
            guard=f"CI type gate running mypy ({invocations[0][0]})",
            mechanism=f"{cfg_path}: follow_imports = skip (global)",
            evidence=Evidence(
                summary=f"{cfg_path} sets follow_imports=skip globally: every import "
                        "is treated as Any, first-party included",
                searched=[cfg_path],
            ),
            question="does this gate check anything across module boundaries? — "
                     "no import is ever followed.",
            fix="remove follow_imports=skip, or scope it to named third-party modules",
        ))
    first_party = set(pkgs)
    for module, body in per.items():
        base = module.split(".")[0].rstrip("*").rstrip(".")
        if base in first_party and body.get("ignore_errors", "").lower() in _TRUE:
            findings.append(Finding(
                rule="R2b", vg_class=2, verdict=VOID,
                guard=f"mypy scope [{module}]",
                mechanism=f"{cfg_path}: per-module ignore_errors=true over first-party code",
                evidence=Evidence(
                    summary=f"[mypy-{module}] ignore_errors=true silences every "
                            f"finding in first-party package '{base}'",
                    searched=[cfg_path],
                ),
                question="what does the gate check in this scope? — every error in "
                         "it is discarded.",
                fix="delete the ignore_errors override, or shrink it to the specific "
                    "legacy modules with a burn-down note",
            ))
    exclude = glob.get("exclude", "")
    for pkg, layout in pkgs.items():
        pkg_dir = f"src/{pkg}/" if layout == "src" else f"{pkg}/"
        if exclude and re.search(exclude, pkg_dir):
            findings.append(Finding(
                rule="R2b", vg_class=2, verdict=VOID,
                guard=f"mypy exclude vs first-party package '{pkg}'",
                mechanism=f"{cfg_path}: exclude regex swallows {pkg_dir}",
                evidence=Evidence(
                    summary=f"exclude = {exclude!r} matches {pkg_dir!r}: the package "
                            "is never checked",
                    searched=[cfg_path],
                ),
                question="is the package inside the gate? — the exclude removes it.",
                fix="narrow the exclude regex so first-party code stays checked",
            ))

    # -- files= entries that match nothing ------------------------------------------
    files_val = glob.get("files", "")
    if files_val:
        missing = [
            f.strip() for f in files_val.split(",")
            if f.strip() and not repo.exists(f.strip())
        ]
        if missing:
            findings.append(Finding(
                rule="R2c", vg_class=2, verdict=VOID,
                guard=f"mypy files= entries in {cfg_path}",
                mechanism="configured check target matches no files",
                evidence=Evidence(
                    summary=f"{len(missing)} files= entr{'y' if len(missing)==1 else 'ies'} "
                            f"do not exist: {missing}",
                    searched=[cfg_path, "repo tree"],
                ),
                question="what does this type-check step check? — its target path "
                         "matches no files.",
                fix="fix the path (file moved or typo), and add a gate that fails on "
                    "an empty target",
            ))
    return findings


# -- R2c: CI type-check step whose target path matches nothing -------------------------


def scan_dead_target(repo: Repo) -> list[Finding]:
    findings = []
    for wf_rel, tool, line in _typecheck_lines(repo):
        tokens = line.split()
        try:
            start = max(i for i, t in enumerate(tokens) if t.endswith(tool))
        except ValueError:
            continue
        paths = []
        skip_next = False
        for t in tokens[start + 1:]:
            if skip_next:
                skip_next = False
                continue
            if t in _VALUE_FLAGS:
                skip_next = True
                continue
            if t.startswith("-") or t in {"||", "&&", "|", ";"}:
                continue
            if "$" in t or "{" in t or "*" in t:
                continue
            paths.append(t)
        if paths and not any(repo.exists(p) for p in paths):
            findings.append(Finding(
                rule="R2c", vg_class=2, verdict=VOID,
                guard=f"{wf_rel}: `{line[:100]}`",
                mechanism=f"{tool} target path matches no files",
                evidence=Evidence(
                    summary=f"none of the target path(s) {paths} exist in the repo tree",
                    searched=[wf_rel, "repo tree"],
                ),
                question="what does this type-check step check? — its target path "
                         "matches no files.",
                fix="fix the path (package moved or typo); a type gate over nothing "
                    "is always green",
            ))
    return findings


# -- R2d: advertised typecheck over non-strict tsconfig ---------------------------------


_TS_STRICT_FLAGS = (
    "noImplicitAny", "strictNullChecks", "strictFunctionTypes",
    "strictBindCallApply", "strictPropertyInitialization", "noImplicitThis",
    "alwaysStrict", "useUnknownInCatchVariables",
)


def scan_tsconfig(repo: Repo) -> list[Finding]:
    ts = repo.tsconfig()
    if ts is None:
        return []
    wf_text = "\n".join(w.text for w in repo.workflows())
    advertises = re.search(r"\btsc\b|type-?check", wf_text, re.I)
    if not advertises:
        return []
    opts = ts.get("compilerOptions", {}) or {}
    strict = opts.get("strict", False)
    individually = any(opts.get(f) for f in _TS_STRICT_FLAGS)
    if strict or individually:
        return []
    return [Finding(
        rule="R2d", vg_class=2, verdict=WARN,
        guard="CI step advertising a typecheck (tsc)",
        mechanism='tsconfig.json: "strict": false and no individual strict flags',
        evidence=Evidence(
            summary="tsconfig has strict=false (or unset) and none of "
                    f"{list(_TS_STRICT_FLAGS[:3])}...; the advertised typecheck is "
                    "weak, not void — implicit any passes silently",
            searched=["tsconfig.json", ".github/workflows/*"],
        ),
        question="how much does this gate actually reject? — implicit any and "
                 "nullability errors pass it.",
        fix='set "strict": true (or adopt individual strict flags with a burn-down)',
    )]


def scan(repo: Repo) -> list[Finding]:
    out = []
    out.extend(scan_vacuous_mypy(repo))
    out.extend(scan_dead_target(repo))
    out.extend(scan_tsconfig(repo))
    return out
