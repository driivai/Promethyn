"""Class 4 — CI conditions that cannot fire.

  R4a  `if:` requiring an event this workflow's triggers never deliver → VOID;
       `if:` comparing against secrets → UNKNOWN (existence is not static)
  R4b  scheduled workflow: static = UNKNOWN; API mode = WARN if never run
  R4d  golden/committed-file assertions whose path matches nothing → VOID
"""

from __future__ import annotations

import re

from .model import UNKNOWN, VOID, WARN, Evidence, Finding
from .repo import Repo

_GENERATED_PREFIXES = (
    "dist/", "build/", "out/", "tmp/", "artifacts/", "coverage", "report",
    "htmlcov/", "target/", "node_modules/", ".pytest_cache/", "site/",
)

_ASSERT_CMDS = re.compile(r"\b(?:diff|cmp|cat|test -f|\[ -f|open\(|read_text)\b")
_PATHLIKE = re.compile(
    r"(?<![\w$./-])((?:[\w.-]+/)+[\w.-]+\.(?:md|txt|json|golden|snap|ambr|yml|yaml|csv))\b"
)


def _triggers(data: dict) -> set[str]:
    on = data.get("on", data.get(True, {}))  # yaml may parse bare `on:` as True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    if isinstance(on, dict):
        return {str(k) for k in on}
    return set()


def _if_conditions(data: dict) -> list[tuple[str, str]]:
    """(location, condition) for every job- and step-level `if:`."""

    out = []
    for job_name, job in (data.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        if "if" in job:
            out.append((f"job {job_name}", str(job["if"])))
        for i, step in enumerate(job.get("steps") or []):
            if isinstance(step, dict) and "if" in step:
                label = step.get("name", f"step {i + 1}")
                out.append((f"job {job_name} / {label}", str(step["if"])))
    return out


def scan_conditions(repo: Repo) -> list[Finding]:
    findings = []
    for wf in repo.workflows():
        if wf.data is None:
            continue
        triggers = _triggers(wf.data)
        for loc, cond in _if_conditions(wf.data):
            for m in re.finditer(r"github\.event_name\s*==\s*['\"](\w+)['\"]", cond):
                event = m.group(1)
                if event not in triggers:
                    findings.append(Finding(
                        rule="R4a", vg_class=4, verdict=VOID,
                        guard=f"{wf.rel}: {loc}",
                        mechanism=f"if: requires event '{event}'; workflow triggers "
                                  f"are {sorted(triggers)}",
                        evidence=Evidence(
                            summary=f"the condition `{cond.strip()[:100]}` requires "
                                    f"github.event_name == '{event}', but this "
                                    f"workflow only triggers on {sorted(triggers)} — "
                                    "the condition can never be true here",
                            searched=[wf.rel],
                        ),
                        question="can this condition ever be true? — the event it "
                                 "requires is not in this workflow's triggers.",
                        fix=f"add '{event}' to the workflow's triggers, or delete the "
                            "guarded block",
                    ))
            if re.search(r"\bsecrets\.\w+", cond):
                findings.append(Finding(
                    rule="R4a", vg_class=4, verdict=UNKNOWN,
                    guard=f"{wf.rel}: {loc}",
                    mechanism="if: compares against a secret",
                    evidence=Evidence(
                        summary=f"the condition `{cond.strip()[:100]}` depends on a "
                                "secret's existence/value; secrets are not visible to "
                                "static analysis (and not readable via the API without "
                                "admin scope)",
                        searched=[wf.rel],
                    ),
                    question="could this condition ever fire? — depends on a secret "
                             "static analysis cannot see.",
                    fix="verify the secret exists in repo/org settings; consider vars.* "
                        "for non-sensitive gates so the gate is auditable",
                ))
    return findings


def scan_schedules(repo: Repo, schedule_probe=None) -> list[Finding]:
    """schedule_probe(workflow_basename) -> int|None runs on record (API mode)."""

    findings = []
    for wf in repo.workflows():
        if wf.data is None:
            continue
        on = wf.data.get("on", wf.data.get(True, {}))
        crons = []
        if isinstance(on, dict) and isinstance(on.get("schedule"), list):
            crons = [str(s.get("cron", "?")) for s in on["schedule"] if isinstance(s, dict)]
        if not crons:
            continue
        basename = wf.rel.rsplit("/", 1)[-1]
        n_runs = schedule_probe(basename) if schedule_probe else None
        if n_runs is None:
            findings.append(Finding(
                rule="R4b", vg_class=4, verdict=UNKNOWN,
                guard=f"{wf.rel} (cron {', '.join(crons)})",
                mechanism="scheduled workflow; run history not visible statically",
                evidence=Evidence(
                    summary="a schedule trigger is configured; whether it has ever "
                            "produced a run is not decidable without the API "
                            "(Action/API mode answers this)",
                    searched=[wf.rel],
                ),
                question="has this schedule ever produced a run? — configured; run "
                         "history not visible statically.",
                fix="run in API mode (GITHUB_TOKEN + --repo) or check the Actions tab: "
                    "a schedule with no runs on record is configured, not proven",
            ))
        elif n_runs == 0:
            findings.append(Finding(
                rule="R4b", vg_class=4, verdict=WARN,
                guard=f"{wf.rel} (cron {', '.join(crons)})",
                mechanism="scheduled workflow with zero scheduled runs on record",
                evidence=Evidence(
                    summary="the API reports 0 runs with event=schedule for this "
                            "workflow: configured, not yet on the record",
                    searched=[f"API: actions/workflows/{basename}/runs?event=schedule"],
                ),
                question="has this schedule ever produced a run? — configured, not "
                         "yet on the record.",
                fix="wait for the first scheduled run and confirm it is green; until "
                    "then the nightly is a plan, not a guard",
            ))
        # n_runs > 0: the schedule is on the record; nothing to report
    return findings


def scan_golden_paths(repo: Repo) -> list[Finding]:
    findings = []
    seen: set[tuple[str, str]] = set()
    for wf in repo.workflows():
        for line in wf.text.splitlines():
            s = line.strip()
            if s.startswith("#") or not _ASSERT_CMDS.search(s):
                continue
            for m in _PATHLIKE.finditer(s):
                path = m.group(1)
                if path.startswith(_GENERATED_PREFIXES):
                    continue
                if "$" in path or "{" in path:
                    continue
                key = (wf.rel, path)
                if key in seen or repo.exists(path):
                    continue
                seen.add(key)
                findings.append(Finding(
                    rule="R4d", vg_class=4, verdict=VOID,
                    guard=f"{wf.rel}: `{s[:90]}`",
                    mechanism=f"assertion reads committed path {path!r} which does "
                              "not exist",
                    evidence=Evidence(
                        summary=f"the step reads {path!r}; no such file exists in the "
                                "repo tree (generated-output directories excluded from "
                                "this rule)",
                        searched=[wf.rel, "repo tree"],
                    ),
                    question="what does this assertion compare against? — the asserted "
                             "path matches nothing in the repo.",
                    fix="fix the path (file moved or typo); an assertion against a "
                        "missing golden either always fails or, worse, is skipped",
                ))
    return findings


def scan(repo: Repo, schedule_probe=None) -> list[Finding]:
    out = []
    out.extend(scan_conditions(repo))
    out.extend(scan_schedules(repo, schedule_probe))
    out.extend(scan_golden_paths(repo))
    return out
