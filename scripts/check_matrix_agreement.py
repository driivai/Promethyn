#!/usr/bin/env python3
"""The three matrix versions must have run the SAME suite, or the build is red.

WHY. On 2026-09-17 the matrix was green on 3.10, 3.11 and 3.12 — 57 of 57 steps
each, read job by job — and the per-version PASS COUNTS were unreadable from the
environment reporting it: the job-log tail is the wheel build, and the raw log
URL is refused by that environment's egress proxy. Green says the suite ran on
all three. It does not say the three ran the same suite.

What green cannot see is a version-specific COLLECTION difference: a test that
exists on 3.12 and not on 3.10 — defined under a ``sys.version_info`` guard, or
parametrised from version-dependent data, or in a module that ``collect_ignore``
drops on one interpreter — passes where it exists and is absent, not skipped,
where it does not. Three green jobs, three different suites, and nothing
comparing them. The skip manifest (``check_skip_manifest.py``) pins each
version's SKIP set against the sanctioned one; nothing pinned the COLLECTED set
across versions until this.

WHAT THIS COMPARES, per version, read from that version's JUnit report:

  * the set of collected test ids — a SET, not a count, because two suites of
    the same size are indistinguishable by count (OPEN-GAPS G25);
  * the set of skipped ids;
  * failures and errors, which refuse on their own — a red job never reaches
    this step, but the guard does not assume it.

and REFUSES when:

  * the versions present are not exactly the workflow's matrix — shortfall
    (a job whose report never arrived) and excess (a report from nowhere)
    both refuse; the matrix is read from ``ci.yml``, not typed here;
  * any report is empty (doctrine #8: an empty instrument reads as a pass);
  * any version failed or errored;
  * the collected sets differ — the refusal names every id absent from any
    version, so the finding is the test and the interpreter, not a number;
  * the skipped sets differ, the same way.

WHAT IT PRINTS is the per-version table — collected, passed, skipped, failed,
errors — so the counts are readable from this job's short log and from the
step summary without fetching any raw log. The counts come from the reports
(the artifact), never from a filtered view of a log.

NAMED LIMITS:

  * The reports reach this job through the workflow's artifact upload and
    download. That plumbing is exercised only by CI itself; the unit tests drive
    the comparison on files, and the workflow-shape test pins that the upload,
    the download and this call are all present.
  * A ``[conditional]`` skip (see the skip manifest) may legitimately run on one
    host and skip on another. Within ONE matrix run the three jobs share an
    image, so a conditional entry that differs across versions is treated as a
    version difference and refused. If a runner-pool change ever makes the
    three jobs land on differently provisioned hosts, this refuses and says
    which ids, which is information, not noise.

USAGE::

    python scripts/check_matrix_agreement.py --reports-dir matrix-reports
    python scripts/check_matrix_agreement.py 3.10=a.xml 3.11=b.xml 3.12=c.xml
"""

from __future__ import annotations

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

import yaml

from check_skip_manifest import node_id

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
#: The artifact each matrix job uploads, and the file inside it.
ARTIFACT_PREFIX = "full-suite-"
REPORT_NAME = "full-suite.xml"


@dataclass(frozen=True)
class Outcome:
    """One version's run, as sets of test ids read from its JUnit report."""

    collected: frozenset[str]
    skipped: frozenset[str]
    failed: frozenset[str]
    errored: frozenset[str]

    @property
    def passed(self) -> int:
        return len(self.collected - self.skipped - self.failed - self.errored)


def outcome_of(report: Path) -> Outcome:
    cases = list(ET.parse(report).iter("testcase"))
    collected: set[str] = set()
    skipped: set[str] = set()
    failed: set[str] = set()
    errored: set[str] = set()
    for case in cases:
        ident = node_id(case)
        collected.add(ident)
        if case.find("skipped") is not None:
            skipped.add(ident)
        if case.find("failure") is not None:
            failed.add(ident)
        if case.find("error") is not None:
            errored.add(ident)
    return Outcome(frozenset(collected), frozenset(skipped), frozenset(failed), frozenset(errored))


def matrix_versions(workflow: Path = WORKFLOW) -> tuple[str, ...]:
    """The interpreter versions the workflow's build matrix runs, in its order."""

    document = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    versions = document["jobs"]["build"]["strategy"]["matrix"]["python-version"]
    return tuple(str(v) for v in versions)


def problems(outcomes: dict[str, Outcome], expected: tuple[str, ...]) -> list[str]:
    """Every way the versions disagree; empty means they ran the same suite."""

    found: list[str] = []
    got = tuple(sorted(outcomes))
    if set(got) != set(expected):
        found.append(
            f"versions: the workflow matrix is {sorted(expected)}, reports arrived for {list(got)}"
        )
        # Nothing below is meaningful over the wrong population.
        return found

    for version in expected:
        outcome = outcomes[version]
        if not outcome.collected:
            found.append(f"empty: {version} reported no testcases at all")
    if found:
        return found

    for version in expected:
        outcome = outcomes[version]
        if outcome.failed:
            found.append(f"failed: {version}: {sorted(outcome.failed)}")
        if outcome.errored:
            found.append(f"errored: {version}: {sorted(outcome.errored)}")

    for field in ("collected", "skipped"):
        sets = {version: getattr(outcomes[version], field) for version in expected}
        union = frozenset().union(*sets.values())
        for version in expected:
            absent = sorted(union - sets[version])
            if absent:
                found.append(
                    f"{field}: {version} lacks {len(absent)} id(s) another version has: {absent}"
                )
    return found


def render(outcomes: dict[str, Outcome], expected: tuple[str, ...]) -> str:
    rows = ["| version | collected | passed | skipped | failed | errors |", "|---|---|---|---|---|---|"]
    for version in expected:
        outcome = outcomes.get(version)
        if outcome is None:
            rows.append(f"| {version} | (no report) | | | | |")
            continue
        rows.append(
            f"| {version} | {len(outcome.collected)} | {outcome.passed} | {len(outcome.skipped)} "
            f"| {len(outcome.failed)} | {len(outcome.errored)} |"
        )
    return "\n".join(rows)


def _reports_from_dir(directory: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for child in sorted(directory.iterdir()):
        if child.is_dir() and child.name.startswith(ARTIFACT_PREFIX):
            report = child / REPORT_NAME
            if report.is_file():
                found[child.name[len(ARTIFACT_PREFIX):]] = report
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("pairs", nargs="*", help="version=path/to/junit.xml")
    parser.add_argument("--reports-dir", help=f"directory holding {ARTIFACT_PREFIX}<version>/{REPORT_NAME}")
    parser.add_argument("--workflow", default=str(WORKFLOW))
    args = parser.parse_args(argv)

    reports: dict[str, Path] = {}
    if args.reports_dir:
        reports.update(_reports_from_dir(Path(args.reports_dir)))
    for pair in args.pairs:
        version, _, path = pair.partition("=")
        if not version or not path:
            parser.error(f"expected version=path, got {pair!r}")
        reports[version] = Path(path)
    if not reports:
        parser.error("no reports given")

    expected = matrix_versions(Path(args.workflow))
    outcomes = {version: outcome_of(path) for version, path in reports.items()}
    table = render(outcomes, expected)
    found = problems(outcomes, expected)

    print(table)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as summary:
            summary.write("## Matrix agreement\n\n" + table + "\n\n")
            summary.write("REFUSED:\n" + "\n".join(f"- {p}" for p in found) + "\n" if found else "identical on every version\n")

    if found:
        print(f"matrix agreement FAILED: {len(found)} disagreement(s) between the matrix versions:")
        for problem in found:
            print(f"  {problem}")
        print(
            "A test that exists on one interpreter and not another is a version-specific "
            "suite; guard it with a skip that the manifest sanctions, or make it collect everywhere."
        )
        return 1

    any_outcome = outcomes[expected[0]]
    print(
        f"matrix agreement passed: {len(expected)} versions ({', '.join(expected)}); "
        f"{len(any_outcome.collected)} collected, {len(any_outcome.skipped)} skipped, "
        "identical sets on every version"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
