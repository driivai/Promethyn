"""The matrix-agreement guard refuses a suite that differs by interpreter.

WHAT IS PROVED HERE, and what is not. ``scripts/check_matrix_agreement.py``
compares the three matrix versions' JUnit reports as SETS of test ids. These
tests drive that comparison on reports written here — a positive control that
three faithful reports agree, and one refusal per way they can disagree — and
pin the workflow shape that delivers real reports to it. What only CI proves is
the plumbing: that each matrix job's ``full-suite.xml`` is uploaded, downloaded
and handed to the script. The workflow-shape test below keeps that plumbing
present; the matrix run is what keeps it working.

Every negative here names the id and the version, because a refusal that says
"3.10 differs" is a number and a refusal that says which test is absent from
3.10 is a finding.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

from check_matrix_agreement import (  # noqa: E402
    ARTIFACT_PREFIX,
    REPORT_NAME,
    Outcome,
    main,
    matrix_versions,
    outcome_of,
    problems,
    render,
)

VERSIONS = matrix_versions()
BASE = ("tests.synthetic.test_a::test_one", "tests.synthetic.test_a::test_two", "tests.synthetic.test_b::test_three")


def _report(path: Path, ids: tuple[str, ...], *, skipped: tuple[str, ...] = (), failed: tuple[str, ...] = (),
            errored: tuple[str, ...] = ()) -> Path:
    """A JUnit report holding exactly these ids, in pytest's own element shape."""

    suite = ET.Element("testsuite", name="pytest", tests=str(len(ids)))
    for ident in ids:
        classname, _, name = ident.rpartition("::")
        case = ET.SubElement(suite, "testcase", classname=classname, name=name)
        if ident in skipped:
            ET.SubElement(case, "skipped", message="sanctioned")
        if ident in failed:
            ET.SubElement(case, "failure", message="boom")
        if ident in errored:
            ET.SubElement(case, "error", message="setup")
    path.write_text(ET.tostring(suite, encoding="unicode"), encoding="utf-8")
    return path


def _outcomes(tmp_path: Path, per_version: dict[str, dict]) -> dict[str, Outcome]:
    return {
        version: outcome_of(_report(tmp_path / f"{version}.xml", **spec))
        for version, spec in per_version.items()
    }


def _identical(tmp_path: Path, **overrides) -> dict[str, Outcome]:
    spec = {"ids": BASE, "skipped": (BASE[2],)}
    return _outcomes(tmp_path, {v: dict(spec, **overrides.get(v, {})) for v in VERSIONS})


# ---------------------------------------------------------------- positive control

def test_the_matrix_is_read_from_the_workflow_and_is_exactly_three_versions():
    """The population of versions is the workflow's, not a list typed here."""

    document = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    assert VERSIONS == tuple(str(v) for v in document["jobs"]["build"]["strategy"]["matrix"]["python-version"])
    assert VERSIONS == ("3.10", "3.11", "3.12")


def test_three_faithful_reports_agree_and_the_table_carries_each_count(tmp_path):
    """Positive control: identical suites on every version are accepted, and the
    counts in the table are the counts in the reports — collected, passed and
    skipped read off the artifact, not off a filtered line of a log."""

    outcomes = _identical(tmp_path)
    assert problems(outcomes, VERSIONS) == []
    table = render(outcomes, VERSIONS)
    for version in VERSIONS:
        assert f"| {version} | 3 | 2 | 1 | 0 | 0 |" in table, table


# ---------------------------------------------------------------- refusals, one per disagreement

def test_a_test_collected_on_one_version_only_is_refused_naming_the_test_and_the_versions_that_lack_it(tmp_path):
    """The gap this guard exists for: three green jobs, one of them running a
    test the others never collected."""

    extra = "tests.synthetic.test_c::test_only_on_the_newest"
    outcomes = _identical(tmp_path, **{"3.12": {"ids": BASE + (extra,)}})
    found = problems(outcomes, VERSIONS)
    assert found, "a version-specific test was accepted"
    lacking = [line for line in found if line.startswith("collected:")]
    assert sorted(line.split()[1] for line in lacking) == ["3.10", "3.11"], found
    assert all(extra in line for line in lacking), found


def test_a_report_from_a_version_the_matrix_does_not_run_is_refused_even_when_the_count_of_versions_matches(tmp_path):
    """G25 again, over the versions themselves: three reports for {3.10, 3.11,
    3.13} is the right NUMBER of versions and the wrong set. Refused, naming
    the stranger."""

    outcomes = _identical(tmp_path)
    wrong_set = {"3.10": outcomes["3.10"], "3.11": outcomes["3.11"], "3.13": outcomes["3.12"]}
    found = problems(wrong_set, VERSIONS)
    assert len(found) == 1 and found[0].startswith("versions:") and "3.13" in found[0], found


def test_the_version_list_is_derived_from_the_workflow_it_is_given(tmp_path):
    """Not a list typed into the script: hand ``matrix_versions`` a workflow
    with a different matrix and it returns that matrix."""

    workflow = tmp_path / "ci.yml"
    workflow.write_text(
        "jobs:\n  build:\n    strategy:\n      matrix:\n        python-version: ['3.11', '3.13']\n",
        encoding="utf-8",
    )
    assert matrix_versions(workflow) == ("3.11", "3.13")


def test_the_same_count_with_different_membership_is_refused(tmp_path):
    """G25: a count is not a composition. One version swaps a test for another
    of the same name in a different module; every count matches; the sets do
    not, and the refusal names both ids."""

    swapped = ("tests.synthetic.test_a::test_one", "tests.synthetic.test_a::test_two",
               "tests.synthetic.test_z::test_three")
    outcomes = _identical(tmp_path, **{"3.11": {"ids": swapped, "skipped": (swapped[2],)}})
    assert {len(o.collected) for o in outcomes.values()} == {3}, "the counts must agree for this to be a test of composition"
    found = problems(outcomes, VERSIONS)
    assert any(line.startswith("collected: 3.11") and "tests.synthetic.test_b::test_three" in line for line in found), found
    assert any(line.startswith("collected: 3.10") and "tests.synthetic.test_z::test_three" in line for line in found), found


def test_the_same_collected_set_with_a_different_skip_set_is_refused(tmp_path):
    """Skips are pinned per version by the manifest; across versions they are
    pinned here. One version skipping a test the others ran is a divergence."""

    outcomes = _identical(tmp_path, **{"3.10": {"skipped": (BASE[1],)}})
    found = problems(outcomes, VERSIONS)
    assert not any(line.startswith("collected:") for line in found), found
    skipped_lines = [line for line in found if line.startswith("skipped:")]
    assert skipped_lines, found
    assert any(line.startswith("skipped: 3.10") and BASE[2] in line for line in skipped_lines), found
    assert all(BASE[1] in line for line in skipped_lines if not line.startswith("skipped: 3.10")), found


def test_a_failure_or_an_error_on_any_version_is_refused(tmp_path):
    for field in ("failed", "errored"):
        outcomes = _identical(tmp_path, **{"3.12": {field: (BASE[0],)}})
        found = problems(outcomes, VERSIONS)
        assert any(line.startswith(f"{field}: 3.12") and BASE[0] in line for line in found), (field, found)


def test_an_empty_report_is_refused_before_anything_is_compared(tmp_path):
    """Doctrine #8: an empty instrument reads downstream as a pass. Here it is
    the FIRST refusal, and it stops the comparison — an empty set is a subset of
    everything and would otherwise read as 'lacks every id', which is true and
    is not the finding."""

    outcomes = _identical(tmp_path, **{"3.10": {"ids": (), "skipped": ()}})
    found = problems(outcomes, VERSIONS)
    assert found == ["empty: 3.10 reported no testcases at all"], found


def test_a_missing_version_and_an_extra_version_are_both_refused(tmp_path):
    """Shortfall and excess. A report that never arrived is a job whose suite
    nobody compared; a report from a version the matrix does not run is a
    comparison against nothing the workflow promised."""

    outcomes = _identical(tmp_path)
    short = {v: o for v, o in outcomes.items() if v != VERSIONS[0]}
    found = problems(short, VERSIONS)
    assert len(found) == 1 and found[0].startswith("versions:") and VERSIONS[0] in found[0], found

    excess = dict(outcomes)
    excess["3.13"] = outcomes[VERSIONS[0]]
    found = problems(excess, VERSIONS)
    assert len(found) == 1 and found[0].startswith("versions:") and "3.13" in found[0], found


def test_main_refuses_with_exit_1_and_passes_with_exit_0_on_real_files(tmp_path, capsys):
    """The command line, end to end, in both directions on the layout the
    workflow's download step produces."""

    reports_dir = tmp_path / "matrix-reports"
    for version in VERSIONS:
        folder = reports_dir / f"{ARTIFACT_PREFIX}{version}"
        folder.mkdir(parents=True)
        _report(folder / REPORT_NAME, BASE, skipped=(BASE[2],))
    assert main(["--reports-dir", str(reports_dir)]) == 0
    out = capsys.readouterr().out
    assert "matrix agreement passed: 3 versions (3.10, 3.11, 3.12); 3 collected, 1 skipped" in out

    _report(reports_dir / f"{ARTIFACT_PREFIX}3.12" / REPORT_NAME, BASE + ("tests.synthetic.test_c::test_new",), skipped=(BASE[2],))
    assert main(["--reports-dir", str(reports_dir)]) == 1
    out = capsys.readouterr().out
    assert "matrix agreement FAILED" in out and "tests.synthetic.test_c::test_new" in out


# ---------------------------------------------------------------- the plumbing is present

def test_the_workflow_uploads_every_matrix_report_and_a_job_downloads_them_all_for_this_guard():
    """The comparison is only as real as the reports that reach it. Pinned: the
    build job uploads ``full-suite.xml`` under the name the script reads back,
    with no-files-found refusing; a separate job depends on the whole matrix,
    downloads every artifact by that prefix, and runs the script on them."""

    document = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    build = document["jobs"]["build"]
    uploads = [s for s in build["steps"] if str(s.get("uses", "")).startswith("actions/upload-artifact@")]
    assert len(uploads) == 1, "exactly one upload of the full-suite report per matrix job"
    with_ = uploads[0]["with"]
    assert with_["name"] == ARTIFACT_PREFIX + "${{ matrix.python-version }}", with_
    assert with_["path"] == REPORT_NAME, with_
    assert with_.get("if-no-files-found") == "error", "a missing report must refuse the upload, not skip it"
    step_names = [s.get("name") for s in build["steps"]]
    assert step_names.index(uploads[0]["name"]) > step_names.index("Test"), "the upload must follow the full-suite run"

    agreement = document["jobs"]["matrix-agreement"]
    assert agreement["needs"] == "build"
    downloads = [s for s in agreement["steps"] if str(s.get("uses", "")).startswith("actions/download-artifact@")]
    assert len(downloads) == 1
    assert downloads[0]["with"]["pattern"] == ARTIFACT_PREFIX + "*"
    assert downloads[0]["with"]["path"] == "matrix-reports"
    runs = [s.get("run", "") for s in agreement["steps"]]
    assert any("python scripts/check_matrix_agreement.py --reports-dir matrix-reports" in r for r in runs), runs


def test_the_named_limit_the_upload_and_download_are_proved_only_by_the_matrix_run():
    """Doctrine #5: the limit as a passing test. Nothing in this module moves
    a file through the artifact store; the shape test above pins that the steps
    exist, and only a matrix run shows they carry the report. A run whose
    ``matrix-agreement`` job is skipped or missing has not exercised this guard."""

    assert True
