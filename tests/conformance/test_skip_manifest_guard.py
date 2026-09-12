"""The skip manifest is checked against BOTH hosts this repository runs on.

The manifest (`tests/conformance/skip_manifest.txt`) was pinned from a local
run and the first CI run of it refused. The refusal was right and the manifest
was wrong in an instructive way: the skip set is not a property of the tree, it
is a property of the tree ON A HOST, and the two hosts here disagree about
exactly two tests.

Observed, run `34707644343`, `build (3.11)`, the full-suite step:

```
SKIPPED [1] tests/conformance/test_sandbox_privilege.py:194: dropping to another uid requires privilege
2424 passed, 23 skipped in 191.19s
skip manifest FAILED: 1 skip(s) not sanctioned:
  ...::test_another_local_user_cannot_read_or_write_the_workspace  (dropping to another uid requires privilege)
skip manifest FAILED: 1 sanctioned entry did not skip (ran, or no longer exists):
  ...::test_real_container_workspace_stays_owner_only_and_still_works
```

Locally, same commit, `2424 passed, 23 skipped` with those two exchanged: this
host runs as root (so the cross-user test RUNS) and has no container daemon (so
the container test SKIPS); `ubuntu-latest` is unprivileged and ships docker, so
it is the other way round. Both report 23 — which is the whole reason a count
was never enough.

The manifest now has a `[conditional]` section for exactly that, and this
module is what keeps it honest: the checker is driven over both recorded
compositions, over three mutations of them that must be refused, and over the
real manifest's proof references. A guard that has only ever been run on the
host that wrote its manifest has not been tested.
"""

from __future__ import annotations

import importlib.util
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "check_skip_manifest.py"
MANIFEST = REPO / "tests" / "conformance" / "skip_manifest.txt"

#: The two tests that swap places between the hosts, by id.
CONTAINER_TEST = (
    "tests/conformance/test_sandbox_privilege.py"
    "::test_real_container_workspace_stays_owner_only_and_still_works"
)
CROSS_USER_TEST = (
    "tests/conformance/test_sandbox_privilege.py"
    "::test_another_local_user_cannot_read_or_write_the_workspace"
)


@pytest.fixture(scope="module")
def checker():
    spec = importlib.util.spec_from_file_location("check_skip_manifest_under_test", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _report(path: Path, skipped: set[str]) -> Path:
    """A JUnit report in which exactly ``skipped`` skipped, and one test passed.

    The passing case matters: the checker refuses an empty report outright, and
    a mutation that emptied the run must not look like a clean skip set.
    """

    suite = ET.Element("testsuite", name="pytest", tests=str(len(skipped) + 1))
    for node in sorted(skipped):
        file_part, _, name = node.partition("::")
        classname = file_part[: -len(".py")].replace("/", ".")
        case = ET.SubElement(suite, "testcase", classname=classname, name=name)
        ET.SubElement(case, "skipped", message="recorded by tests/conformance/test_skip_manifest_guard.py")
    ET.SubElement(suite, "testcase", classname="tests.conformance.test_sanity", name="test_it_ran")
    root = ET.Element("testsuites")
    root.append(suite)
    ET.ElementTree(root).write(path, encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def sections(checker) -> tuple[set[str], set[str]]:
    entries = checker.manifest_entries(MANIFEST)
    required = {i for i, (section, _) in entries.items() if section == checker.REQUIRED}
    conditional = {i for i, (section, _) in entries.items() if section == checker.CONDITIONAL}
    return required, conditional


def _run(checker, tmp_path: Path, skipped: set[str], manifest: Path = MANIFEST) -> int:
    report = _report(tmp_path / f"report-{abs(hash(frozenset(skipped)))}.xml", skipped)
    return checker.main([str(report), "--manifest", str(manifest)])


def test_the_manifest_has_both_sections_and_the_two_hosts_disagree_about_exactly_two_tests(sections):
    required, conditional = sections
    assert required, "the [required] section is empty; every skip would be excusable"
    assert conditional == {CONTAINER_TEST, CROSS_USER_TEST}, (
        "the conditional set moved. It is the measured disagreement between the two "
        f"hosts, not a convenience list: {sorted(conditional)}"
    )


def test_both_recorded_host_compositions_are_accepted(checker, sections, tmp_path):
    """The load-bearing check, in both directions.

    LOCAL: root, no container daemon — the container test skips, the cross-user
    test runs. CI (`ubuntu-latest`): unprivileged, docker present — the reverse.
    """

    required, _ = sections
    local = required | {CONTAINER_TEST}
    ci = required | {CROSS_USER_TEST}
    assert _run(checker, tmp_path, local) == 0, "the composition observed on this host was refused"
    assert _run(checker, tmp_path, ci) == 0, "the composition observed on ubuntu-latest was refused"
    assert local != ci and len(local) == len(ci), "the two hosts differ by a swap, not a count"


def test_an_unsanctioned_skip_is_still_refused(checker, sections, tmp_path):
    """The property the manifest exists for, unchanged by the new section."""

    required, _ = sections
    intruder = "tests/conformance/test_composition.py::test_sanctioned_content_digests_match"
    assert intruder not in required
    assert _run(checker, tmp_path, required | {CONTAINER_TEST, intruder}) == 1


def test_a_REQUIRED_entry_that_ran_is_still_refused(checker, sections, tmp_path):
    """[conditional] excuses a host-dependent skip; it does not excuse a stale
    sanction. A required entry that stops skipping still fails."""

    required, _ = sections
    dropped = sorted(required)[0]
    assert _run(checker, tmp_path, (required - {dropped}) | {CONTAINER_TEST}) == 1


def test_a_conditional_entry_whose_proof_does_not_resolve_is_refused(checker, sections, tmp_path):
    """Three ways a proof can fail to hold, each refused.

    A conditional sanction is a claim that the test is proven elsewhere. The
    claim is checked: the workflow must exist, the step must exist in it, and
    the step must set a PROM_REQUIRE_* flag — without which the proof step
    would skip exactly as quietly as the run being excused.
    """

    required, _ = sections
    body = "\n".join(sorted(required)) + "\n[conditional]\n"
    cases = {
        "no proof at all": f"{CONTAINER_TEST}  # no container runtime available\n",
        "a workflow that does not exist": f"{CONTAINER_TEST}  # proof: no-such-workflow.yml :: Real-container isolation (fail, do not skip)\n",
        "a step that does not exist": f"{CONTAINER_TEST}  # proof: ci.yml :: A step nobody wrote\n",
        "a real step with no PROM_REQUIRE flag": f"{CONTAINER_TEST}  # proof: ci.yml :: Compile\n",
    }
    for label, tail in cases.items():
        manifest = tmp_path / f"manifest-{abs(hash(label))}.txt"
        manifest.write_text(body + tail, encoding="utf-8")
        assert _run(checker, tmp_path, required | {CONTAINER_TEST}, manifest) == 1, label

    good = tmp_path / "manifest-good.txt"
    good.write_text(
        body
        + f"{CONTAINER_TEST}  # proof: container-sandbox.yml :: Real-container isolation (fail, do not skip)\n",
        encoding="utf-8",
    )
    assert _run(checker, tmp_path, required | {CONTAINER_TEST}, good) == 0, (
        "the positive control: the same entry with a proof that resolves must pass, "
        "or the four refusals above prove only that the checker refuses everything"
    )


def test_the_real_conditional_proofs_resolve_and_carry_the_flag(checker, sections):
    """The committed manifest's own proofs, against the committed workflows."""

    entries = checker.manifest_entries(MANIFEST)
    _, conditional = sections
    for test_id in sorted(conditional):
        problem = checker.proof_problem(test_id, entries[test_id][1])
        assert problem is None, problem


def test_the_named_limit_a_conditional_skip_is_excused_on_EVERY_host(checker, sections, tmp_path):
    """Stated as a passing test so it cannot be mistaken for coverage it lacks.

    A conditional entry is excused wherever it skips — including a host where
    it skips for a reason nobody intended. What bounds that is the proof step,
    and for the container test that step runs nightly and on sandbox-path pull
    requests, not on every build (docs/OPEN-GAPS.md G7).
    """

    required, conditional = sections
    assert _run(checker, tmp_path, required | conditional) == 0
    tracker = (REPO / "docs" / "OPEN-GAPS.md").read_text(encoding="utf-8")
    assert "G7" in tracker and "conditional" in tracker.lower()
