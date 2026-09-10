"""The type gate cannot be narrowed back, and cannot be carved out.

TYPE-GATE's finding was not "38 diagnostics". It was that ``mypy.ini`` named an
entry-point list of files, five of the files that mishandle
``Evidence | Unavailable`` sat outside it, and so eleven reproduced crashes and
one authorization fail-open shipped while the type checker already knew about
every one of them.

Fixing the diagnostics does not fix that. What fixes it is the gate covering the
whole tree, permanently, with no exemptions — and that property is exactly the
kind that erodes: a future sprint hits an awkward third-party stub and reaches
for ``[mypy-some.module] ignore_errors = True``; another hits a slow CI run and
trims ``files`` back to "the ones that matter". Both restore the original defect
in one line, and neither breaks a single test unless a test is looking.

This module looks. It asserts, against the real ``mypy.ini`` on disk:

* ``files`` is the whole package directory, not a list of modules;
* there is no per-module ``[mypy-...]`` section at all;
* no ``ignore_errors``, no ``disallow_*=False``, no ``follow_imports=skip``,
  no ``exclude``;
* ``warn_unused_ignores`` and ``warn_redundant_casts`` stay on, so a stale
  ``# type: ignore`` or a silencing ``cast()`` cannot sit unnoticed;
* CI actually runs the gate on every supported Python and fails on it.

And, with the same source-sweep discipline as
``test_the_old_truth_set_pattern_appears_nowhere_else``, it sweeps the whole
source tree for the shortcuts this sprint forbids: a blanket ``# type: ignore``
and a ``getattr(result, "verdict", ...)`` default. A gap that is NAMED is
hardened; a gap that is HIDDEN is a vulnerability.
"""

from __future__ import annotations

import ast
import configparser
import contextlib
import pathlib
import re
import subprocess
import sys
import tempfile
import tokenize
import typing

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
MYPY_INI = REPO / "mypy.ini"
CI_YML = REPO / ".github" / "workflows" / "ci.yml"

#: The package the gate must cover, entire.
CHECKED_TREE = "src/prometheus_protocol"

#: Every tree the gate checks. ``src`` was the whole of it until an independent
#: review found two ``.verdict`` dereferences in tests/ that mypy never saw
#: because tests/ was outside the gate — the same shape as the original finding,
#: one directory over. scripts/ came in with it: the revert-proof runners are
#: load-bearing evidence machinery, and they were unchecked too.
CHECKED_TREES = ("src/prometheus_protocol", "scripts", "tests")

#: Every Python the suite runs on. The gate is a wall only if it stands on all
#: of them: a union narrowing that type-checks on 3.12 and not on 3.10 is still
#: a crash on 3.10.
SUPPORTED_PYTHONS = ("3.10", "3.11", "3.12")


def _config() -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read(MYPY_INI, encoding="utf-8")
    return parser


# --------------------------------------------------------------------------
# 1. the gate covers the whole tree
# --------------------------------------------------------------------------


def test_mypy_checks_the_whole_source_tree_not_a_file_list():
    """``files`` names the package directory. A list of modules is the exact
    configuration that let the eleven crashes through."""

    cfg = _config()
    assert cfg.has_section("mypy"), "mypy.ini has no [mypy] section"
    files = cfg.get("mypy", "files", fallback="")
    entries = [e.strip() for e in files.replace("\n", ",").split(",") if e.strip()]

    assert entries == list(CHECKED_TREES), (
        f"the type gate must check {list(CHECKED_TREES)!r} entire; mypy.ini "
        f"names {entries!r}. An entry-point file list is what let eleven "
        "reproduced crashes and one authorization fail-open ship while mypy "
        "already knew about every one of them."
    )
    assert not any(e.endswith(".py") for e in entries), (
        "the type gate names individual .py files again — this is the narrowing "
        "TYPE-GATE exists to prevent"
    )
    for tree in CHECKED_TREES:
        assert (REPO / tree).is_dir(), tree


def test_the_checked_tree_really_is_every_module_in_the_package():
    """``files = src/prometheus_protocol`` is only whole-tree if mypy walks it.
    Sanity-check that the directory holds substantially the whole package, so a
    future move of code OUT of it would be visible here rather than silently
    shrinking the gate."""

    modules = sorted((REPO / CHECKED_TREE).rglob("*.py"))
    assert len(modules) > 100, (
        f"only {len(modules)} module(s) under {CHECKED_TREE} — if the package "
        "was split, the gate must be widened to cover the new location too"
    )


# --------------------------------------------------------------------------
# 2. no carve-outs
# --------------------------------------------------------------------------


#: THE ALLOWLIST. Every key the gate's config is permitted to carry, with the
#: exact value it must carry. Not a list of forbidden spellings — the previous
#: guard was that, and an independent review walked straight past it with one
#: line (``disable_error_code = union-attr``), which turns the gate green while a
#: real union-attr defect sits in the tree. A denylist can only refuse what
#: somebody thought of; mypy has well over a hundred options and gains more each
#: release, so "which spellings are dangerous?" is not a question that stays
#: answered. "Which keys may this file have?" is.
#:
#: Adding a key here is a deliberate change to this file, reviewed on its own
#: merits. Changing one is the same. Nothing else is admitted.
_ALLOWED_CONFIG = {
    "mypy_path": "src",
    "explicit_package_bases": "True",
    "ignore_missing_imports": "True",
    "warn_unused_ignores": "True",
    "warn_redundant_casts": "True",
    "files": "src/prometheus_protocol, scripts, tests",
}


def test_the_config_carries_exactly_the_allowed_keys_and_values():
    """An allowlist, not a denylist: any new key, changed value or new section
    fails, whether or not anyone anticipated that particular spelling."""

    cfg = _config()
    actual = dict(cfg.items("mypy"))

    unexpected = sorted(set(actual) - set(_ALLOWED_CONFIG))
    assert unexpected == [], (
        f"mypy.ini carries key(s) {unexpected} that are not on the gate's "
        "allowlist. This is how the gate gets turned off: an independent review "
        "disabled it with one unanticipated line (disable_error_code). If a key "
        "genuinely belongs, add it to _ALLOWED_CONFIG deliberately, with the "
        "reason — and note that test_a_planted_union_defect_still_fails_the_gate "
        "will independently refuse it if it weakens what the gate reports."
    )

    missing = sorted(set(_ALLOWED_CONFIG) - set(actual))
    assert missing == [], (
        f"mypy.ini has lost key(s) {missing}; each one is load-bearing"
    )

    wrong = {
        key: (actual[key], expected)
        for key, expected in _ALLOWED_CONFIG.items()
        if actual[key].strip() != expected.strip()
    }
    assert wrong == {}, (
        f"mypy.ini changed allowed key(s) to unallowed value(s): {wrong} "
        "(actual, allowed)"
    )


def test_mypy_ini_has_no_per_module_sections():
    """No ``[mypy-some.module]`` section at all.

    A per-module section is the one-line way to un-check a file. Whether it sets
    ``ignore_errors``, relaxes a ``disallow_*``, or does something harmless
    today, its existence re-opens the door; the guard refuses the door, not just
    the specific settings. (The allowlist above only constrains ``[mypy]``, so
    this is what keeps a second section from being where the carve-out lands.)
    """

    sections = [s for s in _config().sections() if s != "mypy"]
    assert sections == [], (
        f"mypy.ini grew per-module section(s) {sections!r}. A carve-out that "
        "hides a union-attr error is this gate failing at its own job. If a "
        "genuine third-party stub gap forces one, it must be narrow, justified "
        "in a comment naming the reason, and this guard updated deliberately "
        "with that reason — not widened in passing."
    )


# --------------------------------------------------------------------------
# 2b. the behavioural proof — the part that cannot be spelled around
# --------------------------------------------------------------------------

#: A file that is a real ``[union-attr]`` defect and nothing else: reading
#: ``.verdict`` off an ``Evidence | Unavailable``, which is precisely the shape
#: EX-1 exists to make unrepresentable and precisely what the eleven reproduced
#: crashes did.
_PLANTED_DEFECT = """\
from __future__ import annotations

from prometheus_protocol.core.models import Evidence, Unavailable


def read_a_verdict_off_the_union(outcome: Evidence | Unavailable) -> str:
    # An Unavailable has no verdict BY DESIGN. If the gate does not report this,
    # the gate is not doing its job.
    return outcome.verdict.value
"""


#: The REAL CI entry point. CI runs ``python scripts/type_gate.py``; it is that
#: script — not a bare mypy invocation — that decides whether the build passes.
GATE_ENTRY_POINT = REPO / "scripts" / "type_gate.py"


def _run_gate(cwd: pathlib.Path) -> subprocess.CompletedProcess:
    """Run the gate THROUGH the real CI entry point.

    This used to run ``python -m mypy --config-file <config>`` directly while
    claiming to be "the EXACT command CI runs". It was not: CI runs
    ``scripts/type_gate.py``, which builds its own mypy invocation. A flag added
    inside that script — ``--disable-error-code=union-attr`` — left the gate
    green WITH a valid receipt, and the proof, which never passed through the
    script, stayed green with it.

    Going through the entry point means the proof covers the whole execution
    path: the config, the script's flags, and the script's body. Stubbing
    ``main()`` to ``return 0`` now fails the proof too, because the proof
    requires a NON-ZERO exit when a real defect is planted.
    """

    return subprocess.run(
        [sys.executable, str(GATE_ENTRY_POINT)],
        capture_output=True, text=True, cwd=cwd,
    )


def _run_mypy_directly(
    config: pathlib.Path, cwd: pathlib.Path
) -> subprocess.CompletedProcess:
    """A SECOND, INDEPENDENT LAYER — not the mechanism.

    Bypassing the entry point is what lets this layer catch a weakening of the
    entry point itself. It is deliberately a different path, and it is named as a
    layer so nobody mistakes it for the primary proof again.
    """

    return subprocess.run(
        [sys.executable, "-m", "mypy", "--config-file", str(config)],
        capture_output=True, text=True, cwd=cwd,
    )


@contextlib.contextmanager
def _planted_defect():
    """Put the defect inside the gate's scope, and always take it out again."""

    path = REPO / CHECKED_TREE / "_planted_union_defect.py"
    assert not path.exists(), f"{path} already exists; refusing to clobber it"
    path.write_text(_PLANTED_DEFECT, encoding="utf-8")
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)


def test_a_planted_union_defect_still_fails_the_gate():
    """The load-bearing test, and the only one here that cannot be spelled around.

    Every other assertion in this module reasons about TEXT — the config's, the
    workflow's. This one reasons about what the gate DOES: it writes a real
    union-attr defect into the checked tree, runs ``scripts/type_gate.py`` (the
    entry point CI actually runs), and requires a non-zero exit naming it.

    WHAT IT COVERS. Everything on the real execution path: ``mypy.ini``, the
    flags ``type_gate.py`` builds, and ``type_gate.py``'s body. Weakening any of
    the three stops the planted defect being reported and turns this red, without
    anyone having predicted the spelling.

    WHAT IT DOES NOT COVER, corrected from the previous sprint's claim that it
    caught weakening "by any spelling at all". It does not, and could not, catch
    an INLINE ``# mypy:`` directive in another file: such a directive is scoped
    to its own file and the planted defect is in a different one. That class is
    governed separately and structurally, by
    ``test_no_inline_mypy_directive_reconfigures_the_checker_per_file``.
    """

    with _planted_defect() as path:
        result = _run_gate(REPO)

    assert result.returncode != 0, (
        "the type gate reported success with a real union-attr defect planted in "
        f"{path.relative_to(REPO)}. The config has been weakened by SOME means — "
        "compare mypy.ini against _ALLOWED_CONFIG.\n"
        + result.stdout + result.stderr
    )
    assert "union-attr" in result.stdout, (
        "the gate failed, but not on the planted union-attr defect — so this "
        "proof is measuring something else:\n" + result.stdout + result.stderr
    )
    assert "_planted_union_defect.py" in result.stdout, result.stdout


def test_the_planted_defect_is_removed_afterwards():
    """The probe above must not leave a file behind: a stray defect in the tree
    would turn every later gate run red for the wrong reason."""

    assert not (REPO / CHECKED_TREE / "_planted_union_defect.py").exists()


def test_the_behavioural_proof_catches_a_config_the_denylist_missed():
    """Meta-test: the proof is only worth having if it actually catches the
    bypass the previous guard walked past.

    Reproduces the independent review's finding — a copy of ``mypy.ini`` plus
    ``disable_error_code = union-attr`` — and asserts that the gate reports
    SUCCESS under it (the bypass is real) while the planted-defect proof would
    have caught it (the fix is real). Without this, a proof that silently stopped
    proving anything would look identical to a proof that passes.
    """

    # mypy resolves a relative ``files`` against the CONFIG's directory, so the
    # copy carries absolute paths; everything else is byte-identical plus the
    # review's one added line.
    weakened = MYPY_INI.read_text(encoding="utf-8").replace(
        f"files = {CHECKED_TREE}", f"files = {REPO / CHECKED_TREE}"
    ) + "\ndisable_error_code = union-attr\n"
    with tempfile.TemporaryDirectory(prefix="prom-gate-bypass-") as tmp:
        config = pathlib.Path(tmp) / "mypy-bypassed.ini"
        config.write_text(weakened, encoding="utf-8")
        with _planted_defect():
            # The bypassed CONFIG cannot go through the entry point (which pins
            # mypy.ini), so this arm uses the independent direct-mypy layer; the
            # honest arm goes through the real entry point, as the proof does.
            bypassed = _run_mypy_directly(config, REPO)
            honest = _run_gate(REPO)

    assert bypassed.returncode == 0, (
        "the review's bypass no longer turns the gate green — if mypy changed, "
        "re-derive this meta-test against a bypass that does:\n" + bypassed.stdout
    )
    assert honest.returncode != 0 and "union-attr" in honest.stdout, (
        "the shipped config no longer reports the planted defect, so the "
        "behavioural proof is not proving anything:\n" + honest.stdout
    )
    assert not _config_is_allowed(weakened), (
        "the allowlist admits the review's bypass config — it must not"
    )


def _config_is_allowed(text: str) -> bool:
    """Whether ``text`` would pass the allowlist. Used by the meta-test above."""

    parser = configparser.ConfigParser()
    parser.read_string(text)
    if [s for s in parser.sections() if s != "mypy"]:
        return False
    actual = dict(parser.items("mypy"))
    if set(actual) != set(_ALLOWED_CONFIG):
        return False
    return all(
        actual[k].strip() == v.strip() for k, v in _ALLOWED_CONFIG.items()
    )


# --------------------------------------------------------------------------
# 3. CI runs it — structurally, and provably
# --------------------------------------------------------------------------
#
# The guard this replaces matched substrings in the extracted mypy step. An
# independent review walked past it with::
#
#     run: true || python -m mypy --config-file mypy.ini
#
# which contains the gate command, carries no step-level ``if``, no
# ``continue-on-error``, and none of the four blacklisted escapes — and mypy
# never runs. A job-level ``jobs.build.if: false`` was uncovered too, because
# only the step was inspected; and the Python-version check searched the whole
# file's text rather than the job's matrix.
#
# So this section does two different things, and needs both:
#
#   3a. PARSE the workflow as a structure (PyYAML) and assert on the parsed job
#       conditions, the matrix, and the step — not on text that happens to
#       contain a substring.
#   3b. PROVE EXECUTION. ``scripts/type_gate.py`` writes a receipt naming the
#       checker, the file count and the config digest; a mandatory later step
#       requires it. A step that did not execute writes no receipt, however the
#       non-execution was spelled. This is the half that does not depend on
#       anyone predicting the bypass.
#
# HONEST LIMIT: no guard inside a workflow survives that workflow being
# disabled, and a job skipped by ``if: false`` does not run this test either.
# What these assertions buy is that the bypass fails whenever the job runs at
# all — the remaining case (job disabled outright) is visible as a missing
# required check in branch protection, which lives outside the repository and
# is not something a repository test can assert.

GATE_STEP_NAME = "Whole-tree type gate"
RECEIPT_STEP_NAME = "Type gate receipt (the gate must have EXECUTED, not merely existed)"
GATE_COMMAND = "python scripts/type_gate.py"
RECEIPT_COMMAND = "python scripts/check_type_gate_receipt.py"


def _workflow() -> dict:
    import yaml  # declared in the dev extra and pinned in constraints.txt

    return yaml.safe_load(CI_YML.read_text(encoding="utf-8"))


def _build_job() -> dict:
    job = _workflow()["jobs"]["build"]
    assert isinstance(job, dict), "jobs.build is not a mapping"
    return job


def _step_named(job: dict, name: str) -> dict:
    matches = [s for s in job["steps"] if s.get("name") == name]
    assert len(matches) == 1, (
        f"expected exactly one step named {name!r} in jobs.build, found "
        f"{len(matches)}. The gate must be a single, named, findable step."
    )
    return matches[0]


#: THE JOB-LEVEL ALLOWLIST, and the trigger allowlist beside it.
#:
#: The previous sprint asserted ``"if" not in job`` and step-level
#: ``continue-on-error``, and an independent review walked past both: setting
#: ``continue-on-error`` on the JOB makes every step advisory (19 guards passed),
#: and deleting the ``pull_request`` trigger means the workflow never fires on a
#: PR at all (19 guards passed). Neither shape had been enumerated.
#:
#: Adding those two to a rejected list would leave ``timeout-minutes: 1``, a
#: second matrix dimension via ``include:``, ``strategy.max-parallel``, and every
#: future job-level key. So this states what the job is PERMITTED to carry —
#: exactly the discipline that held for the config keys, and the only guard in
#: three rounds that survived attack.
#:
#: Triggers are governed here too. They are INSIDE the boundary the honest-limit
#: note above draws: branch protection lives outside the repository, but which
#: events the workflow answers to is committed in this file.
#: NO ENTRY MAY MEAN "ANY VALUE". The previous version wrote ``None`` for three
#: of the four keys and skipped the comparison for them, so ``services``,
#: ``strategy`` and ``steps`` were permitted KEYS with unconstrained VALUES —
#: which is a set over key names when what varies is the value under them. An
#: entry is therefore either the exact permitted value, or ``_PinnedBy("...")``
#: naming the test in THIS MODULE that pins it, and
#: ``test_no_allowlist_entry_delegates_to_a_test_that_does_not_exist`` requires
#: that test to exist. Delegation is allowed; abdication is not.
class _PinnedBy(typing.NamedTuple):
    test: str


_ALLOWED_JOB_KEYS: dict[str, object] = {
    "runs-on": "ubuntu-latest",
    "services": _PinnedBy("test_the_job_declares_exactly_the_expected_services"),
    "strategy": _PinnedBy("test_the_gate_runs_in_every_matrix_job_on_every_supported_python"),
    "steps": _PinnedBy("test_the_gate_step_command_is_exactly_the_gate_and_nothing_else"),
}

#: The database fixture, pinned. Not because the type gate depends on Postgres,
#: but because ``services`` may not be a key with an unconstrained value: the
#: live-database proofs in this workflow are only proofs of anything if the
#: service they run against is the one they were written for. The env block and
#: the health-check options are deliberately NOT pinned — they are credentials
#: and timing for that same container — and the test below says so.
_ALLOWED_SERVICES = {
    "postgres": {"image": "postgres:16-alpine", "ports": ["5432:5432"]},
}

#: Note the key: PyYAML resolves a bare ``on:`` to the BOOLEAN True (YAML 1.1
#: treats on/off/yes/no as booleans). A guard that looked for the string "on"
#: would silently find nothing and pass — which is the failure mode this whole
#: sprint is about, so it is named rather than left as a trap.
_TRIGGER_KEY = True

#: THE PERMITTED VALUES, PINNED STRUCTURALLY — no entry means "any value".
#:
#: The previous version wrote ``"pull_request": None`` and then read ``None`` as
#: "accept whatever is there". That is a permitted set over trigger NAMES while
#: what varies is the FILTER underneath them, and the gap is total: every one of
#:
#:     pull_request: {paths: ["docs/**"]}
#:     pull_request: {paths-ignore: ["src/**", "scripts/**", "tests/**"]}
#:     pull_request: {branches: ["a-branch-that-does-not-exist"]}
#:
#: leaves ``set(triggers)`` identical, passes the old assertion untouched, and
#: means the workflow never fires on a pull request that changes code. Nineteen
#: guards pass; nothing is gated.
#:
#: ``None`` here is now the PINNED VALUE, not a wildcard: PyYAML resolves a bare
#: ``pull_request:`` with nothing under it to ``None``, and a bare trigger is
#: exactly what is required — an unfiltered trigger, firing on every pull request
#: whatever it touches. Anything else, including a scalar and including a filter
#: that looks harmless, is refused. Denylisting ``paths``/``paths-ignore``/
#: ``branches`` would have closed three spellings and left ``types``,
#: ``branches-ignore``, ``tags`` and whatever Actions adds next.
_ALLOWED_TRIGGERS: dict[str, object] = {
    "push": {"branches": ["main"]},
    "pull_request": None,
}


def _workflow_triggers() -> dict:
    workflow = _workflow()
    assert _TRIGGER_KEY in workflow, (
        "ci.yml has no `on:` key at all — the workflow answers to no events"
    )
    return workflow[_TRIGGER_KEY]


def test_the_workflow_answers_to_exactly_the_permitted_triggers():
    """An allowlist: the gate is worth nothing on a workflow that never fires.

    Deleting ``pull_request:`` leaves every guard passing and every PR unchecked.
    """

    triggers = _workflow_triggers()
    assert set(triggers) == set(_ALLOWED_TRIGGERS), (
        f"ci.yml triggers are {sorted(triggers)}; permitted is "
        f"{sorted(_ALLOWED_TRIGGERS)}. A workflow that does not fire on "
        "pull_request leaves every PR ungated while every guard here passes."
    )
    # Unconditional: there is no branch here that skips the comparison, because
    # a trigger whose value is not compared is a trigger that can be filtered
    # down to nothing while the key stays present.
    for name, expected in _ALLOWED_TRIGGERS.items():
        assert triggers[name] == expected, (
            f"trigger {name!r} is {triggers[name]!r}, permitted {expected!r}. A "
            "paths, paths-ignore or branches filter on pull_request keeps this "
            "key set identical and stops the gate firing on code PRs; a bare "
            "`pull_request:` (parsed as None) fires on all of them. If a filter "
            "is genuinely wanted, change the permitted value here deliberately, "
            "with the reason."
        )


def test_the_build_job_carries_exactly_the_permitted_keys():
    """An allowlist over job-level keys, not a list of forbidden ones.

    ``continue-on-error``, ``if``, ``timeout-minutes`` and anything else a future
    Actions release adds are all refused by not being on the list.
    """

    job = _build_job()
    unexpected = sorted(set(job) - set(_ALLOWED_JOB_KEYS))
    assert unexpected == [], (
        f"jobs.build carries key(s) {unexpected} that are not permitted. This is "
        "how the gate is turned off one scope up: `continue-on-error: true` on "
        "the job makes every step advisory, and `if: false` skips the job and "
        "every guard in it. If a key genuinely belongs, add it to "
        "_ALLOWED_JOB_KEYS deliberately, with the reason."
    )
    missing = sorted(set(_ALLOWED_JOB_KEYS) - set(job))
    assert missing == [], f"jobs.build has lost key(s) {missing}"
    for key, expected in _ALLOWED_JOB_KEYS.items():
        if isinstance(expected, _PinnedBy):
            continue  # pinned by the named test; its existence is asserted below
        assert job[key] == expected, (
            f"jobs.build.{key} is {job[key]!r}, permitted {expected!r}"
        )


def test_no_allowlist_entry_delegates_to_a_test_that_does_not_exist():
    """``_PinnedBy`` is a promise that some OTHER test constrains the value.

    An unkept promise is indistinguishable from "any value permitted", which is
    the defect this replaced — so the promise is checked. If a delegated-to test
    is deleted or renamed, the delegation fails here rather than quietly becoming
    a wildcard.
    """

    delegated = {
        key: value.test
        for key, value in _ALLOWED_JOB_KEYS.items()
        if isinstance(value, _PinnedBy)
    }
    assert delegated, "no delegation left — inline the check or keep this honest"
    for key, name in delegated.items():
        assert name in globals() and callable(globals()[name]), (
            f"jobs.build.{key} delegates its value to {name!r}, which does not "
            "exist in this module. The key would carry ANY value."
        )
        # And it must be a collected test, not a helper: the manifest step in CI
        # requires exactly the test names listed in the manifest, so a delegated
        # check that is not a test would never run.
        assert name.startswith("test_"), f"{name!r} is not a test function"


def test_the_job_declares_exactly_the_expected_services():
    """``services`` is the key ``_ALLOWED_JOB_KEYS`` delegates here.

    The live-database steps in this workflow ("PostgreSQL chokepoint live tests
    (must run, never skip)") assert against a real server. Swapping the image, or
    dropping the port mapping, does not make them skip — it makes them fail for a
    reason unrelated to what they test, or, worse, pass against something else.

    NOT pinned, deliberately: ``env`` and ``options``. Those are the container's
    credentials and its health-check timings; pinning them here would make this
    guard fire on unrelated tuning while proving nothing further.
    """

    services = _build_job()["services"]
    assert set(services) == set(_ALLOWED_SERVICES), (
        f"jobs.build declares services {sorted(services)}; permitted "
        f"{sorted(_ALLOWED_SERVICES)}"
    )
    for name, pinned in _ALLOWED_SERVICES.items():
        for field, expected in pinned.items():
            assert services[name].get(field) == expected, (
                f"services.{name}.{field} is {services[name].get(field)!r}, "
                f"permitted {expected!r}"
            )


def test_the_workflow_defines_exactly_the_expected_jobs():
    """A second job could carry the required-check name while doing nothing."""

    jobs = _workflow()["jobs"]
    assert sorted(jobs) == ["build"], (
        f"ci.yml defines jobs {sorted(jobs)}; expected exactly ['build']"
    )


def test_the_build_job_itself_is_unconditional():
    """``jobs.build.if: false`` disables the gate and everything guarding it.

    The old guard never looked here — it only inspected the extracted mypy step.
    """

    job = _build_job()
    assert "if" not in job, (
        f"jobs.build carries a condition ({job['if']!r}). A conditional job can "
        "skip the type gate — and every other guard in the suite — while the "
        "workflow still looks present."
    )


def test_the_gate_runs_in_every_matrix_job_on_every_supported_python():
    """The matrix is read from the PARSED job, not searched for in the file's
    text: a version list somewhere else in the workflow proved nothing."""

    job = _build_job()
    matrix = job["strategy"]["matrix"]
    versions = sorted(str(v) for v in matrix["python-version"])
    assert versions == sorted(SUPPORTED_PYTHONS), (
        f"jobs.build's matrix is {versions!r}; the gate must run on "
        f"{sorted(SUPPORTED_PYTHONS)!r} — a narrowing that type-checks on 3.12 "
        "and not on 3.10 is still a crash on 3.10"
    )
    # The matrix has exactly one dimension, so every entry is a full job that
    # runs every step. A second dimension with an `include`/`exclude` could drop
    # the gate from some combinations without changing this list.
    assert set(matrix) == {"python-version"}, (
        f"jobs.build's matrix gained dimension(s) {sorted(set(matrix) - {'python-version'})}; "
        "each combination must still run the gate — re-derive this assertion "
        "deliberately rather than widening it"
    )
    assert job["strategy"].get("fail-fast") is False, (
        "fail-fast must stay off, so one Python's gate failure does not cancel "
        "the others and hide whether they would have failed too"
    )


def test_the_gate_step_is_unconditional_and_runs_the_gate_command():
    step = _step_named(_build_job(), GATE_STEP_NAME)
    assert "if" not in step, (
        f"the {GATE_STEP_NAME!r} step is conditional; it must run on every build"
    )
    assert "continue-on-error" not in step, (
        f"the {GATE_STEP_NAME!r} step sets continue-on-error — it must FAIL the build"
    )
    assert "shell" not in step, (
        "the gate step selects a non-default shell; the exit-status semantics "
        "this guard assumes are bash's"
    )


def test_the_gate_step_command_is_exactly_the_gate_and_nothing_else():
    """Parsed as a command, not searched as a substring.

    ``true || python scripts/type_gate.py`` CONTAINS the command and does not
    run it. The step's ``run`` block must consist of the gate invocation alone —
    no prefix, no operator, no second statement.
    """

    step = _step_named(_build_job(), GATE_STEP_NAME)
    lines = [ln.strip() for ln in step["run"].splitlines() if ln.strip()]
    assert lines == [GATE_COMMAND], (
        f"the {GATE_STEP_NAME!r} step runs {lines!r}, not exactly "
        f"[{GATE_COMMAND!r}]. Anything around the invocation — an operator, a "
        "guard word, a second statement — can stop it executing while leaving "
        "the command visible in the file."
    )


def test_a_separate_mandatory_step_requires_the_gate_to_have_executed():
    """3b: presence is not execution. The receipt step is what closes that."""

    job = _build_job()
    step = _step_named(job, RECEIPT_STEP_NAME)
    lines = [ln.strip() for ln in step["run"].splitlines() if ln.strip()]
    assert lines == [RECEIPT_COMMAND], (
        f"the receipt step runs {lines!r}, not exactly [{RECEIPT_COMMAND!r}]"
    )
    assert "if" not in step and "continue-on-error" not in step

    names = [s.get("name") for s in job["steps"]]
    assert names.index(GATE_STEP_NAME) < names.index(RECEIPT_STEP_NAME), (
        "the receipt check runs before the gate that writes the receipt"
    )


def test_the_receipt_is_not_committed_to_the_repository():
    """A committed receipt would satisfy the check without the gate running.

    ``check_type_gate_receipt.py`` also pins the config digest, so a stale
    receipt fails — but the file has no business being in the tree at all.
    """

    receipt = REPO / "type-gate-receipt.json"
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", str(receipt.relative_to(REPO))],
        capture_output=True, text=True, cwd=REPO,
    )
    assert tracked.returncode != 0, (
        "type-gate-receipt.json is tracked in git. It is EVIDENCE OF A RUN, not "
        "a source file; committing one lets the receipt check pass without the "
        "gate executing."
    )


def test_the_gate_runner_refuses_a_run_that_checked_too_few_files():
    """The receipt's file-count floor: a gate whose scope silently shrank
    reports Success over whatever is left."""

    sys.path.insert(0, str(REPO / "scripts"))
    try:
        import type_gate
    finally:
        sys.path.remove(str(REPO / "scripts"))

    assert type_gate.MINIMUM_CHECKED_FILES >= 120
    # The success line the runner insists on: mypy exiting 0 for any other
    # reason (nothing to check at all) is refused rather than accepted.
    assert type_gate._SUCCESS.search("Success: no issues found in 127 source files")
    assert type_gate._SUCCESS.search("Success: no issues found in 0 source files")
    assert not type_gate._SUCCESS.search("Success: no issues found")


# --------------------------------------------------------------------------
# 3d. exhaustiveness: no union narrowing hides in an EXPRESSION
# --------------------------------------------------------------------------
#
# TYPE-GATE's report claimed ``assert_never`` at every ``Evidence | Unavailable``
# and ``Judgment | Unavailable`` branch point. It was not true: several consumers
# narrowed in EXPRESSION form — ternaries in a row constructor, and comprehension
# filters that collect the survivors — with no terminal branch. Not a runtime
# defect for a two-member union, but a false completeness claim, and the
# comprehension shape is genuinely fragile: a filter that selects one member
# DROPS anything that is neither, silently, because a narrowed comprehension is
# well-typed whatever else the union holds. A lever whose claim is "N judges
# agreed" would quietly agree with fewer.
#
# Auditing the claim by reading annotations was how it went wrong: a union
# arrives through a generic verifier, an inferred variable, a collection or a
# helper return, so the signatures do not enumerate the consumers. This sweeps
# the AST for the shape instead, and pins it at ZERO — no allowlist to drift.
# The sweep found one site the independent review had not named
# (``verifier/bank.py``, the bank's own graded/unavailable split), which is the
# argument for sweeping rather than auditing.

#: Only used to check the SANCTIONED entries below, never to decide what is
#: swept. See ``test_no_union_is_narrowed_in_expression_position``.
_UNION_TYPES = {"Unavailable", "Evidence", "Judgment"}

#: Every way Python asks "what type is this?" — a closed set fixed by the
#: language, not a list of the union's spellings.
#:
#: THE PREVIOUS VERSION MATCHED THE WRONG THING. It swept for an ``ast.Name``
#: whose ``id`` was in ``_UNION_TYPES`` — three identifier SPELLINGS. What varies
#: is not the spelling of the test, it is the spelling of the NAME, and there are
#: unlimited spellings of the same symbol::
#:
#:     [r for r in rs if not isinstance(r, models.Unavailable)]   # ast.Attribute
#:     from ...models import Unavailable as Missing
#:     [r for r in rs if not isinstance(r, Missing)]              # different id
#:
#: Both narrow correctly under mypy; neither is an ``ast.Name`` in the set. Nor
#: would the obvious repairs close it — adding ``ast.Attribute.attr`` to the set
#: leaves ``getattr(models, "Unavailable")``, and adding the known aliases leaves
#: the next one.
#:
#: So this restricts the PROPERTY rather than the syntax, which is the reviewer's
#: option (b) and the shape chosen here: within the shipped package, an
#: expression-position test may not be a TYPE TEST AT ALL, whatever type it
#: names. The permitted set is now over the thing that varies — the test
#: expression — instead of over three identifiers. There are exactly eleven such
#: tests in the package today (ten distinct sources; ``runner.py`` carries one of
#: them twice) and none of them touches the union. Each is sanctioned below BY
#: ITS SOURCE, so changing one to test a union member stops matching its sanction
#: and fails.
_TYPE_TEST_CALLS = {"isinstance", "issubclass", "type", "hasattr", "getattr"}


def _type_test_reason(node: ast.AST) -> str | None:
    """Why ``node`` is a type test, or ``None``.

    ``type(x) is C``, ``x.__class__ is C``, ``isinstance``/``issubclass``, and
    the duck-typed pair ``hasattr``/three-argument ``getattr`` — which is how a
    survivor filter is written when someone has been told not to use
    ``isinstance``.
    """

    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            name = (
                func.id if isinstance(func, ast.Name)
                else func.attr if isinstance(func, ast.Attribute)
                else None
            )
            if name in _TYPE_TEST_CALLS:
                return name
        if isinstance(child, ast.Attribute) and child.attr == "__class__":
            return "__class__"
    return None


class _ExpressionTypeTests(ast.NodeVisitor):
    """Every test in expression position, with the reason it is a type test."""

    def __init__(self) -> None:
        self.hits: list[tuple[str, int, str, str]] = []

    def _record(self, kind: str, node: ast.expr) -> None:
        reason = _type_test_reason(node)
        if reason is not None:
            self.hits.append((kind, node.lineno, reason, ast.unparse(node)))

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self._record("ternary", node.test)
        self.generic_visit(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # ``filter(lambda r: not isinstance(r, Unavailable), rs)`` is the same
        # survivor filter wearing a different hat.
        self._record("lambda", node.body)
        self.generic_visit(node)

    def generic_visit(self, node: ast.AST) -> None:
        if isinstance(
            node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
        ):
            for generator in node.generators:
                for condition in generator.ifs:
                    self._record("comprehension filter", condition)
        super().generic_visit(node)


#: The eleven expression-position type tests the package carries, sanctioned by
#: ``path::<normalized test>``. NOT by line — a line number is an identity and
#: shifts with any edit above it; the normalized source is the CONTENT, so
#: editing the test to name a different type stops matching and fails.
#:
#: Every one tests a builtin or a local record type, never a union member; that
#: is asserted independently below rather than left to review.
_SANCTIONED_EXPRESSION_TYPE_TESTS: frozenset[str] = frozenset({
    "src/prometheus_protocol/chokepoint/ownership.py::isinstance(value, str) and value",
    "src/prometheus_protocol/chokepoint/runner.py::isinstance(payload, dict)",
    "src/prometheus_protocol/chokepoint/runner.py::isinstance(seq, int) and (not isinstance(seq, bool))",
    "src/prometheus_protocol/chokepoint/substrate.py::isinstance(row, MountEntry) and counts[row.mount_id] == 1",
    "src/prometheus_protocol/core/transport.py::isinstance(req, DeadlineRequest)",
    "src/prometheus_protocol/core/transport.py::hasattr(sock, 'settimeout')",
    "src/prometheus_protocol/forge/miner.py::(ep := getattr(task, 'entry_point', ''))",
    "src/prometheus_protocol/ledger/sqlite_ledger.py::isinstance(evidence, dict)",
    "src/prometheus_protocol/ledger/tip_anchor.py::isinstance(body, bytes)",
    "src/prometheus_protocol/swarm/roles.py::isinstance(text, str)",
})


def test_no_union_is_narrowed_in_expression_position():
    """No expression-position TYPE TEST in the shipped package, sanctions aside.

    A ternary, a comprehension filter or a lambda cannot carry an exhaustive
    terminal branch, so a third union member is silently taken by the else-branch
    (a verdict nobody reached) or silently dropped from a collection (a quorum
    that never met).

    WHAT THE PERMITTED SET IS OVER: the test expression itself, normalized
    through ``ast.unparse`` and keyed to its file. Every spelling of the type
    being tested — bare name, qualified attribute, import alias, tuple, a
    ``getattr`` on the module — is refused identically, because the guard never
    looks at which type is named.

    WHAT CAN STILL VARY THAT THIS DOES NOT CONSTRAIN, stated rather than left to
    be found: a HELPER. ``[r for r in rs if _ran(r)]``, with ``_ran`` doing the
    ``isinstance`` in statement form one function away, is not a type test at the
    filter site and is not caught here. Closing that needs interprocedural
    resolution; it is not closed, and the thirty-six expression-position tests in
    the package that call a non-builtin are the search space if it ever is. What
    stands behind it is behavioural, not syntactic: the ensemble and k-sample
    levers are driven with a REAL ``Unavailable`` in
    ``test_unavailable_consumers_do_not_crash.py``, and a survivor filter that
    drops the missing list — however it is spelled — fails those.
    """

    # Scoped to the shipped package. In a test, `any(isinstance(r, Unavailable)
    # for r in ...)` is an ASSERTION about a result, not a consumer that would
    # silently drop a third member from a quorum — the property this is about.
    offenders = []
    for path in _package_files():
        rel = path.relative_to(REPO)
        visitor = _ExpressionTypeTests()
        visitor.visit(ast.parse(path.read_text(encoding="utf-8")))
        for kind, line, reason, source in visitor.hits:
            if f"{rel}::{source}" in _SANCTIONED_EXPRESSION_TYPE_TESTS:
                continue
            offenders.append(f"{rel}:{line} ({kind}, {reason}) {source}")

    assert offenders == [], (
        f"expression-position type test at {offenders}. Narrow in statement form "
        "with assert_never, or use core.models.partition_outcomes for the "
        "collection case. If the test genuinely cannot narrow a union — it "
        "inspects a builtin or a local record type — sanction it in "
        "_SANCTIONED_EXPRESSION_TYPE_TESTS by its exact source, with the reason."
    )


def test_no_sanctioned_expression_test_touches_the_union():
    """Belt to the braces above: the sanction list cannot be used to smuggle a
    union narrowing back in.

    This one DOES match identifier spellings, and that is sound here for a reason
    the primary sweep could not rely on: it runs over a hand-written list of ten
    entries whose text is fixed in this file, not over code an attacker chooses.
    A qualified or aliased spelling added to the list would have to be added by
    someone editing this file, and it would be reviewed as what it is.
    """

    for entry in sorted(_SANCTIONED_EXPRESSION_TYPE_TESTS):
        path, _, source = entry.partition("::")
        assert (REPO / path).exists(), f"sanctioned test names a missing file: {entry}"
        mentioned = {
            node.id for node in ast.walk(ast.parse(source, mode="eval"))
            if isinstance(node, ast.Name)
        } | {
            node.attr for node in ast.walk(ast.parse(source, mode="eval"))
            if isinstance(node, ast.Attribute)
        }
        assert not (mentioned & _UNION_TYPES), (
            f"sanctioned expression-position test names a union member: {entry}. "
            "A union may not be narrowed in expression position, sanction or no."
        )


def test_every_sanctioned_expression_test_is_still_present():
    """A sanction for a test that no longer exists is dead weight that would let
    the same source reappear elsewhere in that file unreviewed."""

    observed = set()
    for path in _package_files():
        rel = path.relative_to(REPO)
        visitor = _ExpressionTypeTests()
        visitor.visit(ast.parse(path.read_text(encoding="utf-8")))
        observed |= {f"{rel}::{source}" for _, _, _, source in visitor.hits}

    stale = sorted(_SANCTIONED_EXPRESSION_TYPE_TESTS - observed)
    assert stale == [], (
        f"sanctioned expression-position test(s) no longer in the tree: {stale}. "
        "Remove the sanction in the same change that removed the code."
    )


def test_partition_outcomes_is_exhaustive_and_drops_nothing():
    """The replacement for the survivor-filter shape, exercised directly."""

    from prometheus_protocol.core.models import (
        Evidence,
        Tier,
        Unavailability,
        Unavailable,
        Verdict,
        partition_outcomes,
    )

    evidence = Evidence(
        passed=True, total=1, passed_count=1, failures=(),
        verifier_id="probe", verdict=Verdict.PASS, tier=Tier.HARD,
    )
    missing = Unavailable(
        verifier_id="probe", tier=Tier.HARD,
        reason=Unavailability.INFRA_FAULT, detail="could not run",
    )

    ran, absent = partition_outcomes([evidence, missing, evidence])
    assert ran == [evidence, evidence]
    assert absent == [missing]
    # Nothing is lost: the two halves account for every input, which is the
    # property a filter-to-one-member comprehension cannot offer.
    assert len(ran) + len(absent) == 3
    assert partition_outcomes([]) == ([], [])


# --------------------------------------------------------------------------
# 4. the forbidden shortcuts appear nowhere in the source tree
# --------------------------------------------------------------------------

#: ANY ``# type: ignore``, coded or bare. TYPE-GATE left the tree with none: the
#: eight that existed were not silenced but resolved — four in ``verifier/bank.py``
#: by ``Evidence.decided`` stating the ``__post_init__`` guarantee the field type
#: could not, one by naming ``resolve_signer``'s real requirement as a Protocol,
#: two by passing a named argument instead of splatting an untyped dict, and one
#: by declaring the optional ``fcntl`` module as ``ModuleType | None``. Each was
#: an interface that did not say what it meant; the ignore was standing in for
#: the missing statement.
#:
#: Zero is therefore the honest pin, and a stricter wall than "no BARE ignores":
#: a coded ignore is specific, but it is still a place the checker was told to
#: look away. A genuine third-party stub gap may one day need one — then it is
#: added HERE, deliberately, narrow and with the reason named, the same sanction
#: discipline the Hearth guards use. It does not arrive in passing.
#:
#: Matched against COMMENT TOKENS and ANCHORED AT THE START of the comment,
#: which is exactly where mypy honours it. Measured, not assumed:
#:
#:     x: int = "no"  # type: ignore              -> silenced
#:     x: int = "no"  #type:ignore                -> silenced
#:     x: int = "no"  # type: ignore # noqa       -> silenced
#:     x: int = "no"  # noqa  # type: ignore      -> STILL REPORTED
#:
#: So the directive is real only when the comment BEGINS with it, and prose that
#: mentions one — including every comment in this module — never does. The old
#: backtick lookbehind was a convention standing in for that structural fact and
#: is gone with it.
_ANY_IGNORE = re.compile(r"#\s*type:\s*ignore")

#: Sanctioned ignores, by ``path:line``. Empty, and adding an entry is a
#: deliberate change to this file with a justification in the report.
_SANCTIONED_IGNORES: frozenset[str] = frozenset()


def _source_files() -> list[pathlib.Path]:
    """Every file the gate checks — all three trees, not just src.

    THERE IS NO EXCLUSION, and there must not be one. The previous version of
    this module swept ``[p for p in _source_files() if p.name != _SELF]``, where
    ``_SELF`` was this file's BASENAME. That is a permitted set over the wrong
    thing: the set covers FILENAMES, and what an attacker chooses is the
    filename. A real, checked production module at
    ``src/prometheus_protocol/core/test_type_gate.py`` — inside ``files``,
    inside the gate, reported in mypy's count — was swept out of every check
    below simply by being called that, and could carry
    ``# mypy: disable-error-code="union-attr"`` over a live defect with the gate
    green and every guard here passing.

    The exclusion existed because the sweeps read RAW TEXT, and this module
    necessarily states the forbidden shapes in its own regexes and prose. They
    now read TOKENS and AST nodes instead, so the question each one asks has the
    same answer in this file as in any other and no file needs excusing. Nor
    would the obvious repairs have helped: renaming ``_SELF``, adding a
    "no test-shaped names in src" rule, or excluding the exact PATH all leave a
    set over identity when the thing that varies is content.
    """

    return sorted(
        path for tree in CHECKED_TREES for path in (REPO / tree).rglob("*.py")
    )


def _package_files() -> list[pathlib.Path]:
    """Just the shipped package, for the checks that are about production code."""

    return sorted((REPO / CHECKED_TREE).rglob("*.py"))


def _comment_tokens(path: pathlib.Path) -> list[tuple[int, str]]:
    """Every COMMENT token in ``path``, as ``(line, text)``.

    Token type is what separates a directive from a mention of one. A checker
    directive is a COMMENT; the same characters inside a string literal are a
    STRING — this module's own regexes, and the mutation fixtures in
    ``scripts/type_gate_revert_proofs.py`` which carry the directive as data
    BECAUSE it is the mutation these guards are proved against. Neither is a
    comment, so neither is swept, in whichever file it appears.
    """

    with path.open("rb") as handle:
        return [
            (token.start[0], token.string)
            for token in tokenize.tokenize(handle.readline)
            if token.type == tokenize.COMMENT
        ]


#: INLINE mypy CONFIGURATION, governed as an allowlist whose permitted set is
#: EMPTY. A comment of the form ``# mypy: <key>=<value>`` at the top of a file
#: reconfigures the checker for that whole file. An independent review used one
#: line — ``# mypy: disable-error-code="union-attr"`` — to leave a real
#: union-attr defect in the checked tree with the gate green, the receipt valid,
#: 19 guards passing, 22 behavioural tests passing and the revert runner passing.
#: Nothing saw it.
#:
#: The planted-defect proof could not see it BY CONSTRUCTION: an inline directive
#: is scoped to its own file, and the planted defect lives in a different one. So
#: the previous sprint's claim — that weakening the checker "by any spelling at
#: all" makes the proof go red — was false for this entire class, not by an
#: oversight in the regex but because the proof is per-file and the attack is
#: per-file.
#:
#: This is therefore governed the way the CONFIG KEYS are governed, which is the
#: only guard in three rounds that survived attack: by stating what is permitted.
#: The permitted set is empty. Adding ``disable-error-code`` to a rejected list
#: would close one spelling and leave ``ignore-errors``, the underscore form, and
#: every future inline key — the denylist trap this repository has now walked
#: into three times.
#: Matched against real COMMENT TOKENS, not raw text. ``type_gate_revert_
#: proofs.py`` necessarily carries the directive as a STRING — it is the
#: mutation this guard is proved against — and a text sweep flagged that string,
#: which would have pushed the fix towards excluding the runner and turning the
#: exclusion into a hiding place. Tokenising asks the precise question instead:
#: is there a comment that reconfigures the checker?
#:
#: Anchored at the start of the comment, and swept over the WHOLE file: measured,
#: ``# mypy:`` is honoured on any line, not only the first, and is NOT honoured
#: when other text precedes it in the same comment. The pattern is deliberately
#: wider than what mypy honours (``#mypy:`` and ``# mypy :`` are both refused by
#: mypy and both flagged here) — erring towards flagging is the safe direction.
_INLINE_MYPY_DIRECTIVE = re.compile(r"^#\s*mypy\s*:")

#: Sanctioned inline directives, by ``path:line``. EMPTY, and it stays empty
#: unless a directive is genuinely unavoidable — in which case the entry names
#: the file, the line, and the reason, and is reviewed on its own merits.
_SANCTIONED_INLINE_DIRECTIVES: frozenset[str] = frozenset()


def test_no_inline_mypy_directive_reconfigures_the_checker_per_file():
    """An allowlist with an empty permitted set: no file may reconfigure mypy.

    ``mypy.ini`` is governed by ``_ALLOWED_CONFIG``. This governs the OTHER place
    mypy takes configuration from — the source files themselves — which was
    ungoverned entirely.
    """

    offenders = []
    for path in _source_files():
        for line, text in _comment_tokens(path):
            if not _INLINE_MYPY_DIRECTIVE.match(text.strip()):
                continue
            location = f"{path.relative_to(REPO)}:{line}"
            if location not in _SANCTIONED_INLINE_DIRECTIVES:
                offenders.append(location)
    assert offenders == [], (
        f"inline mypy configuration at {offenders}. A '# mypy:' comment "
        "reconfigures the checker for that whole file, and the planted-defect "
        "proof cannot see it — the defect it plants is in a different file. If a "
        "directive is genuinely unavoidable, add it to "
        "_SANCTIONED_INLINE_DIRECTIVES with the reason; do not tolerate it "
        "silently."
    )


def test_no_type_ignore_survives_anywhere_in_the_source_tree():
    """Every checked file, this one included — see ``_source_files``."""

    offenders = [
        location
        for path in _source_files()
        for line, text in _comment_tokens(path)
        if _ANY_IGNORE.match(text.strip())
        and (location := f"{path.relative_to(REPO)}:{line}") not in _SANCTIONED_IGNORES
    ]
    assert offenders == [], (
        f"unsanctioned '# type: ignore' at {offenders}. Silencing the checker is "
        "the failure mode this gate exists to prevent. Every ignore TYPE-GATE "
        "found turned out to be an interface that did not say what it meant — "
        "fix the interface. If a third-party stub gap genuinely needs one, add "
        "it to _SANCTIONED_IGNORES with the reason, deliberately."
    )


def _distinguishing_attributes() -> frozenset[str]:
    """Every attribute that tells the union's members apart, FROM THE TYPES.

    ``getattr(outcome, "verdict", Verdict.PASS)`` is the fail-open shape the
    sprint names: an ``Unavailable`` has no verdict BY DESIGN, and substituting
    one turns "the verifier could not run" into a verdict nobody reached. But
    ``verdict`` is not the only attribute that separates the members, and the
    previous guard was a regex over that ONE SPELLING — a permitted set over a
    single literal, while what varies is which attribute is being defaulted.
    ``getattr(outcome, "passed", True)`` and ``getattr(outcome, "failures", ())``
    are the same fail-open one word over, and both walked straight past it.

    So the set is derived from the dataclasses themselves: any field present on
    one member of ``Evidence | Unavailable`` (or ``Judgment | Unavailable``) and
    absent from the other. Adding a field to ``Evidence`` widens this guard in
    the same commit, with nobody having to remember to.
    """

    from dataclasses import fields

    from prometheus_protocol.core.models import Evidence, Judgment, Unavailable

    evidence = {f.name for f in fields(Evidence)}
    judgment = {f.name for f in fields(Judgment)}
    unavailable = {f.name for f in fields(Unavailable)}
    return frozenset((evidence ^ unavailable) | (judgment ^ unavailable))


#: Sanctioned ``getattr`` defaults, by ``path::<normalized call>``. The key
#: carries the CALL, not the line: an entry sanctions that exact expression in
#: that file, so rewriting the call to name a different object or a different
#: default no longer matches and fails. Both entries probe a foreign object that
#: merely shares a field name with the union.
_SANCTIONED_GETATTR_DEFAULTS: frozenset[str] = frozenset({
    # ``case.verifier`` is a conformance Verifier protocol object, not an
    # outcome; ``tier`` is optional on it and the default records "unspecified".
    "src/prometheus_protocol/conformance/contract.py::getattr(case.verifier, 'tier', None)",
    # ``exc`` is a urllib/http exception; ``.reason`` is its own attribute and
    # has nothing to do with ``Unavailable.reason``.
    "src/prometheus_protocol/core/transport.py::getattr(exc, 'reason', None)",
})


def test_no_verdict_getattr_default_in_the_source_tree():
    """No ``getattr`` default may stand in for an attribute that distinguishes
    the union's members. Read from the AST, so prose and mutation fixtures that
    quote the shape as text are not calls and are not swept."""

    distinguishing = _distinguishing_attributes()
    assert "verdict" in distinguishing, (
        "the derivation no longer yields the attribute the sprint names — the "
        "models changed shape and this guard must be re-derived deliberately"
    )

    offenders = []
    for path in _source_files():
        rel = path.relative_to(REPO)
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) == 3
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in distinguishing
            ):
                continue
            if f"{rel}::{ast.unparse(node)}" in _SANCTIONED_GETATTR_DEFAULTS:
                continue
            offenders.append(f"{rel}:{node.lineno} ({ast.unparse(node)})")

    assert offenders == [], (
        f"getattr with a default for a union-distinguishing attribute at "
        f"{offenders}. An Unavailable has no verdict, no passed, no failures BY "
        "DESIGN: substituting one turns 'the verifier could not run' into an "
        "outcome nobody reached. Narrow with isinstance, or use "
        "core.models.partition_outcomes."
    )


def test_the_source_tree_type_checks_clean_right_now():
    """The gate's own postcondition, asserted from the suite as well as from CI:
    running the checked-in config over the checked tree reports no diagnostic.

    This is deliberately not a substitute for the CI step (this asserts on ONE
    interpreter; CI asserts on all three). It is here so a local run of the
    suite surfaces a regression before it reaches a reviewer.
    """

    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "mypy", "--config-file", "mypy.ini"],
        capture_output=True, text=True, cwd=REPO,
    )
    assert proc.returncode == 0, (
        "the type gate is not clean:\n" + proc.stdout + proc.stderr
    )
