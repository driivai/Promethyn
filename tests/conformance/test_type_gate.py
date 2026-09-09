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


def _run_gate(config: pathlib.Path, cwd: pathlib.Path) -> subprocess.CompletedProcess:
    """The EXACT command CI runs, against ``config``."""

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

    Every other assertion in this module reasons about the config's TEXT. This
    one reasons about what the gate DOES: it writes a real union-attr defect into
    the checked tree, runs the exact CI command, and requires a non-zero exit
    naming that defect.

    If the config is ever weakened — by ``disable_error_code``, by an
    ``enable_error_code`` inversion, by a per-module section, by a future mypy
    option nobody here has heard of, by any spelling at all — the planted defect
    stops being reported and this test goes red. That property does not depend on
    anyone having predicted the bypass, which is exactly what the denylist this
    replaces could not offer.
    """

    with _planted_defect() as path:
        result = _run_gate(MYPY_INI, REPO)

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
            bypassed = _run_gate(config, REPO)
            honest = _run_gate(MYPY_INI, REPO)

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

_UNION_TYPES = {"Unavailable", "Evidence", "Judgment"}


class _ExpressionNarrowings(ast.NodeVisitor):
    """Collect ``isinstance(x, <union member>)`` used in expression position."""

    def __init__(self) -> None:
        self.hits: list[tuple[str, int]] = []

    def _narrows_a_union(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "isinstance"
            and len(node.args) == 2
            and ast.unparse(node.args[1]) in _UNION_TYPES
        )

    def visit_IfExp(self, node: ast.IfExp) -> None:
        if self._narrows_a_union(node.test):
            self.hits.append(("ternary", node.lineno))
        self.generic_visit(node)

    def generic_visit(self, node: ast.AST) -> None:
        if isinstance(
            node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
        ):
            for generator in node.generators:
                for condition in generator.ifs:
                    if self._narrows_a_union(condition):
                        self.hits.append(("comprehension filter", condition.lineno))
        super().generic_visit(node)


def test_no_union_is_narrowed_in_expression_position():
    """Every union narrowing is statement-form, so it can carry an
    ``assert_never`` and a third member fails the build."""

    # Scoped to the shipped package. In a test, `any(isinstance(r, Unavailable)
    # for r in ...)` is an ASSERTION about a result, not a consumer that would
    # silently drop a third member from a quorum — the property this is about.
    offenders = []
    for path in _package_files():
        visitor = _ExpressionNarrowings()
        visitor.visit(ast.parse(path.read_text(encoding="utf-8")))
        offenders += [
            f"{path.relative_to(REPO)}:{line} ({kind})" for kind, line in visitor.hits
        ]

    assert offenders == [], (
        f"union narrowed in expression position at {offenders}. A ternary or a "
        "comprehension filter cannot carry an exhaustive terminal branch, so a "
        "third union member is silently taken by the else-branch (a verdict "
        "nobody reached) or silently dropped from a collection (a quorum that "
        "never met). Narrow in statement form with assert_never, or use "
        "core.models.partition_outcomes for the collection case."
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
#: Prose that quotes the directive inside backticks (the comments explaining the
#: removals above) is not a directive and is excluded by the lookbehind.
_ANY_IGNORE = re.compile(r"(?<!`)#\s*type:\s*ignore")

#: Sanctioned ignores, by ``path:line``. Empty, and adding an entry is a
#: deliberate change to this file with a justification in the report.
_SANCTIONED_IGNORES: frozenset[str] = frozenset()

#: ``getattr(result, "verdict", <default>)`` — the fail-open shape the sprint
#: names explicitly. With ``PASS`` it is a direct authorization fail-open; with
#: ``ABSTAIN`` it erases the EX-1 distinction between "the verifier declined"
#: and "the verifier could not run".
_VERDICT_GETATTR = re.compile(
    # The whitespace lives INSIDE the lookahead: with `\s*(?!...)` outside it,
    # the engine backtracks the `\s*` to zero and the lookahead passes at the
    # space — so prose that elides the default as `...` matched anyway.
    r"getattr\(\s*[^,()]+,\s*[\"']verdict[\"']\s*,(?!\s*\.\.\.)"
)


def _source_files() -> list[pathlib.Path]:
    """Every file the gate checks — all three trees, not just src."""

    return sorted(
        path for tree in CHECKED_TREES for path in (REPO / tree).rglob("*.py")
    )


def _package_files() -> list[pathlib.Path]:
    """Just the shipped package, for the checks that are about production code."""

    return sorted((REPO / CHECKED_TREE).rglob("*.py"))


#: This module states the forbidden shapes in its own regexes and prose, so it
#: matches itself. Excluded by NAME, like the strict-boolean sweep excludes the
#: parser it is about — not by a pattern that could quietly exclude more.
_SELF = pathlib.Path(__file__).name


def _swept_files() -> list[pathlib.Path]:
    return [p for p in _source_files() if p.name != _SELF]


def test_no_type_ignore_survives_anywhere_in_the_source_tree():
    offenders = [
        location
        for path in _swept_files()
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if _ANY_IGNORE.search(line)
        and (location := f"{path.relative_to(REPO)}:{n}") not in _SANCTIONED_IGNORES
    ]
    assert offenders == [], (
        f"unsanctioned '# type: ignore' at {offenders}. Silencing the checker is "
        "the failure mode this gate exists to prevent. Every ignore TYPE-GATE "
        "found turned out to be an interface that did not say what it meant — "
        "fix the interface. If a third-party stub gap genuinely needs one, add "
        "it to _SANCTIONED_IGNORES with the reason, deliberately."
    )


def test_no_verdict_getattr_default_in_the_source_tree():
    offenders = [
        f"{path.relative_to(REPO)}:{n}"
        for path in _swept_files()
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if _VERDICT_GETATTR.search(line)
    ]
    assert offenders == [], (
        f"getattr(..., 'verdict', <default>) at {offenders}. An Unavailable has "
        "no verdict BY DESIGN: substituting one turns 'the verifier could not "
        "run' into a verdict nobody reached. Narrow with isinstance instead."
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
