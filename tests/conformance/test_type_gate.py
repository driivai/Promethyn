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

import configparser
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
MYPY_INI = REPO / "mypy.ini"
CI_YML = REPO / ".github" / "workflows" / "ci.yml"

#: The package the gate must cover, entire.
CHECKED_TREE = "src/prometheus_protocol"

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

    assert entries == [CHECKED_TREE], (
        f"the type gate must check {CHECKED_TREE!r} entire; mypy.ini names "
        f"{entries!r}. An entry-point file list is what let eleven reproduced "
        "crashes and one authorization fail-open ship while mypy already knew "
        "about every one of them."
    )
    assert not any(e.endswith(".py") for e in entries), (
        "the type gate names individual .py files again — this is the narrowing "
        "TYPE-GATE exists to prevent"
    )
    assert (REPO / CHECKED_TREE).is_dir()


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


def test_mypy_ini_has_no_per_module_sections():
    """No ``[mypy-some.module]`` section at all.

    A per-module section is the one-line way to un-check a file. Whether it sets
    ``ignore_errors``, relaxes a ``disallow_*``, or does something harmless
    today, its existence re-opens the door; the guard refuses the door, not just
    the specific settings.
    """

    sections = [s for s in _config().sections() if s != "mypy"]
    assert sections == [], (
        f"mypy.ini grew per-module section(s) {sections!r}. A carve-out that "
        "hides a union-attr error is this gate failing at its own job. If a "
        "genuine third-party stub gap forces one, it must be narrow, justified "
        "in a comment naming the reason, and this guard updated deliberately "
        "with that reason — not widened in passing."
    )


@pytest.mark.parametrize(
    "option",
    ["ignore_errors", "exclude", "follow_imports", "follow_imports_for_stubs"],
)
def test_the_global_section_does_not_switch_checking_off(option: str):
    """The global section must not disable checking wholesale either."""

    cfg = _config()
    assert not cfg.has_option("mypy", option), (
        f"mypy.ini sets {option!r} globally; the gate must check the tree, not "
        "skip parts of it"
    )


def test_no_disallow_option_is_switched_off():
    """A ``disallow_*=False`` is a carve-out spelled as a default."""

    cfg = _config()
    offenders = {
        key: value
        for key, value in cfg.items("mypy")
        if key.startswith("disallow_") and value.strip().lower() in {"false", "no", "0"}
    }
    assert offenders == {}, (
        f"mypy.ini relaxes {sorted(offenders)} to make the diagnostic count "
        "smaller. The sprint forbids exactly this."
    )


@pytest.mark.parametrize("flag", ["warn_unused_ignores", "warn_redundant_casts"])
def test_the_shortcut_detectors_stay_on(flag: str):
    """``warn_unused_ignores`` and ``warn_redundant_casts`` are what make a
    stale ``# type: ignore`` and a silencing ``cast()`` visible instead of
    permanent."""

    cfg = _config()
    assert cfg.getboolean("mypy", flag, fallback=False) is True, (
        f"{flag} must stay on: without it the two shortcuts this sprint forbids "
        "can sit in the tree unnoticed"
    )


def test_mypy_path_and_explicit_package_bases_keep_the_gate_toothed():
    """Without ``mypy_path=src``, ``ignore_missing_imports`` degrades the
    project's own types to ``Any`` and every union check silently passes — a
    gate that reports success while checking nothing."""

    cfg = _config()
    assert cfg.get("mypy", "mypy_path", fallback="") == "src"
    assert cfg.getboolean("mypy", "explicit_package_bases", fallback=False) is True


# --------------------------------------------------------------------------
# 3. CI runs it, on every supported Python, and fails on it
# --------------------------------------------------------------------------


#: A workflow step begins at ``      - name:``. Splitting on that marker gives
#: the text of each step, which is all these assertions need. Deliberately not
#: a YAML parse: PyYAML is not in the pinned dependency closure (constraints.txt
#: + the SBOM), and a conformance test that ImportErrors in CI is a test that
#: does not run — the precise failure this sprint is about. The "exactly one"
#: assertion below is what stops a parse that finds nothing from passing
#: vacuously.
_STEP_MARKER = re.compile(r"^ {6}- (?=name:|uses:|run:)", re.MULTILINE)


def _ci_steps() -> list[str]:
    text = CI_YML.read_text(encoding="utf-8")
    body = text[text.index("    steps:"):]
    return [s for s in _STEP_MARKER.split(body)[1:]]


#: Matched on the command, not on prose: other steps legitimately MENTION mypy
#: in a comment, and a guard that keys off a comment is a guard that moves when
#: someone edits a sentence.
_GATE_COMMAND = "python -m mypy --config-file mypy.ini"


def _type_gate_step() -> str:
    steps = [s for s in _ci_steps() if _GATE_COMMAND in s]
    assert len(steps) == 1, (
        f"expected exactly one step running {_GATE_COMMAND!r} in the build job, "
        f"found {len(steps)}"
    )
    return steps[0]


def test_ci_runs_the_whole_tree_gate_on_every_supported_python():
    text = CI_YML.read_text(encoding="utf-8")
    matrix = re.search(r"python-version:\s*\[([^\]]+)\]", text)
    assert matrix is not None, "no python-version matrix found in ci.yml"
    versions = sorted(v.strip().strip("\"'") for v in matrix.group(1).split(","))
    assert versions == sorted(SUPPORTED_PYTHONS), (
        f"the CI matrix is {versions!r}; the gate must run on "
        f"{sorted(SUPPORTED_PYTHONS)!r} — a union narrowing that type-checks on "
        "3.12 and not on 3.10 is still a crash on 3.10"
    )

    step = _type_gate_step()
    assert step.lstrip().startswith("name:"), (
        "the type gate must be a named step, so a reviewer can see it in the log"
    )


def test_the_ci_gate_is_blocking_not_advisory():
    """No ``continue-on-error``, no ``|| true``, no ``if:`` that can skip it.
    An advisory gate is not a gate."""

    step = _type_gate_step()
    directives = [
        line.strip() for line in step.splitlines()
        if re.match(r"^\s*(continue-on-error|if):", line)
    ]
    assert directives == [], (
        f"the type gate step carries {directives!r} — it must run on every build "
        "and FAIL it"
    )
    for escape in ("|| true", "|| :", "; true", "--no-error-summary"):
        assert escape not in step, f"the type gate step swallows failure via {escape!r}"


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
_VERDICT_GETATTR = re.compile(r"getattr\(\s*[^,()]+,\s*[\"']verdict[\"']\s*,")


def _source_files() -> list[pathlib.Path]:
    return sorted((REPO / CHECKED_TREE).rglob("*.py"))


def test_no_type_ignore_survives_anywhere_in_the_source_tree():
    offenders = [
        location
        for path in _source_files()
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
        for path in _source_files()
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
