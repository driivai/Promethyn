"""P0 regressions: candidate data must never become trusted verdict metadata.

Local subprocess fixtures are deliberately harmless; they test the protocol,
not containment. Real isolation coverage lives in conformance.
"""

import json
from pathlib import Path

import pytest

from prometheus_protocol.core.models import Case, Evidence, Task, Unavailable, Verdict
from prometheus_protocol.sandbox import Sandbox, SandboxResult, UnsafeLocalSandbox
from prometheus_protocol.verifier import _value_codec as codec
from prometheus_protocol.verifier.runner import SubprocessVerifier


def task(*answers):
    return Task(
        id="boundary",
        entry_point="answer",
        prompt="x",
        split="train",
        cases=tuple(Case(args=(), expected=x) for x in answers),
    )


def run(code, *answers):
    return SubprocessVerifier(sandbox=UnsafeLocalSandbox(), memory_mb=0).verify(
        code=code, task=task(*answers)
    )


@pytest.mark.parametrize(
    "code",
    [
        # The original P0: no function exists and no test case runs.
        (
            "import json, os\njson.dump({'passed':1,'total':1,'failures':[]}, "
            "open('result.json','w'))\nos._exit(0)"
        ),
        "print('all tests passed')\ndef answer(): return 0",
        (
            "import sys\nsys.modules['__main__']._equal = lambda a,b: True\n"
            "def answer(): return 0"
        ),
        (
            "class Liar:\n def __eq__(self, other): return True\n"
            "def answer(): return Liar()"
        ),
        "import os\nos.symlink('/dev/zero', 'result.json')\nos._exit(0)",
        "import os\nos.mkfifo('result.json')\nos._exit(0)",
        'import os\nos.write(1, b\'{"passed":1,"total":1,"failures":[]}\')\nos._exit(0)',
        (
            "from _value_codec import dumps\nimport os\n"
            "os.write(1, dumps([('ok',0)]).encode())\nos._exit(0)"
        ),
    ],
)
def test_candidate_cannot_award_itself_pass(code):
    result = run(code, 42)
    assert isinstance(result, Evidence)
    assert result.verdict == Verdict.FAIL
    assert result.total == 1 and result.passed_count == 0


def test_prints_and_stateful_calls_still_work():
    result = run(
        "n=0\ndef answer():\n global n\n n+=1\n print('hello')\n return n", 1, 2
    )
    assert result.verdict == Verdict.PASS
    assert result.passed_count == result.total == 2
    assert "hello" in result.stderr


def test_mutated_return_values_are_snapshotted():
    result = run("xs=[]\ndef answer():\n xs.append(1)\n return xs", [1], [1, 1])
    assert result.verdict == Verdict.PASS


def test_partial_success_count_is_computed_by_parent():
    result = run("def answer(): return 1", 1, 2)
    assert result.verdict == Verdict.FAIL
    assert result.passed_count == 1 and result.total == 2


class ReplySandbox(Sandbox):
    def __init__(self, wire, **flags):
        self.wire, self.flags = wire, flags

    def run(self, **kwargs):
        return SandboxResult(
            stdout=self.wire, exit_status=0, candidate_started=True, **self.flags
        )


def verify_wire(wire, **flags):
    return SubprocessVerifier(sandbox=ReplySandbox(wire, **flags)).verify(
        code="", task=task(42)
    )


@pytest.mark.parametrize(
    "wire",
    [
        "",
        "null",
        "NaN",
        '{"passed":1,"total":1}',
        codec.dumps([]),
        codec.dumps([("ok", 42), ("ok", 42)]),
        codec.dumps([("pass", 42)]),
        codec.dumps([["ok", 42]]),
        codec.dumps([("error", 42)]),
        codec.dumps([("ok", 42, "extra")]),
        codec.dumps([("ok", 42)]) + codec.dumps([("ok", 42)]),
        '["int", "' + "9" * 5000 + '"]',
        "[" * 2000 + "]" * 2000,
        " " * (codec.MAX_BYTES + 1),
        '["dict", [[["str","a"],["none",""]],[["str","a"],["none",""]]]]',
        '["dict", [[["list",[]],["none",""]]]]',
    ],
)
def test_malformed_or_incomplete_response_fails_closed(wire):
    result = verify_wire(wire)
    assert isinstance(result, Evidence)
    assert result.verdict == Verdict.FAIL
    assert result.total == 1 and result.passed_count == 0


@pytest.mark.parametrize(
    "flag", ["output_truncated", "memory_exceeded", "pids_exceeded"]
)
def test_resource_flags_override_correct_values(flag):
    assert (
        verify_wire(codec.dumps([("ok", 42)]), **{flag: True}).verdict == Verdict.FAIL
    )


@pytest.mark.parametrize("status", [None, 1, -9])
def test_abnormal_exit_overrides_correct_values(status):
    class CrashSandbox(Sandbox):
        def run(self, **kwargs):
            return SandboxResult(
                stdout=codec.dumps([("ok", 42)]),
                exit_status=status,
                candidate_started=True,
            )

    result = SubprocessVerifier(sandbox=CrashSandbox()).verify(code="", task=task(42))
    assert result.verdict == Verdict.FAIL


def test_timeout_overrides_correct_values():
    assert (
        verify_wire(codec.dumps([("ok", 42)]), timed_out=True).verdict
        == Verdict.ABSTAIN
    )


def test_correct_values_without_start_signal_are_unavailable():
    class NotStarted(Sandbox):
        def run(self, **kwargs):
            return SandboxResult(
                stdout=codec.dumps([("ok", 42)]), exit_status=0, candidate_started=False
            )

    result = SubprocessVerifier(sandbox=NotStarted()).verify(code="", task=task(42))
    assert isinstance(result, Unavailable)


def test_expected_answers_never_cross_sandbox_port():
    secret = "expected-only-7a82c934d56f"

    class InspectSandbox(Sandbox):
        def run(self, *, argv, workspace, limits, stdin=""):
            contents = [p.read_text() for p in Path(workspace).iterdir()]
            assert all(secret not in text for text in [*contents, *argv, stdin])
            assert any("input-visible" in text for text in contents)
            return SandboxResult(
                stdout=codec.dumps([("ok", secret)]),
                exit_status=0,
                candidate_started=True,
            )

    result = SubprocessVerifier(sandbox=InspectSandbox()).verify(
        code="",
        task=Task(
            id="x",
            prompt="x",
            split="train",
            entry_point="answer",
            cases=(Case(args=("input-visible",), expected=secret),),
        ),
    )
    # Supplying the right VALUE is permitted; this is not an attestation that
    # a particular function body executed. Counts/verdicts remain parent-owned.
    assert result.verdict == Verdict.PASS


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        42,
        1.25,
        "text",
        b"bytes",
        [1, {2: ("a", False)}],
        {1: "a", "1": "b"},
    ],
)
def test_builtin_values_round_trip_and_verify(value):
    restored = codec.loads(codec.dumps(value))
    assert type(restored) is type(value) and restored == value
    assert run(f"def answer(): return {value!r}", value).verdict == Verdict.PASS


@pytest.mark.parametrize(
    "got,expected,verdict",
    [
        (True, 1, Verdict.FAIL),
        ((1,), [1], Verdict.FAIL),
        (1.0000000001, 1.0, Verdict.PASS),
        (float("nan"), float("nan"), Verdict.FAIL),
        (float("inf"), float("inf"), Verdict.PASS),
    ],
)
def test_parent_comparison_semantics(got, expected, verdict):
    result = SubprocessVerifier(
        sandbox=ReplySandbox(codec.dumps([("ok", got)]))
    ).verify(code="", task=task(expected))
    assert result.verdict == verdict


def test_unsupported_trusted_cases_refuse_before_execution():
    class NeverRun(Sandbox):
        def run(self, **kwargs):
            pytest.fail("unsupported cases must not execute")

    result = SubprocessVerifier(sandbox=NeverRun()).verify(code="", task=task(object()))
    assert isinstance(result, Unavailable)


def test_expected_values_must_fit_complete_response_envelope():
    answer = None
    for _ in range(codec.MAX_DEPTH - 1):
        answer = [answer]
    # The bare value fits, but the case-result envelope would exceed the cap.
    codec.dumps([answer])

    class NeverRun(Sandbox):
        def run(self, **kwargs):
            pytest.fail("unrepresentable responses must be refused before execution")

    result = SubprocessVerifier(sandbox=NeverRun()).verify(code="", task=task(answer))
    assert isinstance(result, Unavailable)


def test_codec_depth_and_node_budgets():
    nested = None
    for _ in range(codec.MAX_DEPTH + 1):
        nested = [nested]
    with pytest.raises(ValueError):
        codec.dumps(nested)
    with pytest.raises(ValueError):
        codec.dumps([None] * codec.MAX_NODES)
    with pytest.raises(ValueError):
        codec.loads(json.dumps(["list", [["none", ""]] * codec.MAX_NODES]))
    with pytest.raises(ValueError):
        codec.loads(
            '["list",' * (codec.MAX_DEPTH + 1)
            + '["none",""]'
            + "]" * (codec.MAX_DEPTH + 1)
        )
