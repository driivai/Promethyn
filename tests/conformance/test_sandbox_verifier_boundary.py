"""P0 verifier boundary through real namespace and container adapters.

CI requires these runtimes explicitly: unavailable means FAIL, not a skip.
"""

import os
import subprocess

import pytest

from prometheus_protocol.core.models import Case, Evidence, Task, Verdict
from prometheus_protocol.sandbox import NamespaceSandbox
from prometheus_protocol.sandbox.container import ContainerSandbox
from prometheus_protocol.verifier.runner import SubprocessVerifier


def required(name):
    return os.environ.get(name, "").lower() in {"1", "true", "yes", "on"}


@pytest.fixture(scope="module")
def real_container():
    if not required("PROM_REQUIRE_CONTAINER"):
        pytest.skip("set PROM_REQUIRE_CONTAINER=1 for real-container verification")
    if not ContainerSandbox.available():
        pytest.fail("PROM_REQUIRE_CONTAINER=1 but container runtime unavailable")
    sandbox = ContainerSandbox()
    pull = subprocess.run(
        [sandbox.runtime, "pull", sandbox.image],
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert pull.returncode == 0, "could not pull required sandbox image"
    return sandbox


CASES = [
    ("def answer(): return 42", Verdict.PASS),
    ("def answer(): return 0", Verdict.FAIL),
    (
        (
            "import json, os\njson.dump({'passed':1,'total':1,'failures':[]}, "
            "open('result.json','w'))\nos._exit(0)"
        ),
        Verdict.FAIL,
    ),
    (
        (
            "import sys\nsys.modules['__main__']._equal=lambda a,b: True\n"
            "def answer(): return 0"
        ),
        Verdict.FAIL,
    ),
    (
        (
            "from _value_codec import dumps\nimport os\n"
            "os.write(1, dumps([('ok',0)]).encode())\nos._exit(0)"
        ),
        Verdict.FAIL,
    ),
    (
        (
            "class Liar:\n def __eq__(self,other): return True\n"
            "def answer(): return Liar()"
        ),
        Verdict.FAIL,
    ),
]


def check(sandbox, code, verdict):
    task = Task(
        id="p0",
        entry_point="answer",
        prompt="x",
        split="train",
        cases=(Case(args=(), expected=42),),
    )
    result = SubprocessVerifier(sandbox=sandbox, memory_mb=0, timeout_s=30).verify(
        code=code, task=task
    )
    assert isinstance(result, Evidence), result
    assert result.verdict == verdict, result.detail
    assert result.total == 1
    assert result.passed_count == (1 if verdict == Verdict.PASS else 0)


@pytest.mark.parametrize("code,verdict", CASES)
def test_namespace_sandbox_verifier_boundary(code, verdict):
    if not NamespaceSandbox.available():
        if required("PROM_REQUIRE_SANDBOX"):
            pytest.fail("PROM_REQUIRE_SANDBOX=1 but namespace runtime unavailable")
        pytest.skip("namespace runtime unavailable")
    check(NamespaceSandbox(), code, verdict)


@pytest.mark.parametrize("code,verdict", CASES)
def test_real_container_sandbox_verifier_boundary(real_container, code, verdict):
    check(real_container, code, verdict)
