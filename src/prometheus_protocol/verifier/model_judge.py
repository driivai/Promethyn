"""Soft, model-judged verifier — an untrusted advisor outside the trusted core.

``ModelJudgeVerifier`` asks the model (through the provider boundary) whether a
candidate solution satisfies a task, and returns a SOFT-tier ``Evidence``. It
runs no code and has no side effect beyond the provider call. The bank decides
its weight: zero until calibrated against the authoritative reference, never
above it. A HARD verdict, when present, always decides the result; the judge
only modulates fused *confidence* and accrues calibration history.

Determinism: with a scripted provider the verdict is reproducible. Like the
hard runner, an ABSTAIN (the judge declines or the provider can't be reached)
creates no calibration sample.
"""

from __future__ import annotations

import re
import time

from prometheus_protocol.core.interfaces import Provider, Verifier
from prometheus_protocol.core.models import Evidence, Task, Tier, Verdict

_JUDGE_SYSTEM_PROMPT = (
    "You are a strict, independent reviewer. Decide whether the candidate "
    "solution satisfies the task. Reply with exactly one word: PASS, FAIL, or "
    "ABSTAIN. Answer ABSTAIN if you cannot decide."
)

# The judge is asked for a single leading verdict word. Match the first
# alphabetic token only, so a verbose or code-shaped reply (e.g. one containing
# the Python ``pass`` keyword) does not masquerade as a verdict.
_FIRST_WORD = re.compile(r"[^A-Za-z]*([A-Za-z]+)")
_VERDICT_BY_WORD = {
    "pass": Verdict.PASS,
    "fail": Verdict.FAIL,
    "abstain": Verdict.ABSTAIN,
}


class ModelJudgeVerifier(Verifier):
    """A soft verifier that grades an outcome via the model provider."""

    VERIFIER_ID = "model-judge"
    TIER = Tier.SOFT

    def __init__(
        self,
        provider: Provider,
        *,
        verifier_id: str | None = None,
        system_prompt: str = _JUDGE_SYSTEM_PROMPT,
    ) -> None:
        self._provider = provider
        self.verifier_id = verifier_id or self.VERIFIER_ID
        self.tier = self.TIER
        self._system_prompt = system_prompt

    def verify(self, *, code: str, task: Task) -> Evidence:
        # The judge sees the task description and the candidate code only — never
        # the hidden cases. It is blind to tests, like the proposer.
        prompt = _build_prompt(task, code)
        started = time.monotonic()
        try:
            response = self._provider.assess(prompt=prompt, system=self._system_prompt)
        except Exception as exc:  # contained advisor: any failure is "no opinion"
            duration = time.monotonic() - started
            return self._evidence(
                Verdict.ABSTAIN, duration, detail=f"judge unavailable: {exc}"
            )
        duration = time.monotonic() - started
        verdict = _parse_verdict(response)
        return self._evidence(verdict, duration, detail=response)

    def _evidence(self, verdict: Verdict, duration_s: float, *, detail: str) -> Evidence:
        return Evidence(
            passed=(verdict == Verdict.PASS),
            total=1,
            passed_count=1 if verdict == Verdict.PASS else 0,
            failures=(),
            verifier_id=self.verifier_id,
            verdict=verdict,
            tier=self.tier,
            cost=duration_s,
            latency_ms=duration_s * 1000.0,
            detail=_clip(detail),
        )


def _build_prompt(task: Task, code: str) -> str:
    return (
        f"Task: {task.prompt}\n"
        f"The function to implement is `{task.entry_point}`.\n\n"
        "Candidate solution:\n"
        f"```python\n{code}\n```\n\n"
        "Does the candidate correctly satisfy the task? "
        "Reply with exactly one word: PASS, FAIL, or ABSTAIN."
    )


def _parse_verdict(response: str) -> Verdict:
    """Strictly read a verdict from the judge's reply.

    The judge is asked for a single word. We read the first verdict word on the
    first non-empty line; anything else (including a model that returned code
    instead of a verdict) is treated as ABSTAIN.
    """

    if not response:
        return Verdict.ABSTAIN
    for line in response.strip().splitlines():
        if not line.strip():
            continue
        match = _FIRST_WORD.match(line)
        if not match:
            return Verdict.ABSTAIN
        return _VERDICT_BY_WORD.get(match.group(1).lower(), Verdict.ABSTAIN)
    return Verdict.ABSTAIN


def _clip(text: str | None, limit: int = 1000) -> str:
    if not text:
        return ""
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "\n... (truncated)"
