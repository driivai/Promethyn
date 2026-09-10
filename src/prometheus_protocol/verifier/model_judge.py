"""Soft, model-judged verifier — an untrusted advisor outside the trusted core.

``ModelJudgeVerifier`` asks the model (through the provider boundary) whether a
candidate solution satisfies a task, and returns a SOFT-tier ``Evidence``. It
runs no code and has no side effect beyond the provider call. The bank decides
its weight: zero until calibrated against the authoritative reference, never
above it. A HARD verdict, when present, always decides the result; the judge
only modulates fused *confidence* and accrues calibration history.

Determinism: with a scripted provider the verdict is reproducible. An ABSTAIN
(the judge ran and declined) creates no calibration sample. A provider that
cannot be reached is not an ABSTAIN at all: ``verify`` returns ``Unavailable``
(could-not-run, no verdict), exactly as the hard runner does when its sandbox
cannot start — so a dead or hostile endpoint is never mistaken for a working
judge with nothing to say (threat model §4).
"""

from __future__ import annotations

import re
import time

from prometheus_protocol.core.diagnostics import Diagnostic
from prometheus_protocol.core.interfaces import Provider, Verifier
from prometheus_protocol.core.models import Evidence, Task, Tier, Unavailability, Unavailable, Verdict

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

    def verify(self, *, code: str, task: Task) -> Evidence | Unavailable:
        # The judge sees the task description and the candidate code only — never
        # the hidden cases. It is blind to tests, like the proposer.
        prompt = _build_prompt(task, code)
        started = time.monotonic()
        try:
            response = self._provider.assess(prompt=prompt, system=self._system_prompt)
        except Exception as exc:
            # The judge could not RUN — a timeout, a refused certificate, a
            # response bomb, a provider with no ``assess`` at all. That is not an
            # opinion, and it must not be reported as one: an ABSTAIN here is
            # indistinguishable from the model saying "I cannot decide", which
            # means a network adversary can manufacture abstentions at will and a
            # dead endpoint looks like a working judge with nothing to say. This
            # is the EX-1 distinction (``Unavailable`` carries no verdict) applied
            # at the transport layer. Advisory tier, so the bank never lets it
            # stand in for an authoritative check — but it is now visible AS a
            # could-not-run, and creates no calibration sample.
            return Unavailable(
                verifier_id=self.verifier_id,
                tier=self.tier,
                reason=Unavailability.INFRA_FAULT,
                # F8/A1 — the exception's TEXT is not quoted. The provider now
                # raises bounded diagnostics, but "the provider is careful" is
                # not a property this line can rely on: a future provider, or a
                # bug, would put upstream bytes here and they would land in a
                # persisted Unavailable. The TYPE is local; the reason code is
                # ours; neither can carry a body.
                detail=Diagnostic(
                    "unavailable", {"operation": "judge.assess"}
                ).message() + f" error_type={type(exc).__name__}",
            )
        duration = time.monotonic() - started
        verdict = _parse_verdict(response)
        # F8/A4 — SUCCESS IS ALSO A CHANNEL, and this was the proof of it. This
        # line used to be ``detail=response``: the RAW MODEL TEXT, verbatim, into
        # a persisted Evidence record. A 200 from an endpoint that reflects the
        # Authorization header therefore wrote "PASS <bearer token>" into the
        # ledger, on the SUCCESS path, where nobody was looking for a leak.
        #
        # THE DECISION: model output does NOT belong in the evidence record.
        # Only a bounded classification of it does — the verdict this side
        # parsed, and the length this side measured. See the module docstring
        # for the reasoning and the cost.
        return self._evidence(verdict, duration, detail=_judgement_detail(verdict, response))

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


def _judgement_detail(verdict: Verdict, response: str) -> str:
    """A bounded classification of a model response — never the response.

    WHAT IS KEPT: the verdict this side parsed, the CONFIDENCE this side parsed,
    and the response's length in characters. All three are computed here; none
    is a substring of what the model sent.

    The confidence is here because it has to be. ``benchmarks/judge_eval.py``
    read it back out of ``Evidence.detail`` with ``parse_confidence`` — the raw
    model text was load-bearing for calibration, which is exactly the trap A4
    warns about: remote text that some downstream feature depends on. Parsing it
    at the boundary keeps the feature and drops the text. A float in [0, 1] that
    this process parsed and range-checked is a local value; the sentence it came
    from is not.

    WHAT IS NOT KEPT, AND WHY NOT A DIGEST EITHER. A truncated SHA-256 of the
    response was considered — it would let an operator prove that two judgements
    saw the same text, and that a response captured out-of-band is the one that
    was judged. It is rejected because a hash of attacker-chosen content is
    still DERIVED from that content: for a short or low-entropy response (an
    endpoint that answers with nothing but a secret) the digest is brute-forcible,
    and a covert channel that is only usable sometimes is still a covert channel.
    The doctrine says the diagnostic is built from local values, and a digest of
    remote bytes is not one.
    """

    from prometheus_protocol.benchmarks.judge_eval import parse_confidence

    confidence = parse_confidence(response)
    parts = [
        "judge_verdict",
        f"verdict={verdict.name}",
        f"response_chars={len(response)}",
    ]
    if confidence is not None:
        parts.append(f"confidence={confidence}")
    return " ".join(parts)


def _clip(text: str | None, limit: int = 1000) -> str:
    if not text:
        return ""
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "\n... (truncated)"
