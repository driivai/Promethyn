"""Soft grounding/faithfulness verifier — the first non-executable-truth domain.

``GroundingVerifier`` asks a model judge (through the provider boundary)
whether a candidate CLAIM is supported by a provided SOURCE text. There is no
program whose output is ground truth here — nothing to execute, nothing to
diff — so this verifier is **Tier.SOFT by construction and can never be
anything else**: it judges, it does not verify against executable reality.

The consequences are structural, not stylistic:

* Its Evidence is advisory. The bank will never let it decide a verdict on its
  own (a soft-only judgment is non-authoritative), and the action gate BLOCKS
  every non-authoritative judgment — so no output of this verifier, however
  confident, can authorize an action by itself. In this domain the HUMAN is
  the authoritative tier: a human grounding review enters as ``Tier.HUMAN``
  evidence, decides the fused verdict, and calibrates this judge, exactly as
  the sandbox calibrates the code judge.
* Its authority is bounded by its MEASURED false-PASS against gold labels
  (``benchmarks/grounding_eval.py``) — measured first, weighted second.
* A malformed or unparseable reply is an ABSTAIN — never an invented verdict,
  never a coerced confidence. An unavailable provider is likewise "no
  opinion".

The verdict vocabulary is the domain's (SUPPORTED / NOT-SUPPORTED / ABSTAIN),
mapped onto the protocol's PASS / FAIL / ABSTAIN. The production prompt asks
for a stated confidence inline because routing in a domain with no hard
backstop depends on it; the strict parser reads the verdict word only, and the
confidence is parsed separately (and separately strictly) by callers that need
it.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from prometheus_protocol.core.interfaces import Provider, Verifier
from prometheus_protocol.core.models import Evidence, Tier, Verdict

#: The production grounding-judge prompt. One verdict token, then a stated
#: confidence in [0, 1]. Judgment is entailment-by-the-source ONLY.
GROUNDING_JUDGE_SYSTEM_PROMPT = (
    "You are a strict grounding reviewer. Decide whether the CLAIM is fully "
    "supported by the SOURCE text alone. Only entailment by the source "
    "counts: outside knowledge, plausibility, or partial support do not. "
    "Reply with exactly one line: SUPPORTED, NOT-SUPPORTED, or ABSTAIN, "
    "followed by a space and your confidence in that verdict as a number "
    "between 0 and 1 (for example: SUPPORTED 0.9). Answer ABSTAIN if you "
    "cannot decide."
)

# First verdict token on the first non-empty line, allowing the hyphenated
# NOT-SUPPORTED as one token. Anything else — including "not", "unsupported",
# or prose — is an ABSTAIN: a verdict is never guessed from a malformed reply.
_FIRST_TOKEN = re.compile(r"[^A-Za-z]*([A-Za-z]+(?:-[A-Za-z]+)?)")
_VERDICT_BY_TOKEN = {
    "supported": Verdict.PASS,
    "not-supported": Verdict.FAIL,
    "abstain": Verdict.ABSTAIN,
}

# The stated confidence must immediately follow the verdict token as one
# well-formed number in [0, 1]; anything else is "unstated", never coerced.
# (Same guard discipline as the code-domain eval parser, with the hyphenated
# verdict token admitted.)
_CONFIDENCE = re.compile(
    r"^[^A-Za-z]*[A-Za-z]+(?:-[A-Za-z]+)?[\s:=,]*([01](?:\.\d+)?)(?![\w.,])"
)


@dataclass(frozen=True)
class GroundingTask:
    """A grounding-domain unit of work: judge claims against this source.

    ``prompt`` is the ask a proposer would answer (for example "State one
    fact from the source"); ``source`` is the text a claim must be entailed
    by. There are no hidden cases and no reference program — ground truth in
    this domain is a labelled human reference, which exists only on the
    evaluation side (``benchmarks/grounding_items.py``), never at runtime.
    """

    id: str
    source: str
    prompt: str = "State one claim that is supported by the source."


class GroundingVerifier(Verifier):
    """A soft verifier that judges claim-vs-source grounding via the provider."""

    VERIFIER_ID = "grounding-judge"
    TIER = Tier.SOFT

    def __init__(
        self,
        provider: Provider,
        *,
        verifier_id: str | None = None,
        system_prompt: str = GROUNDING_JUDGE_SYSTEM_PROMPT,
    ) -> None:
        self._provider = provider
        self.verifier_id = verifier_id or self.VERIFIER_ID
        self.tier = self.TIER
        self._system_prompt = system_prompt

    def verify(self, *, code: str, task: GroundingTask) -> Evidence:
        """Judge ``code`` (the candidate claim) against the task's source."""

        prompt = build_grounding_prompt(source=task.source, claim=code)
        started = time.monotonic()
        try:
            response = self._provider.assess(prompt=prompt, system=self._system_prompt)
        except Exception as exc:  # contained advisor: any failure is "no opinion"
            duration = time.monotonic() - started
            return self._evidence(
                Verdict.ABSTAIN, duration, detail=f"judge unavailable: {exc}"
            )
        duration = time.monotonic() - started
        verdict = parse_grounding_verdict(response)
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


def build_grounding_prompt(*, source: str, claim: str) -> str:
    return (
        "SOURCE:\n"
        f"{source.strip()}\n\n"
        "CLAIM:\n"
        f"{claim.strip()}\n\n"
        "Is the CLAIM fully supported by the SOURCE alone? Reply with exactly "
        "one line: SUPPORTED, NOT-SUPPORTED, or ABSTAIN, followed by your "
        "confidence between 0 and 1."
    )


def parse_grounding_verdict(response: str) -> Verdict:
    """Strictly read a grounding verdict from the judge's reply.

    First verdict token on the first non-empty line; anything unrecognised is
    ABSTAIN. Mirrors the code-domain judge's parser discipline.
    """

    if not response:
        return Verdict.ABSTAIN
    for line in response.strip().splitlines():
        if not line.strip():
            continue
        match = _FIRST_TOKEN.match(line)
        if not match:
            return Verdict.ABSTAIN
        return _VERDICT_BY_TOKEN.get(match.group(1).lower(), Verdict.ABSTAIN)
    return Verdict.ABSTAIN


def parse_grounding_confidence(detail: str) -> float | None:
    """Read the stated confidence from a grounding reply, if any.

    First non-empty line only; exactly one well-formed number in [0, 1]
    immediately after the verdict token. Anything else is "unstated" —
    a confidence is never coerced or invented.
    """

    if not detail:
        return None
    for line in detail.strip().splitlines():
        if not line.strip():
            continue
        match = _CONFIDENCE.match(line)
        if not match:
            return None
        value = float(match.group(1))
        return value if 0.0 <= value <= 1.0 else None
    return None


def _clip(text: str | None, limit: int = 1000) -> str:
    if not text:
        return ""
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "\n... (truncated)"
