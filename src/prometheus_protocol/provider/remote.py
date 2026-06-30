"""Configuration-driven remote model boundary.

``RemoteModelProvider`` is the production proposer. It is vendor-neutral by
construction:

  * It is configured entirely from the environment (``PROM_API_BASE``,
    ``PROM_MODEL``, ``PROM_API_KEY``) via :class:`Config`.
  * It speaks the common chat-completions request contract as JSON over the
    standard-library HTTP client, so it has no third-party dependency.
  * It contains no brand strings or hosted-endpoint defaults. Point it at any
    gateway that accepts the chat-completions request shape.

The request is deterministic where the endpoint allows it (temperature 0).
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Sequence

from prometheus_protocol.core.config import Config
from prometheus_protocol.core.errors import ConfigError
from prometheus_protocol.core.interfaces import Provider
from prometheus_protocol.core.models import Skill

_LOG = logging.getLogger(__name__)

_DEFAULT_SYSTEM_PROMPT = (
    "You write small, correct Python functions. Reply with only the function "
    "source code, defining exactly the requested function, and nothing else."
)

_DEFAULT_ASSESS_SYSTEM_PROMPT = (
    "You are a strict, independent reviewer. Decide whether the candidate "
    "solution satisfies the task. Reply with exactly one word: PASS, FAIL, or "
    "ABSTAIN. Answer ABSTAIN if you cannot decide."
)


class ProviderError(RuntimeError):
    """Raised when the remote endpoint cannot be reached or returns bad data."""


class RemoteModelProvider(Provider):
    """Speaks the chat-completions request contract over stdlib HTTP."""

    def __init__(
        self,
        *,
        api_base: str,
        model: str,
        api_key: str | None = None,
        timeout_s: float = 30.0,
        system_prompt: str = _DEFAULT_SYSTEM_PROMPT,
    ) -> None:
        if not api_base:
            raise ConfigError("api_base is required (set PROM_API_BASE)")
        if not model:
            raise ConfigError("model is required (set PROM_MODEL)")
        self.api_base = api_base.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout_s = timeout_s
        self.system_prompt = system_prompt

    @classmethod
    def from_config(cls, config: Config) -> "RemoteModelProvider":
        return cls(
            api_base=config.api_base or "",
            model=config.model or "",
            api_key=config.api_key,
            timeout_s=config.request_timeout_s,
        )

    def propose_solution(
        self,
        *,
        prompt: str,
        entry_point: str,
        skills: Sequence[Skill] = (),
    ) -> str:
        payload = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": _build_user_message(prompt, entry_point, skills)},
            ],
        }
        data = self._post("/chat/completions", payload)
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError(f"unexpected response shape: {exc}") from exc
        return _extract_code(content)

    def assess(self, *, prompt: str, system: str | None = None) -> str:
        payload = {
            "model": self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system or _DEFAULT_ASSESS_SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        }
        data = self._post("/chat/completions", payload)
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError(f"unexpected response shape: {exc}") from exc

    def _post(self, path: str, payload: dict) -> dict:
        url = self.api_base + path
        # Endpoint and model only — the API key is never logged.
        _LOG.debug("POST %s (model=%s)", url, self.model)
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise ProviderError(f"endpoint returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise ProviderError(f"could not reach endpoint: {exc.reason}") from exc
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise ProviderError(f"endpoint returned non-JSON body: {exc}") from exc


def _build_user_message(
    prompt: str, entry_point: str, skills: Sequence[Skill]
) -> str:
    parts: list[str] = []
    if skills:
        parts.append("Relevant lessons learned from earlier work:")
        for skill in skills:
            parts.append(f"\n## {skill.title}\n{skill.body}")
        parts.append("")
    parts.append(prompt)
    parts.append(f"\nDefine a function named `{entry_point}`.")
    return "\n".join(parts)


def _extract_code(content: str) -> str:
    """Pull a code block out of a chat response, tolerating prose around it."""

    text = content.strip()
    fence = "```"
    if fence not in text:
        return text
    segments = text.split(fence)
    # Fenced blocks are the odd-indexed segments. Prefer the first non-empty.
    for segment in segments[1::2]:
        block = segment
        # Drop an optional language tag on the opening fence line.
        newline = block.find("\n")
        if newline != -1 and " " not in block[:newline].strip():
            block = block[newline + 1:]
        block = block.strip()
        if block:
            return block
    return text
