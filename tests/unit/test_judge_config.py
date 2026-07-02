"""Unit tests: the judge model is independently configurable from the actor.

An independent judge decorrelates grading from proposing. When the judge and
actor share a model (the default), behaviour is unchanged but the runtime says
so loudly, exactly once — a correlated-grader risk an operator should choose
knowingly, never silently.
"""

from __future__ import annotations

import logging

import pytest

from prometheus_protocol.core.config import Config
from prometheus_protocol.core.models import Case, Task, Verdict
from prometheus_protocol.provider.mock import MOCK_MODEL, MockProvider
from prometheus_protocol.provider.remote import RemoteModelProvider
from prometheus_protocol.runtime import factory
from prometheus_protocol.verifier.model_judge import ModelJudgeVerifier

_TASK = Task(id="t/f", entry_point="f", prompt="implement f", split="train",
             cases=(Case((1,), 1),))


@pytest.fixture(autouse=True)
def _fresh_notice_flag(monkeypatch):
    # Each test owns the once-per-process notice state.
    monkeypatch.setattr(factory, "_SHARED_JUDGE_MODEL_WARNED", False)


def _remote_config(**overrides) -> Config:
    base = dict(provider="remote", api_base="https://gw.example/v1",
                model="actor-1", api_key="k")
    base.update(overrides)
    return Config(**base)


# -- env resolution -----------------------------------------------------------


def test_judge_knobs_resolve_from_env():
    config = Config.from_env({
        "PROM_JUDGE_MODEL": "judge-1",
        "PROM_JUDGE_API_BASE": "https://other.example/v1",
        "PROM_JUDGE_API_KEY": "k2",
    })
    assert config.judge_model == "judge-1"
    assert config.judge_api_base == "https://other.example/v1"
    assert config.judge_api_key == "k2"
    empty = Config.from_env({})
    assert empty.judge_model is None
    assert empty.judge_api_base is None and empty.judge_api_key is None
    # Empty-string env values mean unset: the judge inherits the actor's
    # endpoint rather than sending a blank key to it.
    blank = Config.from_env({"PROM_JUDGE_API_BASE": "", "PROM_JUDGE_API_KEY": ""})
    assert blank.judge_api_base is None and blank.judge_api_key is None


# -- routing: the judge runs on the judge model -------------------------------


def test_remote_judge_routes_to_the_judge_model():
    provider = factory.build_judge_provider(_remote_config(judge_model="judge-1"))
    assert isinstance(provider, RemoteModelProvider)
    assert provider.model == "judge-1"
    # Endpoint and key inherit the actor's when no judge override is set.
    assert provider.api_base == "https://gw.example/v1"
    assert provider.api_key == "k"


def test_remote_judge_endpoint_override():
    provider = factory.build_judge_provider(_remote_config(
        judge_model="judge-1",
        judge_api_base="https://other.example/v1",
        judge_api_key="k2",
    ))
    assert provider.api_base == "https://other.example/v1"
    assert provider.api_key == "k2"


def test_mock_judge_gets_a_distinct_identity():
    provider = factory.build_judge_provider(Config(judge_model="judge-x"))
    assert isinstance(provider, MockProvider)
    assert provider.model == "judge-x"
    actor = factory.build_provider(Config())
    assert actor.model == MOCK_MODEL  # the actor identity is unchanged


# -- the shared-model notice --------------------------------------------------


def test_unset_judge_model_shares_the_actor_provider_and_notices_once(caplog):
    with caplog.at_level(logging.WARNING, logger="prometheus_protocol"):
        first = factory.build_judge_provider(Config())
        second = factory.build_judge_provider(Config())
    assert isinstance(first, MockProvider) and first.model == MOCK_MODEL
    assert isinstance(second, MockProvider) and second.model == MOCK_MODEL
    notices = [r for r in caplog.records if "PROM_JUDGE_MODEL" in r.getMessage()]
    assert len(notices) == 1  # loud, but exactly once per process
    assert notices[0].levelno == logging.WARNING


def test_remote_judge_equal_to_actor_model_is_shared_and_notices(caplog):
    with caplog.at_level(logging.WARNING, logger="prometheus_protocol"):
        provider = factory.build_judge_provider(_remote_config(judge_model="actor-1"))
    assert isinstance(provider, RemoteModelProvider)
    assert provider.model == "actor-1"
    assert any("correlated-grader" in r.getMessage() for r in caplog.records)


def test_distinct_judge_model_emits_no_notice(caplog):
    with caplog.at_level(logging.WARNING, logger="prometheus_protocol"):
        factory.build_judge_provider(_remote_config(judge_model="judge-1"))
        factory.build_judge_provider(Config(judge_model="judge-x"))
    assert not [r for r in caplog.records if "correlated-grader" in r.getMessage()]


def test_endpoint_knobs_without_independent_judge_model_warn(caplog):
    # Setting only the judge endpoint does not decorrelate anything; the
    # misconfiguration is loud rather than silently ignored.
    with caplog.at_level(logging.WARNING, logger="prometheus_protocol"):
        provider = factory.build_judge_provider(_remote_config(
            judge_api_base="https://other.example/v1",
        ))
    assert provider.api_base == "https://gw.example/v1"  # actor's, unchanged
    assert any("ignored without" in r.getMessage() for r in caplog.records)


# -- parity: judge verdicts are unchanged by the wiring ------------------------


def test_mock_judge_verdict_is_unchanged_by_independence():
    # The offline provider does not implement assess() either way, so the judge
    # abstains identically whether shared or independent.
    shared = ModelJudgeVerifier(factory.build_judge_provider(Config()))
    independent = ModelJudgeVerifier(
        factory.build_judge_provider(Config(judge_model="judge-x"))
    )
    code = "def f(n):\n    return n\n"
    assert shared.verify(code=code, task=_TASK).verdict == Verdict.ABSTAIN
    assert independent.verify(code=code, task=_TASK).verdict == Verdict.ABSTAIN
