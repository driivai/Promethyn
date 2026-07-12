"""Measure SOFT-judge calibration levers against the recorded baselines.

The independent-family judge is already adopted and proven. This driver measures
whether any of the candidate levers in ``verifier.soft_levers`` lowers SOFT
**false-PASS** (the dangerous direction) FURTHER, on the EXISTING hardest item
sets, through the EXISTING harness — so the numbers are directly comparable to
``docs/judge-quality.md``.

It reuses, unchanged: the item sets (``live_items_v2``, ``grounding_items_v2``),
the fixture-tested fold ``judge_eval.compute_metrics``, and the report renderers.
Only the *judge* is wrapped with the selected lever; nothing else moves. Adopt
nothing here — this reports; ``docs/soft-calibration.md`` records what it licenses.

Levers (``--lever``):

* ``baseline``      — the plain independent judge (the comparison point).
* ``threshold``     — accept a PASS only at stated confidence ≥ ``--min-confidence``
                      (else ABSTAIN). 1× cost.
* ``ensemble``      — N independent judges, unanimity to PASS. N× cost.
* ``k-sample``      — the same judge k times, ``--require`` majority/unanimous.
                      k× cost; a NO-OP unless ``PROM_JUDGE_TEMPERATURE`` > 0.
* ``adversarial``   — elicit the strongest case AGAINST, then re-decide. 2× cost.

The offline default is a deterministic PLUMBING SMOKE (scripted judge) that
proves the driver runs and renders; it is NOT a judge measurement. Real numbers
come from an OPERATOR ``--live`` dispatch (spends credits) — see
``docs/soft-calibration.md`` for the exact commands. Per-lever ARITHMETIC is
proven offline in ``tests/conformance/test_soft_levers.py`` before any live use.
"""

from __future__ import annotations

import argparse
import os
from typing import Sequence

from prometheus_protocol.core.interfaces import Provider, Verifier
from prometheus_protocol.verifier.grounding import (
    GROUNDING_JUDGE_SYSTEM_PROMPT,
    GroundingVerifier,
    parse_grounding_confidence,
)
from prometheus_protocol.verifier.model_judge import ModelJudgeVerifier
from prometheus_protocol.verifier.soft_levers import (
    AdversarialSelfCheckProvider,
    ConfidenceThresholdJudge,
    EnsembleJudge,
    RepeatedSamplingJudge,
)

LEVERS = ("baseline", "threshold", "ensemble", "k-sample", "adversarial")
CODE_SETS = ("live-v1", "live-v2")
GROUNDING_SETS = ("grounding-v1", "grounding-v2")


# --------------------------------------------------------------------------
# provider construction (live: remote; offline: scripted smoke)
# --------------------------------------------------------------------------


def _judge_models(config) -> list[str]:
    """The judge model list. ``PROM_JUDGE_MODELS`` (comma-separated) supplies an
    ensemble of independent models; otherwise the single ``PROM_JUDGE_MODEL``."""

    raw = os.environ.get("PROM_JUDGE_MODELS", "").strip()
    if raw:
        return [m.strip() for m in raw.split(",") if m.strip()]
    single = config.judge_model or config.model
    return [single] if single else []


def _remote_judge_provider(config, model: str, *, temperature: float) -> Provider:
    from prometheus_protocol.provider.remote import RemoteModelProvider

    return RemoteModelProvider(
        api_base=config.judge_api_base or config.api_base or "",
        model=model,
        api_key=config.judge_api_key or config.api_key,
        timeout_s=config.request_timeout_s,
        assess_temperature=temperature,
    )


# --------------------------------------------------------------------------
# domain judge factories (the EVAL system prompt elicits stated confidence)
# --------------------------------------------------------------------------


def _make_domain_judge(domain: str, provider: Provider) -> Verifier:
    if domain == "grounding":
        return GroundingVerifier(provider, system_prompt=GROUNDING_JUDGE_SYSTEM_PROMPT)
    from prometheus_protocol.benchmarks.judge_eval import EVAL_JUDGE_SYSTEM_PROMPT

    return ModelJudgeVerifier(provider, system_prompt=EVAL_JUDGE_SYSTEM_PROMPT)


def _confidence_parser(domain: str):
    if domain == "grounding":
        return parse_grounding_confidence
    from prometheus_protocol.benchmarks.judge_eval import parse_confidence

    return parse_confidence


def build_lever_judge(
    *,
    domain: str,
    lever: str,
    providers: Sequence[Provider],
    min_confidence: float,
    k: int,
    require: str,
    on_disagreement: str,
) -> tuple[Verifier, int]:
    """Wrap the base domain judge with the selected lever.

    Returns ``(judge, model_calls_per_item)``. ``providers`` supplies one
    provider for the single-judge levers, and N for the ensemble.
    """

    parser = _confidence_parser(domain)
    if lever == "baseline":
        return _make_domain_judge(domain, providers[0]), 1
    if lever == "threshold":
        base = _make_domain_judge(domain, providers[0])
        return ConfidenceThresholdJudge(
            base, min_confidence=min_confidence, confidence_parser=parser
        ), 1
    if lever == "ensemble":
        judges = [_make_domain_judge(domain, p) for p in providers]
        j = EnsembleJudge(judges, on_disagreement=on_disagreement)
        return j, j.model_calls_per_item
    if lever == "k-sample":
        base = _make_domain_judge(domain, providers[0])
        j = RepeatedSamplingJudge(base, k=k, require=require)
        return j, j.model_calls_per_item
    if lever == "adversarial":
        wrapped = AdversarialSelfCheckProvider(providers[0])
        return _make_domain_judge(domain, wrapped), 2
    raise ValueError(f"unknown lever {lever!r}")


# --------------------------------------------------------------------------
# running + rendering (reuses the existing harness end to end)
# --------------------------------------------------------------------------


def _run_and_render(*, domain: str, item_set: str, judge: Verifier, judge_model: str,
                    calls_per_item: int, lever: str, live: bool, arm: str) -> str:
    if domain == "grounding":
        from prometheus_protocol.benchmarks import grounding_eval as ge

        if item_set == "grounding-v2":
            from prometheus_protocol.benchmarks.grounding_items_v2 import (
                GROUNDING_ITEM_SET_VERSION_V2 as version,
                build_grounding_items_v2 as build_items,
            )
        else:
            from prometheus_protocol.benchmarks.grounding_items import (
                GROUNDING_ITEM_SET_VERSION as version,
                build_grounding_items as build_items,
            )
        items = build_items()
        rows = ge.run_grounding_eval(items, judge=judge)
        report = ge.render_grounding_report(
            rows, items, judge_model=judge_model,
            mode=f"lever={lever} | {'live provider' if live else 'offline scripted SMOKE'}",
            item_set_version=version,
        )
    else:
        from prometheus_protocol.benchmarks import judge_eval as je

        if item_set == "live-v2":
            from prometheus_protocol.benchmarks.live_items_v2 import (
                LIVE_ITEM_SET_VERSION as version, build_live_eval_items as build_items,
            )
        else:
            from prometheus_protocol.benchmarks.live_items import (
                LIVE_ITEM_SET_VERSION as version, build_live_eval_items as build_items,
            )
        from prometheus_protocol.verifier.runner import SubprocessVerifier

        items = build_items()
        reference = SubprocessVerifier(memory_mb=0)
        rows = je.run_judge_eval(items, judge=judge, reference=reference)
        report = je.render_report(
            rows, judge_model=judge_model,
            mode=f"lever={lever}, item set {version} | "
            f"{'live provider' if live else 'offline scripted SMOKE'}",
        )

    n_items = len(items)
    from prometheus_protocol.benchmarks.soft_calibration_report import render_block, summarize

    summary = summarize(
        rows, set_name=item_set, arm=arm, lever=lever,
        model_calls=calls_per_item * n_items,
    )
    return report + "\n" + render_block(summary)


# --------------------------------------------------------------------------
# offline plumbing smoke (deterministic; NOT a judge measurement)
# --------------------------------------------------------------------------


def _offline_providers(domain: str, lever: str) -> list[Provider]:
    """Deterministic scripted providers for the offline smoke. Illustrative
    only: it proves the driver runs and renders. The judge's real quality is a
    --live number; the arithmetic is proven in the tests."""

    if domain == "grounding":
        from prometheus_protocol.benchmarks.grounding_eval import (
            SCRIPTED_REPLIES_V2, ScriptedGroundingJudgeProvider,
        )
        from prometheus_protocol.benchmarks.grounding_items_v2 import build_grounding_items_v2

        items = build_grounding_items_v2()
        base = ScriptedGroundingJudgeProvider(items, SCRIPTED_REPLIES_V2, model="scripted-a")
        if lever == "ensemble":
            strict = ScriptedGroundingJudgeProvider(items, SCRIPTED_REPLIES_V2, model="scripted-b")
            return [base, strict]
        return [base]

    from prometheus_protocol.benchmarks.judge_eval import (
        SCRIPTED_REPLIES, ScriptedJudgeProvider,
    )

    base = ScriptedJudgeProvider(SCRIPTED_REPLIES, model="scripted-a")
    if lever == "ensemble":
        return [base, ScriptedJudgeProvider(SCRIPTED_REPLIES, model="scripted-b")]
    return [base]


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m prometheus_protocol.benchmarks.soft_calibration_eval",
        description="Measure SOFT-judge calibration levers vs the recorded baseline.",
    )
    p.add_argument("--item-set", choices=CODE_SETS + GROUNDING_SETS, default="grounding-v2")
    p.add_argument("--lever", choices=LEVERS, default="baseline")
    p.add_argument("--min-confidence", type=float, default=0.8,
                   help="threshold lever: minimum stated confidence to accept a PASS")
    p.add_argument("--k", type=int, default=3, help="k-sample lever: number of samples")
    p.add_argument("--require", choices=("majority", "unanimous"), default="majority",
                   help="k-sample lever: vote rule")
    p.add_argument("--on-disagreement", choices=("abstain", "fail"), default="abstain",
                   help="ensemble lever: what a non-unanimous vote returns")
    p.add_argument("--live", action="store_true",
                   help="judge via the configured provider(s) instead of the offline smoke")
    args = p.parse_args(argv)

    domain = "grounding" if args.item_set in GROUNDING_SETS else "code"

    if args.live:
        from prometheus_protocol.core.config import Config

        config = Config.from_env()
        models = _judge_models(config)
        if not models:
            print("error: no judge model configured (set PROM_JUDGE_MODEL, or "
                  "PROM_JUDGE_MODELS for an ensemble).")
            return 1
        if args.lever == "ensemble" and len(models) < 2:
            print("error: --lever ensemble needs >= 2 judge models "
                  "(set PROM_JUDGE_MODELS=modelA,modelB).")
            return 1
        temperature = config.judge_temperature
        if args.lever == "k-sample":
            if temperature <= 0.0:
                print("error: --lever k-sample at PROM_JUDGE_TEMPERATURE=0 draws "
                      "identical samples on a deterministic endpoint — a no-op that "
                      "would spend k× credits for a single-call result. Set "
                      "PROM_JUDGE_TEMPERATURE>0 to sample, or choose another lever.")
                return 1
            if len(models) != 1:
                models = models[:1]
            providers = [_remote_judge_provider(config, models[0], temperature=temperature)]
        else:
            providers = [_remote_judge_provider(config, m, temperature=temperature)
                         for m in models]
        judge_model = ",".join(getattr(pr, "model", "?") for pr in providers)
        # The arm is the correlated-grader axis: a judge sharing the actor's
        # model is the correlated arm; a distinct family is the independent arm.
        # The ensemble is the independence positive control by construction.
        if args.lever == "ensemble":
            arm = "independence-control"
        else:
            actor = config.model or ""
            arm = "correlated" if (models[0] and models[0] == actor) else "independent"
    else:
        providers = _offline_providers(domain, args.lever)
        judge_model = ",".join(getattr(pr, "model", "?") for pr in providers)
        arm = "scripted-smoke"
        if args.item_set in ("live-v1", "live-v2"):
            # The offline smoke has no scripted code-domain live set; use the
            # bundled ten-item reference so the driver still renders.
            print("[smoke] offline code-domain uses the bundled reference set, "
                  "not the live-v2 items; --live measures the real set.")

    judge, calls = build_lever_judge(
        domain=domain, lever=args.lever, providers=providers,
        min_confidence=args.min_confidence, k=args.k,
        require=args.require, on_disagreement=args.on_disagreement,
    )

    if not args.live and args.item_set in ("live-v1", "live-v2"):
        # Offline code smoke: reuse the bundled reference items directly.
        from prometheus_protocol.benchmarks.judge_eval import (
            build_eval_items, render_report, run_judge_eval,
        )
        from prometheus_protocol.verifier.runner import SubprocessVerifier

        from prometheus_protocol.benchmarks.soft_calibration_report import (
            render_block, summarize,
        )

        items = build_eval_items()
        rows = run_judge_eval(items, judge=judge, reference=SubprocessVerifier(memory_mb=0))
        print(render_report(rows, judge_model=judge_model,
                            mode=f"lever={args.lever} | offline scripted SMOKE"), end="")
        summary = summarize(rows, set_name="bundled-code-reference", arm=arm,
                            lever=args.lever, model_calls=calls * len(items))
        print("\n" + render_block(summary), end="")
        return 0

    print(_run_and_render(
        domain=domain, item_set=args.item_set, judge=judge, judge_model=judge_model,
        calls_per_item=calls, lever=args.lever, live=args.live, arm=arm,
    ), end="")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via main() in tests
    raise SystemExit(main())
