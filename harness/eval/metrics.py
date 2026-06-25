"""Small, dependency-free metrics over :class:`RunReport` objects."""

from __future__ import annotations

from typing import Sequence

from prometheus_protocol.core.models import SPLITS, Task
from prometheus_protocol.runtime.orchestrator import Orchestrator, RunReport


def pass_rate(report: RunReport) -> float:
    """Overall fraction of outcomes that passed."""

    return report.pass_rate


def split_rates(report: RunReport) -> dict[str, float]:
    """Pass rate broken down by split."""

    return {split: report.rate_for(split) for split in SPLITS}


def ablation_table(
    orchestrator: Orchestrator,
    heldout_tasks: Sequence[Task],
    skill_ids: Sequence[str],
) -> dict[str, float]:
    """Held-out contribution of each skill id, as ``rate_with - rate_without``."""

    return {
        skill_id: orchestrator.ablation(heldout_tasks, skill_id)
        for skill_id in skill_ids
    }
