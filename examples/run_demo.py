"""Runnable example: the full loop on the bundled benchmark, offline.

Run it directly::

    python examples/run_demo.py

It uses the default simulated provider, an ephemeral registry, and an
in-memory ledger, so it needs no network and no API key. Expect a held-out
baseline of 40%, 100% after one cycle, a +60% ablation contribution for the
mined skill, and a second cycle that finds nothing new to learn.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from prometheus_protocol import Config, build_orchestrator
from prometheus_protocol._examples.python_functions import build_benchmark


def main() -> None:
    benchmark = build_benchmark()
    with tempfile.TemporaryDirectory(prefix="prom-example-") as tmp:
        config = Config(registry_dir=Path(tmp) / "skills", ledger_path=":memory:")
        orch = build_orchestrator(config)

        baseline = orch.baseline(benchmark.heldout)
        print(f"held-out baseline      : {baseline.pass_rate * 100:.0f}%")

        cycle1 = orch.run_cycle(benchmark.train, benchmark.heldout, cycle=1)
        print(f"promoted               : {list(cycle1.promoted)}")
        print(f"held-out after cycle 1 : {cycle1.post_heldout_rate * 100:.0f}%")

        for skill_id in cycle1.promoted:
            print(f"ablation {skill_id}: "
                  f"+{orch.ablation(benchmark.heldout, skill_id) * 100:.0f}%")

        cycle2 = orch.run_cycle(benchmark.train, benchmark.heldout, cycle=2)
        print(f"cycle 2 learned        : {cycle2.learned}")


if __name__ == "__main__":
    main()
