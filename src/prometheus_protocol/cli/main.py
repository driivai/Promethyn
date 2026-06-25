"""Console entry point: ``prometheus-protocol``.

Subcommands:

  demo      Run a baseline then one learning cycle on the bundled example
            benchmark, using ephemeral storage. Offline and repeatable.
  baseline  Run the example benchmark once against the configured storage.
  cycle     Run one learning cycle against the configured storage.
  audit     Summarise the configured experience ledger.

Configuration comes from ``PROM_*`` environment variables (see
``prometheus_protocol.core.config.Config``).
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Sequence

from prometheus_protocol.core.config import Config
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.runtime.factory import build_orchestrator


def _print_run(label: str, report) -> None:
    print(f"{label}: {report.pass_rate * 100:.0f}% "
          f"({sum(1 for o in report.outcomes if o.passed)}/{len(report.outcomes)})")


def _cmd_demo() -> int:
    from prometheus_protocol._examples.python_functions import build_benchmark

    benchmark = build_benchmark()
    with tempfile.TemporaryDirectory(prefix="prom-demo-") as tmp:
        config = Config(
            provider="mock",
            registry_dir=Path(tmp) / "skills",
            ledger_path=":memory:",
        )
        orch = build_orchestrator(config)

        print("Prometheus Protocol — offline demo (simulated provider)\n")
        baseline = orch.baseline(benchmark.heldout)
        _print_run("Held-out baseline      ", baseline)

        cycle1 = orch.run_cycle(benchmark.train, benchmark.heldout, cycle=1)
        print(f"Mined skills           : {[s.id for s in cycle1.mined]}")
        print(f"Promoted skills        : {list(cycle1.promoted)}")
        print(f"Held-out after cycle 1 : {cycle1.post_heldout_rate * 100:.0f}%")

        for skill_id in cycle1.promoted:
            contribution = orch.ablation(benchmark.heldout, skill_id)
            print(f"Ablation ({skill_id}): +{contribution * 100:.0f}%")

        cycle2 = orch.run_cycle(benchmark.train, benchmark.heldout, cycle=2)
        print(f"Cycle 2 learned        : {cycle2.learned} "
              f"(mined {len(cycle2.mined)} skills)")
    return 0


def _cmd_baseline() -> int:
    from prometheus_protocol._examples.python_functions import build_benchmark

    config = Config.from_env()
    orch = build_orchestrator(config)
    benchmark = build_benchmark()
    report = orch.baseline(benchmark.tasks)
    _print_run("Baseline (all)   ", report)
    print(f"  train  : {report.rate_for('train') * 100:.0f}%")
    print(f"  heldout: {report.rate_for('heldout') * 100:.0f}%")
    return 0


def _cmd_cycle() -> int:
    from prometheus_protocol._examples.python_functions import build_benchmark

    config = Config.from_env()
    orch = build_orchestrator(config)
    benchmark = build_benchmark()
    report = orch.run_cycle(benchmark.train, benchmark.heldout, cycle=1)
    print(f"Held-out before : {report.baseline_heldout_rate * 100:.0f}%")
    print(f"Mined           : {[s.id for s in report.mined]}")
    print(f"Promoted        : {list(report.promoted)}")
    print(f"Held-out after  : {report.post_heldout_rate * 100:.0f}%")
    return 0


def _cmd_audit() -> int:
    config = Config.from_env()
    if config.ledger_path != Path(":memory:") and not Path(config.ledger_path).exists():
        print(f"no ledger found at {config.ledger_path}")
        return 1
    ledger = SqliteLedger(config.ledger_path)
    try:
        attempts = ledger.attempts()
        promotions = ledger.promotions()
    finally:
        ledger.close()
    print(f"ledger      : {config.ledger_path}")
    print(f"attempts    : {len(attempts)}")
    print(f"promotions  : {len(promotions)}")
    for promotion in promotions:
        print(
            f"  cycle {promotion['cycle']}: {promotion['action']} "
            f"{promotion['skill_id']} "
            f"({promotion['rate_before'] * 100:.0f}% -> "
            f"{promotion['rate_after'] * 100:.0f}%)"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prometheus-protocol",
        description="A verifiable, reversible, self-improving learning runtime.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="offline baseline + one learning cycle (ephemeral)")
    sub.add_parser("baseline", help="run the example benchmark once")
    sub.add_parser("cycle", help="run one learning cycle")
    sub.add_parser("audit", help="summarise the experience ledger")
    return parser


_COMMANDS = {
    "demo": _cmd_demo,
    "baseline": _cmd_baseline,
    "cycle": _cmd_cycle,
    "audit": _cmd_audit,
}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return _COMMANDS[args.command]()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
