"""Console entry point: ``prometheus-protocol``.

Subcommands:

  demo      Run a baseline then one learning cycle on the bundled example
            benchmark, using ephemeral storage. Offline and repeatable.
  baseline  Run the example benchmark once against the configured storage.
  cycle     Run one learning cycle against the configured storage.
  status    Show the configured storage, promoted skills, and verifier trust
            ranking. Read-only: it runs nothing and changes nothing.
  audit     Summarise the configured experience ledger.

Configuration comes from ``PROM_*`` environment variables (see
``prometheus_protocol.core.config.Config``).

Known errors (a misconfigured provider, an unreadable state file) are reported
as a single ``error: <message>`` line on stderr with a non-zero exit, never a
raw traceback. Pass ``-v`` for lifecycle logging and ``-vv`` to also surface the
full traceback of a handled error.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import tempfile
from importlib.metadata import PackageNotFoundError, version as _dist_version
from pathlib import Path
from typing import Sequence

from prometheus_protocol.core.config import Config
from prometheus_protocol.core.errors import PrometheusError
from prometheus_protocol.execution.pending import PendingActionService
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.provider.remote import ProviderError
from prometheus_protocol.registry.markdown_registry import MarkdownSkillRegistry
from prometheus_protocol.runtime.factory import (
    build_execution_controller,
    build_orchestrator,
)
from prometheus_protocol.verifier.bank import VerifierBank
from prometheus_protocol.verifier.store import SqliteTrustStore

_LOG = logging.getLogger("prometheus_protocol")

# Known, user-facing failure modes. These are presented as a clean message and
# a non-zero exit; anything outside this set is a bug and is left to propagate.
_KNOWN_ERRORS = (PrometheusError, ProviderError, ValueError, FileNotFoundError)


def _print_run(label: str, report) -> None:
    print(f"{label}: {report.pass_rate * 100:.0f}% "
          f"({sum(1 for o in report.outcomes if o.passed)}/{len(report.outcomes)})")


def _cmd_demo(args: argparse.Namespace) -> int:
    from prometheus_protocol._examples.python_functions import build_benchmark

    benchmark = build_benchmark()
    with tempfile.TemporaryDirectory(prefix="prom-demo-") as tmp:
        config = Config(
            provider="mock",
            registry_dir=Path(tmp) / "skills",
            ledger_path=":memory:",
        )
        orch = build_orchestrator(config)

        print("Promethyn — offline demo (simulated provider)\n")
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


def _cmd_baseline(args: argparse.Namespace) -> int:
    from prometheus_protocol._examples.python_functions import build_benchmark

    config = Config.from_env()
    orch = build_orchestrator(config)
    benchmark = build_benchmark()
    report = orch.baseline(benchmark.tasks)
    _print_run("Baseline (all)   ", report)
    print(f"  train  : {report.rate_for('train') * 100:.0f}%")
    print(f"  heldout: {report.rate_for('heldout') * 100:.0f}%")
    return 0


def _cmd_cycle(args: argparse.Namespace) -> int:
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


def _cmd_status(args: argparse.Namespace) -> int:
    """Render configured storage, promoted skills, and the trust ranking.

    Strictly read-only: it never proposes, verifies, mines, or promotes, and it
    does not create state that is not already there — a path that does not yet
    exist is reported as empty rather than initialised.
    """

    config = Config.from_env()
    _LOG.info("status: reading state (read-only)")

    print("Promethyn — status\n")
    print(f"provider     : {config.provider}")
    if config.provider != "mock":
        print(f"model        : {config.model or '(unset)'}")
    print(f"model-judge  : {'on' if config.enable_model_judge else 'off'}")
    print(f"registry dir : {config.registry_dir}")
    print(f"ledger       : {config.ledger_path}")
    print(f"trust store  : {config.trust_store_path}")

    print("\nskills (promoted, in registry):")
    if not _existing_dir(config.registry_dir):
        print("  (none — no registry directory yet)")
    else:
        skills = MarkdownSkillRegistry(config.registry_dir).all()
        if not skills:
            print("  (none)")
        for skill in skills:
            print(f"  {skill.id}  {skill.title}")

    print("\nverifier trust ranking (most reliable first):")
    _print_trust_ranking(config.trust_store_path)
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
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


def _open_ledger_for_pending(config: Config) -> SqliteLedger | None:
    """Open the configured ledger for the pending-action interface, read-safe.

    A ``:memory:`` or not-yet-created ledger has no pending actions to show or
    resolve, so we report that rather than initialise state.
    """

    if config.ledger_path == Path(":memory:") or not Path(config.ledger_path).exists():
        print(f"no ledger found at {config.ledger_path}")
        return None
    return SqliteLedger(config.ledger_path)


def _cmd_pending(args: argparse.Namespace) -> int:
    """List actions halted for human review (read-only)."""

    config = Config.from_env()
    ledger = _open_ledger_for_pending(config)
    if ledger is None:
        return 0
    try:
        pending = PendingActionService(ledger).list_pending()
    finally:
        ledger.close()
    print("Promethyn — pending actions (awaiting human approval)\n")
    if not pending:
        print("  (none)")
        return 0
    for action in pending:
        print(
            f"  #{action.id}  {action.subject_id}  "
            f"[{action.judgment.verdict.value} conf={action.judgment.confidence:.2f} "
            f"risk={action.risk_class}]"
        )
        print(f"      reason: {action.reason}")
    print(
        "\nApprove with:  prometheus-protocol approve <id> --by <you>\n"
        "Reject with :  prometheus-protocol reject <id> --by <you>"
    )
    return 0


def _cmd_approve(args: argparse.Namespace) -> int:
    """Record a human approval, then drive the action to execution.

    The approval is recorded first; unless ``--no-exec`` is given, the approved
    action is executed through the SAME gated, sandboxed, audited controller path
    (never a shortcut around the gate or sandbox). If no isolating sandbox is
    available it fails closed — the approval stands and the refusal is recorded,
    but nothing runs unsandboxed.
    """

    config = Config.from_env()
    ledger = _open_ledger_for_pending(config)
    if ledger is None:
        return 1
    try:
        controller = build_execution_controller(config, ledger=ledger)
        if controller.pending.get(args.id) is None:
            print(f"error: no pending action with id {args.id}", file=sys.stderr)
            return 1
        if args.no_exec:
            controller.pending.approve(args.id, identity=args.by, reason=args.reason or "")
            print(f"approved pending action #{args.id} as {args.by} (recorded, not executed)")
            return 0
        result = controller.approve(args.id, identity=args.by, reason=args.reason or "")
    except (ValueError, KeyError) as exc:
        # Already decided, expired, or unknown id: never silently overwritten.
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        ledger.close()
    if result.refused:
        print(
            f"approved pending action #{args.id} as {args.by}, but execution refused "
            f"(fail-closed): {result.detail}",
            file=sys.stderr,
        )
        return 1
    print(
        f"approved pending action #{args.id} as {args.by} and executed in sandbox "
        f"{result.sandbox_name!r} (exit {result.exit_status})"
    )
    return 0


def _cmd_reject(args: argparse.Namespace) -> int:
    """Record a human rejection. A rejected action is never executed."""

    config = Config.from_env()
    ledger = _open_ledger_for_pending(config)
    if ledger is None:
        return 1
    service = PendingActionService(ledger, ttl_seconds=config.pending_ttl_seconds)
    try:
        if service.get(args.id) is None:
            print(f"error: no pending action with id {args.id}", file=sys.stderr)
            return 1
        service.reject(args.id, identity=args.by, reason=args.reason or "")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        ledger.close()
    print(f"rejected pending action #{args.id} as {args.by}")
    return 0


def _cmd_sweep(args: argparse.Namespace) -> int:
    """Expire pending actions older than the configured TTL (an audited transition)."""

    config = Config.from_env()
    ledger = _open_ledger_for_pending(config)
    if ledger is None:
        return 0
    service = PendingActionService(ledger, ttl_seconds=config.pending_ttl_seconds)
    try:
        if config.pending_ttl_seconds <= 0:
            print("expiry is disabled (PROM_PENDING_TTL=0); nothing to sweep")
            return 0
        expired = service.sweep()
    finally:
        ledger.close()
    print(f"swept: {len(expired)} pending action(s) expired (TTL {config.pending_ttl_seconds}s)")
    for action in expired:
        print(f"  #{action.id}  {action.subject_id}")
    return 0


def _existing_dir(path: Path | str) -> bool:
    return str(path) != ":memory:" and Path(path).is_dir()


def _print_trust_ranking(trust_store_path: Path | str) -> None:
    """Print ``bank.rank()`` for the persisted trust store, read-only.

    If the store does not exist yet, report that rather than creating it.
    """

    if str(trust_store_path) == ":memory:" or not Path(trust_store_path).exists():
        print("  (no trust store yet — run a cycle to calibrate)")
        return
    store = SqliteTrustStore(trust_store_path)
    try:
        entries = VerifierBank(store).rank()
    finally:
        store.close()
    if not entries:
        print("  (no verifiers registered yet)")
        return
    for entry in entries:
        print(
            f"  {entry.verifier_id:<18} tier={entry.tier.value:<11} "
            f"reliability={entry.youden:+.3f}  samples={entry.samples}"
        )


def _product_version() -> str:
    """Resolve the installed version for the ``--version`` banner.

    Looks up the distribution (``prometheus-protocol``), not the import package,
    so this adds no new reference to the package identifier.
    """

    try:
        return _dist_version("prometheus-protocol")
    except PackageNotFoundError:
        return "0.0.0+local"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prometheus-protocol",
        description="Promethyn: a verifiable, reversible, self-improving learning runtime.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Promethyn {_product_version()}",
        help="show the Promethyn product name and version, then exit",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="increase logging (-v: lifecycle at INFO; -vv: DEBUG + tracebacks)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="offline baseline + one learning cycle (ephemeral)")
    sub.add_parser("baseline", help="run the example benchmark once")
    sub.add_parser("cycle", help="run one learning cycle")
    sub.add_parser("status", help="show storage, skills, and verifier ranking (read-only)")
    sub.add_parser("audit", help="summarise the experience ledger")
    sub.add_parser("pending", help="list actions halted for human approval (read-only)")
    sub.add_parser("sweep", help="expire pending actions older than the configured TTL")
    approve = sub.add_parser(
        "approve", help="approve a pending action and execute it through the sandbox"
    )
    approve.add_argument("id", type=int, help="the pending action id (see 'pending')")
    approve.add_argument("--by", required=True, help="the approver's identity (recorded)")
    approve.add_argument("--reason", default="", help="optional note recorded with the decision")
    approve.add_argument(
        "--no-exec",
        action="store_true",
        help="record the approval only; do not execute (default executes through the sandbox)",
    )
    reject = sub.add_parser("reject", help="record a human rejection of a pending action")
    reject.add_argument("id", type=int, help="the pending action id (see 'pending')")
    reject.add_argument("--by", required=True, help="the rejecter's identity (recorded)")
    reject.add_argument("--reason", default="", help="optional note recorded with the decision")
    return parser


_COMMANDS = {
    "demo": _cmd_demo,
    "baseline": _cmd_baseline,
    "cycle": _cmd_cycle,
    "status": _cmd_status,
    "audit": _cmd_audit,
    "pending": _cmd_pending,
    "sweep": _cmd_sweep,
    "approve": _cmd_approve,
    "reject": _cmd_reject,
}


def _resolve_log_level(verbose: int) -> int:
    """Resolve the log level: ``-v`` flags win, else ``PROM_LOG_LEVEL``, else WARNING."""

    if verbose >= 2:
        return logging.DEBUG
    if verbose == 1:
        return logging.INFO
    env = os.environ.get("PROM_LOG_LEVEL", "").strip()
    if env:
        named = logging.getLevelName(env.upper())
        if isinstance(named, int):
            return named
    return logging.WARNING


def _configure_logging(verbose: int) -> None:
    """Attach a single stderr handler to the package logger at the chosen level.

    Existing handlers are cleared first so repeated calls (e.g. in tests) do not
    accumulate duplicates. Propagation is left enabled so log capture in tests
    and any parent handlers still see records.
    """

    logger = logging.getLogger("prometheus_protocol")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(_resolve_log_level(verbose))


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _configure_logging(args.verbose)
    _LOG.info("command: %s", args.command)
    try:
        return _COMMANDS[args.command](args)
    except _KNOWN_ERRORS as exc:
        print(f"error: {exc}", file=sys.stderr)
        # The clean line above is the user-facing report; the traceback is kept
        # for -vv debugging without cluttering the default output.
        _LOG.debug("command %r failed", args.command, exc_info=True)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
