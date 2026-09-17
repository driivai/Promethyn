"""Observed F3/reader mutation probes, exclusively in MutationWorktree.

The second-order runs delete every assert in the new proof module. Report the
surviving raises-based half separately; never present it as reason/receipt
coverage. Run with the repository's environment: python scripts/reachability_reader_proofs.py.
"""

from __future__ import annotations

import ast
import re

from mutation_worktree import MutationWorktree

TESTS = "tests/conformance/test_reachability_readers.py"
PENDING = "src/prometheus_protocol/execution/pending.py"
READERS = "src/prometheus_protocol/ledger/readers.py"
SQLITE = "src/prometheus_protocol/ledger/sqlite_ledger.py"


class WithoutAssertions(ast.NodeTransformer):
    def visit_Assert(self, node: ast.Assert) -> ast.Pass:
        return ast.copy_location(ast.Pass(), node)


def run() -> int:
    from prometheus_protocol.ledger.readers import reader_methods
    from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger

    mutations = (
        ("F3-permissive-none", PENDING, "        if pinned is None:\n", "        if self._reobservation is None or pinned is None:\n"),
        ("reader-guard-deleted", READERS, "    for name in reader_methods(cls):\n", "    for name in ():\n"),
        ("reader-context-substituted", SQLITE, "            snapshot = self._receipt_source()\n", "            snapshot = ReceiptSnapshot([], [], [])\n"),
        ("reader-derivation-handlisted", READERS, "    return tuple(readers)\n", f"    return {reader_methods(SqliteLedger)!r}\n"),
        ("unsupported-reader-refusal-deleted", READERS,
         '                raise TypeError(f"unsupported public ledger reader shape: {cls.__name__}.{name}")\n',
         '                pass  # mutated: silently ignore an unsupported reader\n'),
        ("unsupported-reader-classification-borrowed", READERS,
         '        descriptor = inspect.getattr_static(cls, name)\n',
         '        descriptor = inspect.getattr_static(cls, "chain_tip" if name == "outcome" else name)\n'),
    )
    with MutationWorktree(include_dirty=True) as tree:
        reds, summary = tree.pytest([TESTS])
        print(f"baseline: {summary}")
        clean = re.fullmatch(r"(\d+) passed in [\d.]+s", summary)
        if reds or clean is None:
            raise RuntimeError("baseline did not pass; no mutation evidence collected")
        baseline_count = int(clean.group(1))
        for label, path, old, new in mutations:
            for stripped in (False, True):
                tree.revert()
                tree.apply(path, old, new)
                if stripped:
                    original = (tree.path / TESTS).read_text()
                    weakened = ast.unparse(WithoutAssertions().visit(ast.parse(original))) + "\n"
                    tree.apply(TESTS, original, weakened)
                reds, summary = tree.pytest([TESTS])
                print(f"{label}{'-assertions-deleted' if stripped else ''}: {summary}")
                for node in reds:
                    print(f"  RED {node}")
                counts = re.fullmatch(r"(\d+) failed, (\d+) passed in [\d.]+s", summary)
                if not reds or counts is None:
                    raise RuntimeError(f"{label}: no valid red measurement")
                if int(counts.group(1)) + int(counts.group(2)) != baseline_count:
                    raise RuntimeError(f"{label}: proof population changed from {baseline_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
