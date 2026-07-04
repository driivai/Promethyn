"""External tool connectors, each behind every existing safeguard.

A tool here is an adapter over the same ports the rest of the trusted core
uses: its operations run through the :class:`Sandbox`, its destructive actions
are :class:`ExecutableAction` values that exist only behind an approved
``GateDecision``, and its executions are recorded in the ledger like any
other. Connectors are deliberately narrow — explicit operation sets, no
generic pass-through.
"""

from prometheus_protocol.tools.git import (
    GitBranchDeleteExecutor,
    GitTool,
    GitToolError,
)

__all__ = ["GitTool", "GitBranchDeleteExecutor", "GitToolError"]
