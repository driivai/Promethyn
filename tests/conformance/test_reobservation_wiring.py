"""The wiring guard: re-observation is configured at every composition root.

WHY THIS MODULE EXISTS. ``tests/conformance/test_reobservation_branch_delete.py``
proves the re-observation mechanism thirty ways, and every one of those proofs
builds the controller by hand. None of them proves the mechanism is REACHED by
anything shipped. It was not: when the mechanism merged, every non-test
construction of ``ExecutionController`` omitted ``reobservation=``, the argument
defaulted to ``None``, and ``None`` is exactly the unfixed path the reproduction
measures. A feature no composition root wires is a test suite, not a feature.

WHY A SOURCE-LEVEL GUARD AND NOT AN ASSERTION ON AN INSTANCE. An assertion that
one factory returns a configured controller is a statement about that factory.
The property that has to hold is about the CLASS: no construction of it anywhere
in the shipped tree may leave the argument off. That is a statement about a set
of call sites, and the only instrument that is total over that set is one that
reads the sites. So this walks the source.

WHAT THIS DOES NOT DO. It reads syntax, not semantics. It can see that
``reobservation=`` is passed; it cannot see that the value is a registry that
observes anything — a root passing a registry with every class opted out would
satisfy this guard. The *content* of each root's registry is pinned by
``test_reobservation_branch_delete.py`` (the factory root, PART 7) and by
``test_the_factory_opts_branch_delete_out_for_a_non_git_principal`` below.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

from prometheus_protocol.policy.reobservation import (
    NOT_THIS_PRINCIPAL,
    PHASE_ONE_NOT_COVERED,
)
from prometheus_protocol.policy.snapshot import (
    ACTION_BRANCH_DELETE,
    ACTION_CLASSES,
    ACTION_DATABASE_MIGRATE,
    ACTION_SANDBOX_EXECUTE,
)
from prometheus_protocol.runtime.factory import build_reobservation

SRC = Path(__file__).resolve().parents[2] / "src" / "prometheus_protocol"

CONTROLLER = "ExecutionController"
SERVICE = "PendingActionService"

#: The construction sites this guard knows about, as ``(module, enclosing def)``
#: pairs. Pinned as a SET, not a count: a count is not a composition, and a scan
#: that silently found nothing would otherwise read as a pass (doctrine #8).
#: A new composition root fails this pin, and the author who updates it has to
#: read the rule beneath it on the way past. That is the point.
PINNED_CONTROLLER_SITES = frozenset(
    {
        ("runtime/factory.py", "build_execution_controller"),
        ("orchestration/demo.py", "run_demo"),
        ("tools/stale_branch_demo.py", "run_hero"),
        ("benchmarks/sql_loop_demo.py", "run_loop"),
        ("benchmarks/grounding_loop_demo.py", "run_loop"),
    }
)

#: Bare ``PendingActionService`` constructions that carry no registry, with the
#: reason each is not an approval path. The reason is not taken on trust:
#: ``test_an_exempt_service_never_reaches_a_comparison_method`` checks that the
#: variable each one is bound to is never used to approve or to drive a
#: comparison. An exemption that stops being true fails there.
EXEMPT_SERVICE_SITES = {
    ("cli/main.py", "_cmd_pending"): "lists and sweeps; decides nothing",
    ("cli/main.py", "_cmd_reject"): "rejects; a rejection needs no live state",
    ("cli/main.py", "_cmd_sweep"): "expires lapsed holds; decides nothing",
}
# ``execution/controller.py`` is deliberately NOT listed. Its own default
# construction forwards ``reobservation=reobservation``, so the scan reads it as
# wired and an exemption for it would be a stale promise — which is how this
# comment came to be written: the first draft exempted it and
# ``test_the_exempt_service_sites_are_all_still_there`` refused.

#: Methods that read or act on the pinned target state. A service built without
#: a registry must never be the receiver of one of these.
COMPARISON_METHODS = frozenset(
    {"approve", "pre_approval_entry", "require_state_unmoved_for_execution"}
)


# ---------------------------------------------------------------------------
# the scanner
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Site:
    module: str
    qualname: str
    lineno: int
    keywords: frozenset  # keyword names passed explicitly
    wires: bool  # ``reobservation=`` present and not the literal ``None``
    splat: bool  # ``**kwargs`` present, so the keyword set is not knowable
    bound_to: str | None  # the variable the construction is assigned to

    @property
    def where(self) -> tuple[str, str]:
        return (self.module, self.qualname)


class _Scanner(ast.NodeVisitor):
    def __init__(self, module: str, target: str) -> None:
        self.module = module
        self.target = target
        self._stack: list[str] = []
        self._assign_to: list[str | None] = [None]
        self.sites: list[Site] = []

    def _scoped(self, node):
        self._stack.append(node.name)
        self.generic_visit(node)
        self._stack.pop()

    visit_FunctionDef = _scoped
    visit_AsyncFunctionDef = _scoped
    visit_ClassDef = _scoped

    def visit_Assign(self, node: ast.Assign) -> None:
        name = None
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
        self._assign_to.append(name)
        self.generic_visit(node)
        self._assign_to.pop()

    def visit_Call(self, node: ast.Call) -> None:
        called = (
            node.func.id
            if isinstance(node.func, ast.Name)
            else getattr(node.func, "attr", None)
        )
        if called == self.target:
            explicit = {kw.arg for kw in node.keywords if kw.arg is not None}
            splat = any(kw.arg is None for kw in node.keywords)
            value = next(
                (kw.value for kw in node.keywords if kw.arg == "reobservation"), None
            )
            # A ``**kwargs`` splat makes the keyword set unknowable from the
            # source, so it is never accepted as wiring: "might pass it" is the
            # silent omission this guard exists to refuse.
            wires = (
                not splat
                and value is not None
                and not (isinstance(value, ast.Constant) and value.value is None)
            )
            self.sites.append(
                Site(
                    module=self.module,
                    qualname=".".join(self._stack) or "<module>",
                    lineno=node.lineno,
                    keywords=frozenset(explicit),
                    wires=wires,
                    splat=splat,
                    bound_to=self._assign_to[-1],
                )
            )
        self.generic_visit(node)


def _scan_source(source: str, *, module: str, target: str) -> list[Site]:
    scanner = _Scanner(module, target)
    scanner.visit(ast.parse(source))
    return scanner.sites


def _scan_tree(target: str) -> list[Site]:
    found: list[Site] = []
    for path in sorted(SRC.rglob("*.py")):
        module = path.relative_to(SRC).as_posix()
        found.extend(
            _scan_source(
                path.read_text(encoding="utf-8"), module=module, target=target
            )
        )
    return found


def _receiver_calls(module: str, variable: str) -> set[str]:
    """Every method called on ``variable`` in ``module``."""

    tree = ast.parse((SRC / module).read_text(encoding="utf-8"))
    return {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == variable
    }


# ---------------------------------------------------------------------------
# PART 1 — the scanner measures itself first
# ---------------------------------------------------------------------------
#
# Doctrine #4: every negative has a positive control, and doctrine #8: an
# instrument that returns an empty set reads downstream as a pass. The four
# tests below are what stops a broken scanner from certifying a broken tree.


_WIRED = "controller = ExecutionController(gate=g, executor=e, ledger=l, reobservation=r)"
_OMITTED = "controller = ExecutionController(gate=g, executor=e, ledger=l)"
_EXPLICIT_NONE = "controller = ExecutionController(gate=g, ledger=l, reobservation=None)"
_SPLAT = "controller = ExecutionController(gate=g, ledger=l, **kwargs)"


def test_the_scanner_finds_a_construction_at_all():
    """The discovery half. Without this, a scanner that found nothing would make
    every guard below pass by returning an empty set."""

    sites = _scan_source(
        f"def make():\n    {_WIRED}\n", module="synthetic.py", target=CONTROLLER
    )
    assert len(sites) == 1
    assert sites[0].where == ("synthetic.py", "make")
    assert sites[0].bound_to == "controller"


def test_the_scanner_accepts_a_site_that_wires_reobservation():
    (site,) = _scan_source(_WIRED, module="synthetic.py", target=CONTROLLER)
    assert site.wires is True


def test_the_scanner_flags_a_site_that_omits_the_argument():
    """The mutation that shipped: the argument simply not passed."""

    (site,) = _scan_source(_OMITTED, module="synthetic.py", target=CONTROLLER)
    assert site.wires is False


def test_the_scanner_flags_a_site_that_passes_the_literal_None():
    """Silent omission with extra steps. ``reobservation=None`` is byte-for-byte
    the unfixed path, so the keyword being PRESENT may not satisfy the guard."""

    (site,) = _scan_source(_EXPLICIT_NONE, module="synthetic.py", target=CONTROLLER)
    assert site.wires is False


def test_the_scanner_refuses_a_splat_as_evidence_of_wiring():
    """``**kwargs`` hides the keyword set. Unknowable is not the same as wired,
    and this guard may not read one as the other (doctrine #1)."""

    (site,) = _scan_source(_SPLAT, module="synthetic.py", target=CONTROLLER)
    assert site.splat is True
    assert site.wires is False


def test_the_scanner_names_the_enclosing_function_not_just_the_module():
    """Two roots in one module are two sites. The pin is ``(module, def)``,
    because a module-level pin would let a second root hide behind the first."""

    sites = _scan_source(
        f"def one():\n    {_WIRED}\n\n\ndef two():\n    {_OMITTED}\n",
        module="synthetic.py",
        target=CONTROLLER,
    )
    assert {s.qualname for s in sites} == {"one", "two"}
    assert {s.qualname for s in sites if not s.wires} == {"two"}


# ---------------------------------------------------------------------------
# PART 2 — the guard over the shipped tree
# ---------------------------------------------------------------------------


def test_the_scan_finds_exactly_the_pinned_composition_roots():
    """Membership, not count (G25). A new root fails here before it can fail
    silently at runtime; a root that disappears fails here too."""

    found = {site.where for site in _scan_tree(CONTROLLER)}
    assert found, "the scan found no controller construction at all"
    unpinned = found - PINNED_CONTROLLER_SITES
    missing = PINNED_CONTROLLER_SITES - found
    assert not unpinned, f"composition roots not pinned by this guard: {sorted(unpinned)}"
    assert not missing, f"pinned composition roots no longer present: {sorted(missing)}"


def test_every_composition_root_configures_reobservation():
    """THE GUARD. Every shipped construction of the controller passes a
    registry. This is the test that would have failed on the tree that merged
    the mechanism unwired."""

    omitted = [
        f"{site.module}:{site.lineno} ({site.qualname})"
        for site in _scan_tree(CONTROLLER)
        if not site.wires
    ]
    assert not omitted, (
        "composition roots construct ExecutionController without "
        f"reobservation=: {omitted}"
    )


def test_every_pending_service_either_carries_a_registry_or_is_named_exempt():
    """The second door. The controller builds its own service, but a root may
    hand one in — and a service built without a registry runs the pre-approval
    comparison against nothing."""

    unaccounted = []
    for site in _scan_tree(SERVICE):
        if site.wires:
            continue
        if site.where in EXEMPT_SERVICE_SITES:
            continue
        unaccounted.append(f"{site.module}:{site.lineno} ({site.qualname})")
    assert not unaccounted, (
        "PendingActionService built with no registry and no written exemption: "
        f"{unaccounted}"
    )


def test_the_exempt_service_sites_are_all_still_there():
    """An exemption for a site that no longer exists is a stale promise, and a
    stale promise in an allowlist is a hole the next edit falls into."""

    found = {site.where for site in _scan_tree(SERVICE) if not site.wires}
    stale = set(EXEMPT_SERVICE_SITES) - found
    assert not stale, f"exemptions for sites that no longer exist: {sorted(stale)}"


def test_an_exempt_service_never_reaches_a_comparison_method():
    """The exemptions say "this one decides nothing". This checks it rather than
    believing it: the variable each bare service is bound to is never the
    receiver of approve, pre_approval_entry or require_state_unmoved_for_execution.

    Adding ``service.approve(...)`` beside one of those CLI constructions fails
    here — which is the whole value of writing the exemption down.
    """

    for site in _scan_tree(SERVICE):
        if site.wires or site.where not in EXEMPT_SERVICE_SITES:
            continue
        if site.bound_to is None:
            continue  # not bound to a name; nothing can be called on it
        called = _receiver_calls(site.module, site.bound_to)
        forbidden = called & COMPARISON_METHODS
        assert not forbidden, (
            f"{site.module}:{site.lineno} is exempt as "
            f"{EXEMPT_SERVICE_SITES[site.where]!r} but {site.bound_to} "
            f"reaches {sorted(forbidden)}"
        )


def test_the_receiver_scan_sees_a_call_it_should_flag():
    """Positive control for the instrument above, which is otherwise a set
    intersection that is empty for two different reasons."""

    source = "def f():\n    service = PendingActionService(l)\n    service.approve(1)\n"
    tree = ast.parse(source)
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "service"
    }
    assert called & COMPARISON_METHODS == {"approve"}


# ---------------------------------------------------------------------------
# PART 3 — what the factory decides, per principal
# ---------------------------------------------------------------------------


def test_the_factory_observes_branch_delete_for_a_git_principal(tmp_path):
    registry = build_reobservation(
        target_canonical=f"git://{tmp_path}", base_branch="main"
    )

    assert sorted(registry.observers) == [ACTION_BRANCH_DELETE]
    assert registry.opted_out == {
        ACTION_SANDBOX_EXECUTE: PHASE_ONE_NOT_COVERED,
        ACTION_DATABASE_MIGRATE: PHASE_ONE_NOT_COVERED,
    }


def test_the_factory_opts_branch_delete_out_for_a_non_git_principal():
    """A sandbox deployment has no branch to read. That is a DIFFERENT fact from
    "the mechanism does not cover this class yet", and the two carry different
    reasons into every record — a record that said only "not observed" would
    make a deployment that cannot observe look like one that chose not to."""

    registry = build_reobservation(target_canonical="sandbox://execution")

    assert registry.observers == {}
    assert registry.opted_out[ACTION_BRANCH_DELETE] == NOT_THIS_PRINCIPAL
    assert registry.opted_out[ACTION_SANDBOX_EXECUTE] == PHASE_ONE_NOT_COVERED
    assert NOT_THIS_PRINCIPAL != PHASE_ONE_NOT_COVERED


@pytest.mark.parametrize("target", ["git:///tmp/x", "sandbox://execution", "db://main"])
def test_the_factory_always_returns_a_total_registry(target):
    """Total over the closed action-class set for every principal, so no class
    is ever unobserved by ABSENCE — the posture-by-absence shape G21 refuses."""

    # Every principal gets a total registry; a git one must name its base.
    registry = build_reobservation(
        target_canonical=target,
        base_branch="main" if target.startswith("git://") else None,
    )

    assert set(registry.observers) | set(registry.opted_out) == set(ACTION_CLASSES)
    assert not set(registry.observers) & set(registry.opted_out)


def test_the_factory_reuses_a_supplied_git_tool(tmp_path):
    """A root that already holds a GitTool passes it, so the observer and the
    merge proof read one repository through one instrument. Two tools would be
    two definitions of "unmerged" pinned to one hold."""

    from prometheus_protocol.sandbox.unsafe import UnsafeLocalSandbox
    from prometheus_protocol.tools.git import GitTool

    tool = GitTool(repo_path=tmp_path, sandbox=UnsafeLocalSandbox(), base_branch="main")
    registry = build_reobservation(
        target_canonical=f"git://{tmp_path}", git_tool=tool
    )

    observer = registry.observers[ACTION_BRANCH_DELETE]
    assert observer._tool is tool
