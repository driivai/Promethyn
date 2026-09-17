"""Persisted obligations survive controller replacement (F3)."""

import inspect
import json
from functools import cache, cached_property

import pytest

import test_reobservation_branch_delete as fx
from prometheus_protocol.execution.controller import ExecutionController
from prometheus_protocol.execution.models import PendingStatus
from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger
from prometheus_protocol.ledger.readers import reader_methods
from prometheus_protocol.policy.execution import ExecutionNotAuthorized
from prometheus_protocol.policy.reobservation import (
    MOMENT_PRE_APPROVAL,
    OUTCOME_UNAVAILABLE,
    StateUnreadable,
)


def reopen(controller, ledger, *, reobservation):
    spy = fx.Spy()
    return ExecutionController(
        gate=controller._gate,
        executor=spy,
        ledger=ledger,
        reobservation=reobservation,
    ), spy


def test_F3_observed_hold_reopened_without_registry_records_unavailable_and_refuses(tmp_path):
    fx._make_repo(tmp_path)
    controller, _, original = fx._controller(tmp_path, reobservation=fx._reobservation(tmp_path))
    # Use a file-backed ledger so the reload is a different connection/object.
    original.close()
    first = SqliteLedger(tmp_path / "holds.db")
    controller, _ = reopen(controller, first, reobservation=fx._reobservation(tmp_path))
    held = fx._hold(controller, fx._tool(tmp_path))
    assert held.record["target_state"]["observed"] is True
    fx._add_commit_to_branch(tmp_path)
    first.close()
    ledger = SqliteLedger(tmp_path / "holds.db")
    replacement, spy = reopen(controller, ledger, reobservation=None)

    with pytest.raises(StateUnreadable) as refused:
        replacement.approve(held.id, identity="reviewer")

    assert refused.value.reason == "target_state_unreadable"
    assert spy.calls == []
    assert replacement.pending.get(held.id).status == PendingStatus.PENDING
    observations = fx._observations(ledger)
    assert len(observations) == 1
    receipt = observations[0]["payload"]
    assert receipt["outcome"] == OUTCOME_UNAVAILABLE
    assert receipt["observed"]["moment"] == MOMENT_PRE_APPROVAL
    assert receipt["observed"]["unavailable"]["reason"] == "registry_unavailable"
    assert ledger.verify_chain().ok


def test_F3_observed_hold_with_working_registry_approves_and_executes(tmp_path):
    fx._make_repo(tmp_path)
    registry = fx._reobservation(tmp_path)
    controller, spy, ledger = fx._controller(tmp_path, reobservation=registry)
    held = fx._hold(controller, fx._tool(tmp_path))
    result = controller.approve(held.id, identity="reviewer")
    assert result.executed
    assert len(spy.calls) == 1
    assert [e["payload"]["outcome"] for e in fx._observations(ledger)] == ["matched", "matched"]
    assert ledger.verify_chain().ok


def _read(reader, pending_id):
    arguments = {"pending_id": pending_id, "threshold": 0.5, "workflow_id": "fixture"}
    supplied = {name: arguments[name] for name, parameter in inspect.signature(reader).parameters.items()
                if parameter.default is inspect.Parameter.empty}
    return reader(**supplied)


@pytest.mark.parametrize("method", reader_methods(SqliteLedger))
@pytest.mark.parametrize("attack", ["delete", "substitute"])
def test_every_derived_public_reader_refuses_non_authoritative_outcomes(tmp_path, method, attack):
    """Reader population is reflection-derived; aliases keep the same boundary."""
    import test_execution_authorization_record as held_fx
    ledger = SqliteLedger(":memory:")
    controller, _, _ = held_fx.controller(ledger, route_high_risk=True)
    hold = held_fx.hold(controller, held_fx.action())
    controller.approve(hold.id, identity="human")
    aliased_reader = getattr(ledger, method)
    _read(aliased_reader, hold.id)  # paired positive for this exact reader
    if attack == "delete":
        ledger._conn.execute("DELETE FROM executions")
        expected = "execution_row_missing"
    else:
        ledger._conn.execute("UPDATE executions SET pending_id = ?", (hold.id + 1,))
        expected = "outcome_differs_from_chain_entry"
    ledger._conn.commit()
    with pytest.raises(ExecutionNotAuthorized) as refusal:
        _read(aliased_reader, hold.id)
    assert refusal.value.reason == expected


@pytest.mark.parametrize("attack", ["delete", "substitute"])
def test_future_aliased_reader_is_guarded_without_registration(tmp_path, attack):
    from prometheus_protocol.ledger.sqlite_ledger import SqliteLedger as AliasedConstructor

    class FutureLedger(AliasedConstructor):
        def new_reader(self) -> list[dict]:
            # A new reader which DOES NOT call any existing public reader.
            return [dict(row) for row in self._conn.execute("SELECT * FROM executions")]

    import test_execution_authorization_record as held_fx
    ledger = FutureLedger(":memory:")
    controller, _, _ = held_fx.controller(ledger, route_high_risk=True)
    hold = held_fx.hold(controller, held_fx.action())
    controller.approve(hold.id, identity="human")
    assert ledger.new_reader()[0]["executed"] == 1
    if attack == "delete":
        ledger._conn.execute("DELETE FROM executions")
    else:
        ledger._conn.execute("UPDATE executions SET pending_id = ?", (hold.id + 1,))
    ledger._conn.commit()
    with pytest.raises(ExecutionNotAuthorized):
        ledger.new_reader()


def test_unannotated_future_public_reader_is_not_silently_unclassified():
    with pytest.raises(TypeError, match="unclassified public ledger API"):
        class FutureLedger(SqliteLedger):
            def undisclosed_reader(self):
                return []


@pytest.mark.parametrize("wrapper", [cached_property, cache])
def test_unsupported_public_descriptor_or_callable_is_refused(wrapper):
    """Cached readers must not become a silently unguarded API shape."""
    with pytest.raises(TypeError) as refusal:
        class FutureLedger(SqliteLedger):
            @wrapper
            def outcome(self) -> bool:
                return bool(self._conn.execute("SELECT executed FROM executions").fetchone()[0])
    assert str(refusal.value) == "unsupported public ledger reader shape: FutureLedger.outcome"


@pytest.mark.parametrize("property_reader", [False, True])
def test_new_scalar_readers_cannot_escape_the_default_guard(property_reader):
    """A bool/status projection is as authoritative as a returned row."""
    import test_execution_authorization_record as held_fx

    class FutureLedger(SqliteLedger):
        def ran(self) -> bool:
            return bool(self._conn.execute("SELECT executed FROM executions").fetchone()[0])

        @property
        def outcome_status(self) -> str:
            return str(self._conn.execute("SELECT detail FROM executions").fetchone()[0])

    ledger = FutureLedger(":memory:")
    controller, _, _ = held_fx.controller(ledger, route_high_risk=True)
    held = held_fx.hold(controller, held_fx.action())
    controller.approve(held.id, identity="human")
    assert ledger.ran() is True
    assert isinstance(ledger.outcome_status, str)
    ledger._conn.execute("UPDATE executions SET executed = 0, detail = 'foreign outcome'")
    ledger._conn.commit()
    with pytest.raises(ExecutionNotAuthorized):
        if property_reader:
            ledger.outcome_status
        else:
            ledger.ran()


@pytest.mark.parametrize("attack", ["delete", "substitute"])
def test_persisted_observation_obligation_cannot_be_erased_or_borrowed(tmp_path, attack):
    fx._make_repo(tmp_path)
    controller, _, ledger = fx._controller(tmp_path, reobservation=fx._reobservation(tmp_path))
    hold = fx._hold(controller, fx._tool(tmp_path))
    assert controller.pending.get(hold.id).record["target_state"]["observed"]
    record = dict(hold.record)
    if attack == "delete":
        record.pop("target_state")
    else:
        record["target_state"] = {"observed": False, "reason": "another deployment opted out"}
    ledger._conn.execute("UPDATE pending_actions SET authorization = ? WHERE id = ?", (json.dumps(record), hold.id))
    ledger._conn.commit()
    with pytest.raises(ExecutionNotAuthorized) as refusal:
        controller.pending.get(hold.id)
    assert refusal.value.reason == "record_differs_from_chain_entry"
