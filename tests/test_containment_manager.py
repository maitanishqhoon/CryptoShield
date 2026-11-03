"""
Unit tests for ContainmentManager (Phase 4).
"""

import subprocess
import sys
import pytest

from app.containment.containment_manager import ContainmentManager
from app.containment.lab_write_gate import LabWriteGate
from app.containment.process_controller import ControlledProcessController
from app.containment.process_registry import ControlledProcessRegistry
from app.core.event_bus import EventBus
from app.core.models import (
    ContainmentAction,
    ContainmentDecision,
    ContainmentStatus,
    ThreatLevel,
)


@pytest.fixture
def manager(tmp_path):
    bus = EventBus()
    registry = ControlledProcessRegistry()
    write_gate = LabWriteGate(base_lab_dir=tmp_path)
    controller = ControlledProcessController(
        registry=registry, write_gate=write_gate, graceful_timeout=1.0
    )
    containment_dir = tmp_path / "containment_records"
    mgr = ContainmentManager(
        event_bus=bus,
        registry=registry,
        write_gate=write_gate,
        controller=controller,
        containment_dir=containment_dir,
    )
    yield mgr, registry, write_gate, bus
    registry.clear()
    write_gate.clear()
    mgr.clear()


def test_containment_lifecycle_successful(manager, tmp_path):
    mgr, registry, write_gate, bus = manager

    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])

    run_id = "SIM-MGR-01"
    target_dir = tmp_path / "target_mgr_01"
    target_dir.mkdir()

    registry.register_process(
        simulation_run_id=run_id,
        process_handle=proc,
        pid=proc.pid,
        expected_identity="ManagerTestSimulator",
        associated_lab_target=str(target_dir),
    )
    write_gate.open_gate(run_id, target_dir)
    mgr.controller.register_control_channel(run_id, lambda: proc.terminate())

    events_emitted = []
    bus.subscribe("*", lambda ev: events_emitted.append(ev.event_type))

    decision = ContainmentDecision(
        decision_id="DEC-TEST-01",
        timestamp="2026-11-03T12:00:00Z",
        threat_score=85,
        severity=ThreatLevel.CRITICAL.value,
        decision_reason="CRITICAL simulated ransomware attack",
        recommended_action=ContainmentAction.CONTAIN_SIMULATION.value,
        auto_containment_authorized=True,
        explanation="Authorized containment test",
        simulation_run_id=run_id,
    )

    record = mgr.execute_containment(decision)

    assert record.final_status == ContainmentStatus.CONTAINED.value
    assert "LAB_WRITE_GATE_CLOSED" in record.actions_taken
    assert len(record.timeline) >= 4
    assert mgr.containments_completed == 1

    # Check disk persistence
    saved_file = mgr.containment_dir / f"{record.containment_id}.json"
    assert saved_file.exists()

    # Check EventBus events
    assert "CONTAINMENT_REQUESTED" in events_emitted
    assert "CONTAINMENT_STARTED" in events_emitted
    assert "LAB_WRITE_GATE_CLOSED" in events_emitted
    assert "CONTAINMENT_COMPLETED" in events_emitted


def test_idempotent_duplicate_containment(manager, tmp_path):
    mgr, registry, write_gate, _ = manager

    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])

    run_id = "SIM-MGR-IDEM"
    target_dir = tmp_path / "target_mgr_idem"
    target_dir.mkdir()

    registry.register_process(
        simulation_run_id=run_id,
        process_handle=proc,
        pid=proc.pid,
        expected_identity="IdempotentSimulator",
        associated_lab_target=str(target_dir),
    )
    write_gate.open_gate(run_id, target_dir)
    mgr.controller.register_control_channel(run_id, lambda: proc.terminate())

    decision = ContainmentDecision(
        decision_id="DEC-TEST-IDEM",
        timestamp="2026-11-03T12:00:00Z",
        threat_score=90,
        severity=ThreatLevel.CRITICAL.value,
        decision_reason="CRITICAL threat",
        recommended_action=ContainmentAction.CONTAIN_SIMULATION.value,
        auto_containment_authorized=True,
        explanation="Authorized",
        simulation_run_id=run_id,
    )

    rec1 = mgr.execute_containment(decision)
    assert rec1.final_status == ContainmentStatus.CONTAINED.value

    # Second call for the same run
    rec2 = mgr.execute_containment(decision)
    assert rec2.containment_id == rec1.containment_id
    assert mgr.containments_skipped == 1


def test_containment_unauthorized_recommends_only(manager):
    mgr, _, _, _ = manager

    decision = ContainmentDecision(
        decision_id="DEC-UNAUTH",
        timestamp="2026-11-03T12:00:00Z",
        threat_score=65,
        severity=ThreatLevel.HIGH.value,
        decision_reason="HIGH threat without run association",
        recommended_action=ContainmentAction.CONTAINMENT_RECOMMENDED.value,
        auto_containment_authorized=False,
        explanation="Unauthorized termination",
        simulation_run_id=None,
    )

    record = mgr.execute_containment(decision)
    assert record.final_status == ContainmentStatus.CONTAINMENT_RECOMMENDED.value
    assert record.failure_explanation == "Automatic containment not authorized by policy."

