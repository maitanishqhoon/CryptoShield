"""
Integration tests for CryptoShield Phase 4 Containment Engine.
"""

import subprocess
import sys
import pytest

from app.containment.containment_coordinator import ContainmentCoordinator
from app.containment.containment_manager import ContainmentManager
from app.containment.containment_policy import ContainmentPolicy
from app.containment.lab_write_gate import LabWriteGate
from app.containment.process_controller import ControlledProcessController
from app.containment.process_registry import ControlledProcessRegistry
from app.core.event_bus import EventBus
from app.core.models import (
    ContainmentAction,
    DetectionReason,
    DetectionResult,
    ProcessAttribution,
    SecurityAlert,
    ThreatLevel,
    WriteGateState,
)


@pytest.fixture
def test_environment(tmp_path):
    bus = EventBus()
    registry = ControlledProcessRegistry()
    write_gate = LabWriteGate(base_lab_dir=tmp_path)
    controller = ControlledProcessController(
        registry=registry, write_gate=write_gate, graceful_timeout=1.0
    )
    containment_dir = tmp_path / "containment_audit"
    manager = ContainmentManager(
        event_bus=bus,
        registry=registry,
        write_gate=write_gate,
        controller=controller,
        containment_dir=containment_dir,
    )
    policy = ContainmentPolicy(
        auto_containment_enabled=True,
        critical_threshold=80,
        high_threshold=60,
    )
    coordinator = ContainmentCoordinator(
        event_bus=bus,
        policy=policy,
        manager=manager,
        registry=registry,
    )
    yield coordinator, manager, registry, write_gate, bus
    coordinator.stop()
    registry.clear()
    write_gate.clear()
    manager.clear()


def test_full_containment_pipeline_with_controlled_process(test_environment, tmp_path):
    coord, manager, registry, write_gate, _ = test_environment

    # Spawn real controlled child process
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])

    run_id = "SIM-INT-CRITICAL"
    target_dir = tmp_path / "target_int_critical"
    target_dir.mkdir()

    registry.register_process(
        simulation_run_id=run_id,
        process_handle=proc,
        pid=proc.pid,
        expected_identity="TestIntegrationProcess",
        associated_lab_target=str(target_dir),
        metadata={"simulation_run_id": run_id},
    )
    write_gate.open_gate(run_id, target_dir)
    manager.controller.register_control_channel(run_id, lambda: proc.terminate())

    # Start coordinator
    coord.start()

    # Emit Phase 3 CRITICAL DetectionResult with simulation run attribution
    detection = DetectionResult(
        detection_id="det-int-001",
        timestamp="2026-11-03T12:00:00Z",
        threat_score=85,
        severity=ThreatLevel.CRITICAL.value,
        assessment="CRITICAL: Ransomware-like mass file modification detected",
        reasons=[
            DetectionReason.MASS_FILE_MODIFICATION.value,
            DetectionReason.RAPID_FILE_RENAMING.value,
        ],
        affected_files_count=40,
        canary_access_count=0,
        process_id=proc.pid,
        process_name="python.exe",
        process_attribution=ProcessAttribution.CONFIRMED.value,
        metadata={"simulation_run_id": run_id},
    )

    decision = coord.handle_detection(detection)

    assert decision.auto_containment_authorized
    assert decision.recommended_action == ContainmentAction.CONTAIN_SIMULATION.value

    # Verify process stopped and write gate closed
    assert write_gate.get_state(run_id) == WriteGateState.CLOSED
    assert proc.poll() is not None

    # Verify subsequent writes rejected
    allowed, msg = write_gate.is_write_allowed(run_id, target_dir / "attack_file.txt")
    assert not allowed
    assert "closed" in msg.lower()

    # Verify metrics
    metrics = coord.get_metrics()
    assert metrics["containments_triggered"] == 1
    assert metrics["active_containments_completed"] == 1


def test_unknown_attribution_produces_recommendation_only(test_environment):
    coord, manager, _, _, _ = test_environment
    coord.start()

    detection = DetectionResult(
        detection_id="det-int-unknown",
        timestamp="2026-11-03T12:00:00Z",
        threat_score=90,
        severity=ThreatLevel.CRITICAL.value,
        assessment="CRITICAL: Unattributed ransomware activity",
        reasons=[DetectionReason.MASS_FILE_MODIFICATION.value],
        affected_files_count=50,
        canary_access_count=0,
        process_attribution=ProcessAttribution.UNKNOWN.value,
        metadata={},
    )

    decision = coord.handle_detection(detection)

    assert not decision.auto_containment_authorized
    assert decision.recommended_action == ContainmentAction.CONTAINMENT_RECOMMENDED.value
    assert coord.recommendations_made == 1
    assert manager.containments_completed == 0


def test_canary_alert_triggers_containment_when_associated(test_environment, tmp_path):
    coord, manager, registry, write_gate, _ = test_environment

    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])

    run_id = "SIM-INT-CANARY"
    target_dir = tmp_path / "target_int_canary"
    target_dir.mkdir()

    registry.register_process(
        simulation_run_id=run_id,
        process_handle=proc,
        pid=proc.pid,
        expected_identity="CanaryTargetProcess",
        associated_lab_target=str(target_dir),
    )
    write_gate.open_gate(run_id, target_dir)
    manager.controller.register_control_channel(run_id, lambda: proc.terminate())

    coord.start()

    alert = SecurityAlert(
        alert_id="ALT-CANARY-01",
        timestamp="2026-11-03T12:00:00Z",
        priority="CRITICAL",
        alert_type="CANARY_TAMPERING_BREACH",
        message="Canary decoy tampered",
        source_event_id="EV-1234",
        target_path="Finance/canary_demo.csv",
        process_id=proc.pid,
        metadata={"simulation_run_id": run_id},
    )

    decision = coord.handle_alert(alert)

    assert decision.auto_containment_authorized
    assert decision.recommended_action == ContainmentAction.CONTAIN_SIMULATION.value
    assert proc.poll() is not None
    assert write_gate.get_state(run_id) == WriteGateState.CLOSED

