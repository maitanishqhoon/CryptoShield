"""
Integration tests for DLP Coordinator, Subsystem Lifecycle, and Incident Correlation (Phase 8).
"""

from pathlib import Path
import pytest

from app.core.event_bus import EventBus
from app.core.models import DetectionResult, IncidentStatus, SecurityIncident
from app.detection.incident_manager import IncidentManager
from app.dlp.dlp_coordinator import DLPCoordinator
from app.dlp.models import DLPAction, DLPApprovalStatus, DLPProfile
from app.exfiltration.mock_receiver import MockReceiver
from app.exfiltration.models import TransferStatus
from app.exfiltration.transfer_monitor import TransferMonitor


def test_dlp_coordinator_status_and_profile_switching(tmp_path: Path):
    bus = EventBus()
    coord = DLPCoordinator(
        event_bus=bus,
        profile=DLPProfile.DEFAULT,
        policies_path=tmp_path / "policies.json",
        audit_log_path=tmp_path / "audit.log",
    )

    status = coord.get_status()
    assert status["is_active"] is True
    assert status["profile"] == "DEFAULT"
    assert status["total_rules"] >= 6
    assert status["pending_approvals_count"] == 0

    # Switch profile
    coord.set_profile(DLPProfile.STRICT)
    assert coord.policy_engine.profile == DLPProfile.STRICT
    assert coord.get_status()["profile"] == "STRICT"


def test_dlp_coordinator_approval_and_rejection_workflows(tmp_path: Path):
    bus = EventBus()
    coord = DLPCoordinator(
        event_bus=bus,
        profile=DLPProfile.DEFAULT,
        policies_path=tmp_path / "policies.json",
        audit_log_path=tmp_path / "audit.log",
    )

    # Trigger a quarantine
    eval_res = coord.evaluate_transfer(
        destination_endpoint="127.0.0.1:8999",
        payload_bytes=b"confidential financial audit",
        file_count=1,
        classifications=["CONFIDENTIAL"],
    )
    assert eval_res.action == DLPAction.REQUIRE_APPROVAL
    assert eval_res.approval_token is not None

    token = eval_res.approval_token
    assert coord.get_status()["pending_approvals_count"] == 1

    # Approve transfer
    ok, req = coord.approve_transfer(token, decided_by="compliance_officer")
    assert ok is True
    assert req.status == DLPApprovalStatus.APPROVED.value
    assert coord.get_status()["pending_approvals_count"] == 0


def test_dlp_coordinator_correlate_with_incident(tmp_path: Path):
    bus = EventBus()
    inc_dir = tmp_path / "incidents"
    inc_dir.mkdir(parents=True, exist_ok=True)
    inc_mgr = IncidentManager(event_bus=bus, incidents_dir=inc_dir)

    coord = DLPCoordinator(
        event_bus=bus,
        profile=DLPProfile.DEFAULT,
        policies_path=tmp_path / "policies.json",
        audit_log_path=tmp_path / "audit.log",
    )

    # Simulate DLP blocks
    coord.evaluate_transfer(
        destination_endpoint="127.0.0.1:8999",
        payload_bytes=b"canary leak",
        contains_canary=True,
    )
    coord.evaluate_transfer(
        destination_endpoint="127.0.0.1:8999",
        payload_bytes=b"restricted patent",
        classifications=["RESTRICTED"],
    )

    # Create an active SecurityIncident
    detection = DetectionResult(
        detection_id="DET-001",
        timestamp="2026-11-17T20:00:00Z",
        threat_score=85,
        severity="HIGH",
        assessment="High threat ransomware and canary activity detected",
        reasons=["High file encryption burst", "Canary file access"],
        affected_files_count=10,
        canary_access_count=1,
    )
    incident = inc_mgr.process_detection(detection)
    assert incident is not None
    assert incident.status == "OPEN"

    # Correlate DLP findings into incident
    correlated_inc = coord.correlate_with_incident(inc_mgr, incident_id=incident.incident_id)
    assert correlated_inc is not None
    assert correlated_inc.metadata["dlp_transfers_blocked"] == 2
    assert "dlp_metrics" in correlated_inc.metadata

    # Check timeline record
    timeline_actions = [entry["action"] for entry in correlated_inc.timeline]
    assert "DLP_POLICY_ENFORCED" in timeline_actions


def test_dlp_transfer_monitor_zero_bytes_interception(tmp_path: Path):
    bus = EventBus()
    receiver = MockReceiver(host="127.0.0.1", port=0)
    host, port = receiver.start()

    try:
        coord = DLPCoordinator(
            event_bus=bus,
            policies_path=tmp_path / "policies.json",
            audit_log_path=tmp_path / "audit.log",
        )
        monitor = TransferMonitor(event_bus=bus, mock_receiver=receiver, dlp_gate=coord.transfer_gate)

        # Attempt to transmit RESTRICTED data
        record = monitor.transmit_to_mock_endpoint(
            target_host=host,
            target_port=port,
            payload_bytes=b"HIGHLY_SECRET_KEY_EXFILTRATION_PAYLOAD",
            file_count=1,
            classifications=["RESTRICTED"],
            contains_canary=True,
        )

        assert record.status == TransferStatus.BLOCKED.value
        assert record.bytes_transferred == 0
        assert record.metadata.get("dlp_intercepted") is True
        assert record.metadata.get("dlp_action") == "BLOCK"

        # Verify receiver received 0 bytes
        metrics = receiver.get_metrics()
        assert metrics["total_bytes_received"] == 0
        assert metrics["total_connections"] == 0
    finally:
        receiver.stop()
