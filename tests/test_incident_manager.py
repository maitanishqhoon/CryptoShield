"""
Unit tests for app.detection.incident_manager.
"""

from pathlib import Path

import pytest

from app.core.models import (
    DetectionReason,
    DetectionResult,
    IncidentStatus,
    MonitoringEvent,
    ThreatLevel,
)
from app.detection.incident_manager import IncidentManager


def make_test_detection(
    threat_score: int = 50,
    severity: str = ThreatLevel.MEDIUM.value,
    canary_count: int = 0,
    affected_files: list[str] = None,
) -> DetectionResult:
    return DetectionResult(
        detection_id="det-123",
        timestamp="2026-11-02T12:00:00Z",
        threat_score=threat_score,
        severity=severity,
        assessment="Suspicious file activity detected",
        reasons=[DetectionReason.MASS_FILE_MODIFICATION.value],
        affected_files_count=len(affected_files or []),
        canary_access_count=canary_count,
        affected_files=affected_files or ["Finance/doc1.txt"],
    )


def test_incident_creation_on_threshold(tmp_path: Path):
    mgr = IncidentManager(incidents_dir=tmp_path, auto_create_threshold=40)

    # Below threshold -> no incident
    det_low = make_test_detection(threat_score=20, severity=ThreatLevel.LOW.value)
    inc_low = mgr.process_detection(det_low)
    assert inc_low is None
    assert len(mgr.list_incidents()) == 0

    # Above threshold -> incident created
    det_med = make_test_detection(threat_score=50, severity=ThreatLevel.MEDIUM.value)
    inc = mgr.process_detection(det_med)
    assert inc is not None
    assert inc.status == IncidentStatus.OPEN.value
    assert inc.threat_score == 50
    assert len(mgr.list_incidents()) == 1
    assert (tmp_path / f"{inc.incident_id}.json").exists()


def test_incident_merging_evidence(tmp_path: Path):
    mgr = IncidentManager(incidents_dir=tmp_path, auto_create_threshold=40, merge_window_seconds=60.0)

    # Initial detection
    det1 = make_test_detection(threat_score=45, affected_files=["Finance/file1.txt"])
    inc1 = mgr.process_detection(det1)

    # Follow-up detection with higher score and more files
    det2 = DetectionResult(
        detection_id="det-456",
        timestamp="2026-11-02T12:00:10Z",
        threat_score=85,
        severity=ThreatLevel.CRITICAL.value,
        assessment="Escalated ransomware threat",
        reasons=[DetectionReason.RAPID_FILE_RENAMING.value],
        affected_files_count=1,
        canary_access_count=0,
        affected_files=["Finance/file2.encrypted"],
    )
    inc2 = mgr.process_detection(det2)

    # Should be the same incident updated
    assert inc1.incident_id == inc2.incident_id
    assert inc2.threat_score == 85
    assert inc2.severity == ThreatLevel.CRITICAL.value
    assert "Finance/file1.txt" in inc2.affected_paths
    assert "Finance/file2.encrypted" in inc2.affected_paths
    assert len(inc2.timeline) >= 2


def test_incident_lifecycle_acknowledge_and_resolve(tmp_path: Path):
    mgr = IncidentManager(incidents_dir=tmp_path, auto_create_threshold=40)

    det = make_test_detection(threat_score=60, severity=ThreatLevel.HIGH.value)
    inc = mgr.process_detection(det)

    # Acknowledge
    ack_inc = mgr.acknowledge_incident(inc.incident_id, investigator="SecAnalyst")
    assert ack_inc.status == IncidentStatus.INVESTIGATING.value

    # Resolve
    res_inc = mgr.resolve_incident(inc.incident_id, resolution_notes="False positive verified.")
    assert res_inc.status == IncidentStatus.RESOLVED.value

    # Subsequent detection should create a new incident now that previous is resolved
    det_new = make_test_detection(threat_score=65, severity=ThreatLevel.HIGH.value)
    inc_new = mgr.process_detection(det_new)
    assert inc_new.incident_id != inc.incident_id
    assert len(mgr.list_incidents()) == 2

