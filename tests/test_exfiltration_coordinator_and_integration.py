"""
Tests for Exfiltration Coordinator and Controlled Simulation Integration (Phase 7).
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path
import pytest

from app.core.event_bus import EventBus
from app.core.safety import generate_lab_marker
from app.detection.incident_manager import IncidentManager
from app.exfiltration.exfiltration_coordinator import ExfiltrationCoordinator
from app.simulation.exfiltration_simulator import ControlledExfiltrationSimulator


@pytest.fixture
def isolated_lab(tmp_path: Path):
    """Sets up an authenticated temporary laboratory for testing."""
    lab_dir = tmp_path / "test_lab"
    lab_dir.mkdir(parents=True, exist_ok=True)
    generate_lab_marker(base_lab_dir=lab_dir)
    return lab_dir


def test_coordinator_lifecycle():
    bus = EventBus()
    coord = ExfiltrationCoordinator(event_bus=bus, mock_host="127.0.0.1", mock_port=0)
    assert not coord.is_running()

    host, port = coord.start(ephemeral_port=True)
    assert coord.is_running()
    assert host == "127.0.0.1"
    assert port > 0

    status = coord.get_status()
    assert status["is_running"] is True
    assert status["threat_score"] == 0

    coord.stop()
    assert not coord.is_running()


def test_controlled_exfiltration_simulator_and_correlation(isolated_lab: Path):
    bus = EventBus()
    coord = ExfiltrationCoordinator(event_bus=bus, mock_host="127.0.0.1", mock_port=0)
    host, port = coord.start(ephemeral_port=True)

    sim = ControlledExfiltrationSimulator(
        base_lab_dir=isolated_lab,
        event_bus=bus,
        mock_receiver=coord.receiver,
    )
    try:
        # Prepare fixtures
        target = sim.prepare_fixtures(file_count=12, canary_count=2)
        assert target.exists()

        # Run simulation
        result = sim.run_simulation(mock_host=host, mock_port=port)
        assert result.files_read == 12
        assert result.canaries_read == 2
        assert result.bytes_staged > 0
        assert result.transfer_status == "COMPLETED"

        # Check assessment from coordinator
        assessment = coord.get_assessment()
        assert assessment.threat_score >= 60
        assert assessment.canary_reads_count >= 1
        assert "MASS_FILE_READ_BURST" in assessment.indicators
        assert "CANARY_HONEYPOT_COMPROMISED" in assessment.indicators
        assert "OUTBOUND_TRANSFER_EXECUTED" in assessment.indicators

        # Test incident manager correlation
        incidents_dir = isolated_lab / "incidents"
        inc_mgr = IncidentManager(event_bus=bus, incidents_dir=incidents_dir)

        # Create an incident via process_detection
        from datetime import datetime, timezone
        from app.core.models import DetectionResult
        detection = DetectionResult(
            detection_id="DET-TEST-01",
            timestamp=datetime.now(timezone.utc).isoformat(),
            threat_score=85,
            severity="HIGH",
            assessment="High threat ransomware detection",
            reasons=["MASS_FILE_MODIFICATION"],
            affected_files_count=1,
            canary_access_count=0,
            affected_files=["Finance/doc1.txt"],
            process_attribution="CONFIRMED",
            process_id=1234,
            process_name="test_worker",
        )
        incident = inc_mgr.process_detection(detection)
        assert incident is not None
        assert incident.incident_id in inc_mgr._incidents

        # Correlate exfiltration findings
        correlated = coord.correlate_with_incident(inc_mgr, incident_id=incident.incident_id)
        assert correlated is not None
        assert "exfiltration_assessment" in correlated.metadata
        assert correlated.metadata["exfiltration_threat_score"] == assessment.threat_score
        assert any(t["action"] == "EXFILTRATION_CORRELATED" for t in correlated.timeline)

    finally:
        sim.cleanup()
        assert not sim.target_dir.exists()
        coord.stop()
