"""
Integration tests for CryptoShield Detection and Threat Scoring Engine (Phase 3).
"""

from pathlib import Path

import pytest

from app.core.event_bus import BUS
from app.core.models import (
    FileAction,
    IncidentStatus,
    Manifest,
    ManifestEntry,
    MonitoringEvent,
    ProcessAttribution,
    ThreatLevel,
)
from app.detection.detection_coordinator import DetectionCoordinator
from app.detection.test_harness import ControlledDetectionHarness


@pytest.fixture
def lab_manifest():
    return Manifest(
        manifest_version="1.0.0",
        lab_id="integration-lab",
        generated_at="2026-11-02T12:00:00Z",
        total_files=100,
        total_size_bytes=50000,
        canary_count=1,
        seed=42,
        entries={
            "Finance/salary_canary.csv": ManifestEntry(
                relative_path="Finance/salary_canary.csv",
                file_type="csv",
                file_size_bytes=50,
                data_classification="RESTRICTED",
                sha256="hashcanary",
                is_canary=True,
                department="Finance",
                created_at="2026-11-02T12:00:00Z",
            )
        },
    )


def test_coordinator_eventbus_integration(lab_manifest, tmp_path: Path):
    BUS.clear()
    coordinator = DetectionCoordinator(
        event_bus=BUS,
        manifest=lab_manifest,
        incidents_dir=tmp_path,
        cooldown_seconds=0.0,
    )
    coordinator.start()

    # Emit 45 file modifications via EventBus
    for i in range(45):
        ev = MonitoringEvent(
            event_id=f"burst-ev-{i}",
            timestamp="2026-11-02T12:00:00Z",
            event_type="FILE_MODIFIED",
            source="WATCHDOG",
            relative_path=f"Finance/file_{i}.txt",
            operation=FileAction.MODIFY.value,
            metadata={"department": "Finance"},
        )
        BUS.publish(ev.to_bus_event())

    metrics = coordinator.get_metrics()
    assert metrics["events_processed"] == 45
    assert metrics["duplicate_events_ignored"] == 0
    assert len(coordinator.recent_detections) > 0

    latest = coordinator.recent_detections[-1]
    assert latest.threat_score >= 30
    assert "MASS_FILE_MODIFICATION" in latest.reasons

    coordinator.stop()
    BUS.clear()


def test_canary_breach_creates_incident(lab_manifest, tmp_path: Path):
    BUS.clear()
    coordinator = DetectionCoordinator(
        event_bus=BUS,
        manifest=lab_manifest,
        incidents_dir=tmp_path,
        cooldown_seconds=0.0,
    )
    coordinator.start()

    ev = MonitoringEvent(
        event_id="canary-trip-int-1",
        timestamp="2026-11-02T12:00:00Z",
        event_type="CANARY_ACCESS",
        source="CONTROLLED_INSTRUMENTATION",
        relative_path="Finance/salary_canary.csv",
        is_canary=True,
        canary_id="Finance/salary_canary.csv",
        operation=FileAction.ACCESS.value,
        metadata={"department": "Finance"},
    )
    BUS.publish(ev.to_bus_event())

    incidents = coordinator.incident_manager.list_incidents()
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.threat_score >= 50
    assert len(inc.canary_events) >= 1
    assert inc.status == IncidentStatus.OPEN.value

    coordinator.stop()
    BUS.clear()


def test_all_10_controlled_scenarios_pass():
    """Verify all 10 Phase 3 controlled test scenarios execute cleanly and pass."""
    harness = ControlledDetectionHarness()
    results = harness.run_all_scenarios()

    assert len(results) == 10
    failed_scenarios = [r for r in results if not r.passed]
    assert len(failed_scenarios) == 0, f"Failed scenarios: {[f.name for f in failed_scenarios]}"

