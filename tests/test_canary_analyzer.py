"""
Unit tests for app.detection.canary_analyzer.
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.core.event_bus import BUS, Event
from app.core.models import (
    EventPriority,
    Manifest,
    ManifestEntry,
    MonitoringEvent,
    ProcessAttribution,
)
from app.detection.canary_analyzer import CanaryAnalyzer


@pytest.fixture
def mock_manifest():
    return Manifest(
        manifest_version="1.0.0",
        lab_id="test-lab-canary",
        generated_at="2026-11-02T12:00:00Z",
        total_files=2,
        total_size_bytes=100,
        canary_count=2,
        seed=42,
        entries={
            "Finance/salary_canary.csv": ManifestEntry(
                relative_path="Finance/salary_canary.csv",
                file_type="csv",
                file_size_bytes=50,
                data_classification="RESTRICTED",
                sha256="dummyhash1",
                is_canary=True,
                department="Finance",
                created_at="2026-11-02T12:00:00Z",
            ),
            "HR/payroll_canary.txt": ManifestEntry(
                relative_path="HR/payroll_canary.txt",
                file_type="txt",
                file_size_bytes=50,
                data_classification="CONFIDENTIAL",
                sha256="dummyhash2",
                is_canary=True,
                department="Human Resources",
                created_at="2026-11-02T12:00:00Z",
            ),
        },
    )


def test_canary_access_generates_high_priority_alert(mock_manifest):
    analyzer = CanaryAnalyzer(manifest=mock_manifest)

    ev = MonitoringEvent(
        event_id="canary-ev-1",
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type="CANARY_ACCESS",
        source="CONTROLLED_INSTRUMENTATION",
        relative_path="Finance/salary_canary.csv",
        is_canary=True,
        canary_id="Finance/salary_canary.csv",
        process_attribution=ProcessAttribution.CONFIRMED.value,
        process_id=1234,
        process_name="suspicious_proc",
    )

    evaluation = analyzer.evaluate_events([ev])

    assert evaluation.is_canary_tripped is True
    assert len(evaluation.alerts_generated) == 1
    alert = evaluation.alerts_generated[0]
    assert alert.priority == EventPriority.HIGH.value
    assert alert.target_path == "Finance/salary_canary.csv"
    assert alert.process_id == 1234
    assert any(i.indicator_name == "FIRST_CANARY_ACCESS" for i in evaluation.indicators)


def test_canary_duplicate_event_deduplication(mock_manifest):
    analyzer = CanaryAnalyzer(manifest=mock_manifest)

    ev = MonitoringEvent(
        event_id="canary-ev-repeat",
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type="CANARY_ACCESS",
        source="CONTROLLED_INSTRUMENTATION",
        relative_path="Finance/salary_canary.csv",
        is_canary=True,
    )

    # First call -> generates alert
    eval1 = analyzer.evaluate_events([ev])
    assert len(eval1.alerts_generated) == 1

    # Second call with same event_id -> should NOT generate another alert
    eval2 = analyzer.evaluate_events([ev])
    assert len(eval2.alerts_generated) == 0


def test_multiple_distinct_canary_access(mock_manifest):
    analyzer = CanaryAnalyzer(manifest=mock_manifest)

    ev1 = MonitoringEvent(
        event_id="ev-canary-1",
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type="CANARY_ACCESS",
        source="INSTRUMENTATION",
        relative_path="Finance/salary_canary.csv",
        is_canary=True,
    )
    ev2 = MonitoringEvent(
        event_id="ev-canary-2",
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type="CANARY_ACCESS",
        source="INSTRUMENTATION",
        relative_path="HR/payroll_canary.txt",
        is_canary=True,
    )

    evaluation = analyzer.evaluate_events([ev1, ev2])
    assert len(evaluation.unique_canaries_accessed) == 2
    assert any(i.indicator_name == "ADDITIONAL_CANARY_ACCESS" for i in evaluation.indicators)
    assert len(evaluation.alerts_generated) == 2


def test_canary_tampering_generates_critical_alert(mock_manifest):
    analyzer = CanaryAnalyzer(manifest=mock_manifest)

    ev_delete = MonitoringEvent(
        event_id="ev-canary-del",
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type="FILE_DELETED",
        source="WATCHDOG",
        relative_path="Finance/salary_canary.csv",
        is_canary=True,
    )

    evaluation = analyzer.evaluate_events([ev_delete])
    assert len(evaluation.alerts_generated) == 1
    alert = evaluation.alerts_generated[0]
    assert alert.priority == EventPriority.CRITICAL.value
    assert alert.alert_type == "CANARY_TAMPERING_BREACH"
    assert any(i.indicator_name == "CANARY_FILE_TAMPERED" for i in evaluation.indicators)

