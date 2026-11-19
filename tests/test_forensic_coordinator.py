"""
Unit tests for Forensic Coordinator (Phase 9).
"""

from __future__ import annotations

import json
from pathlib import Path
from app.core.event_bus import Event, EventBus
from app.core.models import SecurityIncident
from app.reporting.forensic_coordinator import FORENSIC_COORDINATOR, ForensicCoordinator


def test_coordinator_singleton():
    """Verify singleton pattern accessor."""
    coord1 = ForensicCoordinator.get_instance()
    coord2 = ForensicCoordinator.get_instance()
    assert coord1 is coord2
    assert FORENSIC_COORDINATOR is not None


def test_coordinator_generate_and_get(tmp_path: Path):
    """Verify report generation, indexing, caching, and retrieval."""
    bus = EventBus()
    reports_dir = tmp_path / "reports"
    incidents_dir = tmp_path / "incidents"
    reports_dir.mkdir(parents=True)
    incidents_dir.mkdir(parents=True)

    coord = ForensicCoordinator(
        event_bus=bus,
        reports_dir=reports_dir,
        incidents_dir=incidents_dir,
        auto_generate_on_resolve=False,
    )

    incident = SecurityIncident(
        incident_id="INC-COORD01",
        first_detected_at="2026-11-19T11:00:00+00:00",
        last_updated_at="2026-11-19T11:00:01+00:00",
        status="RESOLVED",
        threat_score=80,
        severity="HIGH",
        assessment="Assessment coord test",
        detection_reasons=["CANARY_FILE_ACCESS"],
    )

    # Generate report
    dossier = coord.generate_report(incident)
    assert dossier.report_id.startswith("REP-")
    assert dossier.incident_id == "INC-COORD01"
    assert coord.reports_generated_count == 1

    # Retrieve from cache
    cached = coord.get_report(dossier.report_id)
    assert cached is not None
    assert cached.report_id == dossier.report_id

    # Retrieve after cache clear (reads from disk)
    coord.clear()
    from_disk = coord.get_report(dossier.report_id)
    assert from_disk is not None
    assert from_disk.report_id == dossier.report_id


def test_coordinator_list_and_verify(tmp_path: Path):
    """Verify listing reports and verifying cryptographic seals."""
    bus = EventBus()
    reports_dir = tmp_path / "reports"
    incidents_dir = tmp_path / "incidents"
    reports_dir.mkdir(parents=True)
    incidents_dir.mkdir(parents=True)

    coord = ForensicCoordinator(
        event_bus=bus,
        reports_dir=reports_dir,
        incidents_dir=incidents_dir,
        auto_generate_on_resolve=False,
    )

    incident = SecurityIncident(
        incident_id="INC-COORD02",
        first_detected_at="2026-11-19T11:00:00+00:00",
        last_updated_at="2026-11-19T11:00:01+00:00",
        status="RESOLVED",
        threat_score=90,
        severity="CRITICAL",
        assessment="Coord list test",
    )

    dossier = coord.generate_report(incident)

    # List reports
    rep_list = coord.list_reports()
    assert len(rep_list) == 1
    meta = rep_list[0]
    assert meta.report_id == dossier.report_id
    assert meta.incident_id == "INC-COORD02"
    assert meta.threat_score == 90
    assert "json" in meta.export_files
    assert "markdown" in meta.export_files

    # Verify by report ID
    valid, msg = coord.verify_report(dossier.report_id)
    assert valid is True
    assert "verified" in msg.lower()
    assert coord.reports_verified_count == 1


def test_coordinator_eventbus_auto_generation(tmp_path: Path):
    """Verify EventBus auto-generation upon receiving SECURITY_INCIDENT_RESOLVED."""
    bus = EventBus()
    reports_dir = tmp_path / "reports"
    incidents_dir = tmp_path / "incidents"
    reports_dir.mkdir(parents=True)
    incidents_dir.mkdir(parents=True)

    coord = ForensicCoordinator(
        event_bus=bus,
        reports_dir=reports_dir,
        incidents_dir=incidents_dir,
        auto_generate_on_resolve=True,
    )

    incident_data = {
        "incident_id": "INC-BUS01",
        "first_detected_at": "2026-11-19T11:00:00+00:00",
        "last_updated_at": "2026-11-19T11:00:02+00:00",
        "status": "RESOLVED",
        "threat_score": 95,
        "severity": "CRITICAL",
        "assessment": "EventBus trigger test",
        "detection_reasons": ["CANARY_FILE_ACCESS"],
        "contributing_event_ids": [],
        "affected_paths": [],
        "canary_events": [],
        "process_attribution": "UNKNOWN",
        "process_id": None,
        "process_name": None,
        "assessment_history": [],
        "timeline": [],
        "metadata": {},
    }

    # Publish event
    bus.publish(
        Event(
            event_type="SECURITY_INCIDENT_RESOLVED",
            data=incident_data,
            source="test_harness",
        )
    )

    # Check that report was generated
    assert coord.reports_generated_count == 1
    reports = coord.list_reports()
    assert len(reports) == 1
    assert reports[0].incident_id == "INC-BUS01"
