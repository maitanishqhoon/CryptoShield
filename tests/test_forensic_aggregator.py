"""
Unit tests for Forensic Aggregator (Phase 9).
"""

from __future__ import annotations

import json
from pathlib import Path
from app.core.models import (
    IncidentStatus,
    ProcessAttribution,
    SecurityIncident,
)
from app.reporting.aggregator import ForensicAggregator
from app.reporting.models import ForensicDossier


def test_aggregator_basic_incident(tmp_path: Path):
    """Verify aggregator compiles a valid dossier from a SecurityIncident."""
    incidents_dir = tmp_path / "incidents"
    containment_dir = tmp_path / "containment"
    recovery_dir = tmp_path / "recovery" / "reports"
    dlp_log = tmp_path / "dlp" / "audit.log"
    manifest_path = tmp_path / "manifest.json"

    incidents_dir.mkdir(parents=True)
    containment_dir.mkdir(parents=True)
    recovery_dir.mkdir(parents=True)
    dlp_log.parent.mkdir(parents=True)

    # Write dummy manifest
    manifest_path.write_text(json.dumps({"total_files": 1000}), encoding="utf-8")

    aggregator = ForensicAggregator(
        incidents_dir=incidents_dir,
        containment_dir=containment_dir,
        recovery_reports_dir=recovery_dir,
        dlp_audit_log_path=dlp_log,
        manifest_path=manifest_path,
    )

    incident = SecurityIncident(
        incident_id="INC-TEST01",
        first_detected_at="2026-11-19T10:00:00.000000+00:00",
        last_updated_at="2026-11-19T10:00:02.500000+00:00",
        status=IncidentStatus.OPEN.value,
        threat_score=85,
        severity="CRITICAL",
        assessment="CRITICAL: Ransomware heuristic threshold breached.",
        detection_reasons=["MASS_FILE_MODIFICATION", "CANARY_FILE_ACCESS"],
        contributing_event_ids=["EV-1", "EV-2", "EV-3"],
        affected_paths=["Finance/doc_1.txt", "Finance/doc_2.txt", "IT/server_cfg.json"],
        canary_events=[
            {
                "canary_id": "Finance/canary_tokens.json",
                "relative_path": "Finance/canary_tokens.json",
                "timestamp": "2026-11-19T10:00:01.000000+00:00",
                "event_type": "CANARY_ACCESS",
                "operation": "READ",
                "metadata": {"department": "Finance", "classification": "RESTRICTED"},
            }
        ],
        process_attribution=ProcessAttribution.CONFIRMED.value,
        process_id=4567,
        process_name="simulated_locker.py",
        timeline=[
            {
                "timestamp": "2026-11-19T10:00:00.000000+00:00",
                "action": "INCIDENT_CREATED",
                "description": "Incident opened with threat score 85.",
                "severity": "CRITICAL",
            }
        ],
        metadata={
            "exfiltration_assessment": {
                "assessment_id": "EXF-TEST01",
                "risk_tier": "HIGH",
                "threat_score": 75,
                "total_reads_observed": 10,
                "total_staged_bytes": 1024,
                "total_transfers_attempted": 1,
                "total_bytes_exfiltrated": 0,
                "indicators": ["CANARY_ACCESSED"],
            },
            "dlp_metrics": {
                "allowed_count": 0,
                "alerted_count": 0,
                "quarantined_count": 0,
                "blocked_count": 1,
                "blocked_bytes": 1024,
            },
        },
    )

    dossier = aggregator.aggregate(incident)

    assert isinstance(dossier, ForensicDossier)
    assert dossier.incident_id == "INC-TEST01"
    assert dossier.threat_score == 85
    assert dossier.severity == "CRITICAL"
    assert dossier.detection.canaries_compromised_count == 1
    assert "Finance" in dossier.detection.departments_targeted
    assert dossier.metrics.detection_latency_seconds == 2.5
    assert dossier.metrics.exfiltration_bytes_blocked == 1024
    assert dossier.metrics.zero_leakage_verified is True
    assert dossier.chain_of_custody is not None
    assert len(dossier.chain_of_custody.dossier_sha256) == 64


def test_aggregator_timeline_merging(tmp_path: Path):
    """Verify aggregator merges events from multiple subsystems in strict chronological order."""
    aggregator = ForensicAggregator(
        incidents_dir=tmp_path / "incidents",
        containment_dir=tmp_path / "containment",
        recovery_reports_dir=tmp_path / "recovery",
    )

    incident = SecurityIncident(
        incident_id="INC-TIME01",
        first_detected_at="2026-11-19T10:00:00+00:00",
        last_updated_at="2026-11-19T10:00:05+00:00",
        status="RESOLVED",
        threat_score=90,
        severity="CRITICAL",
        assessment="Assessment test",
        timeline=[
            {
                "timestamp": "2026-11-19T10:00:01+00:00",
                "action": "INCIDENT_CREATED",
                "description": "Opened",
            },
            {
                "timestamp": "2026-11-19T10:00:05+00:00",
                "action": "INCIDENT_RESOLVED",
                "description": "Closed",
            },
        ],
        canary_events=[
            {
                "relative_path": "Legal/canary.txt",
                "timestamp": "2026-11-19T10:00:00.500000+00:00",
                "event_type": "CANARY_ACCESS",
                "operation": "OPEN",
                "metadata": {"department": "Legal"},
            }
        ],
    )

    dossier = aggregator.aggregate(incident)
    timeline = dossier.timeline

    # Must contain at least 3 entries (Incident Created, Canary Honeypot Breach, Incident Resolved)
    assert len(timeline) >= 3

    # Check strict chronological ordering
    for i in range(len(timeline) - 1):
        assert timeline[i].timestamp <= timeline[i + 1].timestamp


def test_aggregator_mitre_mapping(tmp_path: Path):
    """Verify MITRE ATT&CK technique mapping against observed evidence."""
    aggregator = ForensicAggregator(
        incidents_dir=tmp_path / "incidents",
        containment_dir=tmp_path / "containment",
        recovery_reports_dir=tmp_path / "recovery",
    )

    incident = SecurityIncident(
        incident_id="INC-MITRE01",
        first_detected_at="2026-11-19T10:00:00+00:00",
        last_updated_at="2026-11-19T10:00:01+00:00",
        status="OPEN",
        threat_score=95,
        severity="CRITICAL",
        assessment="MITRE mapping test",
        detection_reasons=["MASS_FILE_MODIFICATION", "RAPID_FILE_RENAMING"],
        canary_events=[
            {
                "relative_path": "Finance/canary.csv",
                "timestamp": "2026-11-19T10:00:00+00:00",
                "event_type": "CANARY_ACCESS",
                "operation": "READ",
            }
        ],
        metadata={
            "exfiltration_assessment": {
                "assessment_id": "EXF-01",
                "risk_tier": "CRITICAL",
                "threat_score": 90,
                "total_reads_observed": 100,
                "total_staged_bytes": 2048,
                "staging_locations": ["/tmp/stage"],
                "total_transfers_attempted": 1,
            },
            "dlp_metrics": {
                "blocked_count": 1,
                "blocked_bytes": 2048,
            },
        },
    )

    dossier = aggregator.aggregate(incident)
    technique_ids = [t["id"] for t in dossier.mitre_attack_techniques]

    # Must include Encryption (T1486), Canary Discovery (T1083), Staging (T1074), and Exfiltration Attempt (T1048)
    assert "T1486" in technique_ids
    assert "T1083" in technique_ids
    assert "T1074" in technique_ids
    assert "T1048" in technique_ids
