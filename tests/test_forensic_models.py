"""
Unit tests for Forensic Incident Reporting Models (Phase 9).
"""

from __future__ import annotations

import json
from app.reporting.models import (
    ChainOfCustodyRecord,
    ContainmentForensicSummary,
    DLPForensicSummary,
    DetectionForensicSummary,
    ExfiltrationForensicSummary,
    ForensicCanaryRecord,
    ForensicDossier,
    ForensicEvaluationMetrics,
    ForensicSubsystem,
    ForensicTimelineEntry,
    RecoveryForensicSummary,
    ReportFormat,
    ReportMetadata,
)


def test_report_formats_and_subsystems():
    """Verify ReportFormat and ForensicSubsystem enums."""
    assert ReportFormat.JSON.value == "JSON"
    assert ReportFormat.MARKDOWN.value == "MARKDOWN"
    assert ReportFormat.CSV.value == "CSV"
    assert ReportFormat.HTML.value == "HTML"

    assert ForensicSubsystem.DETECTION.value == "DETECTION"
    assert ForensicSubsystem.CONTAINMENT.value == "CONTAINMENT"
    assert ForensicSubsystem.DLP.value == "DLP"
    assert ForensicSubsystem.RECOVERY.value == "RECOVERY"


def test_timeline_entry_serialization():
    """Verify serialization and deserialization of ForensicTimelineEntry."""
    entry = ForensicTimelineEntry(
        timestamp="2026-11-19T12:00:00+00:00",
        subsystem=ForensicSubsystem.DETECTION.value,
        action="CANARY_HONEYPOT_BREACH",
        description="Decoy canary accessed.",
        severity="HIGH",
        threat_score=85,
        event_id="EV-1234",
        metadata={"department": "Finance"},
    )
    d = entry.to_dict()
    assert d["action"] == "CANARY_HONEYPOT_BREACH"
    assert d["severity"] == "HIGH"

    restored = ForensicTimelineEntry.from_dict(d)
    assert restored.timestamp == entry.timestamp
    assert restored.action == entry.action
    assert restored.metadata == {"department": "Finance"}


def test_canary_record_serialization():
    """Verify serialization of ForensicCanaryRecord."""
    rec = ForensicCanaryRecord(
        path="Finance/canary_credentials.json",
        timestamp="2026-11-19T12:00:00+00:00",
        event_type="CANARY_ACCESS",
        operation="READ",
        department="Finance",
        classification="RESTRICTED",
        process_attribution="CONFIRMED",
        process_id=5432,
        tampered=False,
    )
    d = rec.to_dict()
    assert d["path"] == "Finance/canary_credentials.json"
    restored = ForensicCanaryRecord.from_dict(d)
    assert restored.path == rec.path
    assert restored.process_id == 5432


def test_subsystem_summaries():
    """Verify creation and dictionary conversion of subsystem summaries."""
    det = DetectionForensicSummary(
        first_detected_at="2026-11-19T12:00:00+00:00",
        last_detected_at="2026-11-19T12:00:01+00:00",
        detection_latency_seconds=1.0,
        initial_threat_score=60,
        peak_threat_score=90,
        peak_severity="CRITICAL",
        detection_reasons=["CANARY_FILE_ACCESS", "MASS_FILE_MODIFICATION"],
        total_contributing_events=5,
        affected_paths_count=10,
        departments_targeted=["Finance", "IT"],
        canaries_compromised_count=1,
    )
    assert det.to_dict()["peak_threat_score"] == 90
    restored_det = DetectionForensicSummary.from_dict(det.to_dict())
    assert restored_det.departments_targeted == ["Finance", "IT"]

    cont = ContainmentForensicSummary(
        containment_id="CONT-001",
        status="CONTAINED",
        shutdown_method="COOPERATIVE",
        write_gate_status="CLOSED",
        operations_prevented_count=5,
    )
    assert cont.to_dict()["status"] == "CONTAINED"
    assert ContainmentForensicSummary.from_dict(cont.to_dict()).containment_id == "CONT-001"

    exf = ExfiltrationForensicSummary(
        assessment_id="EXF-001",
        risk_tier="CRITICAL",
        threat_score=95,
        staging_volume_bytes=50000,
    )
    assert ExfiltrationForensicSummary.from_dict(exf.to_dict()).threat_score == 95

    dlp = DLPForensicSummary(
        profile="STRICT",
        transfers_blocked=2,
        bytes_blocked_at_gate=1048576,
        zero_byte_leakage_enforced=True,
    )
    assert DLPForensicSummary.from_dict(dlp.to_dict()).bytes_blocked_at_gate == 1048576

    rec = RecoveryForensicSummary(
        recovery_id="REC-001",
        restored_count=10,
        sha256_verification_pass_rate=100.0,
        audit_passed=True,
    )
    assert RecoveryForensicSummary.from_dict(rec.to_dict()).restored_count == 10


def test_forensic_evaluation_metrics():
    """Verify ForensicEvaluationMetrics calculations and round-trip serialization."""
    metrics = ForensicEvaluationMetrics(
        detection_latency_seconds=0.45,
        containment_duration_seconds=0.12,
        recovery_duration_seconds=2.35,
        files_affected_count=15,
        files_preserved_or_restored_count=20000,
        total_enterprise_files=20000,
        protection_success_rate=100.0,
        exfiltration_bytes_blocked=65536,
        exfiltration_leakage_bytes=0,
        zero_leakage_verified=True,
        sha256_hash_match_rate=100.0,
    )
    d = metrics.to_dict()
    assert d["zero_leakage_verified"] is True
    assert d["protection_success_rate"] == 100.0

    restored = ForensicEvaluationMetrics.from_dict(d)
    assert restored.recovery_duration_seconds == 2.35
    assert restored.files_preserved_or_restored_count == 20000


def test_chain_of_custody_and_dossier_hash_determinism():
    """Verify deterministic SHA-256 seal calculation on ForensicDossier."""
    det = DetectionForensicSummary(
        first_detected_at="2026-11-19T12:00:00+00:00",
        last_detected_at="2026-11-19T12:00:01+00:00",
        detection_latency_seconds=1.0,
        initial_threat_score=70,
        peak_threat_score=90,
        peak_severity="CRITICAL",
    )
    cont = ContainmentForensicSummary(containment_id="CONT-123", status="CONTAINED")
    exf = ExfiltrationForensicSummary()
    dlp = DLPForensicSummary()
    rec = RecoveryForensicSummary()
    metrics = ForensicEvaluationMetrics(
        detection_latency_seconds=1.0,
        containment_duration_seconds=0.5,
        recovery_duration_seconds=1.0,
        files_affected_count=5,
        files_preserved_or_restored_count=1000,
        total_enterprise_files=1000,
        protection_success_rate=100.0,
        exfiltration_bytes_blocked=0,
        exfiltration_leakage_bytes=0,
        zero_leakage_verified=True,
        sha256_hash_match_rate=100.0,
    )
    coc = ChainOfCustodyRecord(
        record_id="COC-001",
        incident_id="INC-001",
        sealed_at="2026-11-19T12:05:00+00:00",
        manifest_sha256="abc12345",
    )

    dossier = ForensicDossier(
        report_id="REP-001",
        incident_id="INC-001",
        generated_at="2026-11-19T12:05:00+00:00",
        incident_status="RESOLVED",
        threat_score=90,
        severity="CRITICAL",
        assessment_title="Double-Extortion Defense Test",
        executive_summary="Test summary narrative.",
        detection=det,
        containment=cont,
        exfiltration=exf,
        dlp=dlp,
        recovery=rec,
        metrics=metrics,
        chain_of_custody=coc,
    )

    # Determinism: computing hash multiple times must yield identical output
    hash1 = dossier.compute_dossier_hash()
    hash2 = dossier.compute_dossier_hash()
    assert hash1 == hash2
    assert len(hash1) == 64

    # Seal the dossier
    dossier.chain_of_custody.dossier_sha256 = hash1

    # Round-trip serialization
    dossier_dict = dossier.to_dict()
    restored = ForensicDossier.from_dict(dossier_dict)
    assert restored.report_id == "REP-001"
    assert restored.chain_of_custody.dossier_sha256 == hash1

    # Verify seal remains consistent after serialization
    assert restored.compute_dossier_hash() == hash1
