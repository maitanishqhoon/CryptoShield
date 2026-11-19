"""
Unit tests for Forensic Report Exporter & Seal Verifier (Phase 9).
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from app.reporting.aggregator import ForensicAggregator
from app.reporting.exporter import ReportExporter
from app.reporting.models import (
    ChainOfCustodyRecord,
    ContainmentForensicSummary,
    DLPForensicSummary,
    DetectionForensicSummary,
    ExfiltrationForensicSummary,
    ForensicDossier,
    ForensicEvaluationMetrics,
    ForensicTimelineEntry,
    RecoveryForensicSummary,
    ReportFormat,
)


def _create_sample_dossier() -> ForensicDossier:
    """Helper creating a fully populated sample ForensicDossier."""
    det = DetectionForensicSummary(
        first_detected_at="2026-11-19T14:00:00+00:00",
        last_detected_at="2026-11-19T14:00:01+00:00",
        detection_latency_seconds=1.0,
        initial_threat_score=70,
        peak_threat_score=95,
        peak_severity="CRITICAL",
        detection_reasons=["MASS_FILE_MODIFICATION", "CANARY_FILE_ACCESS"],
        total_contributing_events=12,
        affected_paths_count=5,
        departments_targeted=["Finance", "Legal"],
        canaries_compromised_count=1,
    )
    cont = ContainmentForensicSummary(
        containment_id="CONT-EXP01",
        status="CONTAINED",
        initiated_at="2026-11-19T14:00:01+00:00",
        completed_at="2026-11-19T14:00:01.050000+00:00",
        containment_duration_seconds=0.05,
        shutdown_method="COOPERATIVE",
        write_gate_status="CLOSED",
        operations_prevented_count=10,
        actions_taken=["LAB_WRITE_GATE_CLOSED", "PROCESS_STOPPED"],
    )
    exf = ExfiltrationForensicSummary(
        assessment_id="EXF-EXP01",
        risk_tier="CRITICAL",
        threat_score=90,
        staging_volume_bytes=1048576,
    )
    dlp = DLPForensicSummary(
        profile="STRICT",
        transfers_blocked=2,
        bytes_blocked_at_gate=1048576,
        zero_byte_leakage_enforced=True,
    )
    rec = RecoveryForensicSummary(
        recovery_id="REC-EXP01",
        restored_count=5,
        duration_seconds=0.85,
        sha256_verification_pass_rate=100.0,
        audit_passed=True,
    )
    metrics = ForensicEvaluationMetrics(
        detection_latency_seconds=1.0,
        containment_duration_seconds=0.05,
        recovery_duration_seconds=0.85,
        files_affected_count=5,
        files_preserved_or_restored_count=20000,
        total_enterprise_files=20000,
        protection_success_rate=100.0,
        exfiltration_bytes_blocked=1048576,
        exfiltration_leakage_bytes=0,
        zero_leakage_verified=True,
        sha256_hash_match_rate=100.0,
    )
    timeline = [
        ForensicTimelineEntry(
            timestamp="2026-11-19T14:00:00+00:00",
            subsystem="DETECTION",
            action="CANARY_HONEYPOT_BREACH",
            description="Canary file accessed.",
            severity="CRITICAL",
        ),
        ForensicTimelineEntry(
            timestamp="2026-11-19T14:00:01+00:00",
            subsystem="CONTAINMENT",
            action="CONTAINMENT_COMPLETED",
            description="Process contained via COOPERATIVE.",
            severity="INFO",
        ),
    ]
    coc = ChainOfCustodyRecord(
        record_id="COC-EXP01",
        incident_id="INC-EXP01",
        sealed_at="2026-11-19T14:05:00+00:00",
        manifest_sha256="4ce00a66288954b3aee6e13887d65a5eec6da38a537c2a6e239d00c164e6b56f",
    )

    dossier = ForensicDossier(
        report_id="REP-EXP01",
        incident_id="INC-EXP01",
        generated_at="2026-11-19T14:05:00+00:00",
        incident_status="RESOLVED",
        threat_score=95,
        severity="CRITICAL",
        assessment_title="Double-Extortion Defense Report: INC-EXP01",
        executive_summary="Executive narrative for export testing.",
        detection=det,
        containment=cont,
        exfiltration=exf,
        dlp=dlp,
        recovery=rec,
        metrics=metrics,
        timeline=timeline,
        chain_of_custody=coc,
        mitre_attack_techniques=[
            {
                "id": "T1486",
                "name": "Data Encrypted for Impact",
                "tactic": "Impact",
                "evidence": "Mass modifications observed.",
            }
        ],
    )
    # Compute and seal
    dossier.chain_of_custody.dossier_sha256 = dossier.compute_dossier_hash()
    return dossier


def test_export_all_formats(tmp_path: Path):
    """Verify exporting dossier in JSON, Markdown, CSV, and HTML formats."""
    exporter = ReportExporter(reports_dir=tmp_path)
    dossier = _create_sample_dossier()

    output_files = exporter.export_all(dossier)

    assert "json" in output_files
    assert "markdown" in output_files
    assert "csv" in output_files
    assert "html" in output_files

    for fmt, p in output_files.items():
        assert p.exists()
        assert p.stat().st_size > 0


def test_json_export_and_integrity(tmp_path: Path):
    """Verify JSON export matches schema and validates cryptographic seal."""
    exporter = ReportExporter(reports_dir=tmp_path)
    dossier = _create_sample_dossier()

    json_path = exporter.export_json(dossier)
    assert json_path.exists()

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["report_id"] == "REP-EXP01"
    assert data["incident_id"] == "INC-EXP01"
    assert data["metrics"]["zero_leakage_verified"] is True

    # Verify seal on clean file
    valid, msg = exporter.verify_report_file(json_path)
    assert valid is True
    assert "verified" in msg.lower()


def test_markdown_export_content(tmp_path: Path):
    """Verify Markdown export contains all critical sections and tables."""
    exporter = ReportExporter(reports_dir=tmp_path)
    dossier = _create_sample_dossier()

    md_path = exporter.export_markdown(dossier)
    content = md_path.read_text(encoding="utf-8")

    assert "# CryptoShield — Forensic Incident Report" in content
    assert "Executive Summary" in content
    assert "Key Evaluation & Defense Metrics" in content
    assert "Detection Latency" in content
    assert "Zero-Byte Leakage Verified" in content
    assert "MITRE ATT&CK Mapping" in content
    assert "T1486" in content
    assert "Cryptographic Chain of Custody & Verification Seal" in content
    assert dossier.chain_of_custody.dossier_sha256 in content


def test_csv_export_content(tmp_path: Path):
    """Verify CSV export contains timeline records and valid headers."""
    exporter = ReportExporter(reports_dir=tmp_path)
    dossier = _create_sample_dossier()

    csv_path = exporter.export_csv(dossier)
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = list(csv.reader(f))

    assert len(reader) >= 3  # Header + 2 events
    header = reader[0]
    assert header == [
        "report_id",
        "incident_id",
        "timestamp",
        "subsystem",
        "action",
        "severity",
        "threat_score",
        "description",
    ]
    assert reader[1][3] == "DETECTION"
    assert reader[2][3] == "CONTAINMENT"


def test_html_export_content(tmp_path: Path):
    """Verify HTML export is self-contained with dark styling and badges."""
    exporter = ReportExporter(reports_dir=tmp_path)
    dossier = _create_sample_dossier()

    html_path = exporter.export_html(dossier)
    content = html_path.read_text(encoding="utf-8")

    assert "<!DOCTYPE html>" in content
    assert "CryptoShield Forensic Incident Report" in content
    assert "REP-EXP01" in content
    assert "Detection Latency" in content
    assert "Zero-Byte Leakage" or "Exfiltration Leakage" in content
    assert dossier.chain_of_custody.dossier_sha256 in content


def test_tampering_detection(tmp_path: Path):
    """Verify that tampering with any field in the exported JSON breaks verification."""
    exporter = ReportExporter(reports_dir=tmp_path)
    dossier = _create_sample_dossier()

    json_path = exporter.export_json(dossier)

    # Clean file passes
    valid, _ = exporter.verify_report_file(json_path)
    assert valid is True

    # Tamper with threat_score in JSON
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    data["threat_score"] = 10  # Altered!

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    # Tampered file must fail verification!
    valid_tampered, err_msg = exporter.verify_report_file(json_path)
    assert valid_tampered is False
    assert "mismatch" in err_msg.lower()
