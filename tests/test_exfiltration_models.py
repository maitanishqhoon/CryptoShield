"""
Tests for Data Exfiltration Monitoring Models (Phase 7).
"""

from __future__ import annotations

import pytest

from app.exfiltration.models import (
    ExfiltrationAssessment,
    ExfiltrationRiskTier,
    OutboundTransferRecord,
    ReadBurstEvent,
    StagingEvent,
    StagingType,
    TransferProtocol,
    TransferStatus,
)


def test_exfiltration_risk_tier_values():
    assert ExfiltrationRiskTier.LOW.value == "LOW"
    assert ExfiltrationRiskTier.MEDIUM.value == "MEDIUM"
    assert ExfiltrationRiskTier.HIGH.value == "HIGH"
    assert ExfiltrationRiskTier.CRITICAL.value == "CRITICAL"


def test_transfer_protocol_and_status():
    assert TransferProtocol.MOCK_SOCKET.value == "MOCK_SOCKET"
    assert TransferProtocol.LOCAL_PIPE.value == "LOCAL_PIPE"
    assert TransferStatus.COMPLETED.value == "COMPLETED"
    assert TransferStatus.BLOCKED.value == "BLOCKED"


def test_read_burst_event_serialization():
    burst = ReadBurstEvent(
        burst_id="BURST-12345678",
        timestamp="2026-11-17T12:00:00Z",
        read_count=20,
        duration_seconds=1.5,
        department_counts={"Finance": 12, "Legal": 8},
        classification_counts={"CONFIDENTIAL": 15, "RESTRICTED": 5},
        canary_reads_count=1,
        canary_paths=["IT/network_configs/passwords_master_backup.json"],
        process_id=4567,
        process_name="test_proc",
        process_attribution="CONFIRMED",
    )
    b_dict = burst.to_dict()
    assert b_dict["burst_id"] == "BURST-12345678"
    assert b_dict["read_count"] == 20
    assert b_dict["canary_reads_count"] == 1

    roundtrip = ReadBurstEvent.from_dict(b_dict)
    assert roundtrip.burst_id == burst.burst_id
    assert roundtrip.department_counts == burst.department_counts


def test_staging_event_serialization():
    staging = StagingEvent(
        staging_id="STAGE-87654321",
        timestamp="2026-11-17T12:05:00Z",
        staging_path="runtime/lab/.staging/data.zip",
        staging_type=StagingType.ARCHIVE_ZIP.value,
        staged_files_count=10,
        total_staged_bytes=1048576,
        source_paths=["Finance/doc1.txt", "Legal/doc2.txt"],
        process_id=5678,
    )
    s_dict = staging.to_dict()
    assert s_dict["staging_type"] == "ARCHIVE_ZIP"
    assert s_dict["total_staged_bytes"] == 1048576

    roundtrip = StagingEvent.from_dict(s_dict)
    assert roundtrip.staging_id == staging.staging_id


def test_outbound_transfer_record_serialization():
    xfer = OutboundTransferRecord(
        transfer_id="XFER-11223344",
        timestamp="2026-11-17T12:10:00Z",
        destination_endpoint="127.0.0.1:8999",
        protocol=TransferProtocol.MOCK_SOCKET.value,
        bytes_transferred=65536,
        file_count=5,
        process_id=9999,
        process_name="exfil_sim",
        classifications_included=["RESTRICTED"],
        departments_included=["Finance"],
        contains_canary=True,
        status=TransferStatus.COMPLETED.value,
    )
    x_dict = xfer.to_dict()
    assert x_dict["destination_endpoint"] == "127.0.0.1:8999"
    assert x_dict["contains_canary"] is True

    roundtrip = OutboundTransferRecord.from_dict(x_dict)
    assert roundtrip.transfer_id == xfer.transfer_id


def test_exfiltration_assessment_serialization_and_summary():
    assessment = ExfiltrationAssessment(
        assessment_id="EXFIL-AABBCCDD",
        timestamp="2026-11-17T12:15:00Z",
        threat_score=85,
        risk_tier=ExfiltrationRiskTier.CRITICAL.value,
        indicators=["MASS_FILE_READ_BURST", "CANARY_HONEYPOT_COMPROMISED"],
        read_burst_count=2,
        total_reads_observed=30,
        canary_reads_count=2,
        canaries_compromised=["canary_1.json", "canary_2.json"],
        staging_events_count=1,
        total_staged_bytes=2048,
        transfers_attempted=1,
        transfers_completed=1,
        total_bytes_exfiltrated=2048,
    )
    a_dict = assessment.to_dict()
    assert a_dict["risk_tier"] == "CRITICAL"
    assert a_dict["threat_score"] == 85

    summary = assessment.summary()
    assert "[CRITICAL]" in summary
    assert "Score=85/100" in summary
    assert "Reads=30" in summary
