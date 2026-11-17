"""
Tests for Exfiltration Correlator (Phase 7).
"""

from __future__ import annotations

import pytest

from app.core.event_bus import EventBus
from app.exfiltration.exfiltration_correlator import ExfiltrationCorrelator
from app.exfiltration.models import (
    ExfiltrationRiskTier,
    OutboundTransferRecord,
    ReadBurstEvent,
    StagingEvent,
    StagingType,
    TransferProtocol,
    TransferStatus,
)


def test_correlator_starts_at_low_risk():
    correlator = ExfiltrationCorrelator()
    assessment = correlator.evaluate_current_state()
    assert assessment.threat_score == 0
    assert assessment.risk_tier == ExfiltrationRiskTier.LOW.value
    assert len(assessment.indicators) == 0


def test_correlator_scoring_progression():
    bus = EventBus()
    alerts = []
    bus.subscribe("EXFILTRATION_SECURITY_ALERT", lambda e: alerts.append(e))

    correlator = ExfiltrationCorrelator(event_bus=bus)
    correlator.start()
    try:
        # Step 1: Add single-department read burst (+25) -> Score 25 (MEDIUM)
        burst1 = ReadBurstEvent(
            burst_id="B1",
            timestamp="2026-11-17T12:00:00Z",
            read_count=10,
            duration_seconds=1.0,
            department_counts={"Finance": 10},
            classification_counts={"INTERNAL": 10},
            canary_reads_count=0,
            canary_paths=[],
        )
        a1 = correlator.add_read_burst(burst1)
        assert a1.threat_score == 25
        assert a1.risk_tier == ExfiltrationRiskTier.MEDIUM.value

        # Step 2: Add second burst spanning Legal with sensitive classification (+15 multi-dept, +10 sensitive)
        # Score = 25 + 15 + 10 = 50 (MEDIUM)
        burst2 = ReadBurstEvent(
            burst_id="B2",
            timestamp="2026-11-17T12:00:02Z",
            read_count=10,
            duration_seconds=1.0,
            department_counts={"Legal": 10},
            classification_counts={"RESTRICTED": 10},
            canary_reads_count=0,
            canary_paths=[],
        )
        a2 = correlator.add_read_burst(burst2)
        assert a2.threat_score == 50

        # Step 3: Add honeypot canary read breach (+40)
        # Score = 50 + 40 = 90 (CRITICAL)
        burst3 = ReadBurstEvent(
            burst_id="B3",
            timestamp="2026-11-17T12:00:04Z",
            read_count=1,
            duration_seconds=0.1,
            department_counts={"IT": 1},
            classification_counts={"RESTRICTED": 1},
            canary_reads_count=1,
            canary_paths=["IT/canary.json"],
        )
        a3 = correlator.add_read_burst(burst3)
        assert a3.threat_score >= 90
        assert a3.risk_tier == ExfiltrationRiskTier.CRITICAL.value
        assert "CANARY_HONEYPOT_COMPROMISED" in a3.indicators
        assert len(alerts) >= 1

        # Step 4: Add staging (+20) and transfer (+30) -> Score capped at 100
        staging = StagingEvent(
            staging_id="S1",
            timestamp="2026-11-17T12:00:06Z",
            staging_path="runtime/lab/.staging/pack.zip",
            staging_type=StagingType.ARCHIVE_ZIP.value,
            staged_files_count=20,
            total_staged_bytes=50000,
            source_paths=[],
        )
        correlator.add_staging_event(staging)

        transfer = OutboundTransferRecord(
            transfer_id="X1",
            timestamp="2026-11-17T12:00:08Z",
            destination_endpoint="127.0.0.1:8999",
            protocol=TransferProtocol.MOCK_SOCKET.value,
            bytes_transferred=50000,
            file_count=20,
            status=TransferStatus.COMPLETED.value,
        )
        final_assessment = correlator.add_transfer_record(transfer)
        assert final_assessment.threat_score == 100
        assert final_assessment.risk_tier == ExfiltrationRiskTier.CRITICAL.value
        assert "LOCAL_STAGING_DETECTED" in final_assessment.indicators
        assert "OUTBOUND_TRANSFER_EXECUTED" in final_assessment.indicators
        assert len(final_assessment.timeline) == 5
    finally:
        correlator.stop()
