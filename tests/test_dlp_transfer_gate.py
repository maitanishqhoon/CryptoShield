"""
Unit tests for DLP Transfer Gate (Phase 8).
"""

from pathlib import Path
import pytest

from app.core.event_bus import EventBus
from app.dlp.approval_manager import DLPApprovalManager
from app.dlp.audit_logger import DLPAuditLogger
from app.dlp.models import DLPAction, DLPProfile
from app.dlp.policy_engine import DLPPolicyEngine
from app.dlp.transfer_gate import DLPTransferGate


def test_transfer_gate_evaluates_and_blocks_canary(tmp_path: Path):
    bus = EventBus()
    events = []
    bus.subscribe("DLP_TRANSFER_BLOCKED", lambda e: events.append(e))

    engine = DLPPolicyEngine()
    audit = DLPAuditLogger(log_path=tmp_path / "audit.log")
    gate = DLPTransferGate(policy_engine=engine, audit_logger=audit, event_bus=bus)

    result = gate.evaluate_transfer(
        destination_endpoint="127.0.0.1:8999",
        payload_bytes=b"sensitive canary data",
        file_count=1,
        classifications=["RESTRICTED"],
        contains_canary=True,
    )

    assert result.action == DLPAction.BLOCK
    assert result.allowed is False
    assert len(events) == 1
    assert events[0].data["contains_canary"] is True

    metrics = gate.get_metrics()
    assert metrics["blocked_count"] == 1
    assert metrics["total_evaluations"] == 1


def test_transfer_gate_quarantines_confidential(tmp_path: Path):
    bus = EventBus()
    events = []
    bus.subscribe("DLP_APPROVAL_REQUIRED", lambda e: events.append(e))

    engine = DLPPolicyEngine(profile=DLPProfile.DEFAULT)
    audit = DLPAuditLogger(log_path=tmp_path / "audit.log")
    gate = DLPTransferGate(policy_engine=engine, audit_logger=audit, event_bus=bus)

    result = gate.evaluate_transfer(
        destination_endpoint="127.0.0.1:8999",
        payload_bytes=b"customer payroll",
        file_count=1,
        classifications=["CONFIDENTIAL"],
        contains_canary=False,
    )

    assert result.action == DLPAction.REQUIRE_APPROVAL
    assert result.allowed is False
    assert result.approval_token is not None
    assert result.approval_token.startswith("APR-")

    assert len(events) == 1
    assert events[0].data["approval_token"] == result.approval_token

    metrics = gate.get_metrics()
    assert metrics["quarantined_count"] == 1


def test_transfer_gate_allows_public(tmp_path: Path):
    bus = EventBus()
    events = []
    bus.subscribe("DLP_TRANSFER_ALLOWED", lambda e: events.append(e))

    engine = DLPPolicyEngine()
    audit = DLPAuditLogger(log_path=tmp_path / "audit.log")
    gate = DLPTransferGate(policy_engine=engine, audit_logger=audit, event_bus=bus)

    result = gate.evaluate_transfer(
        destination_endpoint="127.0.0.1:8999",
        payload_bytes=b"public press release",
        file_count=1,
        classifications=["PUBLIC"],
    )

    assert result.action == DLPAction.ALLOW
    assert result.allowed is True
    assert len(events) == 1
    assert gate.get_metrics()["allowed_count"] == 1
