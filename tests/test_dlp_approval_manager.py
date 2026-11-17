"""
Unit tests for DLP Approval Manager (Phase 8).
"""

import pytest

from app.core.event_bus import EventBus
from app.dlp.approval_manager import DLPApprovalManager
from app.dlp.models import DLPAction, DLPApprovalStatus, DLPEvaluationResult


def test_submit_approval_request():
    bus = EventBus()
    mgr = DLPApprovalManager(event_bus=bus)

    evaluation = DLPEvaluationResult(
        evaluation_id="EVAL-001",
        timestamp="2026-11-17T20:00:00Z",
        action=DLPAction.REQUIRE_APPROVAL,
        allowed=False,
        destination_endpoint="127.0.0.1:8999",
        file_count=5,
        bytes_requested=1024,
        classifications_evaluated=["CONFIDENTIAL"],
        reason="Confidential data",
    )

    req = mgr.submit_request(evaluation, transfer_payload=b"demo_payload")

    assert req.approval_token.startswith("APR-")
    assert req.status == DLPApprovalStatus.PENDING.value
    assert req.evaluation_id == "EVAL-001"
    assert mgr.get_payload(req.approval_token) == b"demo_payload"

    pending = mgr.get_pending_requests()
    assert len(pending) == 1
    assert pending[0].approval_token == req.approval_token


def test_approve_request():
    bus = EventBus()
    events = []
    bus.subscribe("DLP_APPROVAL_GRANTED", lambda e: events.append(e))
    mgr = DLPApprovalManager(event_bus=bus)

    evaluation = DLPEvaluationResult(
        evaluation_id="EVAL-002",
        timestamp="2026-11-17T20:00:00Z",
        action=DLPAction.REQUIRE_APPROVAL,
        allowed=False,
        destination_endpoint="127.0.0.1:8999",
    )
    req = mgr.submit_request(evaluation)

    ok, approved_req = mgr.approve(req.approval_token, decided_by="sec_admin")
    assert ok is True
    assert approved_req.status == DLPApprovalStatus.APPROVED.value
    assert approved_req.decided_by == "sec_admin"
    assert len(events) == 1
    assert events[0].data["approval_token"] == req.approval_token

    # No longer pending
    assert len(mgr.get_pending_requests()) == 0


def test_reject_request():
    bus = EventBus()
    events = []
    bus.subscribe("DLP_APPROVAL_REJECTED", lambda e: events.append(e))
    mgr = DLPApprovalManager(event_bus=bus)

    evaluation = DLPEvaluationResult(
        evaluation_id="EVAL-003",
        timestamp="2026-11-17T20:00:00Z",
        action=DLPAction.REQUIRE_APPROVAL,
        allowed=False,
        destination_endpoint="127.0.0.1:8999",
    )
    req = mgr.submit_request(evaluation)

    ok, rejected_req = mgr.reject(req.approval_token, decided_by="sec_admin", reason="Unauthorized")
    assert ok is True
    assert rejected_req.status == DLPApprovalStatus.REJECTED.value
    assert len(events) == 1
    assert events[0].data["approval_token"] == req.approval_token
