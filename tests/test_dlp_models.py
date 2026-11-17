"""
Unit tests for Data Loss Prevention (DLP) Models and Schemas (Phase 8).
"""

import pytest

from app.dlp.models import (
    DLPAction,
    DLPApprovalRequest,
    DLPApprovalStatus,
    DLPAuditRecord,
    DLPEvaluationResult,
    DLPPolicyRule,
    DLPProfile,
)


def test_dlp_action_and_profile_enums():
    assert DLPAction.ALLOW.value == "ALLOW"
    assert DLPAction.ALERT.value == "ALERT"
    assert DLPAction.REQUIRE_APPROVAL.value == "REQUIRE_APPROVAL"
    assert DLPAction.BLOCK.value == "BLOCK"

    assert DLPProfile.DEFAULT.value == "DEFAULT"
    assert DLPProfile.STRICT.value == "STRICT"
    assert DLPProfile.AUDIT_ONLY.value == "AUDIT_ONLY"
    assert DLPProfile.PERMISSIVE.value == "PERMISSIVE"


def test_dlp_policy_rule_matching_canary():
    rule = DLPPolicyRule(
        rule_id="RULE-CANARY",
        name="Canary Guard",
        description="Blocks canary leaks",
        priority=100,
        action=DLPAction.BLOCK,
        block_canaries=True,
        severity="CRITICAL",
        reason="Canary honeypot detected",
    )

    matches, reason = rule.matches({"contains_canary": True})
    assert matches is True
    assert "Canary honeypot detected" in reason

    matches_clean, _ = rule.matches({"contains_canary": False})
    assert matches_clean is False


def test_dlp_policy_rule_matching_classification():
    rule = DLPPolicyRule(
        rule_id="RULE-RESTRICTED",
        name="Restricted Data Guard",
        description="Blocks restricted classifications",
        priority=90,
        action=DLPAction.BLOCK,
        target_classifications=["RESTRICTED"],
        severity="CRITICAL",
    )

    # Matches when RESTRICTED is present
    matches, reason = rule.matches({"classifications": ["INTERNAL", "RESTRICTED"]})
    assert matches is True
    assert "RESTRICTED" in reason

    # Does not match when only PUBLIC / INTERNAL
    matches_non, _ = rule.matches({"classifications": ["PUBLIC", "INTERNAL"]})
    assert matches_non is False


def test_dlp_policy_rule_bulk_volume_matching():
    rule = DLPPolicyRule(
        rule_id="RULE-BULK",
        name="Bulk File Gate",
        description="Throttles mass file transfers",
        priority=70,
        action=DLPAction.REQUIRE_APPROVAL,
        max_file_count=10,
        max_bytes=1000,
    )

    # Exceeds file count
    m1, r1 = rule.matches({"file_count": 15, "bytes": 500})
    assert m1 is True
    assert "15 > 10" in r1

    # Exceeds bytes
    m2, r2 = rule.matches({"file_count": 5, "bytes": 2000})
    assert m2 is True
    assert "2000B > 1000B" in r2

    # Under thresholds
    m3, _ = rule.matches({"file_count": 5, "bytes": 500})
    assert m3 is False


def test_dlp_policy_rule_serialization_roundtrip():
    rule = DLPPolicyRule(
        rule_id="RULE-TEST",
        name="Test Rule",
        description="Serialization test",
        priority=80,
        action=DLPAction.ALERT,
        target_classifications=["CONFIDENTIAL"],
        target_departments=["Finance"],
    )

    d = rule.to_dict()
    assert d["action"] == "ALERT"
    assert d["priority"] == 80

    reconstructed = DLPPolicyRule.from_dict(d)
    assert reconstructed.rule_id == rule.rule_id
    assert reconstructed.action == DLPAction.ALERT
    assert reconstructed.target_classifications == ["CONFIDENTIAL"]


def test_dlp_evaluation_result_and_approval_request():
    eval_res = DLPEvaluationResult(
        evaluation_id="EVAL-123",
        timestamp="2026-11-17T20:00:00Z",
        action=DLPAction.REQUIRE_APPROVAL,
        allowed=False,
        triggered_rule_id="RULE-001",
        reason="Needs approval",
        approval_token="APR-456",
    )
    d = eval_res.to_dict()
    assert d["action"] == "REQUIRE_APPROVAL"
    assert d["allowed"] is False
    assert d["approval_token"] == "APR-456"

    recon_eval = DLPEvaluationResult.from_dict(d)
    assert recon_eval.action == DLPAction.REQUIRE_APPROVAL
    assert recon_eval.allowed is False

    appr_req = DLPApprovalRequest(
        approval_token="APR-456",
        evaluation_id="EVAL-123",
        requested_at="2026-11-17T20:00:00Z",
        status=DLPApprovalStatus.PENDING.value,
        transfer_details={"endpoint": "127.0.0.1:8999"},
    )
    req_dict = appr_req.to_dict()
    assert req_dict["status"] == "PENDING"
    recon_req = DLPApprovalRequest.from_dict(req_dict)
    assert recon_req.approval_token == "APR-456"
