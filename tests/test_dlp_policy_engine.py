"""
Unit tests for Data Loss Prevention (DLP) Policy Engine (Phase 8).
"""

from pathlib import Path
import pytest

from app.dlp.models import DLPAction, DLPPolicyRule, DLPProfile
from app.dlp.policy_engine import DLPPolicyEngine, get_default_enterprise_rules


def test_default_rules_initialization():
    engine = DLPPolicyEngine()
    rules = engine.get_rules()
    assert len(rules) >= 6
    # Verify ordering: highest priority first
    priorities = [r.priority for r in rules]
    assert priorities == sorted(priorities, reverse=True)
    assert priorities[0] == 100  # Canary rule


def test_evaluate_canary_blocks():
    engine = DLPPolicyEngine()
    context = {
        "destination_endpoint": "127.0.0.1:8999",
        "file_count": 1,
        "contains_canary": True,
        "classifications": ["RESTRICTED"],
    }
    result = engine.evaluate(context)
    assert result.action == DLPAction.BLOCK
    assert result.allowed is False
    assert result.triggered_rule_id == "DLP-RULE-001-CANARY"
    assert result.severity == "CRITICAL"


def test_evaluate_restricted_blocks():
    engine = DLPPolicyEngine()
    context = {
        "destination_endpoint": "127.0.0.1:8999",
        "file_count": 2,
        "contains_canary": False,
        "classifications": ["RESTRICTED"],
    }
    result = engine.evaluate(context)
    assert result.action == DLPAction.BLOCK
    assert result.allowed is False
    assert result.triggered_rule_id == "DLP-RULE-002-RESTRICTED"
    assert result.severity == "CRITICAL"


def test_evaluate_confidential_requires_approval_in_default_mode():
    engine = DLPPolicyEngine(profile=DLPProfile.DEFAULT)
    context = {
        "destination_endpoint": "127.0.0.1:8999",
        "file_count": 3,
        "contains_canary": False,
        "classifications": ["CONFIDENTIAL"],
    }
    result = engine.evaluate(context)
    assert result.action == DLPAction.REQUIRE_APPROVAL
    assert result.allowed is False
    assert result.triggered_rule_id == "DLP-RULE-003-CONFIDENTIAL"


def test_evaluate_confidential_blocks_in_strict_mode():
    engine = DLPPolicyEngine(profile=DLPProfile.STRICT)
    context = {
        "destination_endpoint": "127.0.0.1:8999",
        "file_count": 3,
        "contains_canary": False,
        "classifications": ["CONFIDENTIAL"],
    }
    result = engine.evaluate(context)
    assert result.action == DLPAction.BLOCK
    assert result.allowed is False
    assert result.triggered_rule_id == "DLP-RULE-003-CONFIDENTIAL"


def test_evaluate_internal_alerts():
    engine = DLPPolicyEngine(profile=DLPProfile.DEFAULT)
    context = {
        "destination_endpoint": "127.0.0.1:8999",
        "file_count": 2,
        "contains_canary": False,
        "classifications": ["INTERNAL"],
    }
    result = engine.evaluate(context)
    assert result.action == DLPAction.ALERT
    assert result.allowed is True
    assert result.triggered_rule_id == "DLP-RULE-005-INTERNAL"


def test_evaluate_public_allows():
    engine = DLPPolicyEngine(profile=DLPProfile.DEFAULT)
    context = {
        "destination_endpoint": "127.0.0.1:8999",
        "file_count": 1,
        "contains_canary": False,
        "classifications": ["PUBLIC"],
    }
    result = engine.evaluate(context)
    assert result.action == DLPAction.ALLOW
    assert result.allowed is True
    assert result.triggered_rule_id == "DLP-RULE-006-PUBLIC"


def test_audit_only_profile_converts_blocks_to_alerts():
    engine = DLPPolicyEngine(profile=DLPProfile.AUDIT_ONLY)
    context = {
        "destination_endpoint": "127.0.0.1:8999",
        "file_count": 1,
        "contains_canary": True,
        "classifications": ["RESTRICTED"],
    }
    result = engine.evaluate(context)
    assert result.action == DLPAction.ALERT
    assert result.allowed is True
    assert "AUDIT_ONLY MODE" in result.reason


def test_rule_persistence_roundtrip(tmp_path: Path):
    target_file = tmp_path / "policies.json"
    engine = DLPPolicyEngine(policies_path=target_file)
    engine.save_to_file(target_file)

    assert target_file.exists()

    engine2 = DLPPolicyEngine(policies_path=target_file)
    assert len(engine2.get_rules()) == len(engine.get_rules())
    assert engine2.get_rule("DLP-RULE-001-CANARY") is not None
