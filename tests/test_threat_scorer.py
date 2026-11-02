"""
Unit tests for app.detection.threat_scorer.
"""

import pytest

from app.core.models import (
    ContributingIndicator,
    DetectionReason,
    ProcessAttribution,
    ThreatLevel,
)
from app.detection.behavior_analyzer import BehaviorEvaluation
from app.detection.canary_analyzer import CanaryEvaluation
from app.detection.threat_scorer import ThreatScorer


def test_normal_scoring():
    scorer = ThreatScorer()
    b_eval = BehaviorEvaluation()
    c_eval = CanaryEvaluation()

    result = scorer.calculate_score(b_eval, c_eval)
    assert result.threat_score == 0
    assert result.severity == ThreatLevel.NORMAL.value
    assert "NORMAL" in result.assessment


def test_canary_alone_scoring():
    scorer = ThreatScorer()
    b_eval = BehaviorEvaluation()
    c_eval = CanaryEvaluation(
        canary_events_count=1,
        unique_canaries_accessed={"Finance/canary.csv"},
        is_canary_tripped=True,
        reasons=[DetectionReason.CANARY_FILE_ACCESS.value],
        indicators=[
            ContributingIndicator(
                indicator_name="FIRST_CANARY_ACCESS",
                score_contribution=50,
                description="Canary read",
            )
        ],
    )

    result = scorer.calculate_score(b_eval, c_eval)
    assert result.threat_score == 50
    assert result.severity == ThreatLevel.MEDIUM.value
    assert result.canary_access_count == 1
    assert DetectionReason.CANARY_FILE_ACCESS.value in result.reasons


def test_combined_indicators_and_score_capping():
    scorer = ThreatScorer()
    # Behavior with 30 + 20 + 10 + 10 = 70 points
    b_eval = BehaviorEvaluation(
        is_suspicious=True,
        reasons=[
            DetectionReason.MASS_FILE_MODIFICATION.value,
            DetectionReason.RAPID_FILE_RENAMING.value,
            DetectionReason.MULTI_DEPARTMENT_TARGETING.value,
        ],
        indicators=[
            ContributingIndicator("LARGE_MOD", 30, "Large mod"),
            ContributingIndicator("RAPID_RENAME", 20, "Rapid rename"),
            ContributingIndicator("MULTI_DEPT", 10, "Multi dept"),
            ContributingIndicator("SYNERGY", 10, "Synergy"),
        ],
        affected_files_count=45,
    )
    # Canary with 50 points
    c_eval = CanaryEvaluation(
        canary_events_count=1,
        unique_canaries_accessed={"Finance/canary.csv"},
        is_canary_tripped=True,
        reasons=[DetectionReason.CANARY_FILE_ACCESS.value],
        indicators=[
            ContributingIndicator("FIRST_CANARY", 50, "First canary"),
        ],
    )

    result = scorer.calculate_score(b_eval, c_eval)
    # 70 + 50 = 120, capped at 100
    assert result.threat_score == 100
    assert result.severity == ThreatLevel.CRITICAL.value
    assert len(result.reasons) == 4
    assert result.affected_files_count == 45
    assert "exfiltration assessment pending" in result.assessment


def test_legitimate_bulk_suppression():
    scorer = ThreatScorer()
    b_eval = BehaviorEvaluation(
        is_legitimate_bulk=True,
        reasons=[DetectionReason.LEGITIMATE_BULK_ACTIVITY.value],
        indicators=[],
        affected_files_count=100,
    )
    c_eval = CanaryEvaluation()

    result = scorer.calculate_score(b_eval, c_eval)
    assert result.threat_score == 0
    assert result.severity == ThreatLevel.NORMAL.value
    assert "legitimate" in result.assessment.lower()


def test_explanation_formatting():
    scorer = ThreatScorer()
    b_eval = BehaviorEvaluation(
        is_suspicious=True,
        reasons=[DetectionReason.MASS_FILE_MODIFICATION.value],
        indicators=[
            ContributingIndicator("MOD_BURST", 30, "45 files modified"),
        ],
        affected_files_count=45,
    )
    c_eval = CanaryEvaluation()

    result = scorer.calculate_score(b_eval, c_eval)
    report = scorer.format_explanation(result)
    assert "Threat Score: 30/100" in report
    assert "MASS_FILE_MODIFICATION" in report
    assert "45 files modified" in report


def test_canary_alert_priority_independent_of_medium_threat_score():
    """Verify that canary alert priority is HIGH independently of aggregate MEDIUM severity."""
    from app.core.models import EventPriority, SecurityAlert
    scorer = ThreatScorer()
    b_eval = BehaviorEvaluation()
    c_alert = SecurityAlert(
        alert_id="alert-canary-high",
        timestamp="2026-11-02T12:00:00Z",
        priority=EventPriority.HIGH.value,
        alert_type="CANARY_ACCESS_BREACH",
        message="HIGH: Cryptographic canary decoy file accessed.",
        source_event_id="source-1",
    )
    c_eval = CanaryEvaluation(
        canary_events_count=1,
        unique_canaries_accessed={"Finance/salary_canary.csv"},
        is_canary_tripped=True,
        alerts_generated=[c_alert],
        reasons=[DetectionReason.CANARY_FILE_ACCESS.value],
        indicators=[ContributingIndicator("FIRST_CANARY", 50, "First canary read")],
    )

    result = scorer.calculate_score(b_eval, c_eval)
    # Individual alert priority is HIGH
    assert c_eval.alerts_generated[0].priority == EventPriority.HIGH.value
    # Aggregate threat score is 50, which maps to MEDIUM severity
    assert result.threat_score == 50
    assert result.severity == ThreatLevel.MEDIUM.value
    report = scorer.format_explanation(result)
    assert "Alert Note" in report


