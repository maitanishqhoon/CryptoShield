"""
Unit tests for ContainmentPolicy (Phase 4).
"""

import pytest

from app.containment.containment_policy import ContainmentPolicy
from app.core.models import (
    ContainmentAction,
    DetectionReason,
    DetectionResult,
    ProcessAttribution,
    SecurityAlert,
    ThreatLevel,
)


@pytest.fixture
def policy():
    return ContainmentPolicy(
        auto_containment_enabled=True,
        critical_threshold=80,
        high_threshold=60,
    )


def test_normal_score_does_not_trigger_containment(policy):
    detection = DetectionResult(
        detection_id="det-1",
        timestamp="2026-11-03T12:00:00Z",
        threat_score=0,
        severity=ThreatLevel.NORMAL.value,
        assessment="Normal activity",
        reasons=[],
        affected_files_count=2,
        canary_access_count=0,
    )
    decision = policy.evaluate_detection(detection)
    assert decision.recommended_action == ContainmentAction.NONE.value
    assert not decision.auto_containment_authorized


def test_low_score_does_not_trigger_containment(policy):
    detection = DetectionResult(
        detection_id="det-2",
        timestamp="2026-11-03T12:00:00Z",
        threat_score=25,
        severity=ThreatLevel.LOW.value,
        assessment="Low risk fluctuation",
        reasons=[DetectionReason.UNUSUAL_BURST_ACTIVITY.value],
        affected_files_count=5,
        canary_access_count=0,
    )
    decision = policy.evaluate_detection(detection)
    assert decision.recommended_action == ContainmentAction.MONITOR.value
    assert not decision.auto_containment_authorized


def test_medium_score_alerts_without_containment(policy):
    detection = DetectionResult(
        detection_id="det-3",
        timestamp="2026-11-03T12:00:00Z",
        threat_score=45,
        severity=ThreatLevel.MEDIUM.value,
        assessment="Suspicious modification burst",
        reasons=[DetectionReason.MASS_FILE_MODIFICATION.value],
        affected_files_count=18,
        canary_access_count=0,
    )
    decision = policy.evaluate_detection(detection)
    assert decision.recommended_action == ContainmentAction.ALERT_REVIEW.value
    assert not decision.auto_containment_authorized


def test_isolated_canary_read_requires_review(policy):
    detection = DetectionResult(
        detection_id="det-4",
        timestamp="2026-11-03T12:00:00Z",
        threat_score=50,
        severity=ThreatLevel.MEDIUM.value,
        assessment="Canary decoy file access detected",
        reasons=[DetectionReason.CANARY_FILE_ACCESS.value],
        affected_files_count=1,
        canary_access_count=1,
    )
    decision = policy.evaluate_detection(detection)
    assert decision.recommended_action == ContainmentAction.ALERT_REVIEW.value
    assert not decision.auto_containment_authorized
    assert "review required" in decision.decision_reason.lower()


def test_critical_score_unassociated_recommends_containment(policy):
    detection = DetectionResult(
        detection_id="det-5",
        timestamp="2026-11-03T12:00:00Z",
        threat_score=85,
        severity=ThreatLevel.CRITICAL.value,
        assessment="Strong ransomware indicators",
        reasons=[
            DetectionReason.MASS_FILE_MODIFICATION.value,
            DetectionReason.RAPID_FILE_RENAMING.value,
        ],
        affected_files_count=45,
        canary_access_count=0,
        process_attribution=ProcessAttribution.UNKNOWN.value,
    )
    # No simulation_run_id passed -> unassociated
    decision = policy.evaluate_detection(detection, simulation_run_id=None)
    assert decision.recommended_action == ContainmentAction.CONTAINMENT_RECOMMENDED.value
    assert not decision.auto_containment_authorized
    assert "safety policy strictly forbids" in decision.explanation.lower()


def test_critical_score_registered_run_authorizes_containment(policy):
    detection = DetectionResult(
        detection_id="det-6",
        timestamp="2026-11-03T12:00:00Z",
        threat_score=85,
        severity=ThreatLevel.CRITICAL.value,
        assessment="Confirmed simulated attack",
        reasons=[
            DetectionReason.MASS_FILE_MODIFICATION.value,
            DetectionReason.RAPID_FILE_RENAMING.value,
        ],
        affected_files_count=45,
        canary_access_count=0,
    )
    decision = policy.evaluate_detection(
        detection, simulation_run_id="SIM-RUN-101", is_run_registered=True
    )
    assert decision.recommended_action == ContainmentAction.CONTAIN_SIMULATION.value
    assert decision.auto_containment_authorized
    assert decision.simulation_run_id == "SIM-RUN-101"


def test_canary_tampering_policy(policy):
    detection = DetectionResult(
        detection_id="det-7",
        timestamp="2026-11-03T12:00:00Z",
        threat_score=70,
        severity=ThreatLevel.HIGH.value,
        assessment="Canary tampering breach",
        reasons=[DetectionReason.CANARY_FILE_TAMPERED.value],
        affected_files_count=1,
        canary_access_count=1,
    )
    # With registered run
    decision = policy.evaluate_detection(
        detection, simulation_run_id="SIM-CANARY-RUN", is_run_registered=True
    )
    assert decision.recommended_action == ContainmentAction.CONTAIN_SIMULATION.value
    assert decision.auto_containment_authorized

    # Without registered run
    decision_unassoc = policy.evaluate_detection(
        detection, simulation_run_id=None, is_run_registered=False
    )
    assert decision_unassoc.recommended_action == ContainmentAction.CONTAINMENT_RECOMMENDED.value
    assert not decision_unassoc.auto_containment_authorized

