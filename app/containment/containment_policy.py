"""
Containment Policy Engine for CryptoShield (Phase 4).

Evaluates Phase 3 DetectionResult and SecurityAlert telemetry against configurable
security policies. Decides whether threat containment is justified, whether an
explicit registered simulation run is associated, and whether automatic process
containment is authorized.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from app.config import CONFIG
from app.core.logger import get_logger
from app.core.models import (
    ContainmentAction,
    ContainmentDecision,
    DetectionReason,
    DetectionResult,
    SecurityAlert,
    ThreatLevel,
)

logger = get_logger("containment_policy")


class ContainmentPolicy:
    """
    Explainable, rule-based containment policy engine.

    Enforces mandatory safety rules:
    - Never authorizes process termination based solely on PID or process name.
    - Automatic containment is authorized ONLY when a triggering event is explicitly
      associated with an active, registered CryptoShield simulation run.
    - If attribution is UNKNOWN or unassociated, emits CONTAINMENT_RECOMMENDED.
    """

    def __init__(
        self,
        auto_containment_enabled: bool = CONFIG.AUTO_CONTAINMENT_ENABLED,
        critical_threshold: int = CONFIG.AUTO_CONTAINMENT_THRESHOLD,
        high_threshold: int = CONFIG.CONTAINMENT_HIGH_THRESHOLD,
    ) -> None:
        self.auto_containment_enabled = auto_containment_enabled
        self.critical_threshold = critical_threshold
        self.high_threshold = high_threshold

    def evaluate_detection(
        self,
        detection: DetectionResult,
        simulation_run_id: Optional[str] = None,
        is_run_registered: bool = False,
    ) -> ContainmentDecision:
        """
        Evaluate a DetectionResult from Phase 3 against the containment policy.

        Returns an explainable ContainmentDecision.
        """
        decision_id = f"DEC-{uuid.uuid4().hex[:8].upper()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        score = detection.threat_score
        severity = detection.severity
        reasons = list(detection.reasons)

        # 1. NORMAL: Continue monitoring
        if score < CONFIG.SEVERITY_THRESHOLDS.get("LOW", 20) and severity == ThreatLevel.NORMAL.value:
            return ContainmentDecision(
                decision_id=decision_id,
                timestamp=now_iso,
                threat_score=score,
                severity=severity,
                decision_reason="Normal baseline activity; continue standard monitoring.",
                recommended_action=ContainmentAction.NONE.value,
                auto_containment_authorized=False,
                explanation="Threat score indicates normal operational noise. No containment action needed.",
                related_incident_id=detection.incident_id,
                related_detection_id=detection.detection_id,
                simulation_run_id=simulation_run_id,
            )

        # 2. LOW: Record and monitor
        if score < CONFIG.SEVERITY_THRESHOLDS.get("MEDIUM", 40) and severity == ThreatLevel.LOW.value:
            return ContainmentDecision(
                decision_id=decision_id,
                timestamp=now_iso,
                threat_score=score,
                severity=severity,
                decision_reason="Low-level anomalous telemetry observed; maintain passive monitoring.",
                recommended_action=ContainmentAction.MONITOR.value,
                auto_containment_authorized=False,
                explanation="Elevated activity observed within expected threshold bounds; flagged for monitoring.",
                related_incident_id=detection.incident_id,
                related_detection_id=detection.detection_id,
                simulation_run_id=simulation_run_id,
            )

        # 3. Isolated Canary Read (Canary accessed without mass file destruction)
        has_canary_access = (
            DetectionReason.CANARY_FILE_ACCESS.value in reasons
            or detection.canary_access_count > 0
        )
        has_canary_tampering = (
            DetectionReason.CANARY_FILE_TAMPERED.value in reasons
        )
        has_mass_ops = (
            DetectionReason.MASS_FILE_MODIFICATION.value in reasons
            or DetectionReason.RAPID_FILE_RENAMING.value in reasons
            or DetectionReason.LARGE_SCALE_DELETION.value in reasons
        )

        is_isolated_canary_read = (
            has_canary_access
            and not has_canary_tampering
            and not has_mass_ops
            and score < self.critical_threshold
        )

        if is_isolated_canary_read:
            return ContainmentDecision(
                decision_id=decision_id,
                timestamp=now_iso,
                threat_score=score,
                severity=severity,
                decision_reason="Isolated high-priority canary decoy read; review required.",
                recommended_action=ContainmentAction.ALERT_REVIEW.value,
                auto_containment_authorized=False,
                explanation=(
                    "Canary decoy file access detected without widespread destructive modifications. "
                    "Security alert raised; manual operator review required before containment."
                ),
                related_incident_id=detection.incident_id,
                related_detection_id=detection.detection_id,
                simulation_run_id=simulation_run_id,
            )

        # 4. MEDIUM: Raise alert; no automatic containment
        if score < self.high_threshold and severity == ThreatLevel.MEDIUM.value:
            return ContainmentDecision(
                decision_id=decision_id,
                timestamp=now_iso,
                threat_score=score,
                severity=severity,
                decision_reason="Medium severity threat indicators detected; operator alert raised.",
                recommended_action=ContainmentAction.ALERT_REVIEW.value,
                auto_containment_authorized=False,
                explanation="Suspicious burst or pattern detected, but below containment thresholds.",
                related_incident_id=detection.incident_id,
                related_detection_id=detection.detection_id,
                simulation_run_id=simulation_run_id,
            )

        # 5. HIGH: Evaluate corroboration and registered simulation association
        if self.high_threshold <= score < self.critical_threshold:
            corroborated = len(reasons) >= 2 or has_canary_access
            if self.auto_containment_enabled and simulation_run_id and is_run_registered and corroborated:
                return ContainmentDecision(
                    decision_id=decision_id,
                    timestamp=now_iso,
                    threat_score=score,
                    severity=severity,
                    decision_reason="HIGH aggregate threat with corroborating indicators associated with registered simulation run.",
                    recommended_action=ContainmentAction.CONTAIN_SIMULATION.value,
                    auto_containment_authorized=True,
                    explanation=(
                        f"HIGH threat score ({score}/100) with corroborated behavioral indicators "
                        f"explicitly associated with registered simulation run '{simulation_run_id}'. "
                        "Controlled containment authorized."
                    ),
                    related_incident_id=detection.incident_id,
                    related_detection_id=detection.detection_id,
                    simulation_run_id=simulation_run_id,
                )
            else:
                reason_detail = (
                    "No registered simulation run associated"
                    if not (simulation_run_id and is_run_registered)
                    else "Insufficient corroborating behavioral evidence"
                )
                return ContainmentDecision(
                    decision_id=decision_id,
                    timestamp=now_iso,
                    threat_score=score,
                    severity=severity,
                    decision_reason=f"HIGH aggregate threat detected; {reason_detail}.",
                    recommended_action=ContainmentAction.CONTAINMENT_RECOMMENDED.value,
                    auto_containment_authorized=False,
                    explanation=(
                        f"HIGH threat score ({score}/100) warrants containment, but automatic termination is prohibited "
                        f"because {reason_detail.lower()}. Operator containment recommended."
                    ),
                    related_incident_id=detection.incident_id,
                    related_detection_id=detection.detection_id,
                    simulation_run_id=simulation_run_id,
                )

        # 6. CRITICAL canary tampering
        if has_canary_tampering:
            if self.auto_containment_enabled and simulation_run_id and is_run_registered:
                return ContainmentDecision(
                    decision_id=decision_id,
                    timestamp=now_iso,
                    threat_score=score,
                    severity=ThreatLevel.CRITICAL.value,
                    decision_reason="CRITICAL canary tampering associated with active registered simulation run.",
                    recommended_action=ContainmentAction.CONTAIN_SIMULATION.value,
                    auto_containment_authorized=True,
                    explanation=(
                        f"Direct canary tampering detected and explicitly attributed to registered "
                        f"simulation run '{simulation_run_id}'. Immediate controlled process containment authorized."
                    ),
                    related_incident_id=detection.incident_id,
                    related_detection_id=detection.detection_id,
                    simulation_run_id=simulation_run_id,
                )
            else:
                return ContainmentDecision(
                    decision_id=decision_id,
                    timestamp=now_iso,
                    threat_score=score,
                    severity=ThreatLevel.CRITICAL.value,
                    decision_reason="CRITICAL canary tampering without registered simulation association.",
                    recommended_action=ContainmentAction.CONTAINMENT_RECOMMENDED.value,
                    auto_containment_authorized=False,
                    explanation=(
                        "Direct canary tampering detected. However, no active CryptoShield registered "
                        "simulation run was associated with the event. To protect host processes, "
                        "automatic termination is withheld; containment is recommended for review."
                    ),
                    related_incident_id=detection.incident_id,
                    related_detection_id=detection.detection_id,
                    simulation_run_id=simulation_run_id,
                )

        # 7. CRITICAL aggregate threat (score >= critical_threshold)
        if score >= self.critical_threshold:
            if self.auto_containment_enabled and simulation_run_id and is_run_registered:
                return ContainmentDecision(
                    decision_id=decision_id,
                    timestamp=now_iso,
                    threat_score=score,
                    severity=ThreatLevel.CRITICAL.value,
                    decision_reason="CRITICAL aggregate ransomware threat associated with active registered simulation run.",
                    recommended_action=ContainmentAction.CONTAIN_SIMULATION.value,
                    auto_containment_authorized=True,
                    explanation=(
                        f"CRITICAL threat score ({score}/100) exceeds threshold ({self.critical_threshold}). "
                        f"Explicitly associated with registered simulation run '{simulation_run_id}'. "
                        "Automatic controlled containment authorized."
                    ),
                    related_incident_id=detection.incident_id,
                    related_detection_id=detection.detection_id,
                    simulation_run_id=simulation_run_id,
                )
            else:
                assoc_msg = (
                    "no registered simulation run associated"
                    if not simulation_run_id
                    else f"run '{simulation_run_id}' is not an active registered process"
                )
                return ContainmentDecision(
                    decision_id=decision_id,
                    timestamp=now_iso,
                    threat_score=score,
                    severity=ThreatLevel.CRITICAL.value,
                    decision_reason=f"CRITICAL aggregate threat detected ({score}/100); {assoc_msg}.",
                    recommended_action=ContainmentAction.CONTAINMENT_RECOMMENDED.value,
                    auto_containment_authorized=False,
                    explanation=(
                        f"CRITICAL threat detected ({score}/100). Safety policy strictly forbids terminating "
                        f"arbitrary processes when attribution is UNKNOWN or unassociated. "
                        "Containment recommended to cybersecurity operator."
                    ),
                    related_incident_id=detection.incident_id,
                    related_detection_id=detection.detection_id,
                    simulation_run_id=simulation_run_id,
                )

        # Default fallback: Alert and review
        return ContainmentDecision(
            decision_id=decision_id,
            timestamp=now_iso,
            threat_score=score,
            severity=severity,
            decision_reason="Unspecified threat level; review required.",
            recommended_action=ContainmentAction.ALERT_REVIEW.value,
            auto_containment_authorized=False,
            explanation="Threat score does not meet automatic containment criteria.",
            related_incident_id=detection.incident_id,
            related_detection_id=detection.detection_id,
            simulation_run_id=simulation_run_id,
        )

    def evaluate_alert(
        self,
        alert: SecurityAlert,
        simulation_run_id: Optional[str] = None,
        is_run_registered: bool = False,
    ) -> ContainmentDecision:
        """
        Evaluate an immediate SecurityAlert (such as canary trip) from Phase 3.
        """
        decision_id = f"DEC-{uuid.uuid4().hex[:8].upper()}"
        now_iso = datetime.now(timezone.utc).isoformat()
        is_tampering = alert.alert_type == "CANARY_TAMPERING_BREACH"

        if is_tampering:
            if self.auto_containment_enabled and simulation_run_id and is_run_registered:
                return ContainmentDecision(
                    decision_id=decision_id,
                    timestamp=now_iso,
                    threat_score=CONFIG.WEIGHT_CANARY_TAMPERING,
                    severity=ThreatLevel.CRITICAL.value,
                    decision_reason="Immediate alert: Canary decoy file tampered by registered simulation run.",
                    recommended_action=ContainmentAction.CONTAIN_SIMULATION.value,
                    auto_containment_authorized=True,
                    explanation=(
                        f"Canary file '{alert.target_path}' tampered. Explicitly attributed to "
                        f"registered simulation run '{simulation_run_id}'. Containment authorized."
                    ),
                    related_detection_id=alert.detection_id,
                    simulation_run_id=simulation_run_id,
                )
            else:
                return ContainmentDecision(
                    decision_id=decision_id,
                    timestamp=now_iso,
                    threat_score=CONFIG.WEIGHT_CANARY_TAMPERING,
                    severity=ThreatLevel.CRITICAL.value,
                    decision_reason="Immediate alert: Canary decoy file tampered without registered simulation association.",
                    recommended_action=ContainmentAction.CONTAINMENT_RECOMMENDED.value,
                    auto_containment_authorized=False,
                    explanation=(
                        f"Canary file '{alert.target_path}' tampered. Unassociated process attribution; "
                        "process termination withheld by safety policy. Containment recommended."
                    ),
                    related_detection_id=alert.detection_id,
                    simulation_run_id=simulation_run_id,
                )
        else:
            # Isolated canary access read
            return ContainmentDecision(
                decision_id=decision_id,
                timestamp=now_iso,
                threat_score=CONFIG.WEIGHT_FIRST_CANARY,
                severity=ThreatLevel.HIGH.value,
                decision_reason="Immediate alert: Canary decoy file accessed; review required.",
                recommended_action=ContainmentAction.ALERT_REVIEW.value,
                auto_containment_authorized=False,
                explanation=(
                    f"Canary file '{alert.target_path}' accessed. Non-destructive access requires "
                    "operator review before taking containment measures."
                ),
                related_detection_id=alert.detection_id,
                simulation_run_id=simulation_run_id,
            )

