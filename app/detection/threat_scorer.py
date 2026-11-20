"""
Threat Scoring Engine for CryptoShield.

Synthesizes behavioral indicators and canary evaluations into an explainable
threat score between 0 and 100, maps scores to standardized severity levels,
and generates structured, human-readable detection assessments.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.config import CONFIG
from app.core.logger import get_logger
from app.core.models import (
    AssessmentType,
    ContributingIndicator,
    DetectionReason,
    DetectionResult,
    ProcessAttribution,
    ThreatLevel,
)
from app.detection.behavior_analyzer import BehaviorEvaluation
from app.detection.canary_analyzer import CanaryEvaluation

logger = get_logger("threat_scorer")


class ThreatScorer:
    """
    Explainable, rule-based threat scoring engine.
    
    Combines independent indicators into a bounded 0-100 heuristic risk score
    with granular detection reasons and severity categorization.
    """

    def __init__(
        self,
        severity_thresholds: Optional[Dict[str, int]] = None,
        max_score: int = 100,
    ) -> None:
        self.severity_thresholds = severity_thresholds or CONFIG.SEVERITY_THRESHOLDS
        self.max_score = max_score

    def calculate_score(
        self,
        behavior_eval: BehaviorEvaluation,
        canary_eval: CanaryEvaluation,
        window_seconds: float = 5.0,
        incident_id: Optional[str] = None,
        affected_files: Optional[List[str]] = None,
    ) -> DetectionResult:
        """
        Compute total threat score, resolve severity level, and compile
        a fully explainable DetectionResult.
        """
        all_indicators: List[ContributingIndicator] = []
        all_reasons: List[str] = []

        # Ingest behavior indicators
        for ind in behavior_eval.indicators:
            all_indicators.append(ind)
        for r in behavior_eval.reasons:
            if r not in all_reasons:
                all_reasons.append(r)

        # Ingest canary indicators
        for ind in canary_eval.indicators:
            all_indicators.append(ind)
        for r in canary_eval.reasons:
            if r not in all_reasons:
                all_reasons.append(r)

        raw_score = sum(i.score_contribution for i in all_indicators)

        # Handle legitimate bulk activity suppression:
        # If behavior is verified legitimate bulk, zero out behavioral score.
        # But if a canary was also accessed/tampered, retain canary score!
        if behavior_eval.is_legitimate_bulk:
            canary_score = sum(i.score_contribution for i in canary_eval.indicators)
            raw_score = canary_score

        # Bound score between 0 and max_score (100)
        final_score = max(0, min(self.max_score, raw_score))

        # Determine severity level
        severity = self._resolve_severity(final_score)

        # Determine assessment text
        assessment = self._resolve_assessment(
            score=final_score,
            behavior_eval=behavior_eval,
            canary_eval=canary_eval,
        )

        # Process attribution resolution:
        # Prefer confirmed attribution from either behavior or canary
        resolved_attr = ProcessAttribution.UNKNOWN.value
        proc_id: Optional[int] = None
        proc_name: Optional[str] = None

        if canary_eval.process_attribution == ProcessAttribution.CONFIRMED.value:
            resolved_attr = ProcessAttribution.CONFIRMED.value
            proc_id = canary_eval.process_id
            proc_name = canary_eval.process_name
        elif behavior_eval.process_attribution == ProcessAttribution.CONFIRMED.value:
            resolved_attr = ProcessAttribution.CONFIRMED.value
            proc_id = behavior_eval.process_id
            proc_name = behavior_eval.process_name
        elif canary_eval.process_attribution == ProcessAttribution.INFERRED.value:
            resolved_attr = ProcessAttribution.INFERRED.value
            proc_id = canary_eval.process_id
            proc_name = canary_eval.process_name
        elif behavior_eval.process_attribution == ProcessAttribution.INFERRED.value:
            resolved_attr = ProcessAttribution.INFERRED.value
            proc_id = behavior_eval.process_id
            proc_name = behavior_eval.process_name

        affected_count = behavior_eval.affected_files_count
        if canary_eval.canary_events_count > 0:
            affected_count = max(
                affected_count,
                len(canary_eval.unique_canaries_accessed | canary_eval.unique_canaries_tampered),
            )

        total_canaries = len(canary_eval.unique_canaries_accessed | canary_eval.unique_canaries_tampered)

        metadata: Dict[str, Any] = {
            "behavior_explanations": behavior_eval.explanations,
            "canary_explanations": canary_eval.explanations,
            "departments_count": behavior_eval.departments_count,
            "file_types_count": behavior_eval.file_types_count,
            "modified_count": behavior_eval.modified_count,
            "renamed_count": behavior_eval.renamed_count,
            "deleted_count": behavior_eval.deleted_count,
            "is_legitimate_bulk": behavior_eval.is_legitimate_bulk,
        }

        return DetectionResult(
            detection_id=str(uuid.uuid4()),
            timestamp=datetime.now(CONFIG.TIMEZONE).isoformat(),
            threat_score=final_score,
            severity=severity,
            assessment=assessment,
            reasons=all_reasons,
            affected_files_count=affected_count,
            canary_access_count=total_canaries,
            process_attribution=resolved_attr,
            process_id=proc_id,
            process_name=proc_name,
            incident_id=incident_id,
            window_seconds=window_seconds,
            contributing_indicators=all_indicators,
            affected_files=affected_files or [],
            metadata=metadata,
        )

    def _resolve_severity(self, score: int) -> str:
        """Map numeric score (0-100) to ThreatLevel severity."""
        if score >= self.severity_thresholds.get("CRITICAL", 80):
            return ThreatLevel.CRITICAL.value
        elif score >= self.severity_thresholds.get("HIGH", 60):
            return ThreatLevel.HIGH.value
        elif score >= self.severity_thresholds.get("MEDIUM", 40):
            return ThreatLevel.MEDIUM.value
        elif score >= self.severity_thresholds.get("LOW", 20):
            return ThreatLevel.LOW.value
        else:
            return ThreatLevel.NORMAL.value

    def _resolve_assessment(
        self,
        score: int,
        behavior_eval: BehaviorEvaluation,
        canary_eval: CanaryEvaluation,
    ) -> str:
        """Formulate a contextual risk assessment."""
        if behavior_eval.is_legitimate_bulk and not canary_eval.is_canary_tripped:
            return "Verified legitimate bulk file activity (benign maintenance/backup pattern)."

        if score >= 80:
            if canary_eval.is_canary_tripped and (
                behavior_eval.modified_count > 0
                or behavior_eval.renamed_count > 0
                or behavior_eval.affected_files_count > 0
                or len(behavior_eval.indicators) > 0
            ):
                return "CRITICAL: Strong evidence of ransomware-like activity; exfiltration assessment pending."
            return "CRITICAL: Strong evidence of ransomware-like mass encryption or alteration."

        if score >= 60:
            if canary_eval.is_canary_tripped:
                return "HIGH: Suspicious canary breach coupled with anomalous file operations."
            return "HIGH: High-velocity anomalous filesystem activity detected across departments."

        if score >= 40:
            if canary_eval.is_canary_tripped:
                return "MEDIUM: Suspicious canary decoy access detected without widespread mass file activity."
            return "MEDIUM: Suspicious file modification or renaming burst observed."

        if score >= 20:
            if behavior_eval.reasons:
                reasons_text = ", ".join(r.replace("_", " ").title() for r in behavior_eval.reasons)
                return f"LOW: Elevated file activity observed ({reasons_text})."
            return "LOW: Low-risk minor activity fluctuation within baseline expectations."

        return "NORMAL: Baseline enterprise activity; no suspicious patterns detected."

    def format_explanation(self, result: DetectionResult) -> str:
        """Format an explainable, human-readable detection assessment report."""
        lines = [
            f"Threat Score: {result.threat_score}/100",
            f"Severity    : {result.severity}",
            "",
            "Detection Reasons:",
        ]
        if result.reasons:
            for r in result.reasons:
                lines.append(f"- {r}")
        else:
            lines.append("- No suspicious indicators triggered.")

        lines.append("")
        lines.append("Contributing Indicators:")
        if result.contributing_indicators:
            for ind in result.contributing_indicators:
                lines.append(f"  * {ind.indicator_name} (+{ind.score_contribution}): {ind.description}")
        else:
            lines.append("  * None")

        lines.append("")
        lines.append(f"Assessment  : {result.assessment}")
        lines.append(f"Attribution : {result.process_attribution}" + (
            f" (PID: {result.process_id} {result.process_name})" if result.process_id else ""
        ))
        lines.append(f"Affected    : {result.affected_files_count} files, {result.canary_access_count} canaries")
        if result.canary_access_count > 0:
            lines.append("Alert Note  : Individual canary access generates immediate HIGH-priority alerts independently of overall window score.")
        return "\n".join(lines)

