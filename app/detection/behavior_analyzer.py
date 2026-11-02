"""
Behaviour Analyzer for CryptoShield.

Analyzes correlated filesystem activity summaries for ransomware-like behavioural
patterns such as mass modifications, rapid renames, large-scale deletions, multi-department
spread, and extension diversity, while distinguishing legitimate bulk operations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from app.config import CONFIG
from app.core.logger import get_logger
from app.core.models import (
    ContributingIndicator,
    DetectionReason,
    ProcessAttribution,
)
from app.detection.event_correlator import WindowActivitySummary

logger = get_logger("behavior_analyzer")


@dataclass
class BehaviorEvaluation:
    """Evaluation result produced by BehaviourAnalyzer for a specific activity window."""
    indicators: List[ContributingIndicator] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    is_suspicious: bool = False
    is_legitimate_bulk: bool = False
    affected_files_count: int = 0
    departments_count: int = 0
    file_types_count: int = 0
    renamed_count: int = 0
    deleted_count: int = 0
    modified_count: int = 0
    process_attribution: str = ProcessAttribution.UNKNOWN.value
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    explanations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicators": [i.to_dict() for i in self.indicators],
            "reasons": self.reasons,
            "is_suspicious": self.is_suspicious,
            "is_legitimate_bulk": self.is_legitimate_bulk,
            "affected_files_count": self.affected_files_count,
            "departments_count": self.departments_count,
            "file_types_count": self.file_types_count,
            "renamed_count": self.renamed_count,
            "deleted_count": self.deleted_count,
            "modified_count": self.modified_count,
            "process_attribution": self.process_attribution,
            "process_id": self.process_id,
            "process_name": self.process_name,
            "explanations": self.explanations,
        }


class BehaviorAnalyzer:
    """
    Rule-based behavioural analysis engine for filesystem telemetry.
    
    Evaluates multiple orthogonal indicators over sliding activity summaries
    and accounts for legitimate bulk operations (e.g. backup, synchronization).
    """

    def __init__(
        self,
        mod_moderate_threshold: int = CONFIG.BURST_MODERATE_MODIFICATION_THRESHOLD,
        mod_large_threshold: int = CONFIG.BURST_LARGE_MODIFICATION_THRESHOLD,
        rename_threshold: int = CONFIG.BURST_RAPID_RENAME_THRESHOLD,
        deletion_threshold: int = CONFIG.BURST_DELETION_THRESHOLD,
        department_threshold: int = CONFIG.MULTI_DEPARTMENT_THRESHOLD,
        extension_threshold: int = CONFIG.MULTI_EXTENSION_THRESHOLD,
    ) -> None:
        self.mod_moderate_threshold = mod_moderate_threshold
        self.mod_large_threshold = mod_large_threshold
        self.rename_threshold = rename_threshold
        self.deletion_threshold = deletion_threshold
        self.department_threshold = department_threshold
        self.extension_threshold = extension_threshold

    def evaluate(self, summary: WindowActivitySummary) -> BehaviorEvaluation:
        """
        Evaluate a WindowActivitySummary and produce a BehaviorEvaluation.
        
        Applies transparent heuristics based on unique affected files,
        diversity of targets, operation velocity, and source legitimacy.
        """
        eval_result = BehaviorEvaluation(
            affected_files_count=len(summary.unique_files),
            departments_count=len(summary.departments_affected),
            file_types_count=len(summary.file_types_affected),
            renamed_count=len(summary.unique_renamed_files),
            deleted_count=len(summary.unique_deleted_files),
            modified_count=len(summary.unique_modified_files),
            process_attribution=summary.process_attribution,
            process_id=summary.attributed_process_id,
            process_name=summary.attributed_process_name,
        )

        # Early return if no events
        if summary.total_events == 0:
            return eval_result

        # Check for legitimate bulk activity
        if summary.is_legitimate_source:
            eval_result.is_legitimate_bulk = True
            eval_result.reasons.append(DetectionReason.LEGITIMATE_BULK_ACTIVITY.value)
            eval_result.explanations.append(
                f"Observed {summary.total_events} operations originating from an authorized "
                f"or verified legitimate source."
            )
            eval_result.indicators.append(
                ContributingIndicator(
                    indicator_name="LEGITIMATE_BULK_ACTIVITY",
                    score_contribution=0,
                    description="Activity verified as legitimate backup, synchronization, or maintenance source.",
                    observed_value=summary.total_events,
                    threshold=0,
                )
            )
            return eval_result

        suspicious_patterns_count = 0

        # 1. Mass File Modifications (Large vs Moderate)
        mod_count = len(summary.unique_modified_files)
        if mod_count >= self.mod_large_threshold:
            suspicious_patterns_count += 1
            eval_result.reasons.append(DetectionReason.MASS_FILE_MODIFICATION.value)
            eval_result.explanations.append(
                f"Large burst of modifications: {mod_count} unique files modified in {summary.window_seconds:.1f}s "
                f"(threshold: {self.mod_large_threshold})."
            )
            eval_result.indicators.append(
                ContributingIndicator(
                    indicator_name="LARGE_FILE_MODIFICATION_BURST",
                    score_contribution=CONFIG.WEIGHT_LARGE_MODIFICATIONS,
                    description="High-velocity modification of files across the laboratory.",
                    observed_value=mod_count,
                    threshold=self.mod_large_threshold,
                )
            )
        elif mod_count >= self.mod_moderate_threshold:
            suspicious_patterns_count += 1
            eval_result.reasons.append(DetectionReason.MASS_FILE_MODIFICATION.value)
            eval_result.explanations.append(
                f"Moderate burst of modifications: {mod_count} unique files modified in {summary.window_seconds:.1f}s "
                f"(threshold: {self.mod_moderate_threshold})."
            )
            eval_result.indicators.append(
                ContributingIndicator(
                    indicator_name="MODERATE_FILE_MODIFICATION_BURST",
                    score_contribution=CONFIG.WEIGHT_MODERATE_MODIFICATIONS,
                    description="Elevated rate of file modification within short correlation window.",
                    observed_value=mod_count,
                    threshold=self.mod_moderate_threshold,
                )
            )

        # 2. Rapid File Renaming (Common in ransomware encryption/extension append)
        rename_count = len(summary.unique_renamed_files)
        if rename_count >= self.rename_threshold:
            suspicious_patterns_count += 1
            eval_result.reasons.append(DetectionReason.RAPID_FILE_RENAMING.value)
            eval_result.explanations.append(
                f"Rapid file renaming: {rename_count} files renamed or moved in {summary.window_seconds:.1f}s "
                f"(threshold: {self.rename_threshold})."
            )
            eval_result.indicators.append(
                ContributingIndicator(
                    indicator_name="RAPID_FILE_RENAMING",
                    score_contribution=CONFIG.WEIGHT_RAPID_RENAMING,
                    description="Unusual velocity of file renames, typical of ransomware extension alteration.",
                    observed_value=rename_count,
                    threshold=self.rename_threshold,
                )
            )

        # 3. Large-scale Deletions
        del_count = len(summary.unique_deleted_files)
        if del_count >= self.deletion_threshold:
            suspicious_patterns_count += 1
            eval_result.reasons.append(DetectionReason.LARGE_SCALE_DELETION.value)
            eval_result.explanations.append(
                f"Large-scale deletions: {del_count} unique files deleted in {summary.window_seconds:.1f}s "
                f"(threshold: {self.deletion_threshold})."
            )
            eval_result.indicators.append(
                ContributingIndicator(
                    indicator_name="LARGE_SCALE_DELETIONS",
                    score_contribution=CONFIG.WEIGHT_LARGE_DELETIONS,
                    description="Mass deletion of enterprise files.",
                    observed_value=del_count,
                    threshold=self.deletion_threshold,
                )
            )

        # 4. Multi-Department Activity Spread
        # Only evaluate departments where files were actively modified, renamed, or deleted
        active_paths = summary.unique_modified_files | summary.unique_renamed_files | summary.unique_deleted_files
        affected_depts: Set[str] = set()
        for p in active_paths:
            if "/" in p:
                d = p.split("/")[0]
                affected_depts.add(d)

        # Fallback to summary.departments_affected if explicitly populated for active operations
        if not affected_depts and active_paths and summary.departments_affected:
            affected_depts = set(summary.departments_affected)

        dept_count = len(affected_depts)
        if dept_count >= self.department_threshold and (mod_count + rename_count) >= self.department_threshold:
            suspicious_patterns_count += 1
            depts_str = ", ".join(sorted(affected_depts))
            eval_result.reasons.append(DetectionReason.MULTI_DEPARTMENT_TARGETING.value)
            eval_result.explanations.append(
                f"Cross-departmental activity: {dept_count} departments affected ({depts_str}) "
                f"(threshold: {self.department_threshold})."
            )
            eval_result.indicators.append(
                ContributingIndicator(
                    indicator_name="MULTI_DEPARTMENT_SPREAD",
                    score_contribution=CONFIG.WEIGHT_MULTI_DEPARTMENT,
                    description="File operations spanning multiple distinct enterprise departments.",
                    observed_value=dept_count,
                    threshold=self.department_threshold,
                )
            )

        # 5. Multi-Extension Diversity
        active_files_for_ext = summary.unique_modified_files | summary.unique_renamed_files
        target_exts: Set[str] = set()
        for p in active_files_for_ext:
            if "." in p:
                ext = p.rsplit(".", 1)[-1].lower()
                if ext:
                    target_exts.add(ext)

        if not target_exts and active_files_for_ext and summary.file_types_affected:
            target_exts = set(summary.file_types_affected)

        ext_count = len(target_exts)
        if ext_count >= self.extension_threshold and (mod_count + rename_count) >= 10:
            eval_result.reasons.append(DetectionReason.MULTI_EXTENSION_TARGETING.value)
            exts_str = ", ".join(sorted(target_exts))
            eval_result.explanations.append(
                f"Multi-extension diversity: {ext_count} file formats targeted ({exts_str}) "
                f"(threshold: {self.extension_threshold})."
            )
            eval_result.indicators.append(
                ContributingIndicator(
                    indicator_name="MULTI_EXTENSION_DIVERSITY",
                    score_contribution=CONFIG.WEIGHT_MULTI_EXTENSION,
                    description="Operations affecting diverse file formats across the enterprise repository.",
                    observed_value=ext_count,
                    threshold=self.extension_threshold,
                )
            )

        # 6. Combined Pattern Synergy Bonus
        if suspicious_patterns_count >= 2:
            eval_result.reasons.append(DetectionReason.UNUSUAL_BURST_ACTIVITY.value)
            eval_result.explanations.append(
                f"Multiple suspicious behavioural indicators detected concurrently ({suspicious_patterns_count} patterns)."
            )
            eval_result.indicators.append(
                ContributingIndicator(
                    indicator_name="MULTIPLE_SUSPICIOUS_PATTERNS",
                    score_contribution=CONFIG.WEIGHT_MULTIPLE_PATTERNS,
                    description="Co-occurrence of multiple suspicious behavioral indicators.",
                    observed_value=suspicious_patterns_count,
                    threshold=2,
                )
            )

        eval_result.is_suspicious = len(eval_result.indicators) > 0
        return eval_result

