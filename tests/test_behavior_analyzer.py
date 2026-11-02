"""
Unit tests for app.detection.behavior_analyzer.
"""

import pytest

from app.core.models import ContributingIndicator, DetectionReason, ProcessAttribution
from app.detection.behavior_analyzer import BehaviorAnalyzer, BehaviorEvaluation
from app.detection.event_correlator import WindowActivitySummary


def test_normal_activity_not_suspicious():
    analyzer = BehaviorAnalyzer()
    summary = WindowActivitySummary(
        window_seconds=5.0,
        start_time="2026-11-02T12:00:00Z",
        end_time="2026-11-02T12:00:05Z",
        total_events=3,
        unique_files={"Finance/memo.txt", "HR/notes.md"},
        unique_modified_files={"Finance/memo.txt"},
        unique_accessed_files={"HR/notes.md"},
        departments_affected={"Finance", "Human Resources"},
        file_types_affected={"txt", "md"},
    )

    evaluation = analyzer.evaluate(summary)
    assert not evaluation.is_suspicious
    assert len(evaluation.indicators) == 0
    assert len(evaluation.reasons) == 0


def test_moderate_and_large_modification_bursts():
    analyzer = BehaviorAnalyzer(mod_moderate_threshold=15, mod_large_threshold=40)

    # Case 1: Moderate modification burst (20 files)
    mod_files_20 = {f"Finance/file_{i}.txt" for i in range(20)}
    summary_mod = WindowActivitySummary(
        window_seconds=5.0,
        start_time="2026-11-02T12:00:00Z",
        end_time="2026-11-02T12:00:05Z",
        total_events=20,
        unique_files=mod_files_20,
        unique_modified_files=mod_files_20,
        departments_affected={"Finance"},
        file_types_affected={"txt"},
    )
    eval_mod = analyzer.evaluate(summary_mod)
    assert eval_mod.is_suspicious
    assert DetectionReason.MASS_FILE_MODIFICATION.value in eval_mod.reasons
    assert any(i.indicator_name == "MODERATE_FILE_MODIFICATION_BURST" for i in eval_mod.indicators)

    # Case 2: Large modification burst (45 files)
    mod_files_45 = {f"Finance/file_{i}.txt" for i in range(45)}
    summary_large = WindowActivitySummary(
        window_seconds=5.0,
        start_time="2026-11-02T12:00:00Z",
        end_time="2026-11-02T12:00:05Z",
        total_events=45,
        unique_files=mod_files_45,
        unique_modified_files=mod_files_45,
        departments_affected={"Finance"},
        file_types_affected={"txt"},
    )
    eval_large = analyzer.evaluate(summary_large)
    assert eval_large.is_suspicious
    assert any(i.indicator_name == "LARGE_FILE_MODIFICATION_BURST" for i in eval_large.indicators)


def test_rapid_file_renaming():
    analyzer = BehaviorAnalyzer(rename_threshold=10)
    renamed_files = {f"Finance/file_{i}.encrypted" for i in range(12)}
    summary = WindowActivitySummary(
        window_seconds=5.0,
        start_time="2026-11-02T12:00:00Z",
        end_time="2026-11-02T12:00:05Z",
        total_events=12,
        unique_files=renamed_files,
        unique_renamed_files=renamed_files,
        departments_affected={"Finance"},
        file_types_affected={"encrypted"},
    )
    evaluation = analyzer.evaluate(summary)
    assert evaluation.is_suspicious
    assert DetectionReason.RAPID_FILE_RENAMING.value in evaluation.reasons
    assert any(i.indicator_name == "RAPID_FILE_RENAMING" for i in evaluation.indicators)


def test_multi_department_and_pattern_synergy():
    analyzer = BehaviorAnalyzer(mod_large_threshold=40, department_threshold=3)
    mod_files = {f"dept_{i}/file_{j}.txt" for i in range(4) for j in range(11)}  # 44 files
    summary = WindowActivitySummary(
        window_seconds=5.0,
        start_time="2026-11-02T12:00:00Z",
        end_time="2026-11-02T12:00:05Z",
        total_events=44,
        unique_files=mod_files,
        unique_modified_files=mod_files,
        departments_affected={"Finance", "Human Resources", "Legal", "IT"},
        file_types_affected={"txt"},
    )
    evaluation = analyzer.evaluate(summary)
    assert evaluation.is_suspicious
    assert DetectionReason.MASS_FILE_MODIFICATION.value in evaluation.reasons
    assert DetectionReason.MULTI_DEPARTMENT_TARGETING.value in evaluation.reasons
    assert DetectionReason.UNUSUAL_BURST_ACTIVITY.value in evaluation.reasons
    assert any(i.indicator_name == "MULTIPLE_SUSPICIOUS_PATTERNS" for i in evaluation.indicators)


def test_legitimate_bulk_activity_handling():
    analyzer = BehaviorAnalyzer()
    mod_files = {f"Backup/file_{i}.txt" for i in range(100)}
    summary = WindowActivitySummary(
        window_seconds=5.0,
        start_time="2026-11-02T12:00:00Z",
        end_time="2026-11-02T12:00:05Z",
        total_events=100,
        unique_files=mod_files,
        unique_modified_files=mod_files,
        departments_affected={"IT"},
        file_types_affected={"txt"},
        is_legitimate_source=True,
    )
    evaluation = analyzer.evaluate(summary)
    assert evaluation.is_legitimate_bulk is True
    assert DetectionReason.LEGITIMATE_BULK_ACTIVITY.value in evaluation.reasons
    assert evaluation.indicators[0].score_contribution == 0


def test_modification_thresholds_are_mutually_exclusive():
    """Verify that moderate and large bursts are mutually exclusive and never double-counted."""
    analyzer = BehaviorAnalyzer(mod_moderate_threshold=15, mod_large_threshold=40)
    files_50 = {f"Finance/file_{i}.txt" for i in range(50)}
    summary = WindowActivitySummary(
        window_seconds=5.0,
        start_time="2026-11-02T12:00:00Z",
        end_time="2026-11-02T12:00:05Z",
        total_events=50,
        unique_files=files_50,
        unique_modified_files=files_50,
        departments_affected={"Finance"},
        file_types_affected={"txt"},
    )
    evaluation = analyzer.evaluate(summary)
    mod_indicators = [
        i for i in evaluation.indicators
        if i.indicator_name in {"LARGE_FILE_MODIFICATION_BURST", "MODERATE_FILE_MODIFICATION_BURST"}
    ]
    # Exactly one indicator must be added
    assert len(mod_indicators) == 1
    assert mod_indicators[0].indicator_name == "LARGE_FILE_MODIFICATION_BURST"
    # Reason must appear exactly once
    assert evaluation.reasons.count(DetectionReason.MASS_FILE_MODIFICATION.value) == 1


def test_multi_department_does_not_trigger_on_reads():
    """Verify reading files in multiple departments while modifying 1 file does not trigger multi-dept."""
    analyzer = BehaviorAnalyzer(department_threshold=3)
    summary = WindowActivitySummary(
        window_seconds=5.0,
        start_time="2026-11-02T12:00:00Z",
        end_time="2026-11-02T12:00:05Z",
        total_events=5,
        unique_files={"HR/doc.txt", "Legal/doc.txt", "IT/doc.txt", "Finance/single_edit.txt"},
        unique_accessed_files={"HR/doc.txt", "Legal/doc.txt", "IT/doc.txt"},
        unique_modified_files={"Finance/single_edit.txt"},
        departments_affected={"Human Resources", "Legal", "IT", "Finance"},
        file_types_affected={"txt"},
    )
    evaluation = analyzer.evaluate(summary)
    assert DetectionReason.MULTI_DEPARTMENT_TARGETING.value not in evaluation.reasons
    assert not any(i.indicator_name == "MULTI_DEPARTMENT_SPREAD" for i in evaluation.indicators)

