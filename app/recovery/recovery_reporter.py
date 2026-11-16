"""
Recovery Reporter for CryptoShield Phase 6.

Persists forensic recovery reports, audits, and manifests as structured JSON dossiers
under `runtime/recovery/reports/`, and formats human-readable assessment and restoration
summaries for the CLI and logging pipelines.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from app.config import CONFIG
from app.core.logger import get_logger
from app.recovery.models import (
    RecoveryError,
    RecoveryOperationReport,
    WorkspaceAssessmentSummary,
)

logger = get_logger("recovery_reporter")


class RecoveryReporter:
    """
    Manages persistence and presentation of Phase 6 recovery dossiers and integrity assessments.
    """

    def __init__(self, reports_dir: Optional[Path] = None) -> None:
        self.reports_dir = (reports_dir or CONFIG.RECOVERY_REPORTS_DIR).resolve()
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def save_report(
        self,
        report: Union[RecoveryOperationReport, Dict[str, Any]],
    ) -> Path:
        """
        Persist a recovery operation report atomically to disk.

        Args:
            report: RecoveryOperationReport dataclass instance or raw dictionary.

        Returns:
            The Path to the saved report file.
        """
        if isinstance(report, RecoveryOperationReport):
            data = report.to_dict()
            rec_id = report.recovery_id
        elif isinstance(report, dict):
            data = report
            rec_id = str(data.get("recovery_id", f"REC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"))
        else:
            raise RecoveryError(f"Unsupported report type: {type(report)}")

        target_file = self.reports_dir / f"{rec_id}.json"
        tmp_file = target_file.with_suffix(".tmp")

        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            os.replace(str(tmp_file), str(target_file))
            logger.info(f"Persisted recovery report: '{target_file}'")
            return target_file
        except Exception as e:
            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except OSError:
                    pass
            logger.error(f"Failed to persist recovery report: {e}")
            raise RecoveryError(f"Report persistence failed: {e}") from e

    def load_report(self, report_id_or_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Load a recovery report dossier by ID or file path.

        Args:
            report_id_or_path: Report ID (e.g. REC-12345678) or direct path to JSON file.

        Returns:
            Parsed report dictionary.
        """
        candidate = Path(report_id_or_path)
        if candidate.suffix == ".json" and candidate.exists():
            target = candidate
        else:
            # Look up by ID in reports directory
            name = f"{candidate.stem}.json"
            target = self.reports_dir / name

        if not target.exists():
            raise RecoveryError(f"Recovery report not found: '{report_id_or_path}'")

        try:
            with open(target, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            raise RecoveryError(f"Failed to read recovery report '{target}': {e}") from e

    def list_reports(self) -> List[Dict[str, Any]]:
        """
        Enumerate all saved recovery reports sorted by completion timestamp descending.

        Returns:
            List of summary dictionaries.
        """
        results: List[Dict[str, Any]] = []
        if not self.reports_dir.exists():
            return results

        for p in self.reports_dir.glob("REC-*.json"):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                results.append(
                    {
                        "recovery_id": data.get("recovery_id", p.stem),
                        "workspace_id": data.get("workspace_id", "UNKNOWN"),
                        "snapshot_id": data.get("snapshot_id", "UNKNOWN"),
                        "mode": data.get("mode", "UNKNOWN"),
                        "dry_run": data.get("dry_run", False),
                        "authorized": data.get("authorized", False),
                        "completed_at": data.get("completed_at", ""),
                        "duration_seconds": data.get("duration_seconds", 0.0),
                        "total_evaluated": data.get("total_evaluated", 0),
                        "restored_count": data.get("restored_count", 0),
                        "failed_count": data.get("failed_count", 0),
                        "canary_restored_count": data.get("canary_restored_count", 0),
                        "post_recovery_audit_passed": data.get("post_recovery_audit_passed"),
                        "path": str(p),
                    }
                )
            except Exception:
                continue

        results.sort(key=lambda r: str(r.get("completed_at", "")), reverse=True)
        return results

    def format_assessment_summary(self, summary: WorkspaceAssessmentSummary) -> str:
        """
        Format a human-readable ASCII summary table for workspace assessment.
        """
        lines = [
            "================================================================================",
            "                 CRYPTOSHIELD WORKSPACE INTEGRITY ASSESSMENT                    ",
            "================================================================================",
            f"Assessment ID       : {summary.assessment_id}",
            f"Workspace ID        : {summary.workspace_id}",
            f"Baseline Snapshot   : {summary.snapshot_id}",
            f"Assessed At         : {summary.assessed_at}",
            f"Duration            : {summary.duration_seconds:.3f} seconds",
            "--------------------------------------------------------------------------------",
            f"Baseline Manifest Files : {summary.total_manifest_files:,}",
            f"Workspace Files Scanned : {summary.total_workspace_files_scanned:,}",
            "--------------------------------------------------------------------------------",
            f"  [+] INTACT Files      : {summary.intact_count:,}",
            f"  [!] MODIFIED Files    : {summary.modified_count:,}",
            f"  [-] MISSING Files     : {summary.missing_count:,}",
            f"  [?] UNREADABLE Files  : {summary.unreadable_count:,}",
            f"  [*] UNTRACKED Files   : {summary.untracked_count:,}",
            "--------------------------------------------------------------------------------",
            f"  Canary Files Affected : {summary.canary_affected_count:,}",
            "================================================================================",
        ]

        # Detail top affected files if present
        affected = [
            (path, rec)
            for path, rec in summary.records.items()
            if rec.status.value in ("MODIFIED", "MISSING", "UNREADABLE")
        ]
        if affected:
            lines.append("Sample Damaged / Missing Items (up to 10):")
            for path, rec in affected[:10]:
                canary_tag = " [CANARY]" if rec.is_canary else ""
                lines.append(f"  - [{rec.status.value:<10}] {path}{canary_tag}")
            if len(affected) > 10:
                lines.append(f"    ... and {len(affected) - 10} additional items")
            lines.append("================================================================================")

        return "\n".join(lines)

    def format_operation_report(self, report: RecoveryOperationReport) -> str:
        """
        Format a human-readable ASCII summary table for a recovery operation.
        """
        run_mode_label = "DRY-RUN PREVIEW (No Changes)" if report.dry_run else "LIVE RESTORATION (Committed)"
        audit_str = (
            "PASSED (100% Intact)"
            if report.post_recovery_audit_passed is True
            else (
                "FAILED (Discrepancies Found)"
                if report.post_recovery_audit_passed is False
                else "N/A (Preview)"
            )
        )

        lines = [
            "================================================================================",
            "                 CRYPTOSHIELD RECOVERY OPERATION REPORT                         ",
            "================================================================================",
            f"Recovery ID         : {report.recovery_id}",
            f"Workspace ID        : {report.workspace_id}",
            f"Source Snapshot     : {report.snapshot_id}",
            f"Recovery Mode       : {report.mode.value}",
            f"Execution Type      : {run_mode_label}",
            f"Authorized          : {'[YES]' if report.authorized else '[NO]'}",
            f"Overwrite Modified  : {'[YES]' if report.overwrite_modified else '[NO]'}",
            f"Target Filter       : {report.target_filter or 'All Workspace Files'}",
            f"Started At          : {report.started_at}",
            f"Completed At        : {report.completed_at}",
            f"Duration            : {report.duration_seconds:.3f} seconds",
            "--------------------------------------------------------------------------------",
            f"Total Evaluated     : {report.total_evaluated:,}",
            f"  [+] Restored Files     : {report.restored_count:,}",
            f"  [*] Evidence Quarantined : {report.evidence_preserved_count:,}",
            f"  [-] Skipped Intact     : {report.skipped_intact_count:,}",
            f"  [#] Preserved Untracked: {report.untracked_preserved_count:,}",
            f"  [?] Manual Review Reqd : {report.manual_review_count:,}",
            f"  [!] Failed Restorations : {report.failed_count:,}",
            "--------------------------------------------------------------------------------",
            f"Canary Files Restored : {report.canary_restored_count:,}",
            f"Post-Recovery Audit   : {audit_str}",
            "================================================================================",
        ]

        # List sample restored files
        restored_records = [
            r for r in report.file_records if r.outcome.value == "RESTORED"
        ]
        if restored_records:
            lines.append("Restored Items Sample (up to 10):")
            for r in restored_records[:10]:
                canary_tag = " [CANARY]" if r.is_canary else ""
                lines.append(f"  - {r.relative_path}{canary_tag} -> SHA-256: {r.restored_sha256[:16]}...")
            if len(restored_records) > 10:
                lines.append(f"    ... and {len(restored_records) - 10} additional restored items")
            lines.append("================================================================================")

        # List failures if any
        failed_records = [
            r for r in report.file_records if r.outcome.value.startswith("FAILED")
        ]
        if failed_records:
            lines.append("[!] Failed Items:")
            for r in failed_records[:10]:
                lines.append(f"  - {r.relative_path} [{r.outcome.value}]: {r.error_detail}")
            lines.append("================================================================================")

        return "\n".join(lines)
