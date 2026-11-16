"""
Recovery Coordinator for CryptoShield Phase 6.

Central orchestration layer integrating workspace lifecycle management, integrity
assessments, cryptographic two-gate staging, forensic restoration policies, reporting,
and EventBus telemetry for academic demonstrations and production operations.
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from app.config import CONFIG
from app.core.event_bus import Event, EventBus
from app.core.logger import get_logger
from app.recovery.models import (
    FileRestorationOutcome,
    RecoveryError,
    RecoveryOperationReport,
    WorkspaceAssessmentSummary,
)
from app.recovery.recovery_assessor import RecoveryAssessor
from app.recovery.recovery_engine import RecoveryEngine
from app.recovery.recovery_reporter import RecoveryReporter
from app.recovery.restoration_manager import RestorationManager
from app.recovery.workspace_manager import RecoveryWorkspaceManager
from app.vault.snapshot_manager import SnapshotManager

logger = get_logger("recovery_coordinator")


class RecoveryCoordinator:
    """
    Coordinates end-to-end cryptographic recovery operations and telemetry publishing.
    """

    def __init__(
        self,
        workspace_manager: Optional[RecoveryWorkspaceManager] = None,
        assessor: Optional[RecoveryAssessor] = None,
        engine: Optional[RecoveryEngine] = None,
        restoration_manager: Optional[RestorationManager] = None,
        reporter: Optional[RecoveryReporter] = None,
        event_bus: Optional[EventBus] = None,
    ) -> None:
        self.workspace_manager = workspace_manager or RecoveryWorkspaceManager()
        self.engine = engine or RecoveryEngine()
        self.assessor = assessor or RecoveryAssessor(
            workspace_manager=self.workspace_manager
        )
        self.restoration_manager = restoration_manager or RestorationManager(
            workspace_manager=self.workspace_manager,
            recovery_engine=self.engine,
            recovery_assessor=self.assessor,
        )
        self.reporter = reporter or RecoveryReporter()
        self.event_bus = event_bus

    def get_status(self) -> Dict[str, Any]:
        """
        Query system-wide status of the recovery subsystem, including registered workspaces,
        saved reports, and available snapshots.
        """
        workspaces = self.workspace_manager.list_workspaces()
        reports = self.reporter.list_reports()
        
        # Enumerate available snapshots from vault
        snapshots = []
        try:
            sm = SnapshotManager()
            for s in sm.list_snapshots():
                snapshots.append(
                    {
                        "snapshot_id": s.snapshot_id,
                        "created_at": s.created_at,
                        "total_files": s.total_files,
                        "total_encrypted_bytes": s.total_encrypted_bytes,
                        "status": s.completed_status,
                    }
                )
        except Exception as e:
            logger.warning(f"Could not enumerate vault snapshots: {e}")

        return {
            "workspaces_count": len(workspaces),
            "workspaces": [w.to_dict() for w in workspaces],
            "reports_count": len(reports),
            "recent_reports": reports[:5],
            "snapshots_count": len(snapshots),
            "snapshots": snapshots,
            "workspaces_dir": str(self.workspace_manager.workspaces_root),
            "reports_dir": str(self.reporter.reports_dir),
            "staging_dir": str(self.engine.staging_dir),
        }

    def assess(
        self,
        workspace_id: str,
        snapshot_id: str,
        passphrase: Optional[str] = None,
        target_file: Optional[str] = None,
        target_directory: Optional[str] = None,
        overwrite_modified: bool = False,
        full_manifest_scope: bool = False,
    ) -> WorkspaceAssessmentSummary:
        """
        Perform authenticated damage assessment comparing a workspace against a snapshot baseline.
        Publishes 'RECOVERY_ASSESSMENT_COMPLETED' event via EventBus.
        """
        logger.info(f"Assessing workspace '{workspace_id}' against snapshot '{snapshot_id}'")
        aes_key, manifest, _ = self.engine.unlock_snapshot(
            snapshot_id=snapshot_id,
            passphrase=passphrase,
        )

        summary = self.assessor.assess_workspace(
            workspace_id=workspace_id,
            manifest=manifest,
            overwrite_modified=overwrite_modified,
            target_relative_path=target_file,
            target_directory=target_directory,
            full_manifest_scope=full_manifest_scope,
        )

        if self.event_bus is not None:
            try:
                self.event_bus.publish(
                    Event(
                        event_type="RECOVERY_ASSESSMENT_COMPLETED",
                        data=summary.to_dict(),
                        source="recovery",
                    )
                )
            except Exception as e:
                logger.warning(f"Failed to publish assessment telemetry: {e}")

        return summary

    def preview(
        self,
        workspace_id: str,
        snapshot_id: str,
        passphrase: Optional[str] = None,
        target_file: Optional[str] = None,
        target_directory: Optional[str] = None,
        overwrite_modified: bool = True,
    ) -> RecoveryOperationReport:
        """
        Simulate a dry-run restoration plan with zero modifications to workspace files.
        """
        return self.restore(
            workspace_id=workspace_id,
            snapshot_id=snapshot_id,
            passphrase=passphrase,
            target_file=target_file,
            target_directory=target_directory,
            overwrite_modified=overwrite_modified,
            dry_run=True,
            authorize=False,
        )

    def restore(
        self,
        workspace_id: str,
        snapshot_id: str,
        passphrase: Optional[str] = None,
        target_file: Optional[str] = None,
        target_directory: Optional[str] = None,
        overwrite_modified: bool = True,
        dry_run: bool = False,
        authorize: bool = False,
        cancel_event: Optional[threading.Event] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> RecoveryOperationReport:
        """
        Perform preview or live restoration with safety gates, two-gate staging,
        evidence preservation, atomic commits, and telemetry publishing.
        """
        aes_key, manifest, _ = self.engine.unlock_snapshot(
            snapshot_id=snapshot_id,
            passphrase=passphrase,
        )

        report = self.restoration_manager.execute_restoration(
            workspace_id=workspace_id,
            snapshot_id=snapshot_id,
            manifest=manifest,
            aes_key=aes_key,
            dry_run=dry_run,
            authorize=authorize,
            overwrite_modified=overwrite_modified,
            target_relative_path=target_file,
            target_directory=target_directory,
            cancel_event=cancel_event,
            progress_callback=progress_callback,
        )

        # Persist report dossier
        self.reporter.save_report(report)

        # Publish telemetry events if live restoration
        if not dry_run and self.event_bus is not None:
            try:
                self.event_bus.publish(
                    Event(
                        event_type="RECOVERY_COMPLETED",
                        data=report.to_dict(),
                        source="recovery",
                    )
                )

                for rec in report.file_records:
                    if rec.outcome == FileRestorationOutcome.RESTORED and rec.is_canary:
                        self.event_bus.publish(
                            Event(
                                event_type="CANARY_FILE_RESTORED",
                                data={
                                    "workspace_id": workspace_id,
                                    "relative_path": rec.relative_path,
                                    "restored_sha256": rec.restored_sha256,
                                },
                                source="recovery",
                            )
                        )
            except Exception as e:
                logger.warning(f"Failed to publish recovery completion telemetry: {e}")

        return report

    def verify_workspace_integrity(
        self,
        workspace_id: str,
        snapshot_id: str,
        passphrase: Optional[str] = None,
    ) -> WorkspaceAssessmentSummary:
        """
        Audit the cryptographic integrity of a workspace against a snapshot baseline.
        """
        return self.assess(
            workspace_id=workspace_id,
            snapshot_id=snapshot_id,
            passphrase=passphrase,
            overwrite_modified=False,
        )

    def run_recovery_demo(
        self,
        file_count: int = 100,
        snapshot_id: Optional[str] = None,
        passphrase: Optional[str] = None,
        cleanup: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute an automated, end-to-end cryptographic recovery demonstration.

        1. Selects or verifies the snapshot baseline.
        2. Provisions an isolated recovery workspace seeded with `file_count` baseline files.
        3. Simulates controlled ransomware corruption (modifications, deletions, untracked artifacts, canary tampering).
        4. Executes 5-state integrity assessment.
        5. Executes safe dry-run preview.
        6. Executes authorized live restoration with forensic evidence preservation.
        7. Conducts post-recovery audit verifying 100% baseline restoration.
        8. Optionally cleans up the test workspace.

        Returns:
            Dictionary containing metrics, execution timings, throughput, and audit reports.
        """
        demo_start = time.perf_counter()
        logger.info(f"Starting recovery demo: file_count={file_count:,}, cleanup={cleanup}")

        # 1. Resolve Snapshot ID
        if not snapshot_id:
            sm = SnapshotManager()
            snaps = sm.list_snapshots()
            if not snaps:
                raise RecoveryError("No snapshot found in vault. Create a snapshot before running demo.")
            snapshot_id = snaps[0].snapshot_id

        # 2. Resolve Passphrase
        resolved_passphrase = passphrase or os.environ.get("CRYPTOSHIELD_VAULT_PASSPHRASE") or "CryptoShieldVaultPassphrase2026!"

        # 3. Create Isolated Seeded Recovery Workspace
        demo_ws_id = f"demo_rec_{file_count}_{uuid.uuid4().hex[:6]}"
        logger.info(f"Provisioning demo workspace '{demo_ws_id}' seeded with up to {file_count} files...")
        ws_meta = self.workspace_manager.create_workspace(
            workspace_id=demo_ws_id,
            source_snapshot_id=snapshot_id,
            seed_from_lab=True,
            max_seed_files=file_count,
        )

        try:
            # 4. Simulate Controlled Damage
            modify_cnt = max(1, min(50, file_count // 20))
            delete_cnt = max(1, min(50, file_count // 20))
            untracked_cnt = max(1, min(10, file_count // 50))
            damage = self.workspace_manager.simulate_workspace_damage(
                workspace_id=demo_ws_id,
                modify_count=modify_cnt,
                delete_count=delete_cnt,
                untracked_count=untracked_cnt,
                include_canary=True,
            )

            # 5. Damage Assessment
            t_assess = time.perf_counter()
            assessment = self.assess(
                workspace_id=demo_ws_id,
                snapshot_id=snapshot_id,
                passphrase=resolved_passphrase,
                overwrite_modified=True,
            )
            assess_time = time.perf_counter() - t_assess

            # 6. Preview (Dry-Run)
            t_prev = time.perf_counter()
            preview_report = self.preview(
                workspace_id=demo_ws_id,
                snapshot_id=snapshot_id,
                passphrase=resolved_passphrase,
                overwrite_modified=True,
            )
            preview_time = time.perf_counter() - t_prev

            # 7. Live Restoration (Authorized)
            t_rest = time.perf_counter()
            restore_report = self.restore(
                workspace_id=demo_ws_id,
                snapshot_id=snapshot_id,
                passphrase=resolved_passphrase,
                overwrite_modified=True,
                dry_run=False,
                authorize=True,
            )
            restore_time = time.perf_counter() - t_rest

            # 8. Post-Recovery Integrity Audit
            t_post = time.perf_counter()
            post_audit = self.verify_workspace_integrity(
                workspace_id=demo_ws_id,
                snapshot_id=snapshot_id,
                passphrase=resolved_passphrase,
            )
            post_time = time.perf_counter() - t_post

            total_elapsed = time.perf_counter() - demo_start
            throughput = (
                restore_report.restored_count / restore_time if restore_time > 0 else 0.0
            )

            res = {
                "demo_workspace_id": demo_ws_id,
                "snapshot_id": snapshot_id,
                "seeded_file_count": ws_meta.seeded_file_count,
                "damage_simulated": damage,
                "assessment": {
                    "total_scanned": assessment.total_workspace_files_scanned,
                    "intact": assessment.intact_count,
                    "modified": assessment.modified_count,
                    "missing": assessment.missing_count,
                    "untracked": assessment.untracked_count,
                    "canary_affected": assessment.canary_affected_count,
                    "duration_seconds": assess_time,
                },
                "preview": {
                    "restored_planned": preview_report.restored_count,
                    "evidence_planned": preview_report.evidence_preserved_count,
                    "duration_seconds": preview_time,
                },
                "restoration": {
                    "recovery_id": restore_report.recovery_id,
                    "restored_count": restore_report.restored_count,
                    "evidence_quarantined": restore_report.evidence_preserved_count,
                    "canaries_restored": restore_report.canary_restored_count,
                    "failed_count": restore_report.failed_count,
                    "duration_seconds": restore_time,
                    "throughput_files_per_sec": throughput,
                    "audit_passed": restore_report.post_recovery_audit_passed,
                },
                "post_audit": {
                    "intact": post_audit.intact_count,
                    "modified": post_audit.modified_count,
                    "missing": post_audit.missing_count,
                    "untracked": post_audit.untracked_count,
                    "duration_seconds": post_time,
                },
                "total_duration_seconds": total_elapsed,
                "success": (
                    restore_report.failed_count == 0
                    and post_audit.modified_count == 0
                    and post_audit.missing_count == 0
                    and restore_report.restored_count == (modify_cnt + delete_cnt)
                ),
            }

            return res

        finally:
            if cleanup:
                try:
                    self.workspace_manager.delete_workspace(demo_ws_id)
                    logger.info(f"Cleaned up demo workspace '{demo_ws_id}'")
                except Exception as e:
                    logger.warning(f"Failed to cleanup demo workspace '{demo_ws_id}': {e}")


# Global Coordinator Singleton
RECOVERY_COORDINATOR = RecoveryCoordinator()
