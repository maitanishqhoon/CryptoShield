"""
Restoration Manager for CryptoShield Phase 6.

Enforces cryptographic file restoration policies, safety gates, forensic evidence
preservation, two-gate staging validation, and atomic filesystem commits.
"""

from __future__ import annotations

import os
import shutil
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union

from app.config import CONFIG
from app.core.logger import get_logger
from app.recovery.models import (
    FileAssessmentRecord,
    FileAssessmentStatus,
    FileRestorationOutcome,
    FileRestorationRecord,
    PlannedRecoveryAction,
    RecoveryAuthenticationError,
    RecoveryError,
    RecoveryIntegrityError,
    RecoveryMode,
    RecoveryOperationReport,
    RestorationPolicyError,
    WorkspaceAssessmentSummary,
    WorkspaceSafetyError,
)
from app.recovery.recovery_assessor import RecoveryAssessor
from app.recovery.recovery_engine import RecoveryEngine
from app.recovery.workspace_manager import RecoveryWorkspaceManager
from app.vault.models import SnapshotManifest

logger = get_logger("recovery_restoration")


class RestorationManager:
    """
    Orchestrates the safe, authenticated, and atomic restoration of files into
    isolated recovery workspaces based on snapshot baselines and assessment policies.
    """

    def __init__(
        self,
        workspace_manager: Optional[RecoveryWorkspaceManager] = None,
        recovery_engine: Optional[RecoveryEngine] = None,
        recovery_assessor: Optional[RecoveryAssessor] = None,
    ) -> None:
        self.workspace_manager = workspace_manager or RecoveryWorkspaceManager()
        self.recovery_engine = recovery_engine or RecoveryEngine()
        self.recovery_assessor = recovery_assessor or RecoveryAssessor(
            workspace_manager=self.workspace_manager
        )

    def preserve_modified_evidence(
        self,
        workspace_id: str,
        relative_path: str,
        validated_workspace_root: Optional[Path] = None,
    ) -> Optional[str]:
        """
        Preserve a forensically intact copy of a modified or corrupted file before overwriting.
        Stores the file inside `<workspace_root>/.evidence_quarantine/<relative_path>.<timestamp>.evd`.

        Args:
            workspace_id: The ID of the target recovery workspace.
            relative_path: POSIX relative path of the file to preserve.
            validated_workspace_root: Optional pre-validated workspace directory path to avoid redundant marker I/O.

        Returns:
            The relative POSIX path of the preserved evidence within the workspace,
            or None if the source file does not exist on disk.
        """
        if validated_workspace_root is not None:
            workspace_root = validated_workspace_root
        else:
            self.workspace_manager.verify_workspace_marker(workspace_id)
            workspace_root = self.workspace_manager.get_workspace_path(workspace_id)

        target_file = self.workspace_manager.validate_workspace_path(
            workspace_id,
            relative_path,
            validated_workspace_root=workspace_root,
        )
        if not target_file.exists() or not target_file.is_file():
            return None

        # Build evidence quarantine path with microsecond ISO timestamp
        quarantine_root = workspace_root / CONFIG.RECOVERY_EVIDENCE_DIRNAME
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        
        # Preserve directory structure inside evidence quarantine
        rel_obj = Path(relative_path)
        evidence_filename = f"{rel_obj.name}.{timestamp_str}.evd"
        evidence_dir = quarantine_root / rel_obj.parent
        evidence_dir.mkdir(parents=True, exist_ok=True)
        evidence_path = evidence_dir / evidence_filename

        try:
            shutil.copy2(target_file, evidence_path)
            logger.info(
                f"Preserved forensic evidence for '{relative_path}' -> '{evidence_path.name}'"
            )
            return evidence_path.relative_to(workspace_root).as_posix()
        except Exception as e:
            logger.error(f"Failed to preserve evidence for '{relative_path}': {e}")
            raise RecoveryError(f"Evidence preservation failed for '{relative_path}': {e}") from e

    def execute_restoration(
        self,
        workspace_id: str,
        snapshot_id: str,
        manifest: SnapshotManifest,
        aes_key: Optional[bytes] = None,
        session_staging_dir: Optional[Path] = None,
        dry_run: bool = True,
        authorize: bool = False,
        overwrite_modified: bool = True,
        target_relative_path: Optional[str] = None,
        target_directory: Optional[str] = None,
        cancel_event: Optional[threading.Event] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> RecoveryOperationReport:
        """
        Execute file restoration into a validated recovery workspace.

        Enforces:
        1. Safety Gate: Non-dry-run requires explicit authorization (authorize=True).
        2. Policy Gate: Overwriting modified files requires overwrite_modified=True.
        3. Staging Gate: Two-Gate verified plaintext in isolated staging before commit.
        4. Evidence Gate: Modified files forensically quarantined prior to replacement.
        5. Atomic Gate: Workspace commit via atomic rename (os.replace).
        6. Cleanup Gate: Guaranteed purge of staging session upon completion or error.

        Args:
            workspace_id: Target recovery workspace identifier.
            snapshot_id: Source snapshot identifier.
            manifest: Decrypted and authenticated SnapshotManifest.
            aes_key: Decrypted 32-byte AES snapshot key (required when dry_run=False).
            session_staging_dir: Optional explicit staging session path.
            dry_run: If True (default), simulates actions with zero filesystem modifications.
            authorize: Explicit operator authorization required when dry_run=False.
            overwrite_modified: If True, replaces modified files while preserving evidence;
                                if False, skips modified files to prevent data loss.
            target_relative_path: Optional filter for restoring a single relative file path.
            target_directory: Optional filter for restoring a directory subtree.
            cancel_event: Optional threading.Event to abort in-flight restoration.
            progress_callback: Optional progress reporter (current, total, current_file).

        Returns:
            RecoveryOperationReport detailing execution metrics, outcomes, and audit results.
        """
        start_time = time.perf_counter()
        started_at = datetime.now(timezone.utc).isoformat()
        recovery_id = f"REC-{uuid.uuid4().hex[:8].upper()}"

        # 1. Authorization & Policy Gate Check
        if not dry_run and not authorize:
            raise RestorationPolicyError(
                "Restoration execution requires explicit authorization (authorize=True). "
                "Run with dry_run=True to preview planned actions, or specify authorize=True to commit."
            )

        if not dry_run and aes_key is None:
            raise RecoveryAuthenticationError(
                "Decrypted snapshot AES key is required for live restoration."
            )

        # 2. Workspace Safety & Path Validation
        self.workspace_manager.verify_workspace_marker(workspace_id)
        workspace_root = self.workspace_manager.get_workspace_path(workspace_id)

        # Determine recovery mode and target filter string
        if target_relative_path is not None:
            mode = RecoveryMode.SELECTIVE_FILE
            target_filter = target_relative_path
        elif target_directory is not None:
            mode = RecoveryMode.DIRECTORY
            target_filter = target_directory
        else:
            mode = RecoveryMode.FULL_WORKSPACE
            target_filter = None

        logger.info(
            f"Initiating restoration [{recovery_id}] for workspace '{workspace_id}' "
            f"(mode={mode.value}, dry_run={dry_run}, overwrite_modified={overwrite_modified})"
        )

        # 3. Assess Current Workspace State
        assessment = self.recovery_assessor.assess_workspace(
            workspace_id=workspace_id,
            manifest=manifest,
            overwrite_modified=overwrite_modified,
            target_relative_path=target_relative_path,
            target_directory=target_directory,
        )

        total_files = len(assessment.records)
        file_records: List[FileRestorationRecord] = []

        restored_count = 0
        skipped_intact_count = 0
        evidence_preserved_count = 0
        untracked_preserved_count = 0
        manual_review_count = 0
        failed_count = 0
        canary_restored_count = 0

        staging_dir_to_clean: Optional[Path] = None

        try:
            # Create staging session only if live restoration is needed
            if not dry_run:
                staging_dir_to_clean = session_staging_dir or self.recovery_engine.create_staging_session()

            # 4. Process Assessment Records
            for idx, (rel_path, record) in enumerate(assessment.records.items(), start=1):
                if cancel_event is not None and cancel_event.is_set():
                    logger.warning(f"Restoration [{recovery_id}] cancelled by operator at item {idx}/{total_files}")
                    break

                if progress_callback is not None:
                    progress_callback(idx, total_files, rel_path)

                action = record.planned_action
                is_canary = record.is_canary
                opaque_id = record.opaque_id

                # A. Handle INTACT files
                if action == PlannedRecoveryAction.SKIP_INTACT:
                    skipped_intact_count += 1
                    file_records.append(
                        FileRestorationRecord(
                            relative_path=rel_path,
                            status_before=record.status,
                            outcome=FileRestorationOutcome.SKIPPED,
                            opaque_id=opaque_id,
                            restored_sha256=record.current_sha256,
                            is_canary=is_canary,
                        )
                    )
                    continue

                # B. Handle UNTRACKED files
                if action == PlannedRecoveryAction.PRESERVE_UNTRACKED:
                    untracked_preserved_count += 1
                    file_records.append(
                        FileRestorationRecord(
                            relative_path=rel_path,
                            status_before=record.status,
                            outcome=FileRestorationOutcome.PRESERVED_UNTRACKED,
                            opaque_id=None,
                            is_canary=False,
                        )
                    )
                    continue

                # C. Handle MODIFIED files where overwrite is not authorized
                if action == PlannedRecoveryAction.SKIP_MODIFIED_NO_OVERWRITE_AUTH:
                    manual_review_count += 1
                    file_records.append(
                        FileRestorationRecord(
                            relative_path=rel_path,
                            status_before=record.status,
                            outcome=FileRestorationOutcome.SKIPPED,
                            opaque_id=opaque_id,
                            is_canary=is_canary,
                            error_detail="Skipped: overwrite_modified=False",
                        )
                    )
                    continue

                # D. Handle UNREADABLE files
                if action == PlannedRecoveryAction.MANUAL_REVIEW_UNREADABLE:
                    manual_review_count += 1
                    file_records.append(
                        FileRestorationRecord(
                            relative_path=rel_path,
                            status_before=record.status,
                            outcome=FileRestorationOutcome.MANUAL_REVIEW,
                            opaque_id=opaque_id,
                            is_canary=is_canary,
                            error_detail=record.error_detail or "Unreadable file required manual review",
                        )
                    )
                    continue

                # E. Handle Files To Be Restored (MISSING or MODIFIED with evidence preservation)
                if action in (
                    PlannedRecoveryAction.RESTORE_MISSING,
                    PlannedRecoveryAction.RESTORE_MODIFIED_PRESERVE_EVIDENCE,
                ):
                    # In Dry Run mode, simulate success without staging or writes
                    if dry_run:
                        if action == PlannedRecoveryAction.RESTORE_MODIFIED_PRESERVE_EVIDENCE:
                            evidence_preserved_count += 1
                        restored_count += 1
                        if is_canary:
                            canary_restored_count += 1
                        file_records.append(
                            FileRestorationRecord(
                                relative_path=rel_path,
                                status_before=record.status,
                                outcome=FileRestorationOutcome.RESTORED,
                                opaque_id=opaque_id,
                                restored_sha256=record.expected_sha256,
                                is_canary=is_canary,
                            )
                        )
                        continue

                    # LIVE RESTORATION
                    evidence_backup_path: Optional[str] = None
                    if action == PlannedRecoveryAction.RESTORE_MODIFIED_PRESERVE_EVIDENCE:
                        try:
                            evidence_backup_path = self.preserve_modified_evidence(
                                workspace_id,
                                rel_path,
                                validated_workspace_root=workspace_root,
                            )
                            if evidence_backup_path is not None:
                                evidence_preserved_count += 1
                        except Exception as e:
                            logger.error(f"Failed evidence preservation before restoring '{rel_path}': {e}")
                            failed_count += 1
                            file_records.append(
                                FileRestorationRecord(
                                    relative_path=rel_path,
                                    status_before=record.status,
                                    outcome=FileRestorationOutcome.FAILED_IO,
                                    opaque_id=opaque_id,
                                    is_canary=is_canary,
                                    error_detail=f"Evidence preservation failed: {e}",
                                )
                            )
                            continue

                    # Retrieve manifest object entry
                    obj_entry = manifest.entries.get(rel_path)
                    if obj_entry is None:
                        failed_count += 1
                        file_records.append(
                            FileRestorationRecord(
                                relative_path=rel_path,
                                status_before=record.status,
                                outcome=FileRestorationOutcome.FAILED_INTEGRITY,
                                opaque_id=opaque_id,
                                is_canary=is_canary,
                                error_detail="Missing object entry in snapshot manifest",
                            )
                        )
                        continue

                    # Stage decrypted object with Two-Gate verification
                    try:
                        assert staging_dir_to_clean is not None
                        assert aes_key is not None
                        staged_result = self.recovery_engine.stage_decrypted_object(
                            snapshot_id=snapshot_id,
                            aes_key=aes_key,
                            record=obj_entry,
                            session_staging_dir=staging_dir_to_clean,
                            format_version=getattr(manifest, "format_version", "1.0.0"),
                        )
                    except RecoveryAuthenticationError as e:
                        failed_count += 1
                        file_records.append(
                            FileRestorationRecord(
                                relative_path=rel_path,
                                status_before=record.status,
                                outcome=FileRestorationOutcome.FAILED_AUTH,
                                opaque_id=opaque_id,
                                is_canary=is_canary,
                                error_detail=str(e),
                            )
                        )
                        continue
                    except RecoveryIntegrityError as e:
                        failed_count += 1
                        file_records.append(
                            FileRestorationRecord(
                                relative_path=rel_path,
                                status_before=record.status,
                                outcome=FileRestorationOutcome.FAILED_INTEGRITY,
                                opaque_id=opaque_id,
                                is_canary=is_canary,
                                error_detail=str(e),
                            )
                        )
                        continue
                    except Exception as e:
                        failed_count += 1
                        file_records.append(
                            FileRestorationRecord(
                                relative_path=rel_path,
                                status_before=record.status,
                                outcome=FileRestorationOutcome.FAILED_IO,
                                opaque_id=opaque_id,
                                is_canary=is_canary,
                                error_detail=f"Staging failed: {e}",
                            )
                        )
                        continue

                    # Atomic Commit into recovery workspace
                    dest_path = self.workspace_manager.validate_workspace_path(
                        workspace_id,
                        rel_path,
                        validated_workspace_root=workspace_root,
                    )
                    try:
                        dest_path.parent.mkdir(parents=True, exist_ok=True)
                        if staged_result.staged_path is None or not staged_result.staged_path.exists():
                            raise RecoveryError(f"Staged file missing for '{rel_path}'")

                        # os.replace provides atomic file commit across POSIX and Windows
                        os.replace(str(staged_result.staged_path), str(dest_path))

                        restored_count += 1
                        if is_canary:
                            canary_restored_count += 1

                        file_records.append(
                            FileRestorationRecord(
                                relative_path=rel_path,
                                status_before=record.status,
                                outcome=FileRestorationOutcome.RESTORED,
                                opaque_id=opaque_id,
                                restored_sha256=staged_result.computed_sha256,
                                evidence_backup_path=evidence_backup_path,
                                is_canary=is_canary,
                            )
                        )
                    except Exception as e:
                        logger.error(f"Atomic commit failed for '{rel_path}': {e}")
                        failed_count += 1
                        # Attempt to clean up leftover staged file if replace failed
                        if staged_result.staged_path and staged_result.staged_path.exists():
                            try:
                                staged_result.staged_path.unlink()
                            except OSError:
                                pass
                        file_records.append(
                            FileRestorationRecord(
                                relative_path=rel_path,
                                status_before=record.status,
                                outcome=FileRestorationOutcome.FAILED_IO,
                                opaque_id=opaque_id,
                                is_canary=is_canary,
                                error_detail=f"Commit failed: {e}",
                            )
                        )
                        continue

            # 5. Post-Recovery Audit (Only for Live Restorations with Changes)
            post_recovery_audit_passed: Optional[bool] = None
            if not dry_run and restored_count > 0:
                try:
                    post_audit = self.recovery_assessor.assess_workspace(
                        workspace_id=workspace_id,
                        manifest=manifest,
                        overwrite_modified=overwrite_modified,
                        target_relative_path=target_relative_path,
                        target_directory=target_directory,
                    )
                    # Audit passes if 0 modified and 0 missing in scoped assessment
                    post_recovery_audit_passed = (
                        post_audit.modified_count == 0 and post_audit.missing_count == 0
                    )
                    logger.info(
                        f"Post-recovery audit: intact={post_audit.intact_count}, "
                        f"modified={post_audit.modified_count}, missing={post_audit.missing_count}, "
                        f"passed={post_recovery_audit_passed}"
                    )
                except Exception as e:
                    logger.warning(f"Post-recovery audit failed to execute: {e}")
                    post_recovery_audit_passed = False
            elif dry_run:
                post_recovery_audit_passed = None

        finally:
            # 6. Guaranteed Cleanup of Staging Session
            if staging_dir_to_clean is not None:
                self.recovery_engine.cleanup_staging_session(staging_dir_to_clean)

        duration = time.perf_counter() - start_time
        completed_at = datetime.now(timezone.utc).isoformat()

        report = RecoveryOperationReport(
            recovery_id=recovery_id,
            workspace_id=workspace_id,
            snapshot_id=snapshot_id,
            mode=mode,
            dry_run=dry_run,
            authorized=authorize,
            overwrite_modified=overwrite_modified,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            target_filter=target_filter,
            total_evaluated=total_files,
            restored_count=restored_count,
            skipped_intact_count=skipped_intact_count,
            evidence_preserved_count=evidence_preserved_count,
            untracked_preserved_count=untracked_preserved_count,
            manual_review_count=manual_review_count,
            failed_count=failed_count,
            canary_restored_count=canary_restored_count,
            post_recovery_audit_passed=post_recovery_audit_passed,
            file_records=file_records,
        )

        logger.info(
            f"Restoration [{recovery_id}] completed in {duration:.2f}s: "
            f"restored={restored_count}, intact={skipped_intact_count}, "
            f"evidence={evidence_preserved_count}, untracked={untracked_preserved_count}, "
            f"failed={failed_count}, audit_passed={post_recovery_audit_passed}"
        )

        return report
