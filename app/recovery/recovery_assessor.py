"""
Recovery Assessor for CryptoShield (Phase 6).

Performs 5-state integrity assessments (INTACT, MODIFIED, MISSING, UNREADABLE, UNTRACKED)
comparing a registered recovery workspace against an authenticated SnapshotManifest.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from app.config import CONFIG
from app.core.logger import get_logger
from app.recovery.models import (
    FileAssessmentRecord,
    FileAssessmentStatus,
    PlannedRecoveryAction,
    RecoveryError,
    WorkspaceAssessmentSummary,
    WorkspaceSafetyError,
)
from app.recovery.workspace_manager import RecoveryWorkspaceManager
from app.vault.models import SnapshotManifest

logger = get_logger("recovery.assessor")


class RecoveryAssessor:
    """
    Performs forensic integrity assessments across recovery workspaces.
    Categorizes all files into strict 5-state assessment taxonomy.
    """

    def __init__(
        self,
        workspace_manager: Optional[RecoveryWorkspaceManager] = None,
        chunk_size: int = CONFIG.STREAMING_CHUNK_SIZE_BYTES,
    ) -> None:
        self.workspace_manager = workspace_manager or RecoveryWorkspaceManager()
        self.chunk_size = chunk_size

    def compute_file_sha256(self, file_path: Path) -> Tuple[str, int]:
        """
        Compute streaming SHA-256 hash and byte length of a regular file.
        Strictly rejects symbolic links.

        Returns:
            Tuple of (lowercase_sha256_hex, total_bytes).
        """
        if file_path.is_symlink():
            raise OSError(f"Symlink not permitted for integrity calculation: {file_path}")

        hasher = hashlib.sha256()
        byte_size = 0
        with open(file_path, "rb") as f:
            while chunk := f.read(self.chunk_size):
                hasher.update(chunk)
                byte_size += len(chunk)

        return hasher.hexdigest().lower(), byte_size

    def assess_workspace(
        self,
        workspace_id: str,
        manifest: SnapshotManifest,
        overwrite_modified: bool = False,
        target_relative_path: Optional[str] = None,
        target_directory: Optional[str] = None,
        expected_subset_paths: Optional[Set[str]] = None,
        full_manifest_scope: bool = False,
    ) -> WorkspaceAssessmentSummary:
        """
        Perform comprehensive 5-state integrity assessment of a workspace against a snapshot manifest.

        Args:
            workspace_id: Registered recovery workspace ID.
            manifest: Authenticated SnapshotManifest to assess against.
            overwrite_modified: If True, schedule RESTORE_MODIFIED_PRESERVE_EVIDENCE;
                                if False, schedule SKIP_MODIFIED_NO_OVERWRITE_AUTH.
            target_relative_path: Optional filter for single file assessment.
            target_directory: Optional filter for departmental / directory subtree assessment.
            expected_subset_paths: Optional set of relative paths to restrict assessment scope.
            full_manifest_scope: If True, evaluates all manifest entries even if workspace was partially seeded.

        Returns:
            WorkspaceAssessmentSummary with per-file records and aggregate counts.
        """
        start_time = time.perf_counter()

        # Step 1: Validate workspace marker and resolve directory
        self.workspace_manager.verify_workspace_marker(workspace_id)
        workspace_root = self.workspace_manager.get_workspace_path(workspace_id)

        # Check for persisted seeded scope if no explicit filter is given
        if not full_manifest_scope and expected_subset_paths is None and target_relative_path is None and target_directory is None:
            seeded_scope_file = workspace_root / ".cryptoshield_seeded_scope.json"
            if seeded_scope_file.exists():
                try:
                    with open(seeded_scope_file, "r", encoding="utf-8") as f:
                        seeded_data = json.load(f)
                        if isinstance(seeded_data, list):
                            expected_subset_paths = set(seeded_data)
                        elif isinstance(seeded_data, dict):
                            expected_subset_paths = set(seeded_data.get("paths", []))
                except Exception as e:
                    logger.warning(f"Could not read seeded scope file: {e}")

        # Step 2: Determine Manifest Scope
        scoped_manifest_entries = dict(manifest.entries)

        if expected_subset_paths is not None:
            scoped_manifest_entries = {
                k: v for k, v in scoped_manifest_entries.items() if k in expected_subset_paths
            }

        norm_target_path: Optional[str] = None
        if target_relative_path is not None:
            norm_target_path = target_relative_path.replace("\\", "/").strip("/")
            if norm_target_path not in manifest.entries:
                raise RecoveryError(
                    f"Target relative path '{target_relative_path}' not found in manifest entries."
                )
            scoped_manifest_entries = {norm_target_path: manifest.entries[norm_target_path]}

        norm_target_dir: Optional[str] = None
        if target_directory is not None:
            norm_target_dir = target_directory.replace("\\", "/").strip("/")
            matched = {
                k: v
                for k, v in scoped_manifest_entries.items()
                if k == norm_target_dir or k.startswith(f"{norm_target_dir}/")
            }
            if not matched:
                raise RecoveryError(
                    f"Target directory '{target_directory}' has no matching entries in manifest."
                )
            scoped_manifest_entries = matched

        # Step 3: Scan Workspace Disk Files
        discovered_disk_paths: Set[str] = set()

        for root, dirs, filenames in os.walk(workspace_root):
            # Exclude reserved evidence quarantine directory
            if CONFIG.RECOVERY_EVIDENCE_DIRNAME in dirs:
                dirs.remove(CONFIG.RECOVERY_EVIDENCE_DIRNAME)

            for fn in filenames:
                # Exclude recovery safety marker and seeded scope file
                if fn in {CONFIG.RECOVERY_MARKER_FILENAME, ".cryptoshield_seeded_scope.json"}:
                    continue

                full_p = Path(root) / fn
                rel_posix = full_p.relative_to(workspace_root).as_posix()

                if norm_target_path is not None:
                    if rel_posix != norm_target_path:
                        continue
                elif norm_target_dir is not None:
                    if rel_posix != norm_target_dir and not rel_posix.startswith(f"{norm_target_dir}/"):
                        continue

                discovered_disk_paths.add(rel_posix)

        records: Dict[str, FileAssessmentRecord] = {}

        # Step 4: Classify Expected Manifest Entries
        def _assess_entry(item: Tuple[str, Any]) -> Tuple[str, FileAssessmentRecord]:
            rel_path, record = item
            disk_path = workspace_root / Path(rel_path)

            # Check if file exists on disk
            if not disk_path.exists() and not disk_path.is_symlink():
                return rel_path, FileAssessmentRecord(
                    relative_path=rel_path,
                    status=FileAssessmentStatus.MISSING,
                    planned_action=PlannedRecoveryAction.RESTORE_MISSING,
                    expected_sha256=record.original_sha256.lower(),
                    current_sha256=None,
                    expected_size_bytes=record.original_size_bytes,
                    current_size_bytes=None,
                    opaque_id=record.opaque_id,
                    department=record.department,
                    data_classification=record.data_classification,
                    is_canary=record.is_canary,
                    error_detail=None,
                )

            # File exists or is a broken symlink
            try:
                self.workspace_manager.validate_workspace_path(
                    workspace_id,
                    rel_path,
                    validated_workspace_root=workspace_root,
                )
                if disk_path.is_symlink():
                    raise OSError(f"Symlink detected at: {disk_path}")

                computed_sha256, current_size = self.compute_file_sha256(disk_path)

                if (
                    computed_sha256 == record.original_sha256.lower()
                    and current_size == record.original_size_bytes
                ):
                    status = FileAssessmentStatus.INTACT
                    planned_action = PlannedRecoveryAction.SKIP_INTACT
                else:
                    status = FileAssessmentStatus.MODIFIED
                    planned_action = (
                        PlannedRecoveryAction.RESTORE_MODIFIED_PRESERVE_EVIDENCE
                        if overwrite_modified
                        else PlannedRecoveryAction.SKIP_MODIFIED_NO_OVERWRITE_AUTH
                    )

                return rel_path, FileAssessmentRecord(
                    relative_path=rel_path,
                    status=status,
                    planned_action=planned_action,
                    expected_sha256=record.original_sha256.lower(),
                    current_sha256=computed_sha256,
                    expected_size_bytes=record.original_size_bytes,
                    current_size_bytes=current_size,
                    opaque_id=record.opaque_id,
                    department=record.department,
                    data_classification=record.data_classification,
                    is_canary=record.is_canary,
                    error_detail=None,
                )

            except (WorkspaceSafetyError, OSError, PermissionError) as exc:
                return rel_path, FileAssessmentRecord(
                    relative_path=rel_path,
                    status=FileAssessmentStatus.UNREADABLE,
                    planned_action=PlannedRecoveryAction.MANUAL_REVIEW_UNREADABLE,
                    expected_sha256=record.original_sha256.lower(),
                    current_sha256=None,
                    expected_size_bytes=record.original_size_bytes,
                    current_size_bytes=None,
                    opaque_id=record.opaque_id,
                    department=record.department,
                    data_classification=record.data_classification,
                    is_canary=record.is_canary,
                    error_detail=f"{type(exc).__name__}: {str(exc)}",
                )

        if len(scoped_manifest_entries) > 100:
            max_workers = min(16, (os.cpu_count() or 4) * 2)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                for rel_path, rec in executor.map(_assess_entry, scoped_manifest_entries.items()):
                    records[rel_path] = rec
        else:
            for item in scoped_manifest_entries.items():
                rel_path, rec = _assess_entry(item)
                records[rel_path] = rec

        # Step 5: Classify Untracked Workspace Files
        for disk_rel in sorted(discovered_disk_paths):
            if disk_rel not in manifest.entries:
                disk_path = workspace_root / Path(disk_rel)
                c_sha: Optional[str] = None
                c_sz: Optional[int] = None
                err_detail: Optional[str] = None

                try:
                    c_sha, c_sz = self.compute_file_sha256(disk_path)
                except Exception as exc:
                    err_detail = f"{type(exc).__name__}: {str(exc)}"

                records[disk_rel] = FileAssessmentRecord(
                    relative_path=disk_rel,
                    status=FileAssessmentStatus.UNTRACKED,
                    planned_action=PlannedRecoveryAction.PRESERVE_UNTRACKED,
                    expected_sha256=None,
                    current_sha256=c_sha,
                    expected_size_bytes=None,
                    current_size_bytes=c_sz,
                    opaque_id=None,
                    department=None,
                    data_classification=None,
                    is_canary=False,
                    error_detail=err_detail,
                )

        # Step 6: Build Summary
        intact_count = sum(1 for r in records.values() if r.status == FileAssessmentStatus.INTACT)
        modified_count = sum(1 for r in records.values() if r.status == FileAssessmentStatus.MODIFIED)
        missing_count = sum(1 for r in records.values() if r.status == FileAssessmentStatus.MISSING)
        unreadable_count = sum(1 for r in records.values() if r.status == FileAssessmentStatus.UNREADABLE)
        untracked_count = sum(1 for r in records.values() if r.status == FileAssessmentStatus.UNTRACKED)
        canary_affected_count = sum(
            1
            for r in records.values()
            if r.is_canary
            and r.status
            in (
                FileAssessmentStatus.MODIFIED,
                FileAssessmentStatus.MISSING,
                FileAssessmentStatus.UNREADABLE,
            )
        )

        duration = time.perf_counter() - start_time
        summary = WorkspaceAssessmentSummary(
            assessment_id=f"ASSESS-{uuid.uuid4().hex[:8].upper()}",
            workspace_id=workspace_id,
            snapshot_id=manifest.snapshot_id,
            assessed_at=datetime.now(timezone.utc).isoformat(),
            total_manifest_files=len(scoped_manifest_entries),
            total_workspace_files_scanned=len(discovered_disk_paths),
            intact_count=intact_count,
            modified_count=modified_count,
            missing_count=missing_count,
            unreadable_count=unreadable_count,
            untracked_count=untracked_count,
            canary_affected_count=canary_affected_count,
            duration_seconds=round(duration, 4),
            records=records,
        )

        logger.info(
            f"Assessment complete for workspace '{workspace_id}': "
            f"intact={intact_count}, mod={modified_count}, miss={missing_count}, "
            f"unread={unreadable_count}, untracked={untracked_count}, "
            f"canary_affected={canary_affected_count} ({duration:.3f}s)"
        )

        return summary
