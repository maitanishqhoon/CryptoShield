"""
Recovery Workspace Manager for CryptoShield (Phase 6).

Provides isolated, marker-authenticated recovery workspaces under
runtime/recovery/workspaces/ without ever altering the protected runtime/lab/ baseline.
"""

from __future__ import annotations

import hmac
import json
import os
import platform
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from app.config import CONFIG
from app.core.logger import get_logger
from app.core.safety import verify_lab_marker
from app.recovery.models import (
    RecoveryError,
    RecoveryWorkspaceMarker,
    WorkspaceMetadata,
    WorkspaceNotFoundError,
    WorkspaceSafetyError,
    compute_workspace_marker_signature,
)

logger = get_logger("recovery_workspace")

# Regex for safe workspace directory IDs (e.g. WKSP-A1B2C3D4 or alphanumeric slug)
SAFE_WORKSPACE_ID_REGEX = re.compile(r"^[A-Za-z0-9_-]{3,64}$")


class RecoveryWorkspaceManager:
    """
    Manages isolated recovery workspaces. Guarantees that the baseline laboratory
    directory and arbitrary host paths can never be modified, damaged, or deleted.
    """

    def __init__(
        self,
        workspaces_root: Optional[Path] = None,
        lab_dir: Optional[Path] = None,
    ) -> None:
        self.workspaces_root = (workspaces_root or CONFIG.RECOVERY_WORKSPACES_DIR).resolve()
        self.lab_dir = (lab_dir or CONFIG.LAB_DIR).resolve()

        # Ensure root workspaces directory exists
        self.workspaces_root.mkdir(parents=True, exist_ok=True)

    def _validate_workspace_id(self, workspace_id: str) -> None:
        """Validate that a workspace_id is safe and contains no path traversal sequences."""
        if not isinstance(workspace_id, str):
            raise WorkspaceSafetyError(
                f"Workspace ID must be a string, got {type(workspace_id).__name__}"
            )
        if "/" in workspace_id or "\\" in workspace_id:
            raise WorkspaceSafetyError(
                f"Workspace ID contains invalid path separators: '{workspace_id}'"
            )
        if workspace_id in {".", ".."}:
            raise WorkspaceSafetyError(
                f"Workspace ID cannot be '.' or '..': '{workspace_id}'"
            )
        if not SAFE_WORKSPACE_ID_REGEX.match(workspace_id):
            raise WorkspaceSafetyError(
                f"Invalid workspace ID format: '{workspace_id}'. Must match ^[A-Za-z0-9_-]{{3,64}}$"
            )

    def _check_not_lab(self, target_path: Path) -> None:
        """Strictly prevent targeting the protected laboratory directory or its contents."""
        resolved = target_path.resolve()
        if resolved == self.lab_dir:
            raise WorkspaceSafetyError(
                f"[SAFETY VIOLATION] Target '{resolved}' is the protected laboratory directory, not a recovery workspace."
            )
        try:
            resolved.relative_to(self.lab_dir)
            raise WorkspaceSafetyError(
                f"[SAFETY VIOLATION] Target '{resolved}' resides inside protected laboratory directory."
            )
        except ValueError:
            pass

    def create_workspace(
        self,
        workspace_id: Optional[str] = None,
        seed_from_lab: bool = False,
        max_seed_files: Optional[int] = None,
        source_snapshot_id: Optional[str] = None,
    ) -> WorkspaceMetadata:
        """
        Create a new isolated recovery workspace with safety marker.

        Args:
            workspace_id: Optional workspace ID; auto-generates WKSP-<8 hex> if None.
            seed_from_lab: If True, copies baseline lab files into workspace.
            max_seed_files: Optional cap on files to copy, prioritizing all canaries first.
            source_snapshot_id: Optional snapshot ID associated with this recovery attempt.

        Returns:
            WorkspaceMetadata for the newly created workspace.
        """
        if workspace_id is None:
            workspace_id = f"WKSP-{uuid.uuid4().hex[:8].upper()}"

        self._validate_workspace_id(workspace_id)

        workspace_dir = (self.workspaces_root / workspace_id).resolve()
        self._check_not_lab(workspace_dir)

        # Boundary check: direct child of workspaces_root
        if workspace_dir.parent != self.workspaces_root:
            raise WorkspaceSafetyError(
                f"Workspace directory '{workspace_dir}' is not a direct child of '{self.workspaces_root}'"
            )

        if workspace_dir.exists():
            raise WorkspaceSafetyError(
                f"Recovery workspace '{workspace_id}' already exists at '{workspace_dir}'"
            )

        workspace_dir.mkdir(parents=True, exist_ok=False)

        # Create evidence quarantine directory
        quarantine_dir = workspace_dir / CONFIG.RECOVERY_EVIDENCE_DIRNAME
        quarantine_dir.mkdir(parents=True, exist_ok=True)

        seeded_file_count = 0

        if seed_from_lab:
            # Verify laboratory safety marker in strictly read-only mode
            verify_lab_marker(self.lab_dir)

            canary_rel_paths: List[str] = []
            normal_rel_paths: List[str] = []

            manifest_path = self.lab_dir / CONFIG.MANIFEST_FILENAME
            if manifest_path.exists():
                try:
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        manifest_data = json.load(f)
                    entries = manifest_data.get("entries", {})
                    for rel, ent in entries.items():
                        src = self.lab_dir / rel
                        if src.is_file():
                            if ent.get("is_canary"):
                                canary_rel_paths.append(rel)
                            else:
                                normal_rel_paths.append(rel)
                except Exception as e:
                    logger.warning(f"Failed to read manifest for seeding: {e}. Falling back to disk scan.")
                    canary_rel_paths.clear()
                    normal_rel_paths.clear()

            # Fallback if manifest not present or empty
            if not canary_rel_paths and not normal_rel_paths:
                for root, dirs, files in os.walk(self.lab_dir):
                    for fn in files:
                        if fn in {CONFIG.LAB_MARKER_FILENAME, CONFIG.MANIFEST_FILENAME, ".gitkeep"}:
                            continue
                        src = Path(root) / fn
                        rel = src.relative_to(self.lab_dir).as_posix()
                        if "canary" in rel.lower():
                            canary_rel_paths.append(rel)
                        else:
                            normal_rel_paths.append(rel)

            canary_rel_paths.sort()
            normal_rel_paths.sort()
            total_available = len(canary_rel_paths) + len(normal_rel_paths)

            if max_seed_files is None or max_seed_files >= total_available:
                selected_paths = sorted(canary_rel_paths + normal_rel_paths)
            else:
                # Ensure canary files are genuinely included and prioritized across scales
                if max_seed_files <= 20:
                    target_canaries = min(len(canary_rel_paths), max(2, max_seed_files // 2))
                else:
                    target_canaries = min(len(canary_rel_paths), max(10, max_seed_files // 10))

                target_canaries = min(target_canaries, max_seed_files)
                target_normal = max_seed_files - target_canaries
                selected_paths = sorted(canary_rel_paths[:target_canaries] + normal_rel_paths[:target_normal])

            for rel in selected_paths:
                src = self.lab_dir / rel
                dst = workspace_dir / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                seeded_file_count += 1

            # For partial seeded workspaces (< total lab files), persist scope for accurate assessment
            if max_seed_files is not None and len(selected_paths) < total_available:
                scope_file = workspace_dir / ".cryptoshield_seeded_scope.json"
                seeded_canaries = [p for p in selected_paths if p in canary_rel_paths]
                scope_payload = {
                    "paths": selected_paths,
                    "canary_paths": seeded_canaries,
                }
                with open(scope_file, "w", encoding="utf-8") as f:
                    json.dump(scope_payload, f, indent=2)

        # Write safety marker
        workspace_uuid = str(uuid.uuid4())
        created_at = datetime.now(CONFIG.TIMEZONE).isoformat()
        host_platform = platform.platform()
        authorized_root = str(workspace_dir.resolve())

        signature = compute_workspace_marker_signature(
            workspace_id=workspace_id,
            workspace_uuid=workspace_uuid,
            authorized_root=authorized_root,
            source_snapshot_id=source_snapshot_id,
            seeded_file_count=seeded_file_count,
            created_at=created_at,
            host_platform=host_platform,
        )

        marker = RecoveryWorkspaceMarker(
            workspace_id=workspace_id,
            workspace_uuid=workspace_uuid,
            authorized_root=authorized_root,
            source_snapshot_id=source_snapshot_id,
            seeded_file_count=seeded_file_count,
            created_at=created_at,
            host_platform=host_platform,
            signature=signature,
        )

        marker_file = workspace_dir / CONFIG.RECOVERY_MARKER_FILENAME
        with open(marker_file, "w", encoding="utf-8") as f:
            json.dump(marker.to_dict(), f, indent=2)

        logger.info(
            f"Created recovery workspace '{workspace_id}' with {seeded_file_count} seeded files at '{workspace_dir}'"
        )

        return WorkspaceMetadata(
            workspace_id=workspace_id,
            workspace_path=workspace_dir,
            created_at=created_at,
            seeded_file_count=seeded_file_count,
            source_snapshot_id=source_snapshot_id,
            marker_valid=True,
        )

    def seed_from_lab(
        self,
        workspace_id: str,
        max_files: Optional[int] = 100,
    ) -> int:
        """
        Seed an existing isolated recovery workspace with baseline files from runtime/lab/.
        Copies files prioritizing canaries first, and updates the cryptographic safety marker.
        """
        self._validate_workspace_id(workspace_id)
        marker = self.verify_workspace_marker(workspace_id)
        workspace_dir = (self.workspaces_root / workspace_id).resolve()
        self._check_not_lab(workspace_dir)

        # Verify laboratory safety marker in strictly read-only mode
        verify_lab_marker(self.lab_dir)

        canary_rel_paths: List[str] = []
        normal_rel_paths: List[str] = []

        manifest_path = self.lab_dir / CONFIG.MANIFEST_FILENAME
        if manifest_path.exists():
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest_data = json.load(f)
                entries = manifest_data.get("entries", {})
                for rel, ent in entries.items():
                    src = self.lab_dir / rel
                    if src.is_file():
                        if ent.get("is_canary"):
                            canary_rel_paths.append(rel)
                        else:
                            normal_rel_paths.append(rel)
            except Exception as e:
                logger.warning(f"Failed to read manifest for seeding: {e}. Falling back to disk scan.")
                canary_rel_paths.clear()
                normal_rel_paths.clear()

        # Fallback if manifest not present or empty
        if not canary_rel_paths and not normal_rel_paths:
            for root, dirs, files in os.walk(self.lab_dir):
                for fn in files:
                    if fn in {CONFIG.LAB_MARKER_FILENAME, CONFIG.MANIFEST_FILENAME, ".gitkeep"}:
                        continue
                    src = Path(root) / fn
                    rel = src.relative_to(self.lab_dir).as_posix()
                    if "canary" in rel.lower():
                        canary_rel_paths.append(rel)
                    else:
                        normal_rel_paths.append(rel)

        canary_rel_paths.sort()
        normal_rel_paths.sort()
        total_available = len(canary_rel_paths) + len(normal_rel_paths)

        if max_files is None or max_files >= total_available:
            selected_paths = sorted(canary_rel_paths + normal_rel_paths)
        else:
            if max_files <= 20:
                target_canaries = min(len(canary_rel_paths), max(2, max_files // 2))
            else:
                target_canaries = min(len(canary_rel_paths), max(10, max_files // 10))

            target_canaries = min(target_canaries, max_files)
            target_normal = max_files - target_canaries
            selected_paths = sorted(canary_rel_paths[:target_canaries] + normal_rel_paths[:target_normal])

        seeded_file_count = 0
        for rel in selected_paths:
            src = self.lab_dir / rel
            dst = workspace_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            seeded_file_count += 1

        # For partial seeded workspaces (< total lab files), persist scope for accurate assessment
        if max_files is not None and len(selected_paths) < total_available:
            scope_file = workspace_dir / ".cryptoshield_seeded_scope.json"
            seeded_canaries = [p for p in selected_paths if p in canary_rel_paths]
            scope_payload = {
                "paths": selected_paths,
                "canary_paths": seeded_canaries,
            }
            with open(scope_file, "w", encoding="utf-8") as f:
                json.dump(scope_payload, f, indent=2)

        # Update and re-sign safety marker with updated seeded file count
        signature = compute_workspace_marker_signature(
            workspace_id=marker.workspace_id,
            workspace_uuid=marker.workspace_uuid,
            authorized_root=marker.authorized_root,
            source_snapshot_id=marker.source_snapshot_id,
            seeded_file_count=seeded_file_count,
            created_at=marker.created_at,
            host_platform=marker.host_platform,
        )

        updated_marker = RecoveryWorkspaceMarker(
            workspace_id=marker.workspace_id,
            workspace_uuid=marker.workspace_uuid,
            authorized_root=marker.authorized_root,
            source_snapshot_id=marker.source_snapshot_id,
            seeded_file_count=seeded_file_count,
            created_at=marker.created_at,
            host_platform=marker.host_platform,
            signature=signature,
        )

        marker_file = workspace_dir / CONFIG.RECOVERY_MARKER_FILENAME
        with open(marker_file, "w", encoding="utf-8") as f:
            json.dump(updated_marker.to_dict(), f, indent=2)

        logger.info(
            f"Seeded {seeded_file_count} files into recovery workspace '{workspace_id}' and updated safety marker."
        )
        return seeded_file_count

    def verify_workspace_marker(
        self,
        workspace_id_or_path: Union[str, Path],
    ) -> RecoveryWorkspaceMarker:
        """
        Verify that a workspace possesses a valid, untampered safety marker.

        Raises:
            WorkspaceSafetyError: If boundary check fails or marker is tampered/missing.
            WorkspaceNotFoundError: If workspace directory does not exist.
        """
        if isinstance(workspace_id_or_path, Path):
            target = workspace_id_or_path.resolve()
        else:
            str_val = str(workspace_id_or_path).strip()
            if "/" in str_val or "\\" in str_val or Path(str_val).is_absolute():
                target = Path(str_val).resolve()
            else:
                self._validate_workspace_id(str_val)
                target = (self.workspaces_root / str_val).resolve()

        # Safety checks against lab directory
        self._check_not_lab(target)

        # Safety check: direct child of workspaces_root
        if target == self.workspaces_root:
            raise WorkspaceSafetyError("Target cannot be the workspaces root directory itself.")

        try:
            rel = target.relative_to(self.workspaces_root)
            if len(rel.parts) != 1 or rel.parts[0] in {".", ".."}:
                raise WorkspaceSafetyError(
                    f"Workspace '{target}' is not a direct child of '{self.workspaces_root}'"
                )
        except ValueError:
            raise WorkspaceSafetyError(
                f"Workspace '{target}' is outside workspaces root '{self.workspaces_root}'"
            )

        if not target.exists():
            raise WorkspaceNotFoundError(f"Recovery workspace not found at '{target}'")

        if not target.is_dir():
            raise WorkspaceSafetyError(f"Workspace path '{target}' is not a directory.")

        if target.is_symlink():
            raise WorkspaceSafetyError(f"Symlinked workspace directory '{target}' is rejected.")

        marker_file = target / CONFIG.RECOVERY_MARKER_FILENAME
        if not marker_file.exists():
            raise WorkspaceSafetyError(f"Missing recovery marker at '{marker_file}'")

        try:
            with open(marker_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            marker = RecoveryWorkspaceMarker.from_dict(data)
        except Exception as e:
            raise WorkspaceSafetyError(f"Failed to read or parse recovery marker: {e}")

        # Verify authorized root
        if Path(marker.authorized_root).resolve() != target:
            raise WorkspaceSafetyError(
                f"Marker authorized root '{marker.authorized_root}' does not match current workspace '{target}'"
            )

        # Verify signature
        expected_sig = compute_workspace_marker_signature(
            workspace_id=marker.workspace_id,
            workspace_uuid=marker.workspace_uuid,
            authorized_root=marker.authorized_root,
            source_snapshot_id=marker.source_snapshot_id,
            seeded_file_count=marker.seeded_file_count,
            created_at=marker.created_at,
            host_platform=marker.host_platform,
        )

        if not hmac.compare_digest(marker.signature, expected_sig):
            raise WorkspaceSafetyError(
                "Recovery marker signature validation failed. Marker may have been tampered with."
            )

        return marker

    def validate_workspace_path(
        self,
        workspace_id: str,
        target_path: Union[str, Path],
        allow_reserved: bool = False,
        validated_workspace_root: Optional[Path] = None,
        verify_marker: bool = True,
    ) -> Path:
        """
        Validate that target_path resides safely within workspace_id and is not a symlink.

        Args:
            workspace_id: Target recovery workspace identifier.
            target_path: Path candidate to validate.
            allow_reserved: If True, allows targeting reserved files/directories.
            validated_workspace_root: Pre-validated workspace directory path to skip redundant
                                      marker disk I/O in batch operations.
            verify_marker: If True and validated_workspace_root is None, verifies safety marker.

        Raises:
            WorkspaceSafetyError: On traversal, symlink, root targeting, or reserved file access.
        """
        if validated_workspace_root is not None:
            workspace_dir = validated_workspace_root.resolve()
            self._check_not_lab(workspace_dir)
        else:
            if verify_marker:
                self.verify_workspace_marker(workspace_id)
            else:
                self._validate_workspace_id(workspace_id)
            workspace_dir = (self.workspaces_root / workspace_id).resolve()
            self._check_not_lab(workspace_dir)

        # Reject explicit traversal components in string representation
        if isinstance(target_path, str):
            norm_parts = target_path.replace("\\", "/").split("/")
            if ".." in norm_parts:
                raise WorkspaceSafetyError(
                    f"Path traversal '..' detected in target path: '{target_path}'"
                )

        p = Path(target_path)
        if ".." in p.parts:
            raise WorkspaceSafetyError(
                f"Path traversal '..' detected in target path: '{target_path}'"
            )

        if p.is_absolute():
            candidate = p.resolve()
        else:
            candidate = (workspace_dir / p).resolve()

        # Boundary check
        try:
            rel = candidate.relative_to(workspace_dir)
        except ValueError:
            raise WorkspaceSafetyError(
                f"Target path '{candidate}' is outside authorized workspace '{workspace_dir}'"
            )

        if candidate == workspace_dir:
            raise WorkspaceSafetyError(
                "Target path cannot be the workspace root directory itself."
            )

        # Check all path components from workspace_dir down to candidate for symlinks
        curr = workspace_dir
        for part in rel.parts:
            curr = curr / part
            if curr.is_symlink():
                raise WorkspaceSafetyError(
                    f"Symlink detected in path component: '{curr}'"
                )
            if curr.exists():
                try:
                    curr.resolve().relative_to(workspace_dir)
                except ValueError:
                    raise WorkspaceSafetyError(
                        f"Path component '{curr}' resolves outside workspace boundary."
                    )

        # Check reserved files
        if not allow_reserved and len(rel.parts) > 0:
            first_part = rel.parts[0]
            if first_part in {CONFIG.RECOVERY_MARKER_FILENAME, CONFIG.RECOVERY_EVIDENCE_DIRNAME}:
                raise WorkspaceSafetyError(
                    f"Targeting reserved recovery file or directory '{first_part}' is prohibited."
                )

        return candidate

    def list_workspaces(self) -> List[WorkspaceMetadata]:
        """List all recovery workspaces, marking tampered ones with marker_valid=False."""
        results: List[WorkspaceMetadata] = []
        if not self.workspaces_root.exists():
            return results

        for item in sorted(self.workspaces_root.iterdir()):
            if not item.is_dir():
                continue
            try:
                marker = self.verify_workspace_marker(item)
                results.append(
                    WorkspaceMetadata(
                        workspace_id=marker.workspace_id,
                        workspace_path=item.resolve(),
                        created_at=marker.created_at,
                        seeded_file_count=marker.seeded_file_count,
                        source_snapshot_id=marker.source_snapshot_id,
                        marker_valid=True,
                    )
                )
            except WorkspaceSafetyError:
                created_at = ""
                seeded_file_count = 0
                source_snapshot_id = None
                marker_file = item / CONFIG.RECOVERY_MARKER_FILENAME
                if marker_file.exists():
                    try:
                        with open(marker_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        created_at = str(data.get("created_at", ""))
                        seeded_file_count = int(data.get("seeded_file_count", 0))
                        source_snapshot_id = data.get("source_snapshot_id")
                    except Exception:
                        pass
                results.append(
                    WorkspaceMetadata(
                        workspace_id=item.name,
                        workspace_path=item.resolve(),
                        created_at=created_at,
                        seeded_file_count=seeded_file_count,
                        source_snapshot_id=source_snapshot_id,
                        marker_valid=False,
                    )
                )
            except Exception:
                continue

        results.sort(key=lambda m: m.workspace_id)
        return results

    def get_workspace_path(self, workspace_id: str) -> Path:
        """Validate marker and return the resolved workspace directory Path."""
        self.verify_workspace_marker(workspace_id)
        return (self.workspaces_root / workspace_id).resolve()

    def delete_workspace(self, workspace_id: str) -> bool:
        """
        Delete a workspace tree after validating its safety marker.
        Never touches the lab directory.
        """
        self._validate_workspace_id(workspace_id)
        target = (self.workspaces_root / workspace_id).resolve()
        self._check_not_lab(target)

        # Boundary check
        if target.parent != self.workspaces_root:
            raise WorkspaceSafetyError(
                f"Workspace '{target}' is not a direct child of '{self.workspaces_root}'"
            )

        self.verify_workspace_marker(workspace_id)
        shutil.rmtree(target)
        logger.info(f"Deleted recovery workspace '{workspace_id}' at '{target}'")
        return True

    def simulate_workspace_damage(
        self,
        workspace_id: str,
        modify_count: int = 5,
        delete_count: int = 5,
        untracked_count: int = 2,
        include_canary: bool = True,
    ) -> Dict[str, List[str]]:
        """
        Simulate controlled damage strictly inside a recovery workspace.
        Never operates on or touches runtime/lab/.

        Returns:
            Dict containing lists of modified, deleted, untracked, and affected canary relative paths.
        """
        self.verify_workspace_marker(workspace_id)
        workspace_dir = (self.workspaces_root / workspace_id).resolve()
        self._check_not_lab(workspace_dir)

        # Enumerate regular files
        files: List[str] = []
        for root, dirs, filenames in os.walk(workspace_dir):
            if CONFIG.RECOVERY_EVIDENCE_DIRNAME in dirs:
                dirs.remove(CONFIG.RECOVERY_EVIDENCE_DIRNAME)
            for fn in filenames:
                if fn in {CONFIG.RECOVERY_MARKER_FILENAME, ".cryptoshield_seeded_scope.json"}:
                    continue
                full_path = Path(root) / fn
                rel = full_path.relative_to(workspace_dir).as_posix()
                files.append(rel)

        files.sort()

        # Identify known canaries via scope metadata, baseline manifest, and path patterns
        known_canaries: Set[str] = set()

        # 1. From seeded scope file if present
        scope_file = workspace_dir / ".cryptoshield_seeded_scope.json"
        if scope_file.exists():
            try:
                with open(scope_file, "r", encoding="utf-8") as f:
                    scope_data = json.load(f)
                    if isinstance(scope_data, dict) and "canary_paths" in scope_data:
                        known_canaries.update(p.replace("\\", "/") for p in scope_data["canary_paths"])
            except Exception:
                pass

        # 2. From baseline manifest if present
        manifest_path = self.lab_dir / CONFIG.MANIFEST_FILENAME
        if manifest_path.exists():
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest_data = json.load(f)
                for rel_k, ent in manifest_data.get("entries", {}).items():
                    if ent.get("is_canary"):
                        known_canaries.add(rel_k.replace("\\", "/"))
            except Exception:
                pass

        canary_files = [
            f for f in files
            if f in known_canaries or "canary" in f.lower() or "canaries" in f.lower()
        ]
        canary_files.sort()
        normal_files = [f for f in files if f not in canary_files]
        normal_files.sort()

        needed = modify_count + delete_count
        if len(files) < needed:
            raise RecoveryError(
                f"Insufficient files in workspace: {len(files)} available, {needed} required."
            )

        to_modify: List[str] = []
        to_delete: List[str] = []

        if include_canary and canary_files:
            # Guarantee at least 1 canary modified and at least 1 distinct canary deleted
            canary_for_modify = [canary_files[0]] if modify_count > 0 else []

            canary_for_delete = []
            if delete_count > 0:
                if len(canary_files) >= 2:
                    canary_for_delete = [canary_files[1]]
                elif not canary_for_modify:
                    canary_for_delete = [canary_files[0]]

            used_canaries = set(canary_for_modify + canary_for_delete)
            remaining_pool = [f for f in files if f not in used_canaries]

            needed_modify = modify_count - len(canary_for_modify)
            needed_delete = delete_count - len(canary_for_delete)

            to_modify = canary_for_modify + remaining_pool[:needed_modify]
            to_delete = canary_for_delete + remaining_pool[needed_modify : needed_modify + needed_delete]
        else:
            to_modify = files[:modify_count]
            to_delete = files[modify_count : modify_count + delete_count]

        to_modify.sort()
        to_delete.sort()

        # Identify canaries affected
        canaries_affected = sorted(
            list(set(f for f in (to_modify + to_delete) if f in canary_files))
        )

        # 1. Modify selected files
        for rel in to_modify:
            p = workspace_dir / rel
            with open(p, "ab") as f:
                f.write(b"\n# CRYPTOSHIELD_SIMULATED_CORRUPTION_MARKER\n")

        # 2. Delete selected files
        for rel in to_delete:
            p = workspace_dir / rel
            if p.exists():
                p.unlink()

        # 3. Create untracked artifacts
        untracked_files: List[str] = []
        for i in range(1, untracked_count + 1):
            name = f"UNTRACKED_ARTIFACT_{i:03d}.txt"
            p = workspace_dir / name
            p.write_text(f"Untracked test artifact {i:03d}\n", encoding="utf-8")
            untracked_files.append(name)

        return {
            "modified": to_modify,
            "deleted": to_delete,
            "untracked": untracked_files,
            "canaries_affected": canaries_affected,
        }
