"""
Laboratory lifecycle and environment manager for CryptoShield.

Coordinates lab directory initialization, safety marker generation,
status inspection, and guarded clean/reset operations.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from app.config import CONFIG
from app.core.logger import get_logger
from app.core.models import LabMarker
from app.core.safety import (
    SafetyViolationError,
    generate_lab_marker,
    validate_lab_path,
    verify_lab_marker,
)

logger = get_logger("lab_manager")


class LabManager:
    """Manages the isolated laboratory filesystem workspace."""

    def __init__(self, base_lab_dir: Optional[Path] = None) -> None:
        self.lab_dir = (base_lab_dir or CONFIG.LAB_DIR).resolve()
        self.marker_path = self.lab_dir / CONFIG.LAB_MARKER_FILENAME
        self.manifest_path = self.lab_dir / CONFIG.MANIFEST_FILENAME

    def initialize_runtime(self) -> None:
        """Create standard runtime directory tree if not already present."""
        for path in [
            CONFIG.LAB_DIR,
            CONFIG.VAULT_DIR,
            CONFIG.SNAPSHOTS_DIR,
            CONFIG.LOGS_DIR,
            CONFIG.REPORTS_DIR,
        ]:
            path.mkdir(parents=True, exist_ok=True)
            # Create a .gitkeep if empty
            gitkeep = path / ".gitkeep"
            if not gitkeep.exists() and not any(path.iterdir()):
                gitkeep.touch()

    def initialize_lab(self, force_new_marker: bool = False) -> LabMarker:
        """
        Initialize the laboratory environment and install the safety marker.
        Returns the active LabMarker.
        """
        self.initialize_runtime()
        self.lab_dir.mkdir(parents=True, exist_ok=True)

        # Check existing marker
        if self.marker_path.exists() and not force_new_marker:
            try:
                marker = verify_lab_marker(self.lab_dir)
                logger.info(f"Existing valid laboratory marker loaded (ID: {marker.lab_id})")
                return marker
            except SafetyViolationError as e:
                logger.warning(f"Existing marker invalid ({e}). Regenerating marker.")

        marker = generate_lab_marker(self.lab_dir)
        with open(self.marker_path, "w", encoding="utf-8") as f:
            json.dump(marker.to_dict(), f, indent=2)

        logger.info(
            f"Laboratory initialized with safety marker at '{self.marker_path}' (ID: {marker.lab_id})"
        )
        return marker

    def validate_lab(self) -> Tuple[bool, str]:
        """Verify lab readiness and safety marker validity."""
        try:
            marker = verify_lab_marker(self.lab_dir)
            return True, f"Laboratory is valid. Marker ID: {marker.lab_id}"
        except SafetyViolationError as e:
            return False, str(e)

    def clean_lab(self, preserve_marker: bool = True) -> int:
        """
        Safely clean laboratory files.
        Strictly requires an authentic laboratory marker before deleting anything.
        """
        verify_lab_marker(self.lab_dir)

        deleted_count = 0
        logger.warning(f"Purging laboratory target directory: {self.lab_dir}")

        for item in self.lab_dir.iterdir():
            if preserve_marker and item.name == CONFIG.LAB_MARKER_FILENAME:
                continue

            # Ensure every item being deleted is strictly inside the lab
            validate_lab_path(item, self.lab_dir)

            if item.is_file() or item.is_symlink():
                item.unlink()
                deleted_count += 1
            elif item.is_dir():
                shutil.rmtree(item)
                deleted_count += 1

        logger.info(f"Laboratory cleanup complete. Removed {deleted_count} items.")
        return deleted_count

    def get_status(self) -> Dict[str, Any]:
        """Return laboratory metrics, file counts, disk usage, and marker details."""
        is_valid, msg = self.validate_lab()

        files_count = 0
        dirs_count = 0
        total_bytes = 0
        department_counts: Dict[str, int] = {}
        has_manifest = self.manifest_path.exists()

        if self.lab_dir.exists():
            for root, dirs, files in os.walk(self.lab_dir):
                dirs_count += len(dirs)
                for f in files:
                    if f in {CONFIG.LAB_MARKER_FILENAME, CONFIG.MANIFEST_FILENAME}:
                        continue
                    files_count += 1
                    fp = Path(root) / f
                    try:
                        total_bytes += fp.stat().st_size
                    except OSError:
                        pass

                    # Extract top-level department
                    try:
                        rel = fp.relative_to(self.lab_dir)
                        if len(rel.parts) > 1:
                            dept = rel.parts[0]
                            department_counts[dept] = department_counts.get(dept, 0) + 1
                    except Exception:
                        pass

        marker_info = None
        if self.marker_path.exists():
            try:
                marker = verify_lab_marker(self.lab_dir)
                marker_info = {
                    "lab_id": marker.lab_id,
                    "created_at": marker.created_at,
                    "authorized_root": marker.authorized_root,
                }
            except Exception:
                marker_info = {"error": "Invalid or tampered marker"}

        return {
            "lab_dir": str(self.lab_dir),
            "is_valid": is_valid,
            "status_message": msg,
            "has_marker": self.marker_path.exists(),
            "marker_info": marker_info,
            "has_manifest": has_manifest,
            "total_files": files_count,
            "total_directories": dirs_count,
            "total_bytes": total_bytes,
            "total_mb": round(total_bytes / (1024 * 1024), 2),
            "department_counts": department_counts,
        }
