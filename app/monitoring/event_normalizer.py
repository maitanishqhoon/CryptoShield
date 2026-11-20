"""
Telemetry Event Normalizer for CryptoShield.

Converts raw filesystem and process events into standardized, strongly-typed
MonitoringEvent instances. Handles POSIX path normalization, safety boundary
verification, and manifest/canary enrichment without performing file hashes.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from app.config import CONFIG
from app.core.logger import get_logger
from app.core.models import (
    EventPriority,
    FileAction,
    Manifest,
    ManifestEntry,
    MonitoringEvent,
    ProcessAttribution,
)
from app.core.safety import SafetyViolationError, validate_lab_path

logger = get_logger("event_normalizer")


class EventNormalizer:
    """Normalizes raw observations into standardized MonitoringEvent instances."""

    def __init__(
        self,
        base_lab_dir: Optional[Path] = None,
        manifest: Optional[Manifest] = None,
        ignored_dirs: Optional[list[str]] = None,
        ignored_files: Optional[list[str]] = None,
    ) -> None:
        self.lab_dir = (base_lab_dir or CONFIG.LAB_DIR).resolve()
        self.ignored_dirs = set(ignored_dirs or CONFIG.MONITOR_IGNORED_DIRS)
        self.ignored_files = set(ignored_files or CONFIG.MONITOR_IGNORED_FILENAMES)
        self._manifest_entries: Dict[str, ManifestEntry] = {}
        if manifest:
            self.set_manifest(manifest)

    def set_manifest(self, manifest: Manifest) -> None:
        """Update active baseline manifest lookup cache."""
        self._manifest_entries = dict(manifest.entries)
        logger.debug(f"EventNormalizer cached {len(self._manifest_entries)} baseline manifest entries.")

    def update_manifest_entries(self, entries: Dict[str, ManifestEntry]) -> None:
        """Directly update the manifest entries dictionary."""
        self._manifest_entries = dict(entries)

    def is_path_ignored(self, relative_path: str) -> bool:
        """Check if relative path touches ignored directories or filenames."""
        p = Path(relative_path)
        # Check filename
        if p.name in self.ignored_files or p.name.startswith("."):
            return True
        # Check any parent directory component
        for part in p.parts:
            if part in self.ignored_dirs or part.startswith("."):
                return True
        return False

    def normalize_path(self, raw_path: Union[str, Path]) -> Optional[str]:
        """
        Validate path resides in laboratory root, handle symlinks safely,
        and normalize to a POSIX relative path.

        Returns None if path is ignored or outside laboratory boundary.
        """
        try:
            target = Path(raw_path)
            if not target.is_absolute():
                target = (self.lab_dir / target).resolve()
            else:
                target = target.resolve()

            # Enforce laboratory boundary via safety engine
            # If target == lab_dir itself (e.g. root dir creation), ignore
            if target == self.lab_dir:
                return None
            try:
                rel = target.relative_to(self.lab_dir).as_posix()
            except ValueError:
                logger.warning(
                    f"Rejected event outside lab boundary: {target} (lab: {self.lab_dir})"
                )
                return None

            if self.is_path_ignored(rel):
                return None

            return rel
        except Exception as e:
            logger.debug(f"Path normalization failed for '{raw_path}': {e}")
            return None

    def create_filesystem_event(
        self,
        event_type: str,
        raw_path: Union[str, Path],
        dest_raw_path: Optional[Union[str, Path]] = None,
        is_directory: bool = False,
        source: str = "WATCHDOG",
    ) -> Optional[MonitoringEvent]:
        """Normalize raw filesystem events into MonitoringEvent."""
        rel_path = self.normalize_path(raw_path)
        if not rel_path:
            return None

        # Operation mapping
        op_map = {
            "FILE_CREATED": FileAction.CREATE.value,
            "FILE_MODIFIED": FileAction.MODIFY.value,
            "FILE_DELETED": FileAction.DELETE.value,
            "FILE_MOVED": FileAction.RENAME.value,
            "DIR_CREATED": FileAction.CREATE.value,
            "DIR_DELETED": FileAction.DELETE.value,
            "DIR_MOVED": FileAction.RENAME.value,
        }
        operation = op_map.get(event_type, FileAction.MODIFY.value)

        # Baseline manifest lookup
        entry = self._manifest_entries.get(rel_path)
        is_canary = entry.is_canary if entry else False
        canary_id = rel_path if is_canary else None

        # Determine priority: if canary is tampered/modified/deleted via watchdog, flag HIGH/CRITICAL
        priority = EventPriority.NORMAL.value
        if is_canary:
            priority = (
                EventPriority.CRITICAL.value
                if event_type in {"FILE_DELETED", "FILE_MOVED"}
                else EventPriority.HIGH.value
            )

        metadata: Dict[str, Any] = {
            "is_directory": is_directory,
            "manifest_registered": entry is not None,
        }

        if entry:
            metadata["classification"] = entry.data_classification
            metadata["department"] = entry.department
            metadata["baseline_size"] = entry.file_size_bytes

        if dest_raw_path:
            dest_rel = self.normalize_path(dest_raw_path)
            metadata["dest_relative_path"] = dest_rel

        return MonitoringEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(CONFIG.TIMEZONE).isoformat(),
            event_type=event_type,
            source=source,
            relative_path=rel_path,
            is_canary=is_canary,
            canary_id=canary_id,
            process_id=None,
            process_name=None,
            process_attribution=ProcessAttribution.UNKNOWN.value,
            operation=operation,
            priority=priority,
            metadata=metadata,
        )

    def create_access_event(
        self,
        raw_path: Union[str, Path],
        operation: str = "READ",
        process_id: Optional[int] = None,
        process_name: Optional[str] = None,
        source: str = "CONTROLLED_INSTRUMENTATION",
        custom_metadata: Optional[Dict[str, Any]] = None,
    ) -> MonitoringEvent:
        """
        Normalize controlled file-access instrumentation events.
        Specialized handling for CANARY_ACCESS with HIGH priority.
        """
        target = Path(raw_path).resolve()
        # Strictly validate against safety engine
        validate_lab_path(target, base_lab_dir=self.lab_dir)

        rel_path = target.relative_to(self.lab_dir).as_posix()
        entry = self._manifest_entries.get(rel_path)
        is_canary = entry.is_canary if entry else False

        if is_canary:
            event_type = "CANARY_ACCESS"
            priority = CONFIG.CANARY_EVENT_PRIORITY  # Default "HIGH"
            canary_id = rel_path
        else:
            op_clean = operation.upper()
            event_type = f"FILE_{op_clean}" if not op_clean.startswith("FILE_") else op_clean
            priority = EventPriority.NORMAL.value
            canary_id = None

        attribution = (
            ProcessAttribution.CONFIRMED.value
            if process_id is not None
            else ProcessAttribution.UNKNOWN.value
        )

        metadata: Dict[str, Any] = {
            "manifest_registered": entry is not None,
            "access_operation": operation.upper(),
        }
        if entry:
            metadata["classification"] = entry.data_classification
            metadata["department"] = entry.department
            metadata["baseline_size"] = entry.file_size_bytes

        if custom_metadata:
            metadata.update(custom_metadata)

        return MonitoringEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(CONFIG.TIMEZONE).isoformat(),
            event_type=event_type,
            source=source,
            relative_path=rel_path,
            is_canary=is_canary,
            canary_id=canary_id,
            process_id=process_id,
            process_name=process_name,
            process_attribution=attribution,
            operation=FileAction.ACCESS.value,
            priority=priority,
            metadata=metadata,
        )

    def create_process_event(
        self,
        event_type: str,
        process_id: int,
        process_name: Optional[str],
        exe_path: Optional[str] = None,
        username: Optional[str] = None,
        create_time: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MonitoringEvent:
        """Normalize process telemetry observations."""
        meta = metadata or {}
        if exe_path:
            meta["exe"] = exe_path
        if username:
            meta["username"] = username
        if create_time:
            meta["create_time"] = create_time

        return MonitoringEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(CONFIG.TIMEZONE).isoformat(),
            event_type=event_type,
            source="PSUTIL",
            relative_path=None,
            is_canary=False,
            canary_id=None,
            process_id=process_id,
            process_name=process_name,
            process_attribution=ProcessAttribution.CONFIRMED.value,
            operation="PROCESS",
            priority=EventPriority.NORMAL.value,
            metadata=meta,
        )
