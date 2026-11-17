"""
Staging Detector for Data Exfiltration Monitoring (Phase 7).

Detects preparation and aggregation of files for exfiltration, including the creation
of staging directories, suspicious archive creation (.zip, .tar, .7z), and rapid file
aggregation within the laboratory boundary.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from pathlib import Path
import threading
from typing import Any, Callable, Dict, List, Optional
import uuid

from app.config import CONFIG
from app.core.event_bus import BUS, Event, EventBus
from app.core.safety import validate_lab_path
from app.exfiltration.models import StagingEvent, StagingType

logger = logging.getLogger("cryptoshield.exfiltration.staging_detector")

SUSPICIOUS_ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz"}
STAGING_KEYWORD_PATTERNS = {"staging", "stage", "exfil", "archive", "export", "dump", "temp_collect"}


class StagingDetector:
    """
    Monitors laboratory operations for unauthorized file aggregation or archive packaging
    indicative of exfiltration staging behavior.
    """

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        staging_callback: Optional[Callable[[StagingEvent], None]] = None,
    ) -> None:
        self.bus = event_bus or BUS
        self.staging_callback = staging_callback

        self._staging_events: List[StagingEvent] = []
        self._staged_paths_seen: set = set()
        self._lock = threading.Lock()
        self._is_active = False

    def start(self) -> None:
        """Subscribes the staging detector to filesystem creation and move events."""
        with self._lock:
            if self._is_active:
                return
            self._is_active = True
            self.bus.subscribe("FILE_CREATED", self._handle_bus_event)
            self.bus.subscribe("DIR_CREATED", self._handle_bus_event)
            self.bus.subscribe("FILE_MOVED", self._handle_bus_event)
            logger.info("StagingDetector active and subscribed to filesystem events.")

    def stop(self) -> None:
        """Unsubscribes from the EventBus."""
        with self._lock:
            if not self._is_active:
                return
            self._is_active = False
            self.bus.unsubscribe("FILE_CREATED", self._handle_bus_event)
            self.bus.unsubscribe("DIR_CREATED", self._handle_bus_event)
            self.bus.unsubscribe("FILE_MOVED", self._handle_bus_event)
            logger.info("StagingDetector stopped.")

    def record_staging(
        self,
        staging_path: str,
        source_paths: List[str],
        staging_type: StagingType = StagingType.DIRECTORY_AGGREGATION,
        total_staged_bytes: int = 0,
        process_id: Optional[int] = None,
        process_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StagingEvent:
        """
        Explicitly records a staging action (e.g. from controlled simulation or instrumentation).
        """
        with self._lock:
            event = StagingEvent(
                staging_id=f"STAGE-{uuid.uuid4().hex[:8].upper()}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                staging_path=staging_path,
                staging_type=staging_type.value if isinstance(staging_type, StagingType) else str(staging_type),
                staged_files_count=len(source_paths),
                total_staged_bytes=total_staged_bytes,
                source_paths=source_paths,
                process_id=process_id,
                process_name=process_name,
                metadata=metadata or {},
            )
            self._staging_events.append(event)
            self._staged_paths_seen.add(staging_path)
            self._publish_staging(event)
            return event

    def ingest_event(self, event_data: Dict[str, Any]) -> Optional[StagingEvent]:
        """
        Analyzes a single normalized filesystem event to detect staging behaviors.
        """
        with self._lock:
            rel_path = event_data.get("relative_path") or event_data.get("file_path", "")
            if not rel_path or rel_path in self._staged_paths_seen:
                return None

            path_obj = Path(rel_path)
            name_lower = path_obj.name.lower()
            ext_lower = path_obj.suffix.lower()

            # Check 1: Archive creation
            if ext_lower in SUSPICIOUS_ARCHIVE_EXTENSIONS:
                staging_type = StagingType.ARCHIVE_ZIP.value
            # Check 2: Staging directory or directory creation with staging naming
            elif any(pat in name_lower for pat in STAGING_KEYWORD_PATTERNS):
                staging_type = StagingType.DIRECTORY_AGGREGATION.value
            else:
                return None

            self._staged_paths_seen.add(rel_path)
            pid = event_data.get("process_id")
            pname = event_data.get("process_name")

            staging_event = StagingEvent(
                staging_id=f"STAGE-{uuid.uuid4().hex[:8].upper()}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                staging_path=rel_path,
                staging_type=staging_type,
                staged_files_count=1,
                total_staged_bytes=event_data.get("metadata", {}).get("baseline_size", 0),
                source_paths=[rel_path],
                process_id=pid,
                process_name=pname,
                metadata=event_data.get("metadata", {}),
            )
            self._staging_events.append(staging_event)
            self._publish_staging(staging_event)
            return staging_event

    def get_staging_events(self) -> List[StagingEvent]:
        """Returns all recorded staging events."""
        with self._lock:
            return list(self._staging_events)

    def reset(self) -> None:
        """Clears all recorded staging events."""
        with self._lock:
            self._staging_events.clear()
            self._staged_paths_seen.clear()

    def _handle_bus_event(self, event: Event) -> None:
        self.ingest_event(event.data)

    def _publish_staging(self, event: StagingEvent) -> None:
        bus_event = Event(
            event_type="EXFILTRATION_STAGING_DETECTED",
            data=event.to_dict(),
            source="staging_detector",
        )
        self.bus.publish(bus_event)
        if self.staging_callback:
            try:
                self.staging_callback(event)
            except Exception as e:
                logger.error("Error in staging callback: %s", e)
