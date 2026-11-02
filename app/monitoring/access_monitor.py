"""
Controlled File-Access and Canary Decoy Telemetry for CryptoShield.

Provides active instrumentation for controlled laboratory test harnesses and test
applications to record file read/open/access operations and reliably detect
canary decoy access events.

Note on Scope & Limitations:
Watchdog provides OS-level notification of filesystem write/modify/delete/move events,
but operating systems do not generate lightweight filesystem hooks for arbitrary
read/open calls. This AccessMonitor provides the controlled laboratory instrumentation
mechanism required to record and publish reliable file-read and canary-trip telemetry.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Generator, IO, Optional, Union

from app.config import CONFIG
from app.core.event_bus import BUS, EventBus
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
from app.lab.manifest import ManifestManager
from app.monitoring.event_normalizer import EventNormalizer

logger = get_logger("access_monitor")


class AccessMonitor:
    """
    Controlled laboratory file-access instrumentation recorder.
    Intercepts and records laboratory file access, validates boundaries,
    and reliably raises high-priority CANARY_ACCESS telemetry when decoys are read.
    """

    def __init__(
        self,
        base_lab_dir: Optional[Path] = None,
        event_bus: Optional[EventBus] = None,
        normalizer: Optional[EventNormalizer] = None,
        manifest: Optional[Manifest] = None,
        event_callback: Optional[Callable[[MonitoringEvent], None]] = None,
    ) -> None:
        self.lab_dir = (base_lab_dir or CONFIG.LAB_DIR).resolve()
        self.bus = event_bus or BUS
        self.normalizer = normalizer or EventNormalizer(base_lab_dir=self.lab_dir, manifest=manifest)
        self.event_callback = event_callback

        # Canary tracking
        self.canary_access_events: list[MonitoringEvent] = []
        self.total_access_events: int = 0
        self.canary_trips_count: int = 0

        # Load manifest if provided or attempt to load from disk
        if manifest:
            self.set_manifest(manifest)
        else:
            self._try_load_manifest()

    def _try_load_manifest(self) -> None:
        """Attempt to load baseline manifest from lab directory if present."""
        manifest_file = self.lab_dir / CONFIG.MANIFEST_FILENAME
        if manifest_file.exists():
            try:
                manifest = ManifestManager.load_manifest(manifest_file, base_lab_dir=self.lab_dir)
                self.set_manifest(manifest)
            except Exception as e:
                logger.debug(f"Could not automatically load manifest from '{manifest_file}': {e}")

    def set_manifest(self, manifest: Manifest) -> None:
        """Update manifest and register canary paths."""
        self.normalizer.set_manifest(manifest)
        canary_count = sum(1 for e in manifest.entries.values() if e.is_canary)
        logger.info(
            f"AccessMonitor synchronized with baseline manifest ({len(manifest.entries)} files, {canary_count} canaries)."
        )

    def record_access(
        self,
        file_path: Union[str, Path],
        operation: str = "READ",
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
        source: str = "CONTROLLED_INSTRUMENTATION",
        custom_metadata: Optional[Dict[str, Any]] = None,
    ) -> MonitoringEvent:
        """
        Record and publish a file access event.

        Steps:
        1. Validates path against lab boundary using safety engine.
        2. Consults baseline manifest to check for canary status.
        3. Generates CANARY_ACCESS (priority HIGH) or FILE_READ/FILE_OPEN event.
        4. Logs to structured JSONL audit logger.
        5. Publishes structured event to EventBus.
        """
        # Ensure path is safely within laboratory boundary
        validate_lab_path(file_path, base_lab_dir=self.lab_dir)

        # Default process attribution to caller process if not explicitly specified
        caller_pid = pid if pid is not None else os.getpid()
        caller_name = process_name or "controlled_test_harness"

        event = self.normalizer.create_access_event(
            raw_path=file_path,
            operation=operation,
            process_id=caller_pid,
            process_name=caller_name,
            source=source,
            custom_metadata=custom_metadata,
        )

        self.total_access_events += 1

        # Canary Handling: Core requirement
        if event.is_canary:
            self.canary_trips_count += 1
            self.canary_access_events.append(event)
            # High-priority audit logging
            logger.warning(
                f"[CANARY TRIPPED] High-priority canary access detected: '{event.relative_path}' "
                f"(Operation: {operation}, PID: {caller_pid}, Process: {caller_name})",
                extra={
                    "audit_event": "CANARY_ACCESS",
                    "event_id": event.event_id,
                    "relative_path": event.relative_path,
                    "canary_id": event.canary_id,
                    "priority": event.priority,
                    "process_id": caller_pid,
                    "process_name": caller_name,
                },
            )
        else:
            logger.debug(
                f"File access recorded: '{event.relative_path}' (Op: {operation})",
                extra={
                    "audit_event": event.event_type,
                    "event_id": event.event_id,
                    "relative_path": event.relative_path,
                    "priority": event.priority,
                },
            )

        # Publish to event bus
        self.bus.publish(event.to_bus_event())

        # Callback if configured
        if self.event_callback:
            self.event_callback(event)

        return event

    def read_file(
        self,
        file_path: Union[str, Path],
        mode: str = "r",
        encoding: Optional[str] = "utf-8",
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
    ) -> Union[str, bytes]:
        """
        Convenience method: Records FILE_READ or CANARY_ACCESS then safely reads file contents.
        """
        self.record_access(
            file_path=file_path,
            operation="READ",
            pid=pid,
            process_name=process_name,
        )

        target = Path(file_path).resolve()
        if "b" in mode:
            with open(target, "rb") as f:
                return f.read()
        else:
            with open(target, "r", encoding=encoding or "utf-8") as f:
                return f.read()

    @contextmanager
    def open(
        self,
        file_path: Union[str, Path],
        mode: str = "r",
        encoding: Optional[str] = "utf-8",
        pid: Optional[int] = None,
        process_name: Optional[str] = None,
    ) -> Generator[IO[Any], None, None]:
        """
        Context manager for instrumented file access:
        with access_monitor.open(path) as f:
            data = f.read()
        """
        self.record_access(
            file_path=file_path,
            operation="OPEN",
            pid=pid,
            process_name=process_name,
        )

        target = Path(file_path).resolve()
        if "b" in mode:
            with open(target, mode) as f:
                yield f
        else:
            with open(target, mode, encoding=encoding or "utf-8") as f:
                yield f

    def get_status(self) -> Dict[str, Any]:
        """Return instrumentation telemetry statistics."""
        return {
            "total_access_events": self.total_access_events,
            "canary_trips_count": self.canary_trips_count,
            "recent_canaries_tripped": [
                {
                    "event_id": e.event_id,
                    "path": e.relative_path,
                    "timestamp": e.timestamp,
                    "process_id": e.process_id,
                }
                for e in self.canary_access_events[-10:]
            ],
        }
