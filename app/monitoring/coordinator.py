"""
Monitoring Coordinator for CryptoShield.

Orchestrates FilesystemMonitor, ProcessMonitor, and AccessMonitor into a unified
telemetry engine. Handles laboratory verification, duplicate instance prevention,
event bus publishing, structured JSONL audit trails, and clean shutdown.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from app.config import CONFIG
from app.core.event_bus import BUS, EventBus
from app.core.logger import get_logger
from app.core.models import Manifest, MonitoringEvent
from app.core.safety import verify_lab_marker
from app.lab.manifest import ManifestManager
from app.monitoring.access_monitor import AccessMonitor
from app.monitoring.event_normalizer import EventNormalizer
from app.monitoring.filesystem_monitor import FilesystemMonitor
from app.monitoring.process_monitor import ProcessMonitor

logger = get_logger("monitoring_coordinator")


class MonitoringCoordinator:
    """
    Central coordinator orchestrating all Phase 2 monitoring and telemetry subsystems.
    Guarantees thread-safe single-instance execution, laboratory boundary validation,
    and unified event dispatching.
    """

    _instance_lock = threading.Lock()
    _active_instance: Optional[MonitoringCoordinator] = None

    def __init__(
        self,
        base_lab_dir: Optional[Path] = None,
        event_bus: Optional[EventBus] = None,
        queue_capacity: int = CONFIG.MONITOR_EVENT_QUEUE_CAPACITY,
        debounce_seconds: float = CONFIG.MONITOR_DEBOUNCE_SECONDS,
        process_poll_interval: float = CONFIG.PROCESS_POLL_INTERVAL_SECONDS,
        manifest: Optional[Manifest] = None,
    ) -> None:
        self.lab_dir = (base_lab_dir or CONFIG.LAB_DIR).resolve()
        self.bus = event_bus or BUS
        self.queue_capacity = queue_capacity
        self.debounce_seconds = debounce_seconds
        self.process_poll_interval = process_poll_interval

        # Load baseline manifest
        self.manifest: Optional[Manifest] = manifest
        if not self.manifest:
            self._load_baseline_manifest()

        # Shared normalizer
        self.normalizer = EventNormalizer(
            base_lab_dir=self.lab_dir,
            manifest=self.manifest,
        )

        # Subsystems
        self.fs_monitor = FilesystemMonitor(
            base_lab_dir=self.lab_dir,
            event_callback=self._on_telemetry_event,
            normalizer=self.normalizer,
            queue_capacity=self.queue_capacity,
            debounce_seconds=self.debounce_seconds,
        )

        self.proc_monitor = ProcessMonitor(
            event_callback=self._on_telemetry_event,
            normalizer=self.normalizer,
            poll_interval_seconds=self.process_poll_interval,
        )

        self.access_monitor = AccessMonitor(
            base_lab_dir=self.lab_dir,
            event_bus=self.bus,
            normalizer=self.normalizer,
            manifest=self.manifest,
            event_callback=self._on_telemetry_event,
        )

        # Operational metrics
        self.is_running: bool = False
        self.start_time: Optional[float] = None
        self.stop_time: Optional[float] = None
        self.events_observed: int = 0
        self.events_published: int = 0
        self.events_by_type: Dict[str, int] = {}
        self.recent_events: List[MonitoringEvent] = []
        self._max_recent_events: int = 500
        self._custom_listeners: List[Callable[[MonitoringEvent], None]] = []
        self._lock = threading.Lock()

    def _load_baseline_manifest(self) -> None:
        """Load manifest from lab directory if present."""
        manifest_path = self.lab_dir / CONFIG.MANIFEST_FILENAME
        if manifest_path.exists():
            try:
                self.manifest = ManifestManager.load_manifest(
                    manifest_path, base_lab_dir=self.lab_dir
                )
                logger.info(
                    f"Coordinator loaded baseline manifest with {self.manifest.total_files} files "
                    f"and {self.manifest.canary_count} canaries."
                )
            except Exception as e:
                logger.warning(f"Could not load baseline manifest at '{manifest_path}': {e}")

    def add_listener(self, listener: Callable[[MonitoringEvent], None]) -> None:
        """Add a callback listener for all normalized telemetry events."""
        with self._lock:
            if listener not in self._custom_listeners:
                self._custom_listeners.append(listener)

    def remove_listener(self, listener: Callable[[MonitoringEvent], None]) -> None:
        """Remove a previously registered callback listener."""
        with self._lock:
            if listener in self._custom_listeners:
                self._custom_listeners.remove(listener)

    def start(self, enable_process_monitor: bool = True) -> None:
        """
        Validate laboratory and start all monitoring engines.
        Prevents accidental duplicate instances.
        """
        with self._instance_lock:
            with self._lock:
                if self.is_running:
                    logger.warning("MonitoringCoordinator is already running.")
                    return

                # Validate safety marker
                verify_lab_marker(self.lab_dir)

                logger.info(f"Starting MonitoringCoordinator for lab '{self.lab_dir}'...")
                self.start_time = time.time()
                self.is_running = True

                # Start filesystem monitor
                self.fs_monitor.start()

                # Start process telemetry monitor
                if enable_process_monitor:
                    self.proc_monitor.start()

                MonitoringCoordinator._active_instance = self
                logger.info("MonitoringCoordinator started successfully.")

    def stop(self, timeout: float = 3.0) -> None:
        """Gracefully shut down all monitoring subsystems."""
        with self._instance_lock:
            with self._lock:
                if not self.is_running:
                    return

                logger.info("Stopping MonitoringCoordinator...")
                self.is_running = False
                self.stop_time = time.time()

                # Stop filesystem monitor
                self.fs_monitor.stop(timeout=timeout)

                # Stop process monitor
                self.proc_monitor.stop(timeout=timeout)

                if MonitoringCoordinator._active_instance is self:
                    MonitoringCoordinator._active_instance = None

                logger.info(
                    f"MonitoringCoordinator stopped. Total observed: {self.events_observed}, "
                    f"Published: {self.events_published}, "
                    f"Canary trips: {self.access_monitor.canary_trips_count}"
                )

    def _on_telemetry_event(self, event: MonitoringEvent) -> None:
        """
        Internal event sink receiving events from all monitors.
        Publishes to EventBus, records in structured logs, and notifies listeners.
        """
        with self._lock:
            self.events_observed += 1
            self.events_by_type[event.event_type] = (
                self.events_by_type.get(event.event_type, 0) + 1
            )

            # Keep a bounded buffer of recent events for inspection
            self.recent_events.append(event)
            if len(self.recent_events) > self._max_recent_events:
                self.recent_events.pop(0)

        # Audit log into structured JSONL
        extra_data = {
            "telemetry_event": event.event_type,
            "event_id": event.event_id,
            "source": event.source,
            "relative_path": event.relative_path,
            "is_canary": event.is_canary,
            "priority": event.priority,
            "process_id": event.process_id,
        }

        if event.is_canary:
            logger.warning(
                f"[CANARY EVENT] {event.event_type} on {event.relative_path} (Priority: {event.priority})",
                extra=extra_data,
            )
        else:
            logger.debug(
                f"[TELEMETRY] {event.event_type}: {event.relative_path or event.process_name or ''}",
                extra=extra_data,
            )

        # Publish to EventBus
        try:
            self.bus.publish(event.to_bus_event())
            with self._lock:
                self.events_published += 1
        except Exception as e:
            logger.exception(f"Error publishing event {event.event_id} to EventBus: {e}")

        # Notify custom listeners
        for listener in list(self._custom_listeners):
            try:
                listener(event)
            except Exception as e:
                logger.exception(f"Error in listener {listener}: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Return comprehensive system health and operational metrics."""
        end_time = self.stop_time if (not self.is_running and self.stop_time) else time.time()
        uptime = round(end_time - self.start_time, 2) if self.start_time else 0.0
        fs_status = self.fs_monitor.get_status()
        proc_status = self.proc_monitor.get_status()
        access_status = self.access_monitor.get_status()

        return {
            "is_running": self.is_running,
            "monitored_root": str(self.lab_dir),
            "uptime_seconds": uptime,
            "total_events_observed": self.events_observed,
            "total_events_published": self.events_published,
            "events_by_type": dict(self.events_by_type),
            "canary_trips_count": access_status["canary_trips_count"],
            "filesystem_monitor": fs_status,
            "process_monitor": proc_status,
            "access_monitor": access_status,
        }
