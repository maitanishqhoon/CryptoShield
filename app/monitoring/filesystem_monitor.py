"""
Filesystem Activity Monitor for CryptoShield.

Utilizes Python Watchdog to recursively observe filesystem modifications inside the
authorized laboratory root. Enforces boundary safety, filters noisy/duplicate events
via a debouncing queue, normalizes paths, and dispatches standardized MonitoringEvents.
"""

from __future__ import annotations

import os
import queue
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple, Union

from watchdog.events import (
    DirCreatedEvent,
    DirDeletedEvent,
    DirMovedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from app.config import CONFIG
from app.core.logger import get_logger
from app.core.models import MonitoringEvent
from app.core.safety import SafetyViolationError, validate_lab_path, verify_lab_marker
from app.monitoring.event_normalizer import EventNormalizer

logger = get_logger("filesystem_monitor")


class _WatchdogQueueHandler(FileSystemEventHandler):
    """
    Lightweight, non-blocking watchdog event handler.
    Pushes raw filesystem event tuples into a bounded thread-safe queue.
    """

    def __init__(self, raw_queue: queue.Queue[Tuple[str, str, Optional[str], bool]]) -> None:
        super().__init__()
        self._queue = raw_queue
        self.dropped_events: int = 0

    def _enqueue(
        self,
        event_type: str,
        src_path: str,
        dest_path: Optional[str] = None,
        is_directory: bool = False,
    ) -> None:
        try:
            self._queue.put_nowait((event_type, src_path, dest_path, is_directory))
        except queue.Full:
            self.dropped_events += 1
            logger.warning(
                f"[BACKPRESSURE] Watchdog queue saturated! Dropped {event_type} for '{src_path}'. "
                f"Total dropped: {self.dropped_events}"
            )

    def on_created(self, event: FileSystemEvent) -> None:
        ev_type = "DIR_CREATED" if event.is_directory else "FILE_CREATED"
        self._enqueue(ev_type, event.src_path, is_directory=event.is_directory)

    def on_modified(self, event: FileSystemEvent) -> None:
        ev_type = "DIR_MODIFIED" if event.is_directory else "FILE_MODIFIED"
        self._enqueue(ev_type, event.src_path, is_directory=event.is_directory)

    def on_deleted(self, event: FileSystemEvent) -> None:
        ev_type = "DIR_DELETED" if event.is_directory else "FILE_DELETED"
        self._enqueue(ev_type, event.src_path, is_directory=event.is_directory)

    def on_moved(self, event: FileSystemEvent) -> None:
        ev_type = "DIR_MOVED" if event.is_directory else "FILE_MOVED"
        dest = getattr(event, "dest_path", None)
        self._enqueue(ev_type, event.src_path, dest_path=dest, is_directory=event.is_directory)


class FilesystemMonitor:
    """
    Monitors the laboratory directory recursively for all filesystem modifications.
    Coordinates Watchdog Observer, raw event queue, coalescing/debouncing,
    and event normalization.
    """

    def __init__(
        self,
        base_lab_dir: Optional[Path] = None,
        event_callback: Optional[Callable[[MonitoringEvent], None]] = None,
        normalizer: Optional[EventNormalizer] = None,
        queue_capacity: int = CONFIG.MONITOR_EVENT_QUEUE_CAPACITY,
        debounce_seconds: float = CONFIG.MONITOR_DEBOUNCE_SECONDS,
        observer_timeout: float = CONFIG.MONITOR_OBSERVER_TIMEOUT_SECONDS,
    ) -> None:
        self.lab_dir = (base_lab_dir or CONFIG.LAB_DIR).resolve()
        self.event_callback = event_callback
        self.normalizer = normalizer or EventNormalizer(base_lab_dir=self.lab_dir)
        self.queue_capacity = queue_capacity
        self.debounce_seconds = debounce_seconds
        self.observer_timeout = observer_timeout

        self._raw_queue: queue.Queue[Tuple[str, str, Optional[str], bool]] = queue.Queue(
            maxsize=self.queue_capacity
        )
        self._handler = _WatchdogQueueHandler(self._raw_queue)
        self._observer: Optional[Observer] = None
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Telemetry metrics
        self.events_received: int = 0
        self.events_coalesced: int = 0
        self.events_dispatched: int = 0
        self.events_dropped_outside: int = 0
        self._last_event_timestamps: Dict[Tuple[str, str], float] = {}
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return self._observer is not None and self._observer.is_alive()

    def start(self) -> None:
        """Verify lab marker and start watchdog filesystem observer."""
        with self._lock:
            if self.is_running:
                logger.warning("FilesystemMonitor is already running.")
                return

            # Safety check: Verify lab marker before observing
            verify_lab_marker(self.lab_dir)

            logger.info(f"Starting FilesystemMonitor on '{self.lab_dir}' (recursive=True)...")
            self._stop_event.clear()

            # Start worker consumer thread
            self._worker_thread = threading.Thread(
                target=self._process_queue_loop,
                name="CryptoShield-FSWorker",
                daemon=True,
            )
            self._worker_thread.start()

            # Start watchdog observer with responsive low-latency timeout
            self._observer = Observer(timeout=self.observer_timeout)
            self._observer.schedule(self._handler, str(self.lab_dir), recursive=True)
            self._observer.start()
            logger.info("Watchdog observer started successfully.")

    def stop(self, timeout: float = 3.0) -> None:
        """Cleanly stop the watchdog observer and worker thread."""
        with self._lock:
            if not self.is_running and self._observer is None:
                return

            logger.info("Stopping FilesystemMonitor...")
            # Allow observer buffer to flush in-flight OS events
            time.sleep(self.observer_timeout * 2)

            self._stop_event.set()

            if self._observer:
                try:
                    self._observer.stop()
                    self._observer.join(timeout=timeout)
                except Exception as e:
                    logger.warning(f"Error stopping watchdog observer: {e}")
                self._observer = None

            if self._worker_thread:
                self._worker_thread.join(timeout=timeout)
                self._worker_thread = None

            logger.info(
                f"FilesystemMonitor stopped. Received: {self.events_received}, "
                f"Coalesced: {self.events_coalesced}, Dispatched: {self.events_dispatched}, "
                f"Dropped: {self._handler.dropped_events}"
            )

    def _process_queue_loop(self) -> None:
        """Worker thread loop to consume raw events, debounce, and dispatch."""
        while not self._stop_event.is_set() or not self._raw_queue.empty():
            try:
                item = self._raw_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            try:
                self._handle_raw_event(item)
            except Exception as e:
                logger.exception(f"Error handling raw filesystem event {item}: {e}")
            finally:
                self._raw_queue.task_done()

    def _handle_raw_event(self, item: Tuple[str, str, Optional[str], bool]) -> None:
        """Process, debounce, normalize, and dispatch a single raw event."""
        ev_type, src_path, dest_path, is_directory = item
        self.events_received += 1

        # Check safety boundary
        try:
            validate_lab_path(src_path, base_lab_dir=self.lab_dir)
            if dest_path:
                validate_lab_path(dest_path, base_lab_dir=self.lab_dir)
        except SafetyViolationError:
            self.events_dropped_outside += 1
            return

        # Normalize relative path
        rel_path = self.normalizer.normalize_path(src_path)
        if not rel_path:
            return

        # Coalescing / Debounce filter:
        # File writes and renames frequently trigger rapid duplicate events in OS filesystem
        now = time.perf_counter()
        debounce_key = (rel_path, ev_type)
        last_time = self._last_event_timestamps.get(debounce_key, 0.0)
        if (now - last_time) < self.debounce_seconds:
            self.events_coalesced += 1
            return
        self._last_event_timestamps[debounce_key] = now

        # Prune debounce cache if it grows excessively
        if len(self._last_event_timestamps) > 20000:
            cutoff = now - (self.debounce_seconds * 2)
            self._last_event_timestamps = {
                k: v for k, v in self._last_event_timestamps.items() if v > cutoff
            }

        # Normalize event
        norm_event = self.normalizer.create_filesystem_event(
            event_type=ev_type,
            raw_path=src_path,
            dest_raw_path=dest_path,
            is_directory=is_directory,
            source="WATCHDOG",
        )

        if norm_event and self.event_callback:
            self.events_dispatched += 1
            self.event_callback(norm_event)

    def get_status(self) -> Dict[str, Any]:
        """Return runtime health metrics for the filesystem monitor."""
        return {
            "is_running": self.is_running,
            "monitored_root": str(self.lab_dir),
            "queue_size": self._raw_queue.qsize(),
            "queue_capacity": self.queue_capacity,
            "events_received": self.events_received,
            "events_coalesced": self.events_coalesced,
            "events_dispatched": self.events_dispatched,
            "events_dropped_saturation": self._handler.dropped_events,
            "events_dropped_boundary": self.events_dropped_outside,
        }
