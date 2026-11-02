"""
Process Telemetry Monitor for CryptoShield.

Collects non-invasive system process telemetry via psutil. Observes process
lifecycle changes (creation and termination) with configurable polling intervals.
Safely handles inaccessible/terminated processes without terminating or altering
any host system processes.
"""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

import psutil

from app.config import CONFIG
from app.core.logger import get_logger
from app.core.models import MonitoringEvent, ProcessAttribution
from app.monitoring.event_normalizer import EventNormalizer

logger = get_logger("process_monitor")


class ProcessMonitor:
    """
    Lightweight, passive process monitor using psutil.
    Observes process creation and exit events at configurable polling intervals.
    """

    def __init__(
        self,
        event_callback: Optional[Callable[[MonitoringEvent], None]] = None,
        normalizer: Optional[EventNormalizer] = None,
        poll_interval_seconds: float = CONFIG.PROCESS_POLL_INTERVAL_SECONDS,
    ) -> None:
        self.event_callback = event_callback
        self.normalizer = normalizer or EventNormalizer()
        self.poll_interval_seconds = poll_interval_seconds

        self._known_processes: Dict[int, Dict[str, Any]] = {}
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        # Telemetry metrics
        self.polls_completed: int = 0
        self.processes_started_observed: int = 0
        self.processes_exited_observed: int = 0
        self.inaccessible_processes_count: int = 0

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Start passive process polling in a background thread."""
        with self._lock:
            if self.is_running:
                logger.warning("ProcessMonitor is already running.")
                return

            logger.info(
                f"Starting ProcessMonitor with {self.poll_interval_seconds}s polling interval..."
            )
            self._stop_event.clear()

            # Seed initial process table so we don't spam start events for existing OS processes
            self._seed_initial_processes()

            self._thread = threading.Thread(
                target=self._poll_loop,
                name="CryptoShield-ProcWorker",
                daemon=True,
            )
            self._thread.start()
            logger.info(
                f"ProcessMonitor started. Initial active processes indexed: {len(self._known_processes)}"
            )

    def stop(self, timeout: float = 3.0) -> None:
        """Gracefully stop process monitoring loop."""
        with self._lock:
            if not self.is_running:
                return

            logger.info("Stopping ProcessMonitor...")
            self._stop_event.set()
            if self._thread:
                self._thread.join(timeout=timeout)
                self._thread = None

            logger.info(
                f"ProcessMonitor stopped. Polls: {self.polls_completed}, "
                f"Starts: {self.processes_started_observed}, "
                f"Exits: {self.processes_exited_observed}"
            )

    def _seed_initial_processes(self) -> None:
        """Take an initial snapshot of running processes without emitting events."""
        current = {}
        for p in psutil.process_iter(["pid", "name", "exe", "create_time", "username"]):
            try:
                info = p.info
                pid = info.get("pid")
                if pid is not None:
                    current[pid] = self._extract_safe_process_info(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                self.inaccessible_processes_count += 1
            except Exception:
                pass
        self._known_processes = current

    def _extract_safe_process_info(self, info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract only safe, non-sensitive process metadata."""
        create_time_raw = info.get("create_time")
        create_time_iso = None
        if create_time_raw:
            try:
                create_time_iso = datetime.fromtimestamp(
                    create_time_raw, tz=timezone.utc
                ).isoformat()
            except Exception:
                pass

        return {
            "pid": info.get("pid"),
            "name": info.get("name") or "unknown",
            "exe": info.get("exe") or "unknown",
            "username": info.get("username") or "unknown",
            "create_time": create_time_iso,
        }

    def poll_once(self) -> Tuple[List[MonitoringEvent], List[MonitoringEvent]]:
        """
        Execute a single polling iteration.
        Returns (newly_started_events, exited_events).
        """
        current_pids: Dict[int, Dict[str, Any]] = {}

        for p in psutil.process_iter(["pid", "name", "exe", "create_time", "username"]):
            try:
                info = p.info
                pid = info.get("pid")
                if pid is not None:
                    current_pids[pid] = self._extract_safe_process_info(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                self.inaccessible_processes_count += 1
            except Exception:
                pass

        started_events: List[MonitoringEvent] = []
        exited_events: List[MonitoringEvent] = []

        # Detect new processes
        for pid, pinfo in current_pids.items():
            if pid not in self._known_processes:
                event = self.normalizer.create_process_event(
                    event_type="PROCESS_STARTED",
                    process_id=pid,
                    process_name=pinfo["name"],
                    exe_path=pinfo["exe"],
                    username=pinfo["username"],
                    create_time=pinfo["create_time"],
                )
                started_events.append(event)
                self.processes_started_observed += 1

        # Detect terminated processes
        for pid, pinfo in list(self._known_processes.items()):
            if pid not in current_pids:
                event = self.normalizer.create_process_event(
                    event_type="PROCESS_EXITED",
                    process_id=pid,
                    process_name=pinfo.get("name", "unknown"),
                    exe_path=pinfo.get("exe"),
                    username=pinfo.get("username"),
                    create_time=pinfo.get("create_time"),
                )
                exited_events.append(event)
                self.processes_exited_observed += 1

        self._known_processes = current_pids
        self.polls_completed += 1
        return started_events, exited_events

    def _poll_loop(self) -> None:
        """Periodic background polling loop."""
        while not self._stop_event.is_set():
            start_t = time.perf_counter()
            try:
                started, exited = self.poll_once()
                if self.event_callback:
                    for ev in started:
                        self.event_callback(ev)
                    for ev in exited:
                        self.event_callback(ev)
            except Exception as e:
                logger.exception(f"Unexpected error in ProcessMonitor polling loop: {e}")

            # Sleep remaining interval cleanly responding to stop_event
            elapsed = time.perf_counter() - start_t
            sleep_duration = max(0.05, self.poll_interval_seconds - elapsed)
            self._stop_event.wait(timeout=sleep_duration)

    def take_snapshot(self) -> List[Dict[str, Any]]:
        """Return instantaneous snapshot of all currently observed processes."""
        with self._lock:
            return list(self._known_processes.values())

    def get_status(self) -> Dict[str, Any]:
        """Return runtime health status and statistics."""
        return {
            "is_running": self.is_running,
            "tracked_processes": len(self._known_processes),
            "polls_completed": self.polls_completed,
            "processes_started": self.processes_started_observed,
            "processes_exited": self.processes_exited_observed,
            "inaccessible_processes": self.inaccessible_processes_count,
            "poll_interval_seconds": self.poll_interval_seconds,
        }
