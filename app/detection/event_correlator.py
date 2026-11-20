"""
Event Correlation Engine for CryptoShield.

Collects, deduplicates, and temporally aggregates normalized MonitoringEvents
over configurable sliding time windows. Produces structured WindowActivitySummary
records for behavioural and threat analysis without scanning or hashing laboratory files.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from app.config import CONFIG
from app.core.event_bus import BUS, Event, EventBus
from app.core.logger import get_logger
from app.core.models import (
    FileAction,
    MonitoringEvent,
    ProcessAttribution,
)

logger = get_logger("event_correlator")


@dataclass
class WindowActivitySummary:
    """
    Structured temporal summary of filesystem and process activity
    observed across a specific sliding window duration.
    """
    window_seconds: float
    start_time: str
    end_time: str
    total_events: int
    unique_files: Set[str] = field(default_factory=set)
    unique_created_files: Set[str] = field(default_factory=set)
    unique_modified_files: Set[str] = field(default_factory=set)
    unique_deleted_files: Set[str] = field(default_factory=set)
    unique_renamed_files: Set[str] = field(default_factory=set)
    unique_accessed_files: Set[str] = field(default_factory=set)
    departments_affected: Set[str] = field(default_factory=set)
    file_types_affected: Set[str] = field(default_factory=set)
    processes_involved: Dict[int, str] = field(default_factory=dict)
    canary_events: List[MonitoringEvent] = field(default_factory=list)
    event_ids: Set[str] = field(default_factory=set)
    is_legitimate_source: bool = False
    process_attribution: str = ProcessAttribution.UNKNOWN.value
    attributed_process_id: Optional[int] = None
    attributed_process_name: Optional[str] = None
    operation_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "window_seconds": self.window_seconds,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_events": self.total_events,
            "unique_files_count": len(self.unique_files),
            "unique_modified_count": len(self.unique_modified_files),
            "unique_renamed_count": len(self.unique_renamed_files),
            "unique_deleted_count": len(self.unique_deleted_files),
            "unique_created_count": len(self.unique_created_files),
            "unique_accessed_count": len(self.unique_accessed_files),
            "departments_affected": sorted(self.departments_affected),
            "file_types_affected": sorted(self.file_types_affected),
            "processes_involved": self.processes_involved,
            "canary_events_count": len(self.canary_events),
            "is_legitimate_source": self.is_legitimate_source,
            "process_attribution": self.process_attribution,
            "attributed_process_id": self.attributed_process_id,
            "attributed_process_name": self.attributed_process_name,
            "operation_counts": self.operation_counts,
        }


class EventCorrelator:
    """
    Temporal event correlation and aggregation engine.
    
    Subscribes to EventBus telemetry events, deduplicates duplicate event IDs,
    maintains bounded sliding window buffers, and produces structured summaries
    of activity bursts without disk scanning.
    """

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        sliding_windows: Optional[List[float]] = None,
        primary_window: float = CONFIG.DETECTION_PRIMARY_WINDOW,
        dedup_cache_size: int = CONFIG.DEDUPLICATION_CACHE_MAX_SIZE,
        dedup_ttl_seconds: float = CONFIG.DEDUPLICATION_CACHE_TTL_SECONDS,
        verified_legitimate_sources: Optional[Set[str]] = None,
    ) -> None:
        self.bus = event_bus or BUS
        self.sliding_windows = sorted(sliding_windows or CONFIG.DETECTION_SLIDING_WINDOWS)
        self.primary_window = primary_window
        self.max_window = max(self.sliding_windows) if self.sliding_windows else 30.0
        self.dedup_cache_size = dedup_cache_size
        self.dedup_ttl_seconds = dedup_ttl_seconds
        self.verified_legitimate_sources = (
            set(verified_legitimate_sources)
            if verified_legitimate_sources is not None
            else set(CONFIG.VERIFIED_LEGITIMATE_SOURCES)
        )

        # Internal event buffer: list of (timestamp_epoch, MonitoringEvent)
        self._events_buffer: deque[Tuple[float, MonitoringEvent]] = deque()
        self._seen_event_ids: Dict[str, float] = {}  # event_id -> arrival_epoch
        self._latest_event_time: Optional[float] = None
        self._lock = threading.RLock()

        # Operational metrics
        self.events_received: int = 0
        self.events_processed: int = 0
        self.duplicate_events_ignored: int = 0
        self.late_events_handled: int = 0

        # Known enterprise departments for fallback taxonomy extraction
        self._known_departments: Set[str] = set(CONFIG.DEPARTMENTS)

        self._subscribed: bool = False

    def start(self) -> None:
        """Subscribe to EventBus events."""
        with self._lock:
            if not self._subscribed:
                self.bus.subscribe("*", self._on_bus_event)
                self._subscribed = True
                logger.info(
                    f"EventCorrelator subscribed to EventBus (windows: {self.sliding_windows}s, "
                    f"primary: {self.primary_window}s)."
                )

    def stop(self) -> None:
        """Unsubscribe from EventBus."""
        with self._lock:
            if self._subscribed:
                self.bus.unsubscribe("*", self._on_bus_event)
                self._subscribed = False
                logger.info("EventCorrelator stopped and unsubscribed.")

    def _parse_timestamp(self, ts_str: str) -> float:
        """Parse ISO-8601 timestamp to epoch float."""
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=CONFIG.TIMEZONE)
            return dt.timestamp()
        except Exception:
            return time.time()

    def _on_bus_event(self, event: Event) -> None:
        """EventBus callback handler for incoming telemetry."""
        # Check if event has MonitoringEvent payload in data
        if not isinstance(event.data, dict) or "event_id" not in event.data:
            return

        try:
            mon_event = MonitoringEvent.from_dict(event.data)
            self.add_event(mon_event)
        except Exception as e:
            logger.debug(f"EventCorrelator could not parse event {event.event_type}: {e}")

    def add_event(self, event: MonitoringEvent) -> bool:
        """
        Ingest a normalized MonitoringEvent into the sliding window buffer.
        
        Performs deduplication and safe pruning of expired window records.
        Returns True if event was accepted, False if rejected as duplicate or expired.
        """
        now = time.time()
        with self._lock:
            self.events_received += 1

            # Deduplication check
            if event.event_id in self._seen_event_ids:
                self.duplicate_events_ignored += 1
                logger.debug(f"EventCorrelator ignored duplicate event ID: {event.event_id}")
                return False

            event_time = self._parse_timestamp(event.timestamp)

            if self._latest_event_time is None or event_time > self._latest_event_time:
                self._latest_event_time = event_time

            # Drop events that are substantially older than max window relative to latest seen event
            cutoff = self._latest_event_time - (self.max_window * 2.0)
            if event_time < cutoff:
                self.late_events_handled += 1
                logger.debug(
                    f"EventCorrelator dropped delayed event {event.event_id} "
                    f"({self._latest_event_time - event_time:.2f}s behind latest event time)."
                )
                return False

            # Record in deduplication cache
            self._seen_event_ids[event.event_id] = now

            # Insert into buffer maintaining approximate order
            if not self._events_buffer or event_time >= self._events_buffer[-1][0]:
                self._events_buffer.append((event_time, event))
            else:
                # Handle mildly out-of-order event
                self.late_events_handled += 1
                inserted = False
                for idx in range(len(self._events_buffer) - 1, -1, -1):
                    if self._events_buffer[idx][0] <= event_time:
                        self._events_buffer.insert(idx + 1, (event_time, event))
                        inserted = True
                        break
                if not inserted:
                    self._events_buffer.appendleft((event_time, event))

            self.events_processed += 1

            # Prune old events and dedup cache periodically
            self._prune_expired(now)
            return True

    def _prune_expired(self, current_time: float) -> None:
        """Prune events older than max_window and expired dedup cache entries."""
        ref_time = self._latest_event_time if self._latest_event_time is not None else current_time
        cutoff = ref_time - (self.max_window * 1.5)
        while self._events_buffer and self._events_buffer[0][0] < cutoff:
            self._events_buffer.popleft()

        # Prune deduplication cache if exceeding capacity
        if len(self._seen_event_ids) > self.dedup_cache_size:
            ttl_cutoff = current_time - self.dedup_ttl_seconds
            expired_keys = [
                eid for eid, seen_t in self._seen_event_ids.items() if seen_t < ttl_cutoff
            ]
            for eid in expired_keys:
                del self._seen_event_ids[eid]

            # If still oversized, drop oldest 10%
            if len(self._seen_event_ids) > self.dedup_cache_size:
                sorted_keys = sorted(self._seen_event_ids.items(), key=lambda x: x[1])
                for eid, _ in sorted_keys[: len(sorted_keys) // 10]:
                    del self._seen_event_ids[eid]

    def clear(self) -> None:
        """Clear all buffered events and deduplication records."""
        with self._lock:
            self._events_buffer.clear()
            self._seen_event_ids.clear()
            self._latest_event_time = None
            self.events_received = 0
            self.events_processed = 0
            self.duplicate_events_ignored = 0
            self.late_events_handled = 0

    def get_window_summary(
        self,
        window_seconds: Optional[float] = None,
        reference_time: Optional[float] = None,
    ) -> WindowActivitySummary:
        """
        Aggregate activity observed within the sliding window prior to reference_time.
        
        Counts unique affected file paths, categorizes operations, tracks affected
        departments and file extensions, extracts canary trips, and resolves process attribution.
        """
        win_sec = window_seconds if window_seconds is not None else self.primary_window
        ref_time = (
            reference_time
            if reference_time is not None
            else (self._latest_event_time if self._latest_event_time is not None else time.time())
        )
        start_time_epoch = ref_time - win_sec

        start_iso = datetime.fromtimestamp(start_time_epoch, tz=CONFIG.TIMEZONE).isoformat()
        end_iso = datetime.fromtimestamp(ref_time, tz=CONFIG.TIMEZONE).isoformat()

        summary = WindowActivitySummary(
            window_seconds=win_sec,
            start_time=start_iso,
            end_time=end_iso,
            total_events=0,
        )

        with self._lock:
            # Filter events falling within [start_time_epoch, ref_time]
            events_in_window: List[MonitoringEvent] = [
                ev for t, ev in self._events_buffer if start_time_epoch <= t <= ref_time
            ]

        if not events_in_window:
            return summary

        summary.total_events = len(events_in_window)

        confirmed_processes: Dict[int, str] = {}
        inferred_processes: Dict[int, str] = {}
        has_legitimate_source = False

        for ev in events_in_window:
            summary.event_ids.add(ev.event_id)

            # Check for explicitly configured legitimate source classification
            # Do not trust arbitrary process names or unverified telemetry labels.
            # Attribution remains UNKNOWN unless explicitly established.
            test_cls = ev.metadata.get("verified_test_classification")
            if (ev.source in self.verified_legitimate_sources) or (test_cls and test_cls in self.verified_legitimate_sources):
                has_legitimate_source = True

            # Relative path aggregation
            rel_path = ev.relative_path
            if rel_path:
                summary.unique_files.add(rel_path)

                # Department identification
                dept = ev.metadata.get("department")
                if not dept:
                    # Infer department from first folder component
                    first_part = rel_path.split("/")[0] if "/" in rel_path else ""
                    if first_part in self._known_departments:
                        dept = first_part
                if dept:
                    summary.departments_affected.add(dept)

                # File extension identification
                if "." in rel_path:
                    ext = rel_path.rsplit(".", 1)[-1].lower()
                    if ext:
                        summary.file_types_affected.add(ext)

            # Check destination path for rename events
            dest_path = ev.metadata.get("dest_relative_path")
            if dest_path:
                summary.unique_files.add(dest_path)
                if "." in dest_path:
                    ext = dest_path.rsplit(".", 1)[-1].lower()
                    if ext:
                        summary.file_types_affected.add(ext)

            # Operation categorization
            op = ev.operation.upper()
            summary.operation_counts[op] = summary.operation_counts.get(op, 0) + 1

            if ev.event_type == "FILE_CREATED" or op == FileAction.CREATE.value:
                if rel_path:
                    summary.unique_created_files.add(rel_path)
            elif ev.event_type == "FILE_MODIFIED" or op == FileAction.MODIFY.value:
                if rel_path:
                    summary.unique_modified_files.add(rel_path)
            elif ev.event_type == "FILE_DELETED" or op == FileAction.DELETE.value:
                if rel_path:
                    summary.unique_deleted_files.add(rel_path)
            elif ev.event_type == "FILE_MOVED" or op == FileAction.RENAME.value:
                if rel_path:
                    summary.unique_renamed_files.add(rel_path)
            elif op == FileAction.ACCESS.value:
                if rel_path:
                    summary.unique_accessed_files.add(rel_path)

            # Canary events
            if ev.is_canary or ev.event_type == "CANARY_ACCESS":
                summary.canary_events.append(ev)

            # Process attribution tracking
            if ev.process_id is not None:
                p_name = ev.process_name or f"PID_{ev.process_id}"
                if ev.process_attribution == ProcessAttribution.CONFIRMED.value:
                    confirmed_processes[ev.process_id] = p_name
                elif ev.process_attribution == ProcessAttribution.INFERRED.value:
                    inferred_processes[ev.process_id] = p_name

        summary.is_legitimate_source = has_legitimate_source

        # Resolve overall process attribution for this window
        if confirmed_processes:
            summary.processes_involved = confirmed_processes
            summary.process_attribution = ProcessAttribution.CONFIRMED.value
            # Select most frequently appearing process or first
            p_id, p_name = next(iter(confirmed_processes.items()))
            summary.attributed_process_id = p_id
            summary.attributed_process_name = p_name
        elif inferred_processes:
            summary.processes_involved = inferred_processes
            summary.process_attribution = ProcessAttribution.INFERRED.value
            p_id, p_name = next(iter(inferred_processes.items()))
            summary.attributed_process_id = p_id
            summary.attributed_process_name = p_name
        else:
            summary.process_attribution = ProcessAttribution.UNKNOWN.value
            summary.attributed_process_id = None
            summary.attributed_process_name = None

        return summary
