"""
Read Burst Detector for Data Exfiltration Monitoring (Phase 7).

Subscribes to telemetry from EventBus (FILE_READ, FILE_OPEN, CANARY_ACCESS) and detects
high-velocity read bursts across sensitive departments, classifying risk and identifying
unauthorized bulk data collection patterns.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import logging
import threading
import time
from typing import Any, Callable, Deque, Dict, List, Optional
import uuid

from app.config import CONFIG
from app.core.event_bus import BUS, Event, EventBus
from app.core.models import MonitoringEvent
from app.exfiltration.models import ReadBurstEvent

logger = logging.getLogger("cryptoshield.exfiltration.read_detector")


class ReadBurstDetector:
    """
    Sliding-window detector that identifies abnormal clusters of file read operations,
    tracking department diversity, sensitivity tiers, and honeypot canary interactions.
    """

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        burst_threshold: int = CONFIG.EXFILTRATION_READ_BURST_THRESHOLD,
        window_seconds: float = CONFIG.EXFILTRATION_READ_WINDOW_SECONDS,
        burst_callback: Optional[Callable[[ReadBurstEvent], None]] = None,
    ) -> None:
        self.bus = event_bus or BUS
        self.burst_threshold = burst_threshold
        self.window_seconds = window_seconds
        self.burst_callback = burst_callback

        self._window: Deque[Dict[str, Any]] = deque()
        self._lock = threading.Lock()
        self._is_active = False

        self._detected_bursts: List[ReadBurstEvent] = []
        self._canary_reads: List[str] = []
        self._total_reads_processed: int = 0

    def start(self) -> None:
        """Subscribes the detector to file read and canary access events."""
        with self._lock:
            if self._is_active:
                return
            self._is_active = True
            self.bus.subscribe("FILE_READ", self._handle_bus_event)
            self.bus.subscribe("FILE_OPEN", self._handle_bus_event)
            self.bus.subscribe("FILE_ACCESS", self._handle_bus_event)
            self.bus.subscribe("CANARY_ACCESS", self._handle_bus_event)
            logger.info("ReadBurstDetector active (Threshold=%d, Window=%.1fs)", self.burst_threshold, self.window_seconds)

    def stop(self) -> None:
        """Unsubscribes from the EventBus."""
        with self._lock:
            if not self._is_active:
                return
            self._is_active = False
            self.bus.unsubscribe("FILE_READ", self._handle_bus_event)
            self.bus.unsubscribe("FILE_OPEN", self._handle_bus_event)
            self.bus.unsubscribe("FILE_ACCESS", self._handle_bus_event)
            self.bus.unsubscribe("CANARY_ACCESS", self._handle_bus_event)
            logger.info("ReadBurstDetector stopped.")

    def ingest_event(self, event_data: Dict[str, Any]) -> Optional[ReadBurstEvent]:
        """
        Directly ingests a file read or canary access event and evaluates the sliding window.
        Returns a ReadBurstEvent if the event triggers or expands a burst.
        """
        with self._lock:
            self._total_reads_processed += 1
            now = time.time()
            rel_path = event_data.get("relative_path") or event_data.get("file_path", "")
            is_canary = bool(event_data.get("is_canary", False))
            classification = (
                event_data.get("metadata", {}).get("classification")
                or event_data.get("data_classification")
                or "INTERNAL"
            )
            department = (
                event_data.get("metadata", {}).get("department")
                or event_data.get("department")
                or "Unknown"
            )
            pid = event_data.get("process_id")
            pname = event_data.get("process_name")
            attribution = event_data.get("process_attribution", "UNKNOWN")

            if is_canary and rel_path and rel_path not in self._canary_reads:
                self._canary_reads.append(rel_path)

            self._window.append({
                "time": now,
                "relative_path": rel_path,
                "is_canary": is_canary,
                "classification": classification,
                "department": department,
                "process_id": pid,
                "process_name": pname,
                "attribution": attribution,
            })

            # Purge expired window entries
            cutoff = now - self.window_seconds
            while self._window and self._window[0]["time"] < cutoff:
                self._window.popleft()

            # Check threshold
            if len(self._window) >= self.burst_threshold:
                burst = self._create_burst_record(now)
                self._detected_bursts.append(burst)
                self._publish_burst(burst)
                return burst

            return None

    def get_recent_bursts(self) -> List[ReadBurstEvent]:
        """Returns all detected read bursts."""
        with self._lock:
            return list(self._detected_bursts)

    def get_canary_reads(self) -> List[str]:
        """Returns relative paths of all canary honeypots read."""
        with self._lock:
            return list(self._canary_reads)

    def reset(self) -> None:
        """Resets the sliding window and detection records."""
        with self._lock:
            self._window.clear()
            self._detected_bursts.clear()
            self._canary_reads.clear()
            self._total_reads_processed = 0

    def _handle_bus_event(self, event: Event) -> None:
        """Handler for events delivered via EventBus."""
        self.ingest_event(event.data)

    def _create_burst_record(self, now: float) -> ReadBurstEvent:
        """Constructs a ReadBurstEvent from current sliding window items."""
        dept_counts: Dict[str, int] = {}
        class_counts: Dict[str, int] = {}
        canary_paths: List[str] = []
        pids: Dict[int, int] = {}
        pnames: Dict[str, int] = {}
        attributions: Dict[str, int] = {}

        for item in self._window:
            dept = item["department"]
            dept_counts[dept] = dept_counts.get(dept, 0) + 1

            cls_name = item["classification"]
            class_counts[cls_name] = class_counts.get(cls_name, 0) + 1

            if item["is_canary"]:
                cp = item["relative_path"]
                if cp and cp not in canary_paths:
                    canary_paths.append(cp)

            if item["process_id"] is not None:
                pids[item["process_id"]] = pids.get(item["process_id"], 0) + 1
            if item["process_name"]:
                pnames[item["process_name"]] = pnames.get(item["process_name"], 0) + 1
            attr = item["attribution"]
            attributions[attr] = attributions.get(attr, 0) + 1

        primary_pid = max(pids, key=pids.get) if pids else None
        primary_pname = max(pnames, key=pnames.get) if pnames else None
        primary_attr = max(attributions, key=attributions.get) if attributions else "UNKNOWN"

        oldest_time = self._window[0]["time"]
        duration = max(0.01, round(now - oldest_time, 3))

        return ReadBurstEvent(
            burst_id=f"BURST-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.now(CONFIG.TIMEZONE).isoformat(),
            read_count=len(self._window),
            duration_seconds=duration,
            department_counts=dept_counts,
            classification_counts=class_counts,
            canary_reads_count=len(canary_paths),
            canary_paths=canary_paths,
            process_id=primary_pid,
            process_name=primary_pname,
            process_attribution=primary_attr,
        )

    def _publish_burst(self, burst: ReadBurstEvent) -> None:
        """Dispatches burst detection to the EventBus and optional callback."""
        bus_event = Event(
            event_type="EXFILTRATION_READ_BURST_DETECTED",
            data=burst.to_dict(),
            source="read_burst_detector",
        )
        self.bus.publish(bus_event)

        if burst.canary_reads_count > 0:
            canary_event = Event(
                event_type="CANARY_READ_BREACH",
                data={
                    "burst_id": burst.burst_id,
                    "canary_count": burst.canary_reads_count,
                    "canary_paths": burst.canary_paths,
                    "process_id": burst.process_id,
                },
                source="read_burst_detector",
            )
            self.bus.publish(canary_event)

        if self.burst_callback:
            try:
                self.burst_callback(burst)
            except Exception as e:
                logger.error("Error in burst callback: %s", e)
