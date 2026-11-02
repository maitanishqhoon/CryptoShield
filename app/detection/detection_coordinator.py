"""
Detection Coordinator for CryptoShield.

Orchestrates the entire Phase 3 threat detection and scoring pipeline:
- Ingests telemetry via EventCorrelator.
- Evaluates sliding window activity using BehaviorAnalyzer.
- Detects canary breaches via CanaryAnalyzer.
- Scores risks and compiles explainable assessments using ThreatScorer.
- Manages security incident lifecycles via IncidentManager.
- Tracks performance metrics and detection latencies.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from app.config import CONFIG
from app.core.event_bus import BUS, Event, EventBus
from app.core.logger import get_logger
from app.core.models import (
    DetectionResult,
    Manifest,
    MonitoringEvent,
    SecurityAlert,
    SecurityIncident,
)
from app.detection.behavior_analyzer import BehaviorAnalyzer
from app.detection.canary_analyzer import CanaryAnalyzer
from app.detection.event_correlator import EventCorrelator, WindowActivitySummary
from app.detection.incident_manager import IncidentManager
from app.detection.threat_scorer import ThreatScorer

logger = get_logger("detection_coordinator")


class DetectionCoordinator:
    """
    Central orchestration engine for CryptoShield Phase 3 Ransomware Detection.
    
    Provides thread-safe event consumption from EventBus, coordinates analytical
    subsystems, enforces alert cooldowns to mitigate false positive alert storms,
    and publishes structured detection results and security incidents.
    """

    _instance_lock = threading.Lock()
    _active_instance: Optional[DetectionCoordinator] = None

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        base_lab_dir: Optional[Path] = None,
        manifest: Optional[Manifest] = None,
        primary_window: float = CONFIG.DETECTION_PRIMARY_WINDOW,
        cooldown_seconds: float = CONFIG.DETECTION_COOLDOWN_SECONDS,
        incidents_dir: Optional[Path] = None,
    ) -> None:
        self.bus = event_bus or BUS
        self.lab_dir = (base_lab_dir or CONFIG.LAB_DIR).resolve()
        self.manifest = manifest
        self.primary_window = primary_window
        self.cooldown_seconds = cooldown_seconds

        # Subsystems
        self.correlator = EventCorrelator(
            event_bus=self.bus,
            primary_window=self.primary_window,
        )
        self.behavior_analyzer = BehaviorAnalyzer()
        self.canary_analyzer = CanaryAnalyzer(
            manifest=self.manifest,
            event_bus=self.bus,
            base_lab_dir=self.lab_dir,
        )
        self.threat_scorer = ThreatScorer()
        self.incident_manager = IncidentManager(
            event_bus=self.bus,
            incidents_dir=incidents_dir,
        )

        # Operational metrics and state
        self.is_running: bool = False
        self.start_time: Optional[float] = None
        self.stop_time: Optional[float] = None
        self.events_received: int = 0
        self.detections_performed: int = 0
        self.total_latency_ms: float = 0.0
        self.max_latency_ms: float = 0.0
        self.alerts_generated_count: int = 0

        # Recent detections bounded buffer
        self.recent_detections: List[DetectionResult] = []
        self._max_recent_detections: int = 100

        # Cooldown state
        self._last_alert_time: float = 0.0
        self._last_score: int = -1
        self._last_reasons_signature: str = ""

        # Custom detection listeners
        self._listeners: List[Callable[[DetectionResult], None]] = []
        self._lock = threading.RLock()
        self._subscribed = False

    def add_listener(self, listener: Callable[[DetectionResult], None]) -> None:
        """Register a callback for all DetectionResult outputs."""
        with self._lock:
            if listener not in self._listeners:
                self._listeners.append(listener)

    def remove_listener(self, listener: Callable[[DetectionResult], None]) -> None:
        """Unregister a detection callback listener."""
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)

    def start(self) -> None:
        """Start the detection pipeline and subscribe to telemetry events."""
        with self._instance_lock:
            with self._lock:
                if self.is_running:
                    logger.warning("DetectionCoordinator is already running.")
                    return

                logger.info(f"Starting DetectionCoordinator for lab '{self.lab_dir}'...")
                self.start_time = time.time()
                self.is_running = True

                # Subscribe to EventBus
                if not self._subscribed:
                    self.bus.subscribe("*", self._on_bus_event)
                    self._subscribed = True

                DetectionCoordinator._active_instance = self
                logger.info("DetectionCoordinator started successfully.")

    def stop(self) -> None:
        """Gracefully stop the detection pipeline."""
        with self._instance_lock:
            with self._lock:
                if not self.is_running:
                    return

                logger.info("Stopping DetectionCoordinator...")
                self.is_running = False
                self.stop_time = time.time()

                if self._subscribed:
                    self.bus.unsubscribe("*", self._on_bus_event)
                    self._subscribed = False

                if DetectionCoordinator._active_instance is self:
                    DetectionCoordinator._active_instance = None

                logger.info(
                    f"DetectionCoordinator stopped. Detections: {self.detections_performed}, "
                    f"Incidents created: {self.incident_manager.incidents_created_count}"
                )

    def _on_bus_event(self, event: Event) -> None:
        """EventBus consumer for telemetry and canary events."""
        if not self.is_running:
            return

        # Filter out self-generated detection/incident events to avoid recursion
        if event.event_type in {
            "DETECTION_RESULT",
            "SECURITY_INCIDENT_CREATED",
            "SECURITY_INCIDENT_UPDATED",
            "SECURITY_INCIDENT_RESOLVED",
            "CANARY_SECURITY_ALERT",
        }:
            return

        if not isinstance(event.data, dict) or "event_id" not in event.data:
            return

        try:
            mon_event = MonitoringEvent.from_dict(event.data)
            self.process_event(mon_event)
        except Exception as e:
            logger.debug(f"DetectionCoordinator could not process event: {e}")

    def process_event(self, event: MonitoringEvent) -> Optional[DetectionResult]:
        """
        Ingest a single MonitoringEvent and trigger sliding-window evaluation.
        
        Measures processing latency, calculates threat scores, manages cooldown,
        and creates/updates security incidents when warranted.
        """
        start_t = time.perf_counter()

        with self._lock:
            self.events_received += 1

            # Ingest into correlator
            accepted = self.correlator.add_event(event)
            if not accepted:
                return None

            # Evaluate the current primary sliding window
            detection = self.evaluate_current_window()

            # Record latency metric
            latency_ms = (time.perf_counter() - start_t) * 1000.0
            self.detections_performed += 1
            self.total_latency_ms += latency_ms
            if latency_ms > self.max_latency_ms:
                self.max_latency_ms = latency_ms

            return detection

    def evaluate_current_window(
        self,
        window_seconds: Optional[float] = None,
        reference_time: Optional[float] = None,
    ) -> DetectionResult:
        """
        Perform a point-in-time evaluation across the current sliding window.
        """
        win_sec = window_seconds or self.primary_window
        now_epoch = (
            reference_time
            if reference_time is not None
            else (self.correlator._latest_event_time or time.time())
        )

        with self._lock:
            # 1. Correlate window activity
            summary = self.correlator.get_window_summary(
                window_seconds=win_sec,
                reference_time=now_epoch,
            )

            # 2. Analyze filesystem behavior
            behavior_eval = self.behavior_analyzer.evaluate(summary)

            # 3. Analyze canary decoy telemetry
            canary_eval = self.canary_analyzer.evaluate_events(summary.canary_events)
            self.alerts_generated_count += len(canary_eval.alerts_generated)

            # 4. Score threat and formulate explainable assessment
            detection = self.threat_scorer.calculate_score(
                behavior_eval=behavior_eval,
                canary_eval=canary_eval,
                window_seconds=win_sec,
                affected_files=sorted(summary.unique_files),
            )

            # 5. Check Cooldown / Suppression
            reasons_sig = "|".join(sorted(detection.reasons))
            is_same_as_last = (
                detection.threat_score == self._last_score
                and reasons_sig == self._last_reasons_signature
            )
            time_since_last = now_epoch - self._last_alert_time

            # Only suppress if score is not escalating, same reasons, within cooldown,
            # and no fresh canary breach was tripped in this exact evaluation
            if (
                is_same_as_last
                and time_since_last < self.cooldown_seconds
                and not canary_eval.alerts_generated
            ):
                return detection

            self._last_alert_time = now_epoch
            self._last_score = detection.threat_score
            self._last_reasons_signature = reasons_sig

            # 6. Incident Management
            if detection.threat_score >= self.incident_manager.auto_create_threshold or canary_eval.is_canary_tripped:
                # Gather actual events in window for incident audit trail
                raw_events = [ev for _, ev in self.correlator._events_buffer if ev.event_id in summary.event_ids]
                incident = self.incident_manager.process_detection(detection, source_events=raw_events)
                if incident:
                    detection.incident_id = incident.incident_id

            # 7. Record in recent detections buffer
            self.recent_detections.append(detection)
            if len(self.recent_detections) > self._max_recent_detections:
                self.recent_detections.pop(0)

            # 8. Publish detection result to EventBus
            try:
                self.bus.publish(
                    Event(
                        event_type="DETECTION_RESULT",
                        data=detection.to_dict(),
                        source="DETECTION_COORDINATOR",
                    )
                )
            except Exception as e:
                logger.exception(f"Failed to publish DETECTION_RESULT: {e}")

            # 9. Notify registered custom listeners
            for listener in list(self._listeners):
                try:
                    listener(detection)
                except Exception as e:
                    logger.exception(f"Error in detection listener: {e}")

            return detection

    def get_metrics(self) -> Dict[str, Any]:
        """Return comprehensive performance and latency metrics."""
        with self._lock:
            avg_latency = (
                round(self.total_latency_ms / self.detections_performed, 3)
                if self.detections_performed > 0
                else 0.0
            )
            uptime = (
                round((self.stop_time or time.time()) - self.start_time, 2)
                if self.start_time
                else 0.0
            )

            return {
                "is_running": self.is_running,
                "uptime_seconds": uptime,
                "events_received": self.events_received,
                "events_processed": self.correlator.events_processed,
                "duplicate_events_ignored": self.correlator.duplicate_events_ignored,
                "late_events_handled": self.correlator.late_events_handled,
                "detections_performed": self.detections_performed,
                "average_detection_latency_ms": avg_latency,
                "max_detection_latency_ms": round(self.max_latency_ms, 3),
                "alerts_generated_count": self.alerts_generated_count,
                "incidents_created_count": self.incident_manager.incidents_created_count,
                "incidents_updated_count": self.incident_manager.incidents_updated_count,
                "incidents_resolved_count": self.incident_manager.incidents_resolved_count,
            }

    def clear(self) -> None:
        """Reset internal buffers and child subsystem states."""
        with self._lock:
            self.correlator.clear()
            self.canary_analyzer.clear()
            self.incident_manager.clear()
            self.recent_detections.clear()
            self.events_received = 0
            self.detections_performed = 0
            self.total_latency_ms = 0.0
            self.max_latency_ms = 0.0
            self.alerts_generated_count = 0
            self._last_alert_time = 0.0
            self._last_score = -1
            self._last_reasons_signature = ""
