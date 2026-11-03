"""
Containment Coordinator for CryptoShield (Phase 4).

Central orchestrator linking Phase 3 threat detection with Phase 4 containment:
- Subscribes to DETECTION_RESULT, CANARY_SECURITY_ALERT, and incident events on EventBus.
- Evaluates ContainmentPolicy in a non-blocking, thread-safe manner.
- Resolves explicit registered simulation run association.
- Directs ContainmentManager to execute and verify process containment.
- Emits structured containment lifecycle events and tracks containment metrics.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.containment.containment_manager import CONTAINMENT_MGR, ContainmentManager
from app.containment.containment_policy import ContainmentPolicy
from app.containment.process_registry import REGISTRY, ControlledProcessRegistry
from app.core.event_bus import BUS, Event, EventBus
from app.core.logger import get_logger
from app.core.models import (
    ContainmentAction,
    ContainmentDecision,
    DetectionResult,
    SecurityAlert,
)

logger = get_logger("containment_coordinator")


class ContainmentCoordinator:
    """
    Coordinator orchestrating containment evaluation and execution across CryptoShield.
    """

    _instance_lock = threading.Lock()
    _active_instance: Optional[ContainmentCoordinator] = None

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        policy: Optional[ContainmentPolicy] = None,
        manager: Optional[ContainmentManager] = None,
        registry: Optional[ControlledProcessRegistry] = None,
    ) -> None:
        self.bus = event_bus or BUS
        self.policy = policy or ContainmentPolicy()
        self.manager = manager or CONTAINMENT_MGR
        self.registry = registry or REGISTRY

        self.is_running: bool = False
        self.start_time: Optional[float] = None
        self.stop_time: Optional[float] = None
        self._subscribed: bool = False
        self._lock = threading.RLock()

        # Operational metrics
        self.events_evaluated: int = 0
        self.decisions_made: int = 0
        self.containments_triggered: int = 0
        self.recommendations_made: int = 0
        self.total_containment_latency_ms: float = 0.0

        self.recent_decisions: List[ContainmentDecision] = []
        self._listeners: List[Callable[[ContainmentDecision], None]] = []

    def add_listener(self, listener: Callable[[ContainmentDecision], None]) -> None:
        """Register a callback for all ContainmentDecision outputs."""
        with self._lock:
            if listener not in self._listeners:
                self._listeners.append(listener)

    def remove_listener(self, listener: Callable[[ContainmentDecision], None]) -> None:
        """Unregister a listener."""
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)

    def start(self) -> None:
        """Start the containment coordinator and subscribe to EventBus events."""
        with self._instance_lock:
            with self._lock:
                if self.is_running:
                    logger.warning("ContainmentCoordinator is already running.")
                    return

                logger.info("Starting ContainmentCoordinator...")
                self.start_time = time.time()
                self.is_running = True

                if not self._subscribed:
                    self.bus.subscribe("DETECTION_RESULT", self._on_detection_result)
                    self.bus.subscribe("CANARY_SECURITY_ALERT", self._on_canary_alert)
                    self._subscribed = True

                ContainmentCoordinator._active_instance = self
                logger.info("ContainmentCoordinator started successfully.")

    def stop(self) -> None:
        """Gracefully stop the containment coordinator."""
        with self._instance_lock:
            with self._lock:
                if not self.is_running:
                    return

                logger.info("Stopping ContainmentCoordinator...")
                self.is_running = False
                self.stop_time = time.time()

                if self._subscribed:
                    self.bus.unsubscribe("DETECTION_RESULT", self._on_detection_result)
                    self.bus.unsubscribe("CANARY_SECURITY_ALERT", self._on_canary_alert)
                    self._subscribed = False

                if ContainmentCoordinator._active_instance is self:
                    ContainmentCoordinator._active_instance = None

                logger.info("ContainmentCoordinator stopped.")

    def _resolve_simulation_run_id(
        self, data: Dict[str, Any], process_id: Optional[int] = None
    ) -> Tuple[Optional[str], bool]:
        """
        Determine if the event is associated with an active registered simulation run.
        Checks direct metadata, nested metadata, and PID mappings.
        """
        # 1. Direct simulation_run_id in data
        if "simulation_run_id" in data:
            run_id = data["simulation_run_id"]
            if self.registry.is_run_registered(run_id):
                return run_id, True

        # 2. Nested simulation_run_id in data["metadata"]
        meta = data.get("metadata", {})
        if isinstance(meta, dict) and "simulation_run_id" in meta:
            run_id = meta["simulation_run_id"]
            if self.registry.is_run_registered(run_id):
                return run_id, True

        # 3. Check process_id against registry
        pid = process_id or data.get("process_id")
        if pid:
            rec = self.registry.get_record_by_pid(pid)
            if rec:
                return rec.simulation_run_id, True

        # 4. If there is exactly one active registered simulation run currently running in lab
        active_records = [
            r for r in self.registry.list_records()
            if self.registry.is_run_active(r.simulation_run_id)
        ]
        if len(active_records) == 1:
            # Associate if event touched demo target or was during run
            return active_records[0].simulation_run_id, True

        return None, False

    def _on_detection_result(self, event: Event) -> None:
        """Handle incoming DETECTION_RESULT events from Phase 3."""
        if not self.is_running:
            return

        try:
            detection = DetectionResult.from_dict(event.data)
            self.handle_detection(detection)
        except Exception as e:
            logger.debug(f"ContainmentCoordinator could not process detection: {e}")

    def _on_canary_alert(self, event: Event) -> None:
        """Handle incoming CANARY_SECURITY_ALERT events from Phase 3."""
        if not self.is_running:
            return

        try:
            alert = SecurityAlert.from_dict(event.data)
            self.handle_alert(alert)
        except Exception as e:
            logger.debug(f"ContainmentCoordinator could not process canary alert: {e}")

    def handle_detection(self, detection: DetectionResult) -> ContainmentDecision:
        """
        Evaluate DetectionResult against ContainmentPolicy and execute containment if authorized.
        """
        start_t = time.perf_counter()

        with self._lock:
            self.events_evaluated += 1

            # Resolve associated simulation run
            run_id, is_registered = self._resolve_simulation_run_id(
                detection.metadata, detection.process_id
            )

            # Evaluate policy
            decision = self.policy.evaluate_detection(
                detection=detection,
                simulation_run_id=run_id,
                is_run_registered=is_registered,
            )
            self.decisions_made += 1
            self.recent_decisions.append(decision)
            if len(self.recent_decisions) > 100:
                self.recent_decisions.pop(0)

            # Route action
            if decision.auto_containment_authorized:
                self.containments_triggered += 1
                logger.warning(
                    f"[CONTAINMENT TRIGGERED] Initiating containment for simulation run '{run_id}'."
                )
                self.manager.execute_containment(decision)
                latency_ms = (time.perf_counter() - start_t) * 1000.0
                self.total_containment_latency_ms += latency_ms
            elif decision.recommended_action == ContainmentAction.CONTAINMENT_RECOMMENDED.value:
                self.recommendations_made += 1
                logger.warning(
                    f"[CONTAINMENT RECOMMENDED] {decision.decision_reason}"
                )
                # Emit event
                try:
                    self.bus.publish(
                        Event(
                            event_type="CONTAINMENT_RECOMMENDED",
                            data=decision.to_dict(),
                            source="CONTAINMENT_COORDINATOR",
                        )
                    )
                except Exception:
                    pass

            # Notify custom listeners
            for listener in list(self._listeners):
                try:
                    listener(decision)
                except Exception as e:
                    logger.debug(f"Error in containment listener: {e}")

            return decision

    def handle_alert(self, alert: SecurityAlert) -> ContainmentDecision:
        """
        Evaluate immediate SecurityAlert and execute containment if authorized.
        """
        with self._lock:
            self.events_evaluated += 1
            run_id, is_registered = self._resolve_simulation_run_id(
                alert.metadata, alert.process_id
            )

            decision = self.policy.evaluate_alert(
                alert=alert,
                simulation_run_id=run_id,
                is_run_registered=is_registered,
            )
            self.decisions_made += 1

            if decision.auto_containment_authorized:
                self.containments_triggered += 1
                self.manager.execute_containment(decision)
            elif decision.recommended_action == ContainmentAction.CONTAINMENT_RECOMMENDED.value:
                self.recommendations_made += 1
                try:
                    self.bus.publish(
                        Event(
                            event_type="CONTAINMENT_RECOMMENDED",
                            data=decision.to_dict(),
                            source="CONTAINMENT_COORDINATOR",
                        )
                    )
                except Exception:
                    pass

            return decision

    def get_metrics(self) -> Dict[str, Any]:
        """Return operational and performance metrics."""
        with self._lock:
            avg_lat = (
                round(self.total_containment_latency_ms / self.containments_triggered, 2)
                if self.containments_triggered > 0
                else 0.0
            )
            return {
                "is_running": self.is_running,
                "events_evaluated": self.events_evaluated,
                "decisions_made": self.decisions_made,
                "containments_triggered": self.containments_triggered,
                "recommendations_made": self.recommendations_made,
                "average_containment_latency_ms": avg_lat,
                "active_containments_completed": self.manager.containments_completed,
                "containments_failed": self.manager.containments_failed,
                "containments_skipped": self.manager.containments_skipped,
            }

    def clear(self) -> None:
        """Reset internal metrics and state."""
        with self._lock:
            self.events_evaluated = 0
            self.decisions_made = 0
            self.containments_triggered = 0
            self.recommendations_made = 0
            self.total_containment_latency_ms = 0.0
            self.recent_decisions.clear()
            self.manager.clear()

