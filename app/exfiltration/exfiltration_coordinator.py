"""
Exfiltration Coordinator for CryptoShield (Phase 7).

Central orchestrator for the Data Exfiltration Monitoring Subsystem. Coordinates
the MockReceiver, ReadBurstDetector, StagingDetector, TransferMonitor, and
ExfiltrationCorrelator. Bridges exfiltration findings into active SecurityIncidents.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Tuple

from app.config import CONFIG
from app.core.event_bus import BUS, Event, EventBus
from app.core.models import SecurityIncident
from app.detection.incident_manager import IncidentManager
from app.exfiltration.exfiltration_correlator import ExfiltrationCorrelator
from app.exfiltration.mock_receiver import MockReceiver
from app.exfiltration.models import ExfiltrationAssessment, ExfiltrationRiskTier
from app.exfiltration.read_burst_detector import ReadBurstDetector
from app.exfiltration.staging_detector import StagingDetector
from app.exfiltration.transfer_monitor import TransferMonitor

logger = logging.getLogger("cryptoshield.exfiltration.coordinator")


class ExfiltrationCoordinator:
    """
    Subsystem coordinator managing life-cycle, monitoring engines, mock endpoints,
    and incident correlation for data exfiltration defense.
    """

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        mock_host: str = CONFIG.EXFILTRATION_MOCK_HOST,
        mock_port: int = CONFIG.EXFILTRATION_MOCK_PORT,
    ) -> None:
        self.bus = event_bus or BUS
        self.mock_host = mock_host
        self.mock_port = mock_port

        self.receiver = MockReceiver(host=self.mock_host, port=self.mock_port)
        self.read_detector = ReadBurstDetector(event_bus=self.bus)
        self.staging_detector = StagingDetector(event_bus=self.bus)
        self.transfer_monitor = TransferMonitor(event_bus=self.bus, mock_receiver=self.receiver)
        self.correlator = ExfiltrationCorrelator(event_bus=self.bus)

        self._lock = threading.Lock()
        self._is_running = False

    def is_running(self) -> bool:
        """Returns True if coordinator monitoring engines and receiver are active."""
        with self._lock:
            return self._is_running

    def start(self, ephemeral_port: bool = False) -> Tuple[str, int]:
        """
        Starts the mock socket receiver, read burst detector, staging detector,
        and exfiltration correlator.
        """
        with self._lock:
            if self._is_running:
                return self.receiver.host, self.receiver.actual_port

            if ephemeral_port:
                self.receiver.requested_port = 0

            host, port = self.receiver.start()
            self.read_detector.start()
            self.staging_detector.start()
            self.correlator.start()
            self._is_running = True

            logger.info("ExfiltrationCoordinator fully operational on %s:%d", host, port)
            return host, port

    def stop(self) -> None:
        """Stops all exfiltration detectors and closes the mock receiver."""
        with self._lock:
            if not self._is_running:
                return

            self.read_detector.stop()
            self.staging_detector.stop()
            self.correlator.stop()
            self.receiver.stop()
            self._is_running = False
            logger.info("ExfiltrationCoordinator stopped.")

    def get_assessment(self) -> ExfiltrationAssessment:
        """Returns the latest consolidated exfiltration assessment."""
        return self.correlator.evaluate_current_state()

    def get_status(self) -> Dict[str, Any]:
        """Returns comprehensive status telemetry across all exfiltration components."""
        with self._lock:
            assessment = self.correlator.evaluate_current_state()
            receiver_metrics = self.receiver.get_metrics()
            transfer_metrics = self.transfer_monitor.get_metrics()

            return {
                "is_running": self._is_running,
                "endpoint": self.receiver.endpoint,
                "threat_score": assessment.threat_score,
                "risk_tier": assessment.risk_tier,
                "indicators": assessment.indicators,
                "read_bursts_count": len(self.read_detector.get_recent_bursts()),
                "canary_reads": self.read_detector.get_canary_reads(),
                "staging_events_count": len(self.staging_detector.get_staging_events()),
                "transfers": transfer_metrics,
                "receiver": receiver_metrics,
            }

    def correlate_with_incident(
        self,
        incident_manager: IncidentManager,
        incident_id: Optional[str] = None,
    ) -> Optional[SecurityIncident]:
        """
        Correlates the current exfiltration assessment into a SecurityIncident dossier,
        recording risk tier, indicator findings, and timeline records.
        """
        target_incident: Optional[SecurityIncident] = None

        if incident_id:
            target_incident = incident_manager.get_incident(incident_id)
        else:
            # Query open or investigating incidents
            active_incidents = incident_manager.list_incidents(status="OPEN")
            if not active_incidents:
                active_incidents = incident_manager.list_incidents(status="INVESTIGATING")
            if active_incidents:
                target_incident = active_incidents[0]

        if not target_incident:
            logger.warning("No active SecurityIncident found to correlate exfiltration findings.")
            return None

        assessment = self.correlator.evaluate_current_state(correlated_incident_id=target_incident.incident_id)

        # Attach exfiltration assessment to incident metadata
        target_incident.metadata["exfiltration_assessment"] = assessment.to_dict()
        target_incident.metadata["exfiltration_risk_tier"] = assessment.risk_tier
        target_incident.metadata["exfiltration_threat_score"] = assessment.threat_score
        target_incident.last_updated_at = datetime.now(CONFIG.TIMEZONE).isoformat()

        # Add chronological action to incident timeline
        target_incident.timeline.append({
            "timestamp": datetime.now(CONFIG.TIMEZONE).isoformat(),
            "action": "EXFILTRATION_CORRELATED",
            "description": (
                f"Exfiltration assessment [{assessment.risk_tier}] correlated: "
                f"{len(assessment.indicators)} indicators detected "
                f"(Reads={assessment.total_reads_observed}, Staged={assessment.total_staged_bytes}B, "
                f"Transferred={assessment.total_bytes_exfiltrated}B)."
            ),
            "assessment_id": assessment.assessment_id,
            "risk_tier": assessment.risk_tier,
            "threat_score": assessment.threat_score,
        })

        # Persist updated incident record
        incident_manager._save_incident_to_disk(target_incident)

        # Publish bus notification
        self.bus.publish(
            Event(
                event_type="INCIDENT_EXFILTRATION_CORRELATED",
                data={
                    "incident_id": target_incident.incident_id,
                    "assessment_id": assessment.assessment_id,
                    "risk_tier": assessment.risk_tier,
                    "threat_score": assessment.threat_score,
                },
                source="exfiltration_coordinator",
            )
        )
        logger.info(
            "Correlated exfiltration assessment %s with incident %s",
            assessment.assessment_id,
            target_incident.incident_id,
        )
        return target_incident

    def reset(self) -> None:
        """Resets all sub-detectors, metrics, and correlators."""
        with self._lock:
            self.read_detector.reset()
            self.staging_detector.reset()
            self.transfer_monitor.reset()
            self.receiver.reset_metrics()
            self.correlator.reset()


# Global singleton instance
EXFILTRATION_COORDINATOR = ExfiltrationCoordinator()
