"""
CryptoShield — Qt EventBus Bridge (Phase 10)
Connects background thread-based EventBus to Qt Signals for thread-safe UI updates.
"""

from typing import Any, Dict, Optional
from PySide6.QtCore import QObject, Signal

from app.core.event_bus import BUS, Event, EventBus
from app.core.logger import get_logger

logger = get_logger("ui.bridge")


class EventBusBridge(QObject):
    """
    Bridge connecting CryptoShield's thread-safe EventBus to Qt's signal/slot mechanism.
    All events arriving from background threads (Watchdog, psutil, detection, DLP)
    are emitted as Qt signals to guarantee thread-safe GUI updates on the main thread.
    """

    # Generic stream signal for every event
    event_received = Signal(object)  # Event instance

    # Specific semantic signals for rapid UI binding
    threat_updated = Signal(int, str)       # (threat_score: int, severity: str)
    incident_created = Signal(dict)         # Incident dossier dict
    incident_resolved = Signal(str, str)    # (incident_id, resolution_notes)
    containment_triggered = Signal(dict)    # Containment details dict
    write_gate_changed = Signal(bool)       # (is_locked: bool)
    dlp_interception = Signal(dict)         # DLP evaluation / interception dict
    dlp_profile_changed = Signal(str)       # Active security posture profile name
    exfiltration_activity = Signal(dict)    # Outbound transfer and exfiltration telemetry
    recovery_progress = Signal(str, int, int) # (status_text, current, total)
    log_emitted = Signal(str)               # Formatted human-readable message

    def __init__(self, bus: Optional[EventBus] = None, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self.bus: EventBus = bus or BUS
        self._connected: bool = False

    def connect_bus(self) -> None:
        """Subscribe internal handler to the EventBus."""
        if not self._connected:
            self.bus.subscribe("*", self._on_bus_event)
            self._connected = True
            logger.info("EventBusBridge connected to EventBus.")

    def disconnect_bus(self) -> None:
        """Unsubscribe handler from the EventBus."""
        if self._connected:
            self.bus.unsubscribe("*", self._on_bus_event)
            self._connected = False
            logger.info("EventBusBridge disconnected from EventBus.")

    def _on_bus_event(self, event: Event) -> None:
        """
        Receives an Event from any background thread and emits the corresponding Qt Signal.
        Qt handles inter-thread queuing automatically.
        """
        try:
            # Emit generic event
            self.event_received.emit(event)

            et = event.event_type
            data = event.data or {}

            # Detection events
            if et == "DETECTION_RESULT":
                score = int(data.get("score", data.get("threat_score", 0)))
                severity = str(data.get("severity", "NORMAL"))
                self.threat_updated.emit(score, severity)

            # Security incident events
            elif et in ("SECURITY_INCIDENT_CREATED", "SECURITY_INCIDENT_UPDATED"):
                self.incident_created.emit(data)
                score = int(data.get("threat_score", 0))
                severity = str(data.get("severity", "NORMAL"))
                self.threat_updated.emit(score, severity)
                self.log_emitted.emit(f"[INCIDENT] {data.get('incident_id', 'INC-???')} - Threat {score}/100 [{severity}]")

            elif et == "SECURITY_INCIDENT_RESOLVED":
                inc_id = str(data.get("incident_id", ""))
                notes = str(data.get("resolution_notes", "Resolved"))
                self.incident_resolved.emit(inc_id, notes)
                self.threat_updated.emit(0, "NORMAL")
                self.log_emitted.emit(f"[RESOLVED] Incident {inc_id}: {notes}")

            # Canary security alert
            elif et in ("CANARY_ACCESS", "CANARY_SECURITY_ALERT"):
                path = data.get("path", data.get("file_path", "unknown"))
                self.log_emitted.emit(f"[CANARY ALERT] Honeypot interaction detected: {path}")

            # Containment events
            elif et in ("CONTAINMENT_COMPLETED", "CONTAINMENT_REQUESTED", "CONTAINMENT_TRIGGERED"):
                self.containment_triggered.emit(data)
                self.write_gate_changed.emit(True)
                self.log_emitted.emit(f"[CONTAINMENT] Containment action executed: {data.get('action', 'LOCK')}")

            # DLP events
            elif et in ("DLP_TRANSFER_BLOCKED", "DLP_ACTION_EVALUATED", "DLP_TRANSFER_QUARANTINED", "DLP_APPROVAL_REQUIRED", "DLP_ALERT_TRIGGERED", "DLP_TRANSFER_ALLOWED"):
                self.dlp_interception.emit(data)
                self.exfiltration_activity.emit({"event_type": et, **data})
                action = data.get("action", "EVALUATE")
                self.log_emitted.emit(f"[DLP] Transfer {action} - Policy rule matched")

            elif et in (
                "EXFILTRATION_TRANSFER_COMPLETED",
                "EXFILTRATION_TRANSFER_BLOCKED",
                "EXFILTRATION_TRANSFER_FAILED",
                "STAGING_ARCHIVE_CREATED",
                "FILE_READ_BURST",
            ):
                self.exfiltration_activity.emit({"event_type": et, **data})
                if "TRANSFER" in et:
                    status_val = data.get("status", "MONITORED")
                    dest = data.get("destination_endpoint", "127.0.0.1")
                    b_count = data.get("bytes_transferred", 0)
                    self.log_emitted.emit(f"[EXFILTRATION] Outbound transfer to {dest}: {b_count:,} bytes ({status_val})")
                elif et == "STAGING_ARCHIVE_CREATED":
                    self.log_emitted.emit(f"[EXFILTRATION] Staging archive created: {data.get('archive_path', '')}")

            elif et == "DLP_PROFILE_CHANGED":
                profile_name = str(data.get("profile", data.get("new_profile", "DEFAULT")))
                self.dlp_profile_changed.emit(profile_name)
                self.log_emitted.emit(f"[DLP] Security posture profile switched to {profile_name}")

            # Recovery events
            elif et in ("RECOVERY_PROGRESS", "RECOVERY_STEP"):
                status_msg = str(data.get("status", data.get("stage", "Restoring...")))
                cur = int(data.get("current", 0))
                tot = int(data.get("total", 100))
                self.recovery_progress.emit(status_msg, cur, tot)

        except Exception as e:
            logger.error(f"Error dispatching bus event through bridge: {e}")
