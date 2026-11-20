"""
Security Incident Manager for CryptoShield.

Maintains security incident lifecycles, correlates sequential detection results,
preserves chronological audit timelines, and enables incident investigation
and resolution without permanently deleting security records.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from app.config import CONFIG
from app.core.event_bus import BUS, Event, EventBus
from app.core.logger import get_logger
from app.core.models import (
    DetectionResult,
    IncidentStatus,
    MonitoringEvent,
    ProcessAttribution,
    SecurityIncident,
)

logger = get_logger("incident_manager")


class IncidentManager:
    """
    Manages the lifecycle of security incidents.
    
    Correlates continuous detections into single consolidated incidents,
    maintains chronological timelines, manages status transitions (OPEN -> INVESTIGATING -> RESOLVED),
    and persists records to JSON files in the incidents directory.
    """

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        incidents_dir: Optional[Path] = None,
        auto_create_threshold: int = CONFIG.INCIDENT_AUTO_CREATE_THRESHOLD,
        merge_window_seconds: float = CONFIG.INCIDENT_MERGE_WINDOW_SECONDS,
    ) -> None:
        self.bus = event_bus or BUS
        self.incidents_dir = incidents_dir or CONFIG.incidents_dir
        self.auto_create_threshold = auto_create_threshold
        self.merge_window_seconds = merge_window_seconds

        self._incidents: Dict[str, SecurityIncident] = {}
        self._active_incident_id: Optional[str] = None
        self._lock = threading.RLock()

        # Operational metrics
        self.incidents_created_count: int = 0
        self.incidents_updated_count: int = 0
        self.incidents_resolved_count: int = 0

        # Ensure storage directory exists
        try:
            self.incidents_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.debug(f"Could not create incidents directory: {e}")

    def _parse_timestamp(self, ts_str: str) -> float:
        """Parse ISO timestamp to epoch float."""
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=CONFIG.TIMEZONE)
            return dt.timestamp()
        except Exception:
            return datetime.now(CONFIG.TIMEZONE).timestamp()

    def process_detection(
        self,
        detection: DetectionResult,
        source_events: Optional[List[MonitoringEvent]] = None,
    ) -> Optional[SecurityIncident]:
        """
        Evaluate a DetectionResult.
        
        If criteria are met (threat score >= auto_create_threshold or canary access > 0):
        - Merges into active related open incident if within merge_window_seconds.
        - Otherwise, creates a new SecurityIncident.
        """
        is_incident_worthy = (
            detection.threat_score >= self.auto_create_threshold
            or detection.canary_access_count > 0
        )

        if not is_incident_worthy:
            return None

        with self._lock:
            now_dt = datetime.now(CONFIG.TIMEZONE)
            now_epoch = now_dt.timestamp()

            # Check if there is an active OPEN or INVESTIGATING incident to merge into
            target_incident: Optional[SecurityIncident] = None

            if self._active_incident_id and self._active_incident_id in self._incidents:
                candidate = self._incidents[self._active_incident_id]
                if candidate.status in {IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value}:
                    last_update_epoch = self._parse_timestamp(candidate.last_updated_at)
                    if (now_epoch - last_update_epoch) <= self.merge_window_seconds:
                        target_incident = candidate

            if target_incident:
                incident = self._update_incident(target_incident, detection, source_events, now_dt.isoformat())
            else:
                incident = self._create_incident(detection, source_events, now_dt.isoformat())

            # Assign incident_id back to detection result
            detection.incident_id = incident.incident_id

            # Save incident snapshot to disk
            self._save_incident_to_disk(incident)
            return incident

    def _create_incident(
        self,
        detection: DetectionResult,
        source_events: Optional[List[MonitoringEvent]],
        timestamp: str,
    ) -> SecurityIncident:
        """Create and publish a new SecurityIncident."""
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"

        event_ids: List[str] = []
        affected_paths: Set[str] = set(detection.affected_files)
        canary_records: List[Dict[str, Any]] = []

        if source_events:
            for ev in source_events:
                event_ids.append(ev.event_id)
                if ev.relative_path:
                    affected_paths.add(ev.relative_path)
                if ev.is_canary or ev.event_type == "CANARY_ACCESS":
                    canary_records.append(ev.to_dict())

        timeline_entry = {
            "timestamp": timestamp,
            "action": "INCIDENT_CREATED",
            "threat_score": detection.threat_score,
            "severity": detection.severity,
            "description": f"Incident opened with assessment: {detection.assessment}",
            "detection_id": detection.detection_id,
        }

        assessment_record = {
            "timestamp": timestamp,
            "threat_score": detection.threat_score,
            "severity": detection.severity,
            "reasons": detection.reasons,
            "assessment": detection.assessment,
        }

        incident = SecurityIncident(
            incident_id=incident_id,
            first_detected_at=timestamp,
            last_updated_at=timestamp,
            status=IncidentStatus.OPEN.value,
            threat_score=detection.threat_score,
            severity=detection.severity,
            assessment=detection.assessment,
            detection_reasons=list(detection.reasons),
            contributing_event_ids=event_ids,
            affected_paths=sorted(affected_paths),
            canary_events=canary_records,
            process_attribution=detection.process_attribution,
            process_id=detection.process_id,
            process_name=detection.process_name,
            assessment_history=[assessment_record],
            timeline=[timeline_entry],
            metadata={"initial_detection_id": detection.detection_id},
        )

        self._incidents[incident_id] = incident
        self._active_incident_id = incident_id
        self.incidents_created_count += 1

        logger.warning(
            f"[INCIDENT CREATED] {incident_id} (Score: {incident.threat_score}, "
            f"Severity: {incident.severity}, Status: {incident.status})"
        )

        # Publish to EventBus
        try:
            self.bus.publish(
                Event(
                    event_type="SECURITY_INCIDENT_CREATED",
                    data=incident.to_dict(),
                    source="INCIDENT_MANAGER",
                )
            )
        except Exception as e:
            logger.exception(f"Failed to publish incident created event: {e}")

        return incident

    def _update_incident(
        self,
        incident: SecurityIncident,
        detection: DetectionResult,
        source_events: Optional[List[MonitoringEvent]],
        timestamp: str,
    ) -> SecurityIncident:
        """Update existing incident with fresh detection telemetry."""
        incident.last_updated_at = timestamp

        # Escalate score and severity if higher
        if detection.threat_score > incident.threat_score:
            incident.threat_score = detection.threat_score
            incident.severity = detection.severity
            incident.assessment = detection.assessment

        # Merge detection reasons
        for r in detection.reasons:
            if r not in incident.detection_reasons:
                incident.detection_reasons.append(r)

        # Merge affected paths and event ids
        affected_set = set(incident.affected_paths)
        for p in detection.affected_files:
            affected_set.add(p)

        if source_events:
            for ev in source_events:
                if ev.event_id not in incident.contributing_event_ids:
                    incident.contributing_event_ids.append(ev.event_id)
                if ev.relative_path:
                    affected_set.add(ev.relative_path)
                if ev.is_canary or ev.event_type == "CANARY_ACCESS":
                    incident.canary_events.append(ev.to_dict())

        incident.affected_paths = sorted(affected_set)

        # Update process attribution if previously unknown
        if (
            incident.process_attribution == ProcessAttribution.UNKNOWN.value
            and detection.process_attribution != ProcessAttribution.UNKNOWN.value
        ):
            incident.process_attribution = detection.process_attribution
            incident.process_id = detection.process_id
            incident.process_name = detection.process_name

        # Append timeline and assessment records
        timeline_entry = {
            "timestamp": timestamp,
            "action": "EVIDENCE_CORRELATED",
            "threat_score": detection.threat_score,
            "severity": detection.severity,
            "description": f"New evidence correlated: {len(detection.reasons)} reasons triggered.",
            "detection_id": detection.detection_id,
        }
        incident.timeline.append(timeline_entry)

        assessment_record = {
            "timestamp": timestamp,
            "threat_score": detection.threat_score,
            "severity": detection.severity,
            "reasons": detection.reasons,
            "assessment": detection.assessment,
        }
        incident.assessment_history.append(assessment_record)

        self.incidents_updated_count += 1
        logger.info(
            f"[INCIDENT UPDATED] {incident.incident_id} (Score: {incident.threat_score}, "
            f"Total Files: {len(incident.affected_paths)})"
        )

        # Publish to EventBus
        try:
            self.bus.publish(
                Event(
                    event_type="SECURITY_INCIDENT_UPDATED",
                    data=incident.to_dict(),
                    source="INCIDENT_MANAGER",
                )
            )
        except Exception as e:
            logger.exception(f"Failed to publish incident update event: {e}")

        return incident

    def acknowledge_incident(
        self,
        incident_id: str,
        investigator: Optional[str] = None,
    ) -> Optional[SecurityIncident]:
        """Transition incident from OPEN to INVESTIGATING."""
        with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None

            now = datetime.now(CONFIG.TIMEZONE).isoformat()
            incident.status = IncidentStatus.INVESTIGATING.value
            incident.last_updated_at = now

            incident.timeline.append(
                {
                    "timestamp": now,
                    "action": "STATUS_CHANGED",
                    "new_status": IncidentStatus.INVESTIGATING.value,
                    "investigator": investigator or "operator",
                    "description": "Incident under active cybersecurity investigation.",
                }
            )

            self._save_incident_to_disk(incident)
            logger.info(f"Incident {incident_id} acknowledged by {investigator or 'operator'}.")
            return incident

    def resolve_incident(
        self,
        incident_id: str,
        resolution_notes: str,
        resolver: Optional[str] = None,
    ) -> Optional[SecurityIncident]:
        """Transition incident to RESOLVED."""
        with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None

            now = datetime.now(CONFIG.TIMEZONE).isoformat()
            incident.status = IncidentStatus.RESOLVED.value
            incident.last_updated_at = now

            incident.timeline.append(
                {
                    "timestamp": now,
                    "action": "INCIDENT_RESOLVED",
                    "resolver": resolver or "operator",
                    "notes": resolution_notes,
                    "description": f"Incident marked resolved: {resolution_notes}",
                }
            )

            if self._active_incident_id == incident_id:
                self._active_incident_id = None

            self.incidents_resolved_count += 1
            self._save_incident_to_disk(incident)

            logger.info(f"Incident {incident_id} marked RESOLVED.")

            try:
                self.bus.publish(
                    Event(
                        event_type="SECURITY_INCIDENT_RESOLVED",
                        data=incident.to_dict(),
                        source="INCIDENT_MANAGER",
                    )
                )
            except Exception as e:
                logger.exception(f"Failed to publish incident resolved event: {e}")

            return incident

    def get_incident(self, incident_id: str) -> Optional[SecurityIncident]:
        """Retrieve an incident by ID."""
        with self._lock:
            return self._incidents.get(incident_id)

    def list_incidents(self, status: Optional[str] = None) -> List[SecurityIncident]:
        """List all incidents, optionally filtered by status."""
        with self._lock:
            if status:
                return [inc for inc in self._incidents.values() if inc.status == status]
            return list(self._incidents.values())

    def _save_incident_to_disk(self, incident: SecurityIncident) -> Optional[Path]:
        """Persist incident JSON representation safely to incidents directory."""
        try:
            self.incidents_dir.mkdir(parents=True, exist_ok=True)
            target = self.incidents_dir / f"{incident.incident_id}.json"
            with open(target, "w", encoding="utf-8") as f:
                json.dump(incident.to_dict(), f, indent=2)
            return target
        except Exception as e:
            logger.debug(f"Could not persist incident {incident.incident_id} to disk: {e}")
            return None

    def clear(self) -> None:
        """Clear all in-memory incident records."""
        with self._lock:
            self._incidents.clear()
            self._active_incident_id = None
            self.incidents_created_count = 0
            self.incidents_updated_count = 0
            self.incidents_resolved_count = 0

