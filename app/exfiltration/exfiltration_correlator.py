"""
Exfiltration Correlator for Data Exfiltration Monitoring (Phase 7).

Correlates telemetry across read bursts, honeypot canary breaches, local archive staging,
and simulated outbound network transfers. Computes composite exfiltration risk scores,
assigns severity tiers, and produces structured exfiltration assessments.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import threading
from typing import Any, Callable, Dict, List, Optional
import uuid

from app.config import CONFIG
from app.core.event_bus import BUS, Event, EventBus
from app.exfiltration.models import (
    ExfiltrationAssessment,
    ExfiltrationRiskTier,
    OutboundTransferRecord,
    ReadBurstEvent,
    StagingEvent,
)

logger = logging.getLogger("cryptoshield.exfiltration.correlator")


class ExfiltrationCorrelator:
    """
    Fuses multi-modal exfiltration indicators into a single structured assessment,
    scoring threat levels and tracking chronological activity progression.
    """

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        assessment_callback: Optional[Callable[[ExfiltrationAssessment], None]] = None,
    ) -> None:
        self.bus = event_bus or BUS
        self.assessment_callback = assessment_callback

        self._read_bursts: List[ReadBurstEvent] = []
        self._staging_events: List[StagingEvent] = []
        self._transfer_records: List[OutboundTransferRecord] = []
        self._compromised_canaries: set = set()
        self._timeline: List[Dict[str, Any]] = []

        self._lock = threading.Lock()
        self._is_active = False
        self._last_assessment: Optional[ExfiltrationAssessment] = None

    def start(self) -> None:
        """Subscribes the correlator to exfiltration and telemetry events."""
        with self._lock:
            if self._is_active:
                return
            self._is_active = True
            self.bus.subscribe("EXFILTRATION_READ_BURST_DETECTED", self._handle_read_burst)
            self.bus.subscribe("CANARY_READ_BREACH", self._handle_canary_breach)
            self.bus.subscribe("EXFILTRATION_STAGING_DETECTED", self._handle_staging)
            self.bus.subscribe("EXFILTRATION_TRANSFER_COMPLETED", self._handle_transfer)
            self.bus.subscribe("EXFILTRATION_TRANSFER_FAILED", self._handle_transfer)
            logger.info("ExfiltrationCorrelator active and listening for telemetry.")

    def stop(self) -> None:
        """Unsubscribes the correlator from the EventBus."""
        with self._lock:
            if not self._is_active:
                return
            self._is_active = False
            self.bus.unsubscribe("EXFILTRATION_READ_BURST_DETECTED", self._handle_read_burst)
            self.bus.unsubscribe("CANARY_READ_BREACH", self._handle_canary_breach)
            self.bus.unsubscribe("EXFILTRATION_STAGING_DETECTED", self._handle_staging)
            self.bus.unsubscribe("EXFILTRATION_TRANSFER_COMPLETED", self._handle_transfer)
            self.bus.unsubscribe("EXFILTRATION_TRANSFER_FAILED", self._handle_transfer)
            logger.info("ExfiltrationCorrelator stopped.")

    def add_read_burst(self, burst: ReadBurstEvent) -> ExfiltrationAssessment:
        """Records a read burst and updates the composite assessment."""
        with self._lock:
            self._read_bursts.append(burst)
            for cp in burst.canary_paths:
                self._compromised_canaries.add(cp)
            self._timeline.append({
                "timestamp": burst.timestamp,
                "event": "READ_BURST_DETECTED",
                "details": f"Observed {burst.read_count} reads across {len(burst.department_counts)} departments.",
                "burst_id": burst.burst_id,
            })
            return self._compute_assessment_locked()

    def add_staging_event(self, staging: StagingEvent) -> ExfiltrationAssessment:
        """Records a staging action and updates the composite assessment."""
        with self._lock:
            self._staging_events.append(staging)
            self._timeline.append({
                "timestamp": staging.timestamp,
                "event": "STAGING_DETECTED",
                "details": f"Staged {staging.staged_files_count} files ({staging.total_staged_bytes:,}B) in {staging.staging_path}.",
                "staging_id": staging.staging_id,
            })
            return self._compute_assessment_locked()

    def add_transfer_record(self, transfer: OutboundTransferRecord) -> ExfiltrationAssessment:
        """Records an outbound transfer and updates the composite assessment."""
        with self._lock:
            self._transfer_records.append(transfer)
            if transfer.contains_canary:
                self._compromised_canaries.add("outbound_canary_payload")
            self._timeline.append({
                "timestamp": transfer.timestamp,
                "event": f"TRANSFER_{transfer.status}",
                "details": f"Sent {transfer.bytes_transferred:,}B to {transfer.destination_endpoint} via {transfer.protocol}.",
                "transfer_id": transfer.transfer_id,
            })
            return self._compute_assessment_locked()

    def evaluate_current_state(self, correlated_incident_id: Optional[str] = None) -> ExfiltrationAssessment:
        """Evaluates all current telemetry and returns a fresh assessment."""
        with self._lock:
            return self._compute_assessment_locked(correlated_incident_id)

    def reset(self) -> None:
        """Resets correlator telemetry history."""
        with self._lock:
            self._read_bursts.clear()
            self._staging_events.clear()
            self._transfer_records.clear()
            self._compromised_canaries.clear()
            self._timeline.clear()
            self._last_assessment = None

    def _handle_read_burst(self, event: Event) -> None:
        try:
            burst = ReadBurstEvent.from_dict(event.data)
            self.add_read_burst(burst)
        except Exception as e:
            logger.error("Error handling read burst event: %s", e)

    def _handle_canary_breach(self, event: Event) -> None:
        with self._lock:
            for cp in event.data.get("canary_paths", []):
                self._compromised_canaries.add(cp)

    def _handle_staging(self, event: Event) -> None:
        try:
            staging = StagingEvent.from_dict(event.data)
            self.add_staging_event(staging)
        except Exception as e:
            logger.error("Error handling staging event: %s", e)

    def _handle_transfer(self, event: Event) -> None:
        try:
            transfer = OutboundTransferRecord.from_dict(event.data)
            self.add_transfer_record(transfer)
        except Exception as e:
            logger.error("Error handling transfer event: %s", e)

    def _compute_assessment_locked(self, correlated_incident_id: Optional[str] = None) -> ExfiltrationAssessment:
        """Calculates score, tier, and indicators from all accumulated telemetry."""
        score = 0
        indicators: List[str] = []

        total_reads = sum(b.read_count for b in self._read_bursts)
        total_staged_bytes = sum(s.total_staged_bytes for s in self._staging_events)
        total_transferred_bytes = sum(
            t.bytes_transferred for t in self._transfer_records if t.status == "COMPLETED"
        )
        completed_transfers = sum(1 for t in self._transfer_records if t.status == "COMPLETED")

        # Indicator 1: Mass read bursts
        if self._read_bursts:
            score += CONFIG.EXFILTRATION_MASS_READ_WEIGHT
            indicators.append("MASS_FILE_READ_BURST")

        # Indicator 2: Honeypot canary read breach
        if self._compromised_canaries:
            score += CONFIG.EXFILTRATION_CANARY_READ_WEIGHT
            indicators.append("CANARY_HONEYPOT_COMPROMISED")

        # Indicator 3: Department diversity across reads
        all_depts = set()
        all_classes = set()
        for b in self._read_bursts:
            all_depts.update(b.department_counts.keys())
            all_classes.update(b.classification_counts.keys())

        if len(all_depts) >= 2:
            score += 15
            indicators.append("MULTI_DEPARTMENT_HARVESTING")

        # Indicator 4: High-sensitivity classification access
        if "RESTRICTED" in all_classes or "CONFIDENTIAL" in all_classes:
            score += 10
            indicators.append("SENSITIVE_CLASSIFICATION_TARGETED")

        # Indicator 5: Local staging / archive preparation
        if self._staging_events:
            score += CONFIG.EXFILTRATION_STAGING_WEIGHT
            indicators.append("LOCAL_STAGING_DETECTED")

        # Indicator 6: Outbound transfer execution
        if completed_transfers > 0:
            score += CONFIG.EXFILTRATION_TRANSFER_WEIGHT
            indicators.append("OUTBOUND_TRANSFER_EXECUTED")

        # Cap score at 100
        threat_score = min(100, max(0, score))

        # Assign Risk Tier
        if threat_score >= CONFIG.EXFILTRATION_CRITICAL_THRESHOLD:
            risk_tier = ExfiltrationRiskTier.CRITICAL.value
        elif threat_score >= CONFIG.EXFILTRATION_HIGH_THRESHOLD:
            risk_tier = ExfiltrationRiskTier.HIGH.value
        elif threat_score >= 20:
            risk_tier = ExfiltrationRiskTier.MEDIUM.value
        else:
            risk_tier = ExfiltrationRiskTier.LOW.value

        assessment = ExfiltrationAssessment(
            assessment_id=f"EXFIL-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            threat_score=threat_score,
            risk_tier=risk_tier,
            indicators=indicators,
            read_burst_count=len(self._read_bursts),
            total_reads_observed=total_reads,
            canary_reads_count=len(self._compromised_canaries),
            canaries_compromised=sorted(list(self._compromised_canaries)),
            staging_events_count=len(self._staging_events),
            total_staged_bytes=total_staged_bytes,
            transfers_attempted=len(self._transfer_records),
            transfers_completed=completed_transfers,
            total_bytes_exfiltrated=total_transferred_bytes,
            timeline=list(self._timeline),
            correlated_incident_id=correlated_incident_id,
            metadata={
                "departments_harvested": sorted(list(all_depts)),
                "classifications_harvested": sorted(list(all_classes)),
            },
        )

        self._last_assessment = assessment
        self._publish_assessment(assessment)
        return assessment

    def _publish_assessment(self, assessment: ExfiltrationAssessment) -> None:
        """Publishes the assessment and dispatches alerts on high/critical tiers."""
        bus_event = Event(
            event_type="EXFILTRATION_ASSESSMENT_COMPLETED",
            data=assessment.to_dict(),
            source="exfiltration_correlator",
        )
        self.bus.publish(bus_event)

        if assessment.risk_tier in (ExfiltrationRiskTier.HIGH.value, ExfiltrationRiskTier.CRITICAL.value):
            alert_event = Event(
                event_type="EXFILTRATION_SECURITY_ALERT",
                data={
                    "assessment_id": assessment.assessment_id,
                    "risk_tier": assessment.risk_tier,
                    "threat_score": assessment.threat_score,
                    "indicators": assessment.indicators,
                    "canary_reads": assessment.canary_reads_count,
                    "bytes_exfiltrated": assessment.total_bytes_exfiltrated,
                },
                source="exfiltration_correlator",
            )
            self.bus.publish(alert_event)

        if self.assessment_callback:
            try:
                self.assessment_callback(assessment)
            except Exception as e:
                logger.error("Error in assessment callback: %s", e)
