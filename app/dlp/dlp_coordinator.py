"""
Data Loss Prevention (DLP) Coordinator for CryptoShield (Phase 8).

Central lifecycle coordinator orchestrating DLP policy evaluation, transfer gate
interception, operator approval management, audit logging, and SecurityIncident correlation.
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
from app.dlp.approval_manager import DLPApprovalManager
from app.dlp.audit_logger import DLPAuditLogger
from app.dlp.models import (
    DLPApprovalRequest,
    DLPEvaluationResult,
    DLPProfile,
)
from app.dlp.policy_engine import DLPPolicyEngine
from app.dlp.transfer_gate import DLPTransferGate

logger = logging.getLogger("cryptoshield.dlp.coordinator")


class DLPCoordinator:
    """
    Subsystem coordinator managing life-cycle, transfer gate interception,
    approval workflows, and incident dossier correlation for DLP defense.
    """

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        profile: DLPProfile = DLPProfile.DEFAULT,
        policies_path: Optional[Path] = None,
        audit_log_path: Optional[Path] = None,
    ) -> None:
        self.bus = event_bus or BUS
        self.policy_engine = DLPPolicyEngine(profile=profile, policies_path=policies_path)
        self.approval_manager = DLPApprovalManager(event_bus=self.bus)
        self.audit_logger = DLPAuditLogger(log_path=audit_log_path)
        self.transfer_gate = DLPTransferGate(
            policy_engine=self.policy_engine,
            approval_manager=self.approval_manager,
            audit_logger=self.audit_logger,
            event_bus=self.bus,
            enabled=CONFIG.DLP_ENABLED,
        )

        self._lock = threading.RLock()
        self._is_active = True

        # Hook into ExfiltrationCoordinator transfer monitor if available
        self._attach_to_exfiltration_monitor()

    def _attach_to_exfiltration_monitor(self) -> None:
        """Hooks the DLP transfer gate into the exfiltration subsystem's TransferMonitor."""
        try:
            from app.exfiltration.exfiltration_coordinator import EXFILTRATION_COORDINATOR
            if EXFILTRATION_COORDINATOR and EXFILTRATION_COORDINATOR.transfer_monitor:
                EXFILTRATION_COORDINATOR.transfer_monitor.dlp_gate = self.transfer_gate
                logger.info("DLP Transfer Gate successfully attached to TransferMonitor.")
        except Exception as e:
            logger.debug("Could not attach DLP gate to TransferMonitor: %s", e)

    def is_active(self) -> bool:
        with self._lock:
            return self._is_active

    def set_active(self, active: bool) -> None:
        with self._lock:
            self._is_active = active
            self.transfer_gate.enabled = active
            logger.info("DLPCoordinator active status set to: %s", active)

    def set_profile(self, profile: DLPProfile) -> None:
        """Switches the DLP policy profile across the subsystem and persists configuration."""
        with self._lock:
            self.policy_engine.set_profile(profile)
            try:
                self.policy_engine.save_to_file()
            except Exception as e:
                logger.debug("Could not persist DLP profile: %s", e)
            self.audit_logger.log_event(
                event_type="DLP_PROFILE_CHANGED",
                action="PROFILE_SWITCH",
                rule_id=None,
                details={"new_profile": profile.value},
            )
            self.bus.publish(
                Event(
                    event_type="DLP_PROFILE_CHANGED",
                    data={"profile": profile.value, "new_profile": profile.value},
                    source="dlp_coordinator",
                )
            )

    def evaluate_transfer(
        self,
        destination_endpoint: str,
        payload_bytes: Optional[bytes] = None,
        file_count: int = 1,
        process_id: Optional[int] = None,
        process_name: Optional[str] = None,
        classifications: Optional[List[str]] = None,
        departments: Optional[List[str]] = None,
        contains_canary: bool = False,
    ) -> DLPEvaluationResult:
        """Direct gateway to evaluate candidate outbound transfer."""
        return self.transfer_gate.evaluate_transfer(
            destination_endpoint=destination_endpoint,
            payload_bytes=payload_bytes,
            file_count=file_count,
            process_id=process_id,
            process_name=process_name,
            classifications=classifications,
            departments=departments,
            contains_canary=contains_canary,
        )

    def approve_transfer(
        self,
        approval_token: str,
        decided_by: str = "operator",
        reason: str = "Authorized by operator",
    ) -> Tuple[bool, Optional[DLPApprovalRequest]]:
        """Grants administrative authorization to a quarantined transfer."""
        ok, req = self.approval_manager.approve(approval_token, decided_by=decided_by, reason=reason)
        if ok and req:
            self.audit_logger.log_event(
                event_type="DLP_APPROVAL_GRANTED",
                action="APPROVE",
                rule_id=req.transfer_details.get("triggered_rule_id"),
                details=req.to_dict(),
            )
        return ok, req

    def reject_transfer(
        self,
        approval_token: str,
        decided_by: str = "operator",
        reason: str = "Denied by operator",
    ) -> Tuple[bool, Optional[DLPApprovalRequest]]:
        """Denies administrative authorization to a quarantined transfer."""
        ok, req = self.approval_manager.reject(approval_token, decided_by=decided_by, reason=reason)
        if ok and req:
            self.audit_logger.log_event(
                event_type="DLP_APPROVAL_REJECTED",
                action="REJECT",
                rule_id=req.transfer_details.get("triggered_rule_id"),
                details=req.to_dict(),
            )
        return ok, req

    def get_status(self) -> Dict[str, Any]:
        """Returns comprehensive status telemetry across the DLP subsystem."""
        with self._lock:
            metrics = self.transfer_gate.get_metrics()
            pending_approvals = self.approval_manager.get_pending_requests()
            rules = self.policy_engine.get_rules()

            return {
                "is_active": self._is_active,
                "profile": self.policy_engine.profile.value,
                "total_rules": len(rules),
                "enabled_rules": len([r for r in rules if r.enabled]),
                "pending_approvals_count": len(pending_approvals),
                "metrics": metrics,
            }

    def correlate_with_incident(
        self,
        incident_manager: IncidentManager,
        incident_id: Optional[str] = None,
    ) -> Optional[SecurityIncident]:
        """
        Enriches a SecurityIncident with DLP enforcement outcomes,
        blocked exfiltration records, and authorization audit entries.
        """
        target_incident: Optional[SecurityIncident] = None

        if incident_id:
            target_incident = incident_manager.get_incident(incident_id)
        else:
            active_incidents = incident_manager.list_incidents(status="OPEN")
            if not active_incidents:
                active_incidents = incident_manager.list_incidents(status="INVESTIGATING")
            if active_incidents:
                target_incident = active_incidents[0]

        if not target_incident:
            logger.warning("No active SecurityIncident found to correlate DLP telemetry.")
            return None

        metrics = self.transfer_gate.get_metrics()

        # Update incident metadata
        target_incident.metadata["dlp_profile"] = self.policy_engine.profile.value
        target_incident.metadata["dlp_metrics"] = metrics
        target_incident.metadata["dlp_transfers_blocked"] = metrics["blocked_count"]
        target_incident.metadata["dlp_transfers_quarantined"] = metrics["quarantined_count"]
        target_incident.last_updated_at = datetime.now(CONFIG.TIMEZONE).isoformat()

        # Add chronological action to incident timeline
        target_incident.timeline.append({
            "timestamp": datetime.now(CONFIG.TIMEZONE).isoformat(),
            "action": "DLP_POLICY_ENFORCED",
            "description": (
                f"DLP policy enforcement ({self.policy_engine.profile.value}): "
                f"{metrics['blocked_count']} blocked, {metrics['quarantined_count']} quarantined, "
                f"{metrics['alerted_count']} alerted, {metrics['allowed_count']} allowed."
            ),
            "profile": self.policy_engine.profile.value,
            "blocked_count": metrics["blocked_count"],
            "quarantined_count": metrics["quarantined_count"],
        })

        # Persist updated incident record
        incident_manager._save_incident_to_disk(target_incident)

        self.bus.publish(
            Event(
                event_type="INCIDENT_DLP_CORRELATED",
                data={
                    "incident_id": target_incident.incident_id,
                    "dlp_metrics": metrics,
                },
                source="dlp_coordinator",
            )
        )

        logger.info("Correlated DLP telemetry with incident %s", target_incident.incident_id)
        return target_incident

    def reset(self) -> None:
        """Resets metrics, approval queue, and audit cache."""
        with self._lock:
            self.transfer_gate.reset_metrics()
            self.approval_manager.reset()
            self.policy_engine.reset_to_defaults()
            self.audit_logger.clear()


# Global singleton instance
DLP_COORDINATOR = DLPCoordinator()
