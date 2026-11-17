"""
Data Loss Prevention (DLP) Transfer Gate for CryptoShield (Phase 8).

Active interception enforcement gate that evaluates candidate outbound data transfers,
enforcing rule-based ALLOW, ALERT, REQUIRE_APPROVAL, and BLOCK actions prior to
actual transmission to the mock loopback receiver.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, List, Optional
import uuid

from app.core.event_bus import BUS, Event, EventBus
from app.dlp.approval_manager import DLPApprovalManager
from app.dlp.audit_logger import DLPAuditLogger
from app.dlp.models import (
    DLPAction,
    DLPEvaluationResult,
)
from app.dlp.policy_engine import DLPPolicyEngine

logger = logging.getLogger("cryptoshield.dlp.transfer_gate")


class DLPTransferGate:
    """
    Interception enforcement gate. Evaluates candidate transfers against policy rules,
    records audit telemetry, dispatches event notifications, and controls transmission
    authorization.
    """

    def __init__(
        self,
        policy_engine: Optional[DLPPolicyEngine] = None,
        approval_manager: Optional[DLPApprovalManager] = None,
        audit_logger: Optional[DLPAuditLogger] = None,
        event_bus: Optional[EventBus] = None,
        enabled: bool = True,
    ) -> None:
        self.bus = event_bus or BUS
        self.policy_engine = policy_engine or DLPPolicyEngine()
        self.approval_manager = approval_manager or DLPApprovalManager(event_bus=self.bus)
        self.audit_logger = audit_logger or DLPAuditLogger()
        self.enabled = enabled

        self._lock = threading.RLock()
        self._total_evaluations: int = 0
        self._allowed_transfers_count: int = 0
        self._alerted_transfers_count: int = 0
        self._quarantined_transfers_count: int = 0
        self._blocked_transfers_count: int = 0

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
        custom_metadata: Optional[Dict[str, Any]] = None,
    ) -> DLPEvaluationResult:
        """
        Intercepts and evaluates an outbound data transmission attempt.
        Returns a DLPEvaluationResult indicating whether transmission is authorized.
        """
        with self._lock:
            self._total_evaluations += 1

            # If DLP gate is disabled, allow by default
            if not self.enabled:
                result = DLPEvaluationResult(
                    evaluation_id=f"DLP-EVAL-{uuid.uuid4().hex[:8].upper()}",
                    timestamp="",
                    action=DLPAction.ALLOW,
                    allowed=True,
                    reason="DLP Transfer Gate is disabled; permissive bypass.",
                    destination_endpoint=destination_endpoint,
                )
                self._allowed_transfers_count += 1
                return result

            # Build evaluation context
            byte_size = len(payload_bytes) if payload_bytes is not None else 0
            transfer_context = {
                "destination_endpoint": destination_endpoint,
                "bytes": byte_size,
                "file_count": file_count,
                "process_id": process_id,
                "process_name": process_name,
                "classifications": classifications or [],
                "departments": departments or [],
                "contains_canary": contains_canary,
            }
            if custom_metadata:
                transfer_context.update(custom_metadata)

            # Evaluate against policy rules
            result = self.policy_engine.evaluate(transfer_context)

            # Enforce outcome
            if result.action == DLPAction.BLOCK:
                self._blocked_transfers_count += 1
                logger.warning(
                    "[DLP INTERCEPTION] BLOCKED transfer to %s: %s (Rule: %s, Severity: %s)",
                    destination_endpoint,
                    result.reason,
                    result.triggered_rule_id,
                    result.severity,
                )

                # Emit bus event
                self.bus.publish(
                    Event(
                        event_type="DLP_TRANSFER_BLOCKED",
                        data=result.to_dict(),
                        source="dlp_transfer_gate",
                    )
                )

                # Audit log
                self.audit_logger.log_event(
                    event_type="DLP_TRANSFER_BLOCKED",
                    action=result.action.value,
                    rule_id=result.triggered_rule_id,
                    details=result.to_dict(),
                )

            elif result.action == DLPAction.REQUIRE_APPROVAL:
                self._quarantined_transfers_count += 1
                # Quarantine in approval manager
                req = self.approval_manager.submit_request(
                    evaluation=result,
                    transfer_payload=payload_bytes,
                    transfer_details=transfer_context,
                )
                logger.info(
                    "[DLP QUARANTINE] Transfer to %s requires approval (Token: %s)",
                    destination_endpoint,
                    req.approval_token,
                )

                # Audit log
                self.audit_logger.log_event(
                    event_type="DLP_APPROVAL_REQUIRED",
                    action=result.action.value,
                    rule_id=result.triggered_rule_id,
                    details=req.to_dict(),
                )

            elif result.action == DLPAction.ALERT:
                self._alerted_transfers_count += 1
                logger.warning(
                    "[DLP AUDIT ALERT] Monitored transfer to %s triggered alert: %s",
                    destination_endpoint,
                    result.reason,
                )

                self.bus.publish(
                    Event(
                        event_type="DLP_ALERT_TRIGGERED",
                        data=result.to_dict(),
                        source="dlp_transfer_gate",
                    )
                )

                self.audit_logger.log_event(
                    event_type="DLP_ALERT_TRIGGERED",
                    action=result.action.value,
                    rule_id=result.triggered_rule_id,
                    details=result.to_dict(),
                )

            elif result.action == DLPAction.ALLOW:
                self._allowed_transfers_count += 1
                self.bus.publish(
                    Event(
                        event_type="DLP_TRANSFER_ALLOWED",
                        data=result.to_dict(),
                        source="dlp_transfer_gate",
                    )
                )
                self.audit_logger.log_event(
                    event_type="DLP_TRANSFER_ALLOWED",
                    action=result.action.value,
                    rule_id=result.triggered_rule_id,
                    details=result.to_dict(),
                )

            return result

    def get_metrics(self) -> Dict[str, Any]:
        """Returns aggregate operational metrics of the transfer gate."""
        with self._lock:
            return {
                "enabled": self.enabled,
                "profile": self.policy_engine.profile.value,
                "total_evaluations": self._total_evaluations,
                "allowed_count": self._allowed_transfers_count,
                "alerted_count": self._alerted_transfers_count,
                "quarantined_count": self._quarantined_transfers_count,
                "blocked_count": self._blocked_transfers_count,
            }

    def reset_metrics(self) -> None:
        with self._lock:
            self._total_evaluations = 0
            self._allowed_transfers_count = 0
            self._alerted_transfers_count = 0
            self._quarantined_transfers_count = 0
            self._blocked_transfers_count = 0
