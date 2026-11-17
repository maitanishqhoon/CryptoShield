"""
Data Loss Prevention (DLP) Approval Manager for CryptoShield (Phase 8).

Manages quarantined outbound transfers requiring administrative authorization
(REQUIRE_APPROVAL), tracking unique approval tokens, operator decisions, and
audit lifecycle states.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

from app.config import CONFIG
from app.core.event_bus import BUS, Event, EventBus
from app.dlp.models import (
    DLPApprovalRequest,
    DLPApprovalStatus,
    DLPEvaluationResult,
)

logger = logging.getLogger("cryptoshield.dlp.approval_manager")


class DLPApprovalManager:
    """
    Thread-safe registry for managing pending and resolved DLP authorization requests.
    """

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        default_timeout_seconds: float = CONFIG.DLP_APPROVAL_TIMEOUT_SECONDS,
    ) -> None:
        self.bus = event_bus or BUS
        self.default_timeout_seconds = default_timeout_seconds
        self._lock = threading.RLock()
        self._requests: Dict[str, DLPApprovalRequest] = {}
        self._payload_cache: Dict[str, bytes] = {}

    def submit_request(
        self,
        evaluation: DLPEvaluationResult,
        transfer_payload: Optional[bytes] = None,
        transfer_details: Optional[Dict[str, Any]] = None,
    ) -> DLPApprovalRequest:
        """
        Creates a new pending approval request for a transfer evaluated as REQUIRE_APPROVAL.
        """
        with self._lock:
            token = f"APR-{uuid.uuid4().hex[:8].upper()}"
            evaluation.approval_token = token

            details = transfer_details or {}
            details.update({
                "destination_endpoint": evaluation.destination_endpoint,
                "file_count": evaluation.file_count,
                "bytes_requested": evaluation.bytes_requested,
                "classifications": evaluation.classifications_evaluated,
                "departments": evaluation.departments_evaluated,
                "contains_canary": evaluation.contains_canary,
                "triggered_rule_id": evaluation.triggered_rule_id,
                "reason": evaluation.reason,
            })

            req = DLPApprovalRequest(
                approval_token=token,
                evaluation_id=evaluation.evaluation_id,
                requested_at=datetime.now(timezone.utc).isoformat(),
                status=DLPApprovalStatus.PENDING.value,
                transfer_details=details,
            )

            self._requests[token] = req
            if transfer_payload is not None:
                self._payload_cache[token] = transfer_payload

            # Publish event
            self.bus.publish(
                Event(
                    event_type="DLP_APPROVAL_REQUIRED",
                    data=req.to_dict(),
                    source="dlp_approval_manager",
                )
            )

            logger.info("Created DLP approval request %s for evaluation %s", token, evaluation.evaluation_id)
            return req

    def approve(
        self,
        approval_token: str,
        decided_by: str = "operator",
        reason: str = "Authorized by operator",
    ) -> Tuple[bool, Optional[DLPApprovalRequest]]:
        """
        Grants approval for a pending quarantined transfer.
        """
        with self._lock:
            req = self._requests.get(approval_token)
            if not req:
                logger.warning("Approval request %s not found", approval_token)
                return False, None

            if req.status != DLPApprovalStatus.PENDING.value:
                logger.warning("Approval request %s is already %s", approval_token, req.status)
                return False, req

            req.status = DLPApprovalStatus.APPROVED.value
            req.decided_at = datetime.now(timezone.utc).isoformat()
            req.decided_by = decided_by
            req.decision_reason = reason

            self.bus.publish(
                Event(
                    event_type="DLP_APPROVAL_GRANTED",
                    data=req.to_dict(),
                    source="dlp_approval_manager",
                )
            )

            logger.info("Approval granted for token %s by %s", approval_token, decided_by)
            return True, req

    def reject(
        self,
        approval_token: str,
        decided_by: str = "operator",
        reason: str = "Rejected by operator",
    ) -> Tuple[bool, Optional[DLPApprovalRequest]]:
        """
        Denies authorization for a quarantined transfer.
        """
        with self._lock:
            req = self._requests.get(approval_token)
            if not req:
                return False, None

            if req.status != DLPApprovalStatus.PENDING.value:
                return False, req

            req.status = DLPApprovalStatus.REJECTED.value
            req.decided_at = datetime.now(timezone.utc).isoformat()
            req.decided_by = decided_by
            req.decision_reason = reason

            self.bus.publish(
                Event(
                    event_type="DLP_APPROVAL_REJECTED",
                    data=req.to_dict(),
                    source="dlp_approval_manager",
                )
            )

            logger.info("Approval rejected for token %s by %s", approval_token, decided_by)
            return True, req

    def get_pending_requests(self) -> List[DLPApprovalRequest]:
        """Returns all currently pending authorization requests."""
        with self._lock:
            return [
                r for r in self._requests.values()
                if r.status == DLPApprovalStatus.PENDING.value
            ]

    def get_request(self, approval_token: str) -> Optional[DLPApprovalRequest]:
        with self._lock:
            return self._requests.get(approval_token)

    def get_all_requests(self) -> List[DLPApprovalRequest]:
        with self._lock:
            return list(self._requests.values())

    def get_payload(self, approval_token: str) -> Optional[bytes]:
        with self._lock:
            return self._payload_cache.get(approval_token)

    def cleanup_expired(self, timeout_seconds: Optional[float] = None) -> int:
        """Marks pending requests older than timeout as EXPIRED."""
        limit = timeout_seconds or self.default_timeout_seconds
        now_epoch = time.time()
        expired_count = 0

        with self._lock:
            for req in list(self._requests.values()):
                if req.status == DLPApprovalStatus.PENDING.value:
                    try:
                        req_epoch = datetime.fromisoformat(req.requested_at).timestamp()
                        if now_epoch - req_epoch > limit:
                            req.status = DLPApprovalStatus.EXPIRED.value
                            req.decided_at = datetime.now(timezone.utc).isoformat()
                            req.decision_reason = f"Expired after {limit}s without decision"
                            expired_count += 1
                    except Exception:
                        pass
        return expired_count

    def reset(self) -> None:
        """Clears all approval requests and payload caches."""
        with self._lock:
            self._requests.clear()
            self._payload_cache.clear()
