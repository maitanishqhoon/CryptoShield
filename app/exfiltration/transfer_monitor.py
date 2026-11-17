"""
Outbound Transfer Monitor for Data Exfiltration Monitoring (Phase 7).

Monitors, logs, and instruments simulated outbound data transmissions to the local
mock receiver endpoint (127.0.0.1), enforcing strict loopback-only safety boundaries.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional
import uuid

from app.config import CONFIG
from app.core.event_bus import BUS, Event, EventBus
from app.exfiltration.models import OutboundTransferRecord, TransferProtocol, TransferStatus

logger = logging.getLogger("cryptoshield.exfiltration.transfer_monitor")


class TransferMonitor:
    """
    Monitors outbound transfer attempts. Guarantees that any network interaction
    is strictly constrained to loopback endpoints (127.0.0.1 / localhost).
    """

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        mock_receiver: Optional[Any] = None,
        transfer_callback: Optional[Callable[[OutboundTransferRecord], None]] = None,
        dlp_gate: Optional[Any] = None,
    ) -> None:
        self.bus = event_bus or BUS
        self.mock_receiver = mock_receiver
        self.transfer_callback = transfer_callback
        self.dlp_gate = dlp_gate

        self._transfer_records: List[OutboundTransferRecord] = []
        self._lock = threading.Lock()
        self._total_bytes_transferred: int = 0
        self._total_transfers_completed: int = 0
        self._total_transfers_failed: int = 0
        self._total_transfers_blocked: int = 0

    def record_transfer(
        self,
        destination_endpoint: str,
        bytes_transferred: int,
        file_count: int,
        protocol: TransferProtocol = TransferProtocol.MOCK_SOCKET,
        process_id: Optional[int] = None,
        process_name: Optional[str] = None,
        classifications: Optional[List[str]] = None,
        departments: Optional[List[str]] = None,
        contains_canary: bool = False,
        status: TransferStatus = TransferStatus.COMPLETED,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> OutboundTransferRecord:
        """
        Records an outbound transfer telemetry entry. Validates loopback safety.
        """
        # Validate endpoint safety
        host = destination_endpoint.split(":")[0] if ":" in destination_endpoint else destination_endpoint
        if host not in ("127.0.0.1", "localhost"):
            raise ValueError(
                f"Security Invariant: Exfiltration transfers must only target loopback (127.0.0.1), got {destination_endpoint}"
            )

        with self._lock:
            record = OutboundTransferRecord(
                transfer_id=f"XFER-{uuid.uuid4().hex[:8].upper()}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                destination_endpoint=destination_endpoint,
                protocol=protocol.value if isinstance(protocol, TransferProtocol) else str(protocol),
                bytes_transferred=bytes_transferred,
                file_count=file_count,
                process_id=process_id,
                process_name=process_name,
                classifications_included=classifications or [],
                departments_included=departments or [],
                contains_canary=contains_canary,
                status=status.value if isinstance(status, TransferStatus) else str(status),
                metadata=metadata or {},
            )
            self._transfer_records.append(record)

            if status == TransferStatus.COMPLETED:
                self._total_bytes_transferred += bytes_transferred
                self._total_transfers_completed += 1
            elif status == TransferStatus.BLOCKED:
                self._total_transfers_blocked += 1
            elif status == TransferStatus.FAILED:
                self._total_transfers_failed += 1

            self._publish_transfer(record)
            return record

    def transmit_to_mock_endpoint(
        self,
        target_host: str,
        target_port: int,
        payload_bytes: bytes,
        file_count: int = 1,
        process_id: Optional[int] = None,
        process_name: Optional[str] = "controlled_exfiltration_simulator",
        classifications: Optional[List[str]] = None,
        departments: Optional[List[str]] = None,
        contains_canary: bool = False,
        chunk_size: int = 65536,
    ) -> OutboundTransferRecord:
        """
        Executes an actual TCP socket transmission to the local MockReceiver endpoint.
        Transmits data in chunks and records real-time throughput metrics.
        If a DLPTransferGate is attached, intercepts and evaluates the transfer before transmission.
        """
        if target_host not in ("127.0.0.1", "localhost"):
            raise ValueError(f"Security Invariant: Outbound target must be 127.0.0.1, got {target_host}")

        endpoint_str = f"{target_host}:{target_port}"

        # DLP Interception Check
        if self.dlp_gate:
            evaluation = self.dlp_gate.evaluate_transfer(
                destination_endpoint=endpoint_str,
                payload_bytes=payload_bytes,
                file_count=file_count,
                process_id=process_id,
                process_name=process_name,
                classifications=classifications,
                departments=departments,
                contains_canary=contains_canary,
            )
            if not evaluation.allowed:
                logger.warning(
                    "[DLP GATE] Transfer to %s intercepted and BLOCKED: %s (Action: %s)",
                    endpoint_str,
                    evaluation.reason,
                    evaluation.action.value,
                )
                return self.record_transfer(
                    destination_endpoint=endpoint_str,
                    bytes_transferred=0,  # Zero bytes transferred!
                    file_count=file_count,
                    protocol=TransferProtocol.MOCK_SOCKET,
                    process_id=process_id,
                    process_name=process_name,
                    classifications=classifications,
                    departments=departments,
                    contains_canary=contains_canary,
                    status=TransferStatus.BLOCKED,
                    metadata={
                        "dlp_intercepted": True,
                        "dlp_action": evaluation.action.value,
                        "dlp_rule_id": evaluation.triggered_rule_id,
                        "dlp_reason": evaluation.reason,
                        "dlp_evaluation_id": evaluation.evaluation_id,
                        "approval_token": evaluation.approval_token,
                        "payload_size_requested": len(payload_bytes),
                    },
                )
        total_sent = 0
        transfer_status = TransferStatus.COMPLETED

        protocol_used = TransferProtocol.MOCK_SOCKET
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect((target_host, target_port))

                # Stream payload in chunks
                for offset in range(0, len(payload_bytes), chunk_size):
                    chunk = payload_bytes[offset : offset + chunk_size]
                    sock.sendall(chunk)
                    total_sent += len(chunk)

        except (PermissionError, OSError) as e:
            # If the host environment or sandbox restricts raw outbound socket connections (e.g. WinError 10013),
            # seamlessly route via MockReceiver's in-memory loopback transport bridge
            logger.debug("Socket connect restricted by environment (%s); routing to in-memory loopback bridge.", e)
            try:
                receiver = self.mock_receiver
                if not receiver:
                    from app.exfiltration.exfiltration_coordinator import EXFILTRATION_COORDINATOR
                    receiver = EXFILTRATION_COORDINATOR.receiver

                if receiver and receiver.is_running():
                    total_sent = receiver.deliver_mock_payload(payload_bytes)
                    transfer_status = TransferStatus.COMPLETED
                    protocol_used = TransferProtocol.LOCAL_PIPE
                else:
                    transfer_status = TransferStatus.FAILED
            except Exception as bridge_err:
                logger.error("Bridge delivery failed: %s", bridge_err)
                transfer_status = TransferStatus.FAILED
        except Exception as e:
            logger.error("Error during mock exfiltration socket transmission: %s", e)
            transfer_status = TransferStatus.FAILED

        return self.record_transfer(
            destination_endpoint=endpoint_str,
            bytes_transferred=total_sent,
            file_count=file_count,
            protocol=protocol_used,
            process_id=process_id,
            process_name=process_name,
            classifications=classifications,
            departments=departments,
            contains_canary=contains_canary,
            status=transfer_status,
            metadata={"payload_size_requested": len(payload_bytes)},
        )

    def get_transfer_records(self) -> List[OutboundTransferRecord]:
        """Returns all recorded transfer events."""
        with self._lock:
            return list(self._transfer_records)

    def get_metrics(self) -> Dict[str, Any]:
        """Returns aggregate metrics on monitored transfer operations."""
        with self._lock:
            return {
                "total_bytes_transferred": self._total_bytes_transferred,
                "total_transfers_completed": self._total_transfers_completed,
                "total_transfers_failed": self._total_transfers_failed,
                "total_transfers_blocked": self._total_transfers_blocked,
                "total_transfers_monitored": len(self._transfer_records),
            }

    def reset(self) -> None:
        """Clears all transfer history and metrics."""
        with self._lock:
            self._transfer_records.clear()
            self._total_bytes_transferred = 0
            self._total_transfers_completed = 0
            self._total_transfers_failed = 0
            self._total_transfers_blocked = 0

    def _publish_transfer(self, record: OutboundTransferRecord) -> None:
        """Publishes transfer records to the EventBus."""
        if record.status == TransferStatus.COMPLETED.value:
            event_type = "EXFILTRATION_TRANSFER_COMPLETED"
        elif record.status == TransferStatus.BLOCKED.value:
            event_type = "EXFILTRATION_TRANSFER_BLOCKED"
        else:
            event_type = "EXFILTRATION_TRANSFER_FAILED"

        bus_event = Event(
            event_type=event_type,
            data=record.to_dict(),
            source="transfer_monitor",
        )
        self.bus.publish(bus_event)

        if self.transfer_callback:
            try:
                self.transfer_callback(record)
            except Exception as e:
                logger.error("Error in transfer callback: %s", e)
