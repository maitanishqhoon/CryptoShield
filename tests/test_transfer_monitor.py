"""
Tests for Outbound Transfer Monitor (Phase 7).
"""

from __future__ import annotations

import pytest

from app.core.event_bus import EventBus
from app.exfiltration.models import TransferProtocol, TransferStatus
from app.exfiltration.transfer_monitor import TransferMonitor


def test_transfer_monitor_rejects_external_destination():
    monitor = TransferMonitor()
    with pytest.raises(ValueError, match="must only target loopback"):
        monitor.record_transfer(
            destination_endpoint="192.168.1.50:8080",
            bytes_transferred=1024,
            file_count=1,
        )


def test_transfer_monitor_records_loopback_transfer():
    bus = EventBus()
    completed_events = []
    bus.subscribe("EXFILTRATION_TRANSFER_COMPLETED", lambda e: completed_events.append(e))

    monitor = TransferMonitor(event_bus=bus)
    record = monitor.record_transfer(
        destination_endpoint="127.0.0.1:8999",
        bytes_transferred=4096,
        file_count=3,
        protocol=TransferProtocol.MOCK_SOCKET,
        classifications=["RESTRICTED"],
        departments=["Finance"],
        contains_canary=True,
        status=TransferStatus.COMPLETED,
    )

    assert record.bytes_transferred == 4096
    assert record.contains_canary is True
    assert record.status == "COMPLETED"
    assert len(completed_events) == 1

    metrics = monitor.get_metrics()
    assert metrics["total_bytes_transferred"] == 4096
    assert metrics["total_transfers_completed"] == 1
    assert metrics["total_transfers_failed"] == 0


def test_transfer_monitor_metrics_and_reset():
    monitor = TransferMonitor()
    monitor.record_transfer(
        destination_endpoint="127.0.0.1:8999",
        bytes_transferred=1000,
        file_count=1,
        status=TransferStatus.COMPLETED,
    )
    monitor.record_transfer(
        destination_endpoint="127.0.0.1:8999",
        bytes_transferred=0,
        file_count=0,
        status=TransferStatus.FAILED,
    )

    metrics = monitor.get_metrics()
    assert metrics["total_transfers_monitored"] == 2
    assert metrics["total_transfers_completed"] == 1
    assert metrics["total_transfers_failed"] == 1

    monitor.reset()
    assert monitor.get_metrics()["total_transfers_monitored"] == 0
