"""
Tests for Safe Local Mock Receiver (Phase 7).
"""

from __future__ import annotations

import pytest

from app.exfiltration.mock_receiver import MockReceiver


def test_mock_receiver_rejects_external_hosts():
    with pytest.raises(ValueError, match="must only bind to localhost"):
        MockReceiver(host="192.168.1.100")

    with pytest.raises(ValueError, match="must only bind to localhost"):
        MockReceiver(host="8.8.8.8")


def test_mock_receiver_lifecycle():
    receiver = MockReceiver(host="127.0.0.1", port=0)
    assert not receiver.is_running()

    host, port = receiver.start()
    assert receiver.is_running()
    assert host == "127.0.0.1"
    assert port > 0
    assert receiver.endpoint == f"127.0.0.1:{port}"

    receiver.stop()
    assert not receiver.is_running()


def test_mock_receiver_context_manager():
    with MockReceiver(host="127.0.0.1", port=0) as receiver:
        assert receiver.is_running()
    assert not receiver.is_running()


def test_mock_receiver_deliver_mock_payload():
    receiver = MockReceiver(host="127.0.0.1", port=0)
    receiver.start()
    try:
        data = b"Simulated exfiltration packet payload 12345"
        delivered = receiver.deliver_mock_payload(data)
        assert delivered == len(data)

        metrics = receiver.get_metrics()
        assert metrics["total_bytes_received"] == len(data)
        assert metrics["total_connections"] == 1

        receiver.reset_metrics()
        metrics_reset = receiver.get_metrics()
        assert metrics_reset["total_bytes_received"] == 0
        assert metrics_reset["total_connections"] == 0
    finally:
        receiver.stop()
