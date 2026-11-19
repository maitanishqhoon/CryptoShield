"""
Unit tests for CryptoShield EventBusBridge and AsyncWorker (Phase 10).
"""

import os
import sys
import time
import pytest

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication
from app.core.event_bus import Event, EventBus
from app.ui.bridge import EventBusBridge
from app.ui.workers import AsyncWorker


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


def test_event_bus_bridge_signals(qapp):
    """Test EventBusBridge signal emission from EventBus events."""
    bus = EventBus()
    bridge = EventBusBridge(bus=bus)
    bridge.connect_bus()

    received_events = []
    threat_signals = []
    incidents = []
    containment_signals = []

    bridge.event_received.connect(lambda ev: received_events.append(ev))
    bridge.threat_updated.connect(lambda s, sev: threat_signals.append((s, sev)))
    bridge.incident_created.connect(lambda d: incidents.append(d))
    bridge.containment_triggered.connect(lambda d: containment_signals.append(d))

    # Publish generic event
    ev1 = Event(event_type="FILE_CREATED", data={"path": "test.txt"})
    bus.publish(ev1)
    assert len(received_events) == 1
    assert received_events[0].event_type == "FILE_CREATED"

    # Publish detection result
    ev2 = Event(event_type="DETECTION_RESULT", data={"score": 85, "severity": "CRITICAL"})
    bus.publish(ev2)
    assert len(threat_signals) == 1
    assert threat_signals[0] == (85, "CRITICAL")

    # Publish incident event
    ev3 = Event(event_type="SECURITY_INCIDENT_CREATED", data={"incident_id": "INC-12345678", "threat_score": 90, "severity": "CRITICAL"})
    bus.publish(ev3)
    assert len(incidents) == 1
    assert incidents[0]["incident_id"] == "INC-12345678"

    # Publish containment event
    ev4 = Event(event_type="CONTAINMENT_COMPLETED", data={"containment_id": "CONT-ABCDEF12", "action": "LOCK"})
    bus.publish(ev4)
    assert len(containment_signals) == 1

    # Disconnect
    bridge.disconnect_bus()
    bus.publish(Event(event_type="FILE_MODIFIED", data={}))
    assert len(received_events) == 4  # Unchanged after disconnect


def test_async_worker_execution(qapp):
    """Test AsyncWorker non-blocking execution, signals, and results."""
    def sample_task(val: int) -> int:
        return val * 2

    worker = AsyncWorker(sample_task, 21)
    results = []
    started_flags = []

    worker.signals.started.connect(lambda: started_flags.append(True))
    worker.signals.finished.connect(lambda r: results.append(r))

    worker.start()
    worker.wait(2000)
    qapp.processEvents()

    assert len(started_flags) == 1
    assert len(results) == 1
    assert results[0] == 42


def test_async_worker_progress(qapp):
    """Test AsyncWorker with a function that takes a progress callback."""
    def progress_task(progress=None):
        if progress:
            progress(50, 100, "Halfway")
            progress(100, 100, "Done")
        return "SUCCESS"

    worker = AsyncWorker(progress_task)
    progress_updates = []
    results = []

    worker.signals.progress.connect(lambda c, t, m: progress_updates.append((c, t, m)))
    worker.signals.finished.connect(lambda r: results.append(r))

    worker.start()
    worker.wait(2000)
    qapp.processEvents()

    assert len(progress_updates) == 2
    assert progress_updates[0] == (50, 100, "Halfway")
    assert progress_updates[1] == (100, 100, "Done")
    assert results == ["SUCCESS"]


def test_async_worker_error_handling(qapp):
    """Test AsyncWorker properly catches exceptions and emits error signal."""
    def failing_task():
        raise ValueError("Simulated Task Failure")

    worker = AsyncWorker(failing_task)
    errors = []

    worker.signals.error.connect(lambda e: errors.append(e))

    worker.start()
    worker.wait(2000)
    qapp.processEvents()

    assert len(errors) == 1
    assert "Simulated Task Failure" in errors[0]
