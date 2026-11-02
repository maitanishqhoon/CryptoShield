"""
Unit and integration tests for MonitoringCoordinator.
"""

import time
from pathlib import Path
from typing import List

import pytest

from app.core.event_bus import BUS, Event
from app.core.models import MonitoringEvent
from app.core.safety import SafetyViolationError
from app.lab.lab_manager import LabManager
from app.monitoring.coordinator import MonitoringCoordinator


@pytest.fixture
def temp_lab(tmp_path: Path) -> Path:
    mgr = LabManager(base_lab_dir=tmp_path)
    mgr.initialize_lab()
    return tmp_path


def test_coordinator_requires_valid_marker(tmp_path: Path):
    """Test that coordinator refuses to start in an uninitialized directory without marker."""
    coordinator = MonitoringCoordinator(base_lab_dir=tmp_path)
    with pytest.raises(SafetyViolationError):
        coordinator.start()


def test_coordinator_lifecycle_and_duplicate_prevention(temp_lab: Path):
    """Test start, stop, duplicate start handling, and status metrics."""
    coord1 = MonitoringCoordinator(base_lab_dir=temp_lab)
    assert not coord1.is_running

    coord1.start(enable_process_monitor=False)
    assert coord1.is_running
    assert MonitoringCoordinator._active_instance is coord1

    # Attempting to start again should log warning and remain safe
    coord1.start()
    assert coord1.is_running

    status = coord1.get_status()
    assert status["is_running"] is True
    assert status["monitored_root"] == str(temp_lab)

    coord1.stop()
    assert not coord1.is_running
    assert MonitoringCoordinator._active_instance is None


def test_coordinator_unifies_events_and_dispatches_to_bus(temp_lab: Path):
    """Test that coordinator routes filesystem and access events to EventBus and listeners."""
    coordinator = MonitoringCoordinator(
        base_lab_dir=temp_lab,
        debounce_seconds=0.01,
    )

    listener_events: List[MonitoringEvent] = []
    bus_events: List[Event] = []

    def on_listener(ev: MonitoringEvent):
        listener_events.append(ev)

    def on_bus(ev: Event):
        bus_events.append(ev)

    coordinator.add_listener(on_listener)
    BUS.subscribe("*", on_bus)

    try:
        coordinator.start(enable_process_monitor=False)
        time.sleep(0.15)

        # 1. Trigger access instrumentation
        test_file = temp_lab / "Finance" / "budget.csv"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("item,cost\nserver,5000\n", encoding="utf-8")
        time.sleep(0.15)

        coordinator.access_monitor.read_file(test_file)
        time.sleep(0.15)

        assert len(listener_events) > 0
        assert len(bus_events) > 0
        assert coordinator.events_observed > 0

    finally:
        coordinator.stop()
        BUS.unsubscribe("*", on_bus)
