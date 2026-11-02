"""
Unit tests for AccessMonitor controlled instrumentation.
"""

import os
from pathlib import Path
from typing import List

import pytest

from app.core.event_bus import BUS, Event
from app.core.models import FileAction, Manifest, ManifestEntry, MonitoringEvent
from app.core.safety import SafetyViolationError
from app.lab.lab_manager import LabManager
from app.monitoring.access_monitor import AccessMonitor


@pytest.fixture
def temp_lab(tmp_path: Path) -> Path:
    mgr = LabManager(base_lab_dir=tmp_path)
    mgr.initialize_lab()
    return tmp_path


def test_access_monitor_normal_file_read(temp_lab: Path):
    """Test instrumented read of an ordinary (non-canary) file."""
    captured: List[MonitoringEvent] = []

    monitor = AccessMonitor(
        base_lab_dir=temp_lab,
        event_callback=lambda ev: captured.append(ev),
    )

    doc = temp_lab / "Legal" / "contract.txt"
    doc.parent.mkdir(parents=True, exist_ok=True)
    doc.write_text("Confidential Non-Disclosure Agreement", encoding="utf-8")

    content = monitor.read_file(doc, pid=12345, process_name="test_reader")
    assert content == "Confidential Non-Disclosure Agreement"

    assert len(captured) == 1
    ev = captured[0]
    assert ev.event_type == "FILE_READ"
    assert ev.relative_path == "Legal/contract.txt"
    assert not ev.is_canary
    assert ev.canary_id is None
    assert ev.priority == "NORMAL"
    assert ev.process_id == 12345
    assert ev.process_name == "test_reader"
    assert ev.source == "CONTROLLED_INSTRUMENTATION"


def test_access_monitor_context_manager(temp_lab: Path):
    """Test instrumented open() context manager."""
    captured: List[MonitoringEvent] = []

    monitor = AccessMonitor(
        base_lab_dir=temp_lab,
        event_callback=lambda ev: captured.append(ev),
    )

    doc = temp_lab / "IT" / "server_config.xml"
    doc.parent.mkdir(parents=True, exist_ok=True)
    doc.write_text("<config><port>8080</port></config>", encoding="utf-8")

    with monitor.open(doc, "r") as f:
        data = f.read()

    assert "<port>8080</port>" in data
    assert len(captured) == 1
    assert captured[0].event_type == "FILE_OPEN"
    assert captured[0].relative_path == "IT/server_config.xml"


def test_access_monitor_outside_boundary_rejection(temp_lab: Path, tmp_path_factory):
    """Test that AccessMonitor rejects paths outside lab root via SafetyEngine."""
    outside_dir = tmp_path_factory.mktemp("outside_host")
    outside_file = outside_dir / "system.ini"
    outside_file.write_text("secret_os_data")

    monitor = AccessMonitor(base_lab_dir=temp_lab)

    with pytest.raises(SafetyViolationError):
        monitor.record_access(outside_file)

    with pytest.raises(SafetyViolationError):
        monitor.read_file(outside_file)
