"""
Unit and integration tests for FilesystemMonitor and Watchdog telemetry.
"""

import time
from pathlib import Path
from typing import List

import pytest

from app.core.models import MonitoringEvent
from app.lab.lab_manager import LabManager
from app.monitoring.event_normalizer import EventNormalizer
from app.monitoring.filesystem_monitor import FilesystemMonitor


@pytest.fixture
def temp_lab(tmp_path: Path) -> Path:
    """Fixture providing an authentic temporary laboratory directory."""
    mgr = LabManager(base_lab_dir=tmp_path)
    mgr.initialize_lab()
    return tmp_path


def test_filesystem_file_lifecycle(temp_lab: Path):
    """Test observation of file create, modify, rename, and delete events."""
    captured: List[MonitoringEvent] = []

    def on_event(ev: MonitoringEvent):
        captured.append(ev)

    monitor = FilesystemMonitor(
        base_lab_dir=temp_lab,
        event_callback=on_event,
        debounce_seconds=0.01,
        observer_timeout=0.02,
    )
    monitor.start()
    time.sleep(0.2)  # Allow watchdog observer to initialize

    try:
        # 1. Create directory and file
        fin_dir = temp_lab / "Finance"
        fin_dir.mkdir(parents=True, exist_ok=True)
        time.sleep(0.1)

        test_file = fin_dir / "q1_report.csv"
        test_file.write_text("col1,col2\nval1,val2\n", encoding="utf-8")
        time.sleep(0.2)

        # 2. Modify file
        with open(test_file, "a", encoding="utf-8") as f:
            f.write("val3,val4\n")
        time.sleep(0.2)

        # 3. Rename file
        renamed_file = fin_dir / "q1_report_final.csv"
        test_file.rename(renamed_file)
        time.sleep(0.2)

        # 4. Delete file
        renamed_file.unlink()
        time.sleep(0.2)

    finally:
        monitor.stop()

    event_types = [e.event_type for e in captured]
    assert any("CREATED" in t for t in event_types), f"Expected creation event in {event_types}"
    assert any("MODIFIED" in t for t in event_types), f"Expected modification event in {event_types}"
    assert any("MOVED" in t for t in event_types), f"Expected move/rename event in {event_types}"
    assert any("DELETED" in t for t in event_types), f"Expected deletion event in {event_types}"

    # Verify normalized relative paths
    csv_events = [e for e in captured if e.relative_path and "q1_report" in e.relative_path]
    assert len(csv_events) > 0
    for ev in csv_events:
        assert not ev.relative_path.startswith("/")
        assert not ev.relative_path.startswith("\\")
        assert "\\" not in ev.relative_path  # POSIX normalized


def test_filesystem_directory_events(temp_lab: Path):
    """Test observation of directory creation and nested directory creation."""
    captured: List[MonitoringEvent] = []

    monitor = FilesystemMonitor(
        base_lab_dir=temp_lab,
        event_callback=lambda ev: captured.append(ev),
        debounce_seconds=0.01,
        observer_timeout=0.02,
    )
    monitor.start()
    time.sleep(0.2)

    try:
        sub_dir = temp_lab / "Operations" / "Deep" / "Nested"
        sub_dir.mkdir(parents=True, exist_ok=True)
        time.sleep(0.3)
    finally:
        monitor.stop()

    dir_events = [e for e in captured if "DIR" in e.event_type]
    assert len(dir_events) >= 1
    assert any("Operations" in e.relative_path for e in dir_events)


def test_filesystem_event_coalescing(temp_lab: Path):
    """Test that rapid multiple modifications on the same file are debounced."""
    captured: List[MonitoringEvent] = []

    monitor = FilesystemMonitor(
        base_lab_dir=temp_lab,
        event_callback=lambda ev: captured.append(ev),
        debounce_seconds=0.20,  # 200ms debounce
        observer_timeout=0.02,
    )
    monitor.start()
    time.sleep(0.2)

    try:
        test_file = temp_lab / "rapid_write.txt"
        test_file.write_text("init\n")
        time.sleep(0.1)

        # Rapidly write 10 times
        for i in range(10):
            with open(test_file, "a") as f:
                f.write(f"line {i}\n")
            time.sleep(0.01)

        time.sleep(0.3)
    finally:
        monitor.stop()

    status = monitor.get_status()
    # At least some events must have been coalesced
    assert status["events_coalesced"] > 0, f"Expected coalesced events, got {status}"


def test_filesystem_clean_shutdown(temp_lab: Path):
    """Test that monitor can cleanly start and stop repeatedly without leaking threads."""
    monitor = FilesystemMonitor(base_lab_dir=temp_lab)
    assert not monitor.is_running

    monitor.start()
    assert monitor.is_running
    monitor.stop()
    assert not monitor.is_running

    # Re-start and re-stop
    monitor.start()
    assert monitor.is_running
    monitor.stop()
    assert not monitor.is_running


def test_filesystem_safety_boundary(temp_lab: Path, tmp_path_factory):
    """Test rejection of paths outside lab, path traversal, and boundary enforcement."""
    normalizer = EventNormalizer(base_lab_dir=temp_lab)

    # 1. Path strictly inside lab
    valid_path = temp_lab / "Finance" / "doc.txt"
    assert normalizer.normalize_path(valid_path) == "Finance/doc.txt"

    # 2. Path outside lab
    outside_dir = tmp_path_factory.mktemp("outside_host")
    outside_file = outside_dir / "secret.txt"
    assert normalizer.normalize_path(outside_file) is None

    # 3. Path traversal attempt (e.g. lab/../outside)
    traversal_file = temp_lab / ".." / outside_dir.name / "secret.txt"
    assert normalizer.normalize_path(traversal_file) is None

    # 4. Target lab root itself is ignored (not a file event)
    assert normalizer.normalize_path(temp_lab) is None


def test_filesystem_ignored_files_and_directories(temp_lab: Path):
    """Ensure lab marker, git directories, and hidden files are ignored."""
    normalizer = EventNormalizer(base_lab_dir=temp_lab)

    # Marker file
    marker_file = temp_lab / ".cryptoshield_lab_marker"
    assert normalizer.normalize_path(marker_file) is None

    # Git directory
    git_file = temp_lab / ".git" / "config"
    assert normalizer.normalize_path(git_file) is None

    # Pytest cache
    cache_file = temp_lab / ".pytest_cache" / "v" / "cache"
    assert normalizer.normalize_path(cache_file) is None

