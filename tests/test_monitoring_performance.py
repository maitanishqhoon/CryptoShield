"""
Performance, throughput, latency, and resource-safety tests for Monitoring Engine.
"""

import os
import queue
import time
from pathlib import Path
from unittest.mock import patch

import psutil
import pytest

from app.core.models import MonitoringEvent
from app.lab.lab_manager import LabManager
from app.monitoring.coordinator import MonitoringCoordinator
from app.monitoring.filesystem_monitor import FilesystemMonitor


@pytest.fixture
def temp_lab(tmp_path: Path) -> Path:
    mgr = LabManager(base_lab_dir=tmp_path)
    mgr.initialize_lab()
    return tmp_path


def test_controlled_event_bursts_and_latency(temp_lab: Path):
    """Test rapid burst of 100 events measuring processing latency and throughput."""
    coordinator = MonitoringCoordinator(base_lab_dir=temp_lab)
    coordinator.start(enable_process_monitor=False)

    latencies = []
    test_dir = temp_lab / "BurstTest"
    test_dir.mkdir(parents=True, exist_ok=True)

    try:
        for i in range(100):
            fp = test_dir / f"f_{i:03d}.txt"
            t0 = time.perf_counter()
            fp.write_text(f"content {i}")
            ev = coordinator.access_monitor.record_access(fp)
            lat_ms = (time.perf_counter() - t0) * 1000.0
            latencies.append(lat_ms)

        avg_lat = sum(latencies) / len(latencies)
        assert avg_lat < 10.0, f"Average instrumentation latency exceeded 10ms: {avg_lat:.2f}ms"
        assert coordinator.events_observed >= 100

    finally:
        coordinator.stop()


def test_queue_saturation_and_graceful_drop():
    """Verify that queue saturation drops events gracefully with warning without crashing."""
    raw_q: queue.Queue = queue.Queue(maxsize=10)
    from app.monitoring.filesystem_monitor import _WatchdogQueueHandler

    handler = _WatchdogQueueHandler(raw_q)
    assert handler.dropped_events == 0

    # Fill queue to capacity (10 items)
    for i in range(10):
        handler._enqueue("FILE_CREATED", f"/path/{i}")

    assert raw_q.full()
    assert handler.dropped_events == 0

    # Overfill queue (next 5 items should be safely dropped and counted)
    for i in range(10, 15):
        handler._enqueue("FILE_CREATED", f"/path/{i}")

    assert handler.dropped_events == 5
    assert raw_q.qsize() == 10


def test_no_repeated_file_hashing_during_monitoring(temp_lab: Path):
    """Confirm monitoring events do NOT compute SHA-256 disk hashes of files."""
    coordinator = MonitoringCoordinator(base_lab_dir=temp_lab)
    coordinator.start(enable_process_monitor=False)

    test_file = temp_lab / "Finance" / "audit.csv"
    test_file.parent.mkdir(parents=True, exist_ok=True)
    test_file.write_text("a,b,c\n1,2,3\n")

    with patch("app.lab.manifest.compute_file_sha256") as mock_hash:
        for _ in range(50):
            coordinator.access_monitor.record_access(test_file)

        # compute_file_sha256 should NEVER be invoked for monitoring/access events
        assert mock_hash.call_count == 0

    coordinator.stop()


def test_monitoring_shutdown_releases_resources(temp_lab: Path):
    """Confirm monitoring shutdown terminates all worker and observer threads."""
    initial_threads = psutil.Process(os.getpid()).num_threads()

    coordinator = MonitoringCoordinator(base_lab_dir=temp_lab)
    coordinator.start(enable_process_monitor=True)
    assert coordinator.is_running
    time.sleep(0.2)

    active_threads = psutil.Process(os.getpid()).num_threads()
    assert active_threads > initial_threads

    coordinator.stop()
    assert not coordinator.is_running
    time.sleep(0.3)

    # Threads should have cleanly returned to near initial state
    final_threads = psutil.Process(os.getpid()).num_threads()
    assert final_threads <= initial_threads + 1
