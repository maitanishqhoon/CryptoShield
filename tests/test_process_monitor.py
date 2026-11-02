"""
Unit and integration tests for ProcessMonitor and psutil telemetry.
"""

import os
import subprocess
import sys
import time
from typing import List

import psutil
import pytest

from app.core.models import MonitoringEvent, ProcessAttribution
from app.monitoring.process_monitor import ProcessMonitor


def test_process_snapshot_collection():
    """Test instantaneous snapshot collection of running processes."""
    monitor = ProcessMonitor()
    monitor._seed_initial_processes()
    snapshot = monitor.take_snapshot()

    assert len(snapshot) > 0
    # Current process should be in snapshot
    current_pid = os.getpid()
    matching = [p for p in snapshot if p["pid"] == current_pid]
    assert len(matching) == 1
    p = matching[0]
    assert "pid" in p
    assert "name" in p
    assert "exe" in p
    assert "username" in p

    # Ensure sensitive items like environment vars or command line arguments are NOT exposed
    assert "cmdline" not in p
    assert "environ" not in p
    assert "passwords" not in p


def test_process_lifecycle_start_and_exit():
    """Test detecting newly spawned and terminated process via poll_once."""
    events_started: List[MonitoringEvent] = []
    events_exited: List[MonitoringEvent] = []

    def on_event(ev: MonitoringEvent):
        if ev.event_type == "PROCESS_STARTED":
            events_started.append(ev)
        elif ev.event_type == "PROCESS_EXITED":
            events_exited.append(ev)

    monitor = ProcessMonitor(event_callback=on_event, poll_interval_seconds=0.1)
    monitor._seed_initial_processes()

    # Launch a controlled short-lived subprocess
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.5)"])
    sub_pid = proc.pid

    try:
        # First poll: Should detect new process
        started, exited = monitor.poll_once()
        started_pids = [e.process_id for e in started]
        assert sub_pid in started_pids

        # Wait for subprocess to finish
        proc.wait(timeout=2.0)

        # Second poll: Should detect process exit
        started_2, exited_2 = monitor.poll_once()
        exited_pids = [e.process_id for e in exited_2]
        assert sub_pid in exited_pids

    finally:
        if proc.poll() is None:
            proc.kill()


def test_process_graceful_handling_of_inaccessible():
    """Test that inaccessible or invalid processes do not crash the telemetry engine."""
    monitor = ProcessMonitor()

    # Simulate empty info or invalid pid
    safe_info = monitor._extract_safe_process_info({"pid": 99999999, "name": None, "exe": None})
    assert safe_info["pid"] == 99999999
    assert safe_info["name"] == "unknown"
    assert safe_info["exe"] == "unknown"


def test_process_no_termination_or_alteration():
    """Verify that ProcessMonitor never kills, suspends, or alters any host process."""
    monitor = ProcessMonitor()
    current_pid = os.getpid()

    # Verify current process is alive before and after
    assert psutil.pid_exists(current_pid)
    monitor.poll_once()
    assert psutil.pid_exists(current_pid)


def test_process_attribution_unknown_for_filesystem():
    """Verify that filesystem events default attribution to UNKNOWN without false claims."""
    from app.monitoring.event_normalizer import EventNormalizer

    normalizer = EventNormalizer()
    ev = normalizer.create_filesystem_event(
        event_type="FILE_MODIFIED",
        raw_path="Finance/report.csv",
    )
    assert ev is not None
    assert ev.process_attribution == ProcessAttribution.UNKNOWN.value
    assert ev.process_id is None
    assert ev.process_name is None
