"""
Comprehensive test suite for Canary Decoy File Monitoring and High-Priority Telemetry.
"""

import json
import os
from pathlib import Path
from typing import List

import psutil
import pytest

from app.config import CONFIG
from app.core.event_bus import BUS, Event
from app.core.models import Manifest, ManifestEntry, MonitoringEvent
from app.lab.lab_manager import LabManager
from app.monitoring.access_monitor import AccessMonitor


@pytest.fixture
def lab_with_canary(tmp_path: Path):
    """Fixture providing a lab initialized with a registered canary manifest."""
    mgr = LabManager(base_lab_dir=tmp_path)
    mgr.initialize_lab()

    # Create one normal file and one canary file
    normal_path = tmp_path / "Finance" / "ledger.csv"
    normal_path.parent.mkdir(parents=True, exist_ok=True)
    normal_path.write_text("account,balance\n1001,500\n", encoding="utf-8")

    canary_path = tmp_path / "Finance" / "salary_canary_decoy.csv"
    canary_path.write_text("name,salary\nAlice,100000\nBob,120000\n", encoding="utf-8")

    manifest = Manifest(
        manifest_version="1.0.0",
        lab_id="test-lab-canary",
        generated_at="2026-11-02T12:00:00Z",
        total_files=2,
        total_size_bytes=100,
        canary_count=1,
        seed=42,
        entries={
            "Finance/ledger.csv": ManifestEntry(
                relative_path="Finance/ledger.csv",
                file_type="csv",
                file_size_bytes=30,
                data_classification="CONFIDENTIAL",
                sha256="dummyhash1",
                is_canary=False,
                department="Finance",
                created_at="2026-11-02T12:00:00Z",
            ),
            "Finance/salary_canary_decoy.csv": ManifestEntry(
                relative_path="Finance/salary_canary_decoy.csv",
                file_type="csv",
                file_size_bytes=50,
                data_classification="RESTRICTED",
                sha256="dummyhash2",
                is_canary=True,
                department="Finance",
                created_at="2026-11-02T12:00:00Z",
            ),
        },
    )

    return tmp_path, manifest, normal_path, canary_path


def test_canary_access_generates_distinct_event(lab_with_canary):
    """Test that accessing a canary triggers a CANARY_ACCESS event with HIGH priority."""
    lab_dir, manifest, normal_path, canary_path = lab_with_canary

    monitor = AccessMonitor(base_lab_dir=lab_dir, manifest=manifest)

    # 1. Read normal file
    ev_normal = monitor.record_access(normal_path)
    assert ev_normal.event_type == "FILE_READ"
    assert not ev_normal.is_canary
    assert ev_normal.priority == "NORMAL"
    assert ev_normal.canary_id is None

    # 2. Read canary file
    ev_canary = monitor.record_access(canary_path, pid=os.getpid(), process_name="test_canary_proc")
    assert ev_canary.event_type == "CANARY_ACCESS"
    assert ev_canary.is_canary is True
    assert ev_canary.canary_id == "Finance/salary_canary_decoy.csv"
    assert ev_canary.priority in {"HIGH", "CRITICAL"}
    assert ev_canary.relative_path == "Finance/salary_canary_decoy.csv"
    assert ev_canary.metadata.get("classification") == "RESTRICTED"
    assert ev_canary.metadata.get("department") == "Finance"


def test_canary_published_to_event_bus(lab_with_canary):
    """Verify that CANARY_ACCESS events are published to the global EventBus."""
    lab_dir, manifest, _, canary_path = lab_with_canary

    bus_events: List[Event] = []

    def bus_listener(ev: Event):
        if ev.event_type == "CANARY_ACCESS":
            bus_events.append(ev)

    BUS.subscribe("CANARY_ACCESS", bus_listener)

    try:
        monitor = AccessMonitor(base_lab_dir=lab_dir, manifest=manifest)
        monitor.record_access(canary_path)

        assert len(bus_events) == 1
        bus_ev = bus_events[0]
        assert bus_ev.event_type == "CANARY_ACCESS"
        assert bus_ev.data["is_canary"] is True
        assert bus_ev.data["relative_path"] == "Finance/salary_canary_decoy.csv"
        assert bus_ev.data["priority"] == "HIGH"
    finally:
        BUS.unsubscribe("CANARY_ACCESS", bus_listener)


def test_canary_appears_in_jsonl_log(lab_with_canary):
    """Verify that canary access is recorded in structured JSONL audit trail."""
    lab_dir, manifest, _, canary_path = lab_with_canary
    json_log = CONFIG.json_log_path

    monitor = AccessMonitor(base_lab_dir=lab_dir, manifest=manifest)
    ev = monitor.record_access(canary_path, pid=9999, process_name="malicious_sim")

    # Read the tail of the JSON log file
    assert json_log.exists(), f"JSON log file missing at {json_log}"
    with open(json_log, "r", encoding="utf-8") as f:
        lines = f.readlines()

    canary_logs = []
    for line in lines[-20:]:
        try:
            entry = json.loads(line)
            if entry.get("audit_event") == "CANARY_ACCESS" or entry.get("canary_id") == "Finance/salary_canary_decoy.csv":
                canary_logs.append(entry)
        except Exception:
            pass

    assert len(canary_logs) >= 1
    log_entry = canary_logs[-1]
    assert log_entry.get("audit_event") == "CANARY_ACCESS"
    assert log_entry.get("relative_path") == "Finance/salary_canary_decoy.csv"


def test_canary_does_not_terminate_process(lab_with_canary):
    """Verify that in Phase 2, canary tripping does NOT terminate or contain any process."""
    lab_dir, manifest, _, canary_path = lab_with_canary
    current_pid = os.getpid()

    monitor = AccessMonitor(base_lab_dir=lab_dir, manifest=manifest)
    monitor.record_access(canary_path, pid=current_pid)

    # Calling process must still be fully alive
    assert psutil.pid_exists(current_pid)
    assert monitor.canary_trips_count == 1
