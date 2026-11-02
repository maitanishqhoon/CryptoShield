"""
Unit tests for app.detection.event_correlator.
"""

import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.event_bus import BUS, Event
from app.core.models import FileAction, MonitoringEvent, ProcessAttribution
from app.detection.event_correlator import EventCorrelator


def make_test_event(
    event_id: str = None,
    relative_path: str = "Finance/invoice.csv",
    event_type: str = "FILE_MODIFIED",
    operation: str = FileAction.MODIFY.value,
    timestamp: str = None,
    process_id: int = None,
    process_attribution: str = ProcessAttribution.UNKNOWN.value,
    is_canary: bool = False,
    source: str = "WATCHDOG",
    department: str = "Finance",
) -> MonitoringEvent:
    return MonitoringEvent(
        event_id=event_id or str(uuid.uuid4()),
        timestamp=timestamp or datetime.now(timezone.utc).isoformat(),
        event_type=event_type,
        source=source,
        relative_path=relative_path,
        is_canary=is_canary,
        process_id=process_id,
        process_name="test_proc" if process_id else None,
        process_attribution=process_attribution,
        operation=operation,
        metadata={"department": department},
    )


def test_correlator_ingests_and_summarizes():
    correlator = EventCorrelator(sliding_windows=[1.0, 5.0, 10.0], primary_window=5.0)

    # Ingest 3 events for 2 unique files
    ev1 = make_test_event(relative_path="Finance/doc1.txt")
    ev2 = make_test_event(relative_path="Finance/doc1.txt")  # Same file, another event
    ev3 = make_test_event(relative_path="HR/resume.pdf", department="Human Resources")

    assert correlator.add_event(ev1) is True
    assert correlator.add_event(ev2) is True
    assert correlator.add_event(ev3) is True

    summary = correlator.get_window_summary(window_seconds=5.0)
    assert summary.total_events == 3
    assert len(summary.unique_files) == 2
    assert "Finance/doc1.txt" in summary.unique_files
    assert "HR/resume.pdf" in summary.unique_files
    assert len(summary.unique_modified_files) == 2
    assert "Finance" in summary.departments_affected
    assert "Human Resources" in summary.departments_affected


def test_correlator_deduplicates_event_ids():
    correlator = EventCorrelator()
    dup_id = "duplicate-uuid-12345"

    ev1 = make_test_event(event_id=dup_id, relative_path="Finance/file.txt")
    ev2 = make_test_event(event_id=dup_id, relative_path="Finance/file.txt")

    assert correlator.add_event(ev1) is True
    assert correlator.add_event(ev2) is False  # Rejected duplicate

    assert correlator.events_received == 2
    assert correlator.events_processed == 1
    assert correlator.duplicate_events_ignored == 1

    summary = correlator.get_window_summary(5.0)
    assert summary.total_events == 1


def test_correlator_sliding_window_expiration():
    correlator = EventCorrelator(sliding_windows=[1.0, 5.0], primary_window=5.0)

    now = datetime.now(timezone.utc)
    old_ts = (now - timedelta(seconds=15)).isoformat()
    fresh_ts = now.isoformat()

    ev_old = make_test_event(relative_path="Finance/old.txt", timestamp=old_ts)
    ev_fresh = make_test_event(relative_path="Finance/fresh.txt", timestamp=fresh_ts)

    correlator.add_event(ev_old)
    correlator.add_event(ev_fresh)

    # 5-second window should only contain the fresh event
    summary_5s = correlator.get_window_summary(window_seconds=5.0, reference_time=now.timestamp())
    assert summary_5s.total_events == 1
    assert "Finance/fresh.txt" in summary_5s.unique_files
    assert "Finance/old.txt" not in summary_5s.unique_files


def test_correlator_process_attribution_rules():
    correlator = EventCorrelator()

    # Case 1: Unknown attribution
    ev_unknown = make_test_event(process_attribution=ProcessAttribution.UNKNOWN.value)
    correlator.add_event(ev_unknown)
    summary = correlator.get_window_summary()
    assert summary.process_attribution == ProcessAttribution.UNKNOWN.value
    assert summary.attributed_process_id is None

    correlator.clear()

    # Case 2: Confirmed attribution
    ev_confirmed = make_test_event(
        process_id=9999,
        process_attribution=ProcessAttribution.CONFIRMED.value,
    )
    correlator.add_event(ev_confirmed)
    summary = correlator.get_window_summary()
    assert summary.process_attribution == ProcessAttribution.CONFIRMED.value
    assert summary.attributed_process_id == 9999
    assert summary.attributed_process_name == "test_proc"


def test_correlator_event_bus_subscription():
    BUS.clear()
    correlator = EventCorrelator()
    correlator.start()

    ev = make_test_event(relative_path="IT/script.sh", department="IT")
    BUS.publish(ev.to_bus_event())

    summary = correlator.get_window_summary(5.0)
    assert summary.total_events == 1
    assert "IT/script.sh" in summary.unique_files

    correlator.stop()
    BUS.clear()

