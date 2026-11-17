"""
Tests for Staging Detector (Phase 7).
"""

from __future__ import annotations

import pytest

from app.core.event_bus import EventBus
from app.exfiltration.models import StagingType
from app.exfiltration.staging_detector import StagingDetector


def test_archive_creation_detection():
    bus = EventBus()
    detected_events = []
    bus.subscribe("EXFILTRATION_STAGING_DETECTED", lambda e: detected_events.append(e))

    detector = StagingDetector(event_bus=bus)
    detector.start()
    try:
        # Ingest archive creation event (.zip)
        event = detector.ingest_event({
            "relative_path": "runtime/lab/.staging/staged_archive.zip",
            "process_id": 4321,
            "process_name": "compressor",
            "metadata": {"baseline_size": 20480},
        })

        assert event is not None
        assert event.staging_type == StagingType.ARCHIVE_ZIP.value
        assert "staged_archive.zip" in event.staging_path
        assert len(detected_events) == 1
    finally:
        detector.stop()


def test_staging_directory_keyword_detection():
    bus = EventBus()
    detector = StagingDetector(event_bus=bus)
    detector.start()
    try:
        event = detector.ingest_event({
            "relative_path": "runtime/lab/temp_collect_folder",
            "process_id": 5555,
        })
        assert event is not None
        assert event.staging_type == StagingType.DIRECTORY_AGGREGATION.value
    finally:
        detector.stop()


def test_normal_file_creation_ignored():
    bus = EventBus()
    detector = StagingDetector(event_bus=bus)
    detector.start()
    try:
        event = detector.ingest_event({
            "relative_path": "Finance/invoices/inv_123.txt",
            "process_id": 1111,
        })
        assert event is None
        assert len(detector.get_staging_events()) == 0
    finally:
        detector.stop()


def test_record_staging_explicit():
    bus = EventBus()
    detector = StagingDetector(event_bus=bus)
    event = detector.record_staging(
        staging_path="runtime/lab/.staging/manual.zip",
        source_paths=["Finance/inv1.txt", "Legal/doc1.txt"],
        staging_type=StagingType.ARCHIVE_ZIP,
        total_staged_bytes=10000,
        process_id=9876,
    )
    assert event.staged_files_count == 2
    assert event.total_staged_bytes == 10000
    assert len(detector.get_staging_events()) == 1
