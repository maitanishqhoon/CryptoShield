"""
Tests for Read Burst Detector (Phase 7).
"""

from __future__ import annotations

import time
import pytest

from app.core.event_bus import EventBus
from app.exfiltration.read_burst_detector import ReadBurstDetector


def test_normal_reads_below_threshold_do_not_trigger_burst():
    bus = EventBus()
    detector = ReadBurstDetector(event_bus=bus, burst_threshold=5, window_seconds=2.0)
    detector.start()
    try:
        # Ingest 3 normal reads (below threshold of 5)
        for i in range(3):
            burst = detector.ingest_event({
                "relative_path": f"Finance/invoices/inv_{i}.txt",
                "is_canary": False,
                "data_classification": "INTERNAL",
                "department": "Finance",
            })
            assert burst is None
        assert len(detector.get_recent_bursts()) == 0
    finally:
        detector.stop()


def test_rapid_reads_exceeding_threshold_trigger_burst():
    bus = EventBus()
    detected_bursts = []
    detector = ReadBurstDetector(
        event_bus=bus,
        burst_threshold=5,
        window_seconds=3.0,
        burst_callback=lambda b: detected_bursts.append(b),
    )
    detector.start()
    try:
        # Ingest 6 reads rapidly
        last_burst = None
        for i in range(6):
            dept = "Finance" if i % 2 == 0 else "Legal"
            burst = detector.ingest_event({
                "relative_path": f"{dept}/doc_{i}.txt",
                "is_canary": False,
                "data_classification": "CONFIDENTIAL",
                "department": dept,
                "process_id": 1234,
                "process_name": "worker_proc",
            })
            if burst:
                last_burst = burst

        assert last_burst is not None
        assert last_burst.read_count >= 5
        assert "Finance" in last_burst.department_counts
        assert "Legal" in last_burst.department_counts
        assert len(detected_bursts) >= 1
    finally:
        detector.stop()


def test_canary_read_registers_breach():
    bus = EventBus()
    canary_events = []
    bus.subscribe("CANARY_READ_BREACH", lambda e: canary_events.append(e))

    detector = ReadBurstDetector(event_bus=bus, burst_threshold=3, window_seconds=3.0)
    detector.start()
    try:
        # Ingest 2 normal reads and 1 canary read (total 3 = threshold)
        detector.ingest_event({
            "relative_path": "Finance/doc_1.txt",
            "is_canary": False,
            "department": "Finance",
        })
        detector.ingest_event({
            "relative_path": "Legal/doc_2.txt",
            "is_canary": False,
            "department": "Legal",
        })
        burst = detector.ingest_event({
            "relative_path": "IT/network_configs/passwords_master_backup.json",
            "is_canary": True,
            "data_classification": "RESTRICTED",
            "department": "IT",
        })

        assert burst is not None
        assert burst.canary_reads_count == 1
        assert "IT/network_configs/passwords_master_backup.json" in detector.get_canary_reads()
        assert len(canary_events) == 1
    finally:
        detector.stop()


def test_sliding_window_expiration():
    bus = EventBus()
    detector = ReadBurstDetector(event_bus=bus, burst_threshold=3, window_seconds=0.2)
    detector.start()
    try:
        detector.ingest_event({"relative_path": "Finance/doc1.txt", "department": "Finance"})
        detector.ingest_event({"relative_path": "Finance/doc2.txt", "department": "Finance"})
        # Wait for window to expire
        time.sleep(0.3)
        # Add 1 more read: total in window is now only 1 (not 3)
        burst = detector.ingest_event({"relative_path": "Finance/doc3.txt", "department": "Finance"})
        assert burst is None
        assert len(detector.get_recent_bursts()) == 0
    finally:
        detector.stop()
