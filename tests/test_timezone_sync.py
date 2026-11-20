"""
Unit tests for Indian Standard Time (IST) Synchronization across CryptoShield.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from app.config import CONFIG
from app.core.event_bus import Event
from app.core.models import SecurityIncident
from app.core.safety import generate_lab_marker
from app.core.time import (
    IST,
    format_ist,
    from_timestamp_ist,
    now_iso,
    now_ist,
    parse_iso_to_ist,
)
from app.reporting.aggregator import ForensicAggregator
from app.reporting.exporter import ReportExporter
from app.reporting.models import ForensicDossier, ForensicTimelineEntry


def test_ist_constants_and_helpers():
    """Verify IST timezone offset, name, and helper functions."""
    assert CONFIG.TIMEZONE == IST
    assert CONFIG.TIMEZONE_NAME == "IST"
    assert IST.utcoffset(None) == timedelta(hours=5, minutes=30)
    assert IST.tzname(None) == "IST"

    dt_now = now_ist()
    assert dt_now.tzinfo == IST

    iso_str = now_iso()
    assert "+05:30" in iso_str

    formatted = format_ist(dt_now)
    assert "IST" in formatted

    epoch_ts = 1772534400.0
    dt_from_ts = from_timestamp_ist(epoch_ts)
    assert dt_from_ts.tzinfo == IST
    assert dt_from_ts.utcoffset() == timedelta(hours=5, minutes=30)


def test_parse_iso_to_ist():
    """Verify parsing naive, UTC 'Z', and offset timestamps into IST."""
    # UTC timestamp with Z
    dt_utc = parse_iso_to_ist("2026-11-20T12:00:00Z")
    assert dt_utc.tzinfo == IST
    # 12:00 UTC == 17:30 IST
    assert dt_utc.hour == 17
    assert dt_utc.minute == 30

    # Explicit offset timestamp (+00:00)
    dt_zero = parse_iso_to_ist("2026-11-20T12:00:00+00:00")
    assert dt_zero.hour == 17
    assert dt_zero.minute == 30

    # Already in IST
    dt_ist = parse_iso_to_ist("2026-11-20T19:30:00+05:30")
    assert dt_ist.hour == 19
    assert dt_ist.minute == 30

    # Naive timestamp (assumed IST)
    dt_naive = parse_iso_to_ist("2026-11-20T19:30:00")
    assert dt_naive.tzinfo == IST
    assert dt_naive.hour == 19
    assert dt_naive.minute == 30


def test_event_bus_event_ist_timestamp():
    """Verify Event default timestamps are localized in IST."""
    ev = Event(event_type="TEST_EVENT", data={"test": True})
    assert "+05:30" in ev.timestamp


def test_safety_marker_ist_timestamp(tmp_path: Path):
    """Verify LabMarker generated timestamp contains IST offset."""
    marker = generate_lab_marker(base_lab_dir=tmp_path)
    assert "+05:30" in marker.created_at


def test_forensic_reports_ist_synchronization(tmp_path: Path):
    """Verify forensic reports render timestamps in IST."""
    from tests.test_forensic_exporter import _create_sample_dossier

    dossier = _create_sample_dossier()
    exporter = ReportExporter(reports_dir=tmp_path)
    files = exporter.export_all(dossier)

    # Check Markdown
    md_content = files["markdown"].read_text(encoding="utf-8")
    assert "Timestamp (IST)" in md_content
    assert "Timestamp (UTC)" not in md_content

    # Check HTML
    html_content = files["html"].read_text(encoding="utf-8")
    assert "Time (IST)" in html_content
    assert "Time (UTC)" not in html_content
    assert "Sealed:</strong>" in html_content
    assert "IST</span>" in html_content
