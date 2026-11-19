"""
Unit tests for CryptoShield UI Theme and Reusable Components (Phase 10).
"""

import os
import sys
import pytest

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication
from app.ui.theme import (
    ThemeColors,
    get_severity_color,
    get_severity_bg,
    create_status_badge,
    create_section_header,
    apply_soc_theme,
)
from app.ui.components.kpi_card import KPICard
from app.ui.components.threat_gauge import ThreatGauge
from app.ui.components.event_table import EventTable
from app.core.event_bus import Event


@pytest.fixture(scope="session")
def qapp():
    """Ensure a singleton QApplication instance exists for offscreen tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


def test_theme_palette_and_helpers(qapp):
    """Test theme color mappings and widget helpers."""
    assert ThemeColors.BG_ROOT.startswith("#")
    assert ThemeColors.RED == "#ef4444"
    assert ThemeColors.GREEN == "#10b981"

    assert get_severity_color("CRITICAL") == ThemeColors.RED
    assert get_severity_color("HIGH") == ThemeColors.ORANGE
    assert get_severity_color("MEDIUM") == ThemeColors.AMBER
    assert get_severity_color("LOW") == ThemeColors.CYAN
    assert get_severity_color("NORMAL") == ThemeColors.GREEN

    badge = create_status_badge("TEST_BADGE", ThemeColors.GREEN)
    assert badge.text() == "TEST_BADGE"

    header = create_section_header("Test Title", "Test Subtitle")
    assert header is not None


def test_kpi_card(qapp):
    """Test KPICard initialization and mutations."""
    card = KPICard("Files Protected", "10,000", "Intact baseline")
    assert card.lbl_title.text() == "FILES PROTECTED"
    assert card.lbl_value.text() == "10,000"
    assert card.lbl_subtitle.text() == "Intact baseline"

    card.set_value("20,000", accent_color=ThemeColors.GREEN)
    assert card.lbl_value.text() == "20,000"
    assert card.accent_color == ThemeColors.GREEN

    card.set_subtitle("Verified clean")
    assert card.lbl_subtitle.text() == "Verified clean"


def test_threat_gauge(qapp):
    """Test ThreatGauge scoring, color transitions, and progress bar."""
    gauge = ThreatGauge()
    assert gauge.score == 0
    assert gauge.severity == "NORMAL"
    assert gauge.progress_bar.value() == 0

    # Low threat
    gauge.set_threat(20)
    assert gauge.score == 20
    assert gauge.severity == "LOW"
    assert gauge.progress_bar.value() == 20

    # Medium threat
    gauge.set_threat(45)
    assert gauge.score == 45
    assert gauge.severity == "MEDIUM"

    # High threat
    gauge.set_threat(75)
    assert gauge.score == 75
    assert gauge.severity == "HIGH"

    # Critical threat
    gauge.set_threat(95)
    assert gauge.score == 95
    assert gauge.severity == "CRITICAL"
    assert gauge.progress_bar.value() == 95

    # Out-of-bounds bounding
    gauge.set_threat(150)
    assert gauge.score == 100
    gauge.set_threat(-20)
    assert gauge.score == 0


def test_event_table(qapp):
    """Test EventTable row appending, filtering, and clearing."""
    table = EventTable()
    assert table.table.rowCount() == 0

    # Add standard event
    ev1 = Event(
        event_type="FILE_MODIFIED",
        data={"path": "Finance/invoices/inv1.txt", "department": "Finance", "classification": "INTERNAL"},
    )
    table.add_event(ev1)
    assert table.table.rowCount() == 1

    # Add canary event
    ev2 = Event(
        event_type="CANARY_ACCESS",
        data={"path": "IT/network/passwords.json", "department": "IT", "is_canary": True},
    )
    table.add_event(ev2)
    assert table.table.rowCount() == 2

    # Test text search filtering
    table.input_search.setText("passwords")
    assert table.table.rowCount() == 1

    table.input_search.setText("")
    assert table.table.rowCount() == 2

    # Test category filtering
    table.combo_filter.setCurrentText("Canary Breaches")
    assert table.table.rowCount() == 1

    table.combo_filter.setCurrentText("All Events")
    assert table.table.rowCount() == 2

    # Test clear
    table.clear_table()
    assert table.table.rowCount() == 0
    assert len(table._all_records) == 0
