"""
Unit and Integration tests for Stage 10.4: SimulationTab, CryptoShieldMainWindow, and app_launcher.
"""

import os
import sys
import pytest

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication
from app.core.event_bus import Event, EventBus
from app.ui.app_launcher import launch_gui
from app.ui.bridge import EventBusBridge
from app.ui.main_window import CryptoShieldMainWindow
from app.ui.tabs.simulation_tab import SimulationTab


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


def test_simulation_tab(qapp):
    """Test SimulationTab launcher buttons and DLP demonstration execution."""
    tab = SimulationTab()
    assert tab.btn_s1 is not None
    assert tab.btn_s2 is not None
    assert tab.btn_s3 is not None
    assert tab.btn_s4 is not None
    assert tab.btn_s5 is not None

    # Run DLP simulation scenario
    tab._run_dlp_demo()
    assert tab.active_worker is not None
    tab.active_worker.wait(5000)
    qapp.processEvents()

    assert tab.kpi_containment.lbl_value.text() == "BLOCKED"
    assert tab.kpi_leakage.lbl_value.text().startswith("0 BYTES")
    assert "DLP multi-tier enforcement demonstration completed" in tab.txt_console.toPlainText()


def test_crypto_shield_main_window(qapp):
    """Test CryptoShieldMainWindow tab hosting, ribbon synchronization, and event signals."""
    bus = EventBus()
    bridge = EventBusBridge(bus=bus)
    bridge.connect_bus()

    window = CryptoShieldMainWindow(bridge=bridge)
    assert window.tabs.count() == 8
    assert "Dashboard" in window.tabs.tabText(0)
    assert "Simulation" in window.tabs.tabText(7)

    # Test tab switching across all 8 tabs
    for idx in range(8):
        window.tabs.setCurrentIndex(idx)
        qapp.processEvents()
        assert window.tabs.currentIndex() == idx

    # Test bridge signal updating top ribbon
    bridge.threat_updated.emit(90, "CRITICAL")
    qapp.processEvents()
    assert "CRITICAL" in window.badge_threat.text()

    bridge.write_gate_changed.emit(True)
    qapp.processEvents()
    assert "LOCKED" in window.badge_gate.text()

    bridge.write_gate_changed.emit(False)
    qapp.processEvents()
    assert "UNLOCKED" in window.badge_gate.text()

    bridge.disconnect_bus()


def test_app_launcher_headless(qapp):
    """Test launch_gui in headless offscreen mode."""
    exit_code = launch_gui(args=["test_runner", "--offscreen"], offscreen=True)
    assert exit_code == 0
