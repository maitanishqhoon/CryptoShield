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


def test_simulation_tab_all_scenarios(qapp, isolated_runtime):
    """Test SimulationTab launcher buttons, bridge telemetry, and scenario executions."""
    bus = EventBus()
    bridge = EventBusBridge(bus=bus)
    bridge.connect_bus()

    tab = SimulationTab(bridge=bridge)
    assert tab.btn_s1 is not None
    assert tab.btn_s2 is not None
    assert tab.btn_s3 is not None
    assert tab.btn_s4 is not None
    assert tab.btn_s5 is not None
    assert tab.combo_pacing is not None
    assert tab.combo_pacing.count() == 3

    # Verify pacing profiles
    p_rapid = tab._get_pacing_parameters()
    assert p_rapid["mode"] == "rapid"
    tab.combo_pacing.setCurrentIndex(0)
    p_demo = tab._get_pacing_parameters()
    assert p_demo["mode"] == "demo"
    assert p_demo["containment_pre_delay"] > p_rapid["containment_pre_delay"]
    tab.combo_pacing.setCurrentIndex(1)
    p_ext = tab._get_pacing_parameters()
    assert p_ext["mode"] == "extended"
    assert p_ext["stage_delay"] > p_demo["stage_delay"]
    tab.combo_pacing.setCurrentIndex(2)  # Return to rapid for fast test execution

    # Test bridge telemetry log stream
    bridge.log_emitted.emit("Unit test telemetry beacon")
    assert "[TELEMETRY] Unit test telemetry beacon" in tab.txt_console.toPlainText()

    # 1. Test Scenario 3: DLP multi-tier demonstration
    tab._run_dlp_demo()
    assert tab.active_worker is not None
    tab.active_worker.wait(8000)
    qapp.processEvents()
    assert tab.kpi_containment.lbl_value.text() == "BLOCKED"
    assert tab.kpi_leakage.lbl_value.text().startswith("0 BYTES")
    assert "DLP multi-tier enforcement demonstration completed" in tab.txt_console.toPlainText()

    # 2. Test Scenario 1: Containment demonstration
    tab._run_containment_demo()
    assert tab.active_worker is not None
    tab.active_worker.wait(8000)
    qapp.processEvents()
    assert "LOCKED" in tab.kpi_containment.lbl_value.text()
    assert "contained in" in tab.txt_console.toPlainText()

    # 3. Test Scenario 2: Exfiltration demonstration
    tab._run_exfiltration_demo()
    assert tab.active_worker is not None
    tab.active_worker.wait(8000)
    qapp.processEvents()
    assert tab.kpi_containment.lbl_value.text() == "MONITORED"
    assert "Exfiltration simulation completed" in tab.txt_console.toPlainText()

    # 4. Test Scenario 4: Double-extortion forensic demonstration
    tab._run_forensic_demo()
    assert tab.active_worker is not None
    tab.active_worker.wait(8000)
    qapp.processEvents()
    assert "CONTAINED" in tab.kpi_containment.lbl_value.text()
    assert tab.kpi_leakage.lbl_value.text().startswith("0 BYTES")
    assert "Double-Extortion Defense & Forensics Demo Completed" in tab.txt_console.toPlainText()

    # 5. Test Scenario 5: Cryptographic recovery demonstration
    tab._run_recovery_demo()
    assert tab.active_worker is not None
    tab.active_worker.wait(15000)
    qapp.processEvents()
    assert "PRESERVED" in tab.kpi_containment.lbl_value.text()
    assert "RESTORED" in tab.kpi_restored.lbl_value.text()
    assert "Cryptographic Recovery Demo Completed" in tab.txt_console.toPlainText()

    bridge.disconnect_bus()


def test_crypto_shield_main_window(qapp, isolated_runtime):
    """Test CryptoShieldMainWindow tab hosting, ribbon synchronization, and event signals."""
    bus = EventBus()
    bridge = EventBusBridge(bus=bus)
    bridge.connect_bus()

    window = CryptoShieldMainWindow(bridge=bridge)
    assert window.tabs.count() == 8
    assert "Dashboard" in window.tabs.tabText(0)
    assert "Lab" in window.tabs.tabText(1)
    assert "Containment" in window.tabs.tabText(2)
    assert "Vault" in window.tabs.tabText(3)
    assert "Recovery" in window.tabs.tabText(4)
    assert "Exfiltration" in window.tabs.tabText(5)
    assert "Forensic" in window.tabs.tabText(6)
    assert "Simulation" in window.tabs.tabText(7)

    # Test tab switching across all 8 tabs
    for idx in range(8):
        window.tabs.setCurrentIndex(idx)
        qapp.processEvents()
        assert window.tabs.currentIndex() == idx

    # Test clock update
    window._update_clock()
    assert "IST" in window.lbl_clock.text()

    # Test bridge signals updating top ribbon
    bridge.threat_updated.emit(90, "CRITICAL")
    qapp.processEvents()
    assert "CRITICAL" in window.badge_threat.text()

    bridge.write_gate_changed.emit(True)
    qapp.processEvents()
    assert "LOCKED" in window.badge_gate.text()

    bridge.write_gate_changed.emit(False)
    qapp.processEvents()
    assert "UNLOCKED" in window.badge_gate.text()

    # Test DLP posture badge update
    bridge.dlp_profile_changed.emit("STRICT")
    qapp.processEvents()
    assert "DLP: STRICT" in window.badge_dlp.text()

    bridge.dlp_profile_changed.emit("DEFAULT")
    qapp.processEvents()
    assert "DLP: DEFAULT" in window.badge_dlp.text()

    # Test status bar
    assert window.statusBar() is not None
    assert "ONLINE" in window.lbl_sb_bus.text()

    bridge.disconnect_bus()


def test_app_launcher_headless(qapp, isolated_runtime):
    """Test launch_gui in headless offscreen mode."""
    exit_code = launch_gui(args=["test_runner", "--offscreen"], offscreen=True)
    assert exit_code == 0
