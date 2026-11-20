"""
Unit tests for Stage 10.2 Tabs: DashboardTab, LabTab, ContainmentTab, VaultTab.
"""

import os
import sys
import pytest

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication
from app.core.event_bus import Event, EventBus
from app.ui.bridge import EventBusBridge
from app.ui.tabs.dashboard_tab import DashboardTab
from app.ui.tabs.lab_tab import LabTab
from app.ui.tabs.containment_tab import ContainmentTab
from app.ui.tabs.vault_tab import VaultTab


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


def test_dashboard_tab(qapp):
    """Test DashboardTab initialization, bridge signals, threat scoring, and incident lifecycle."""
    bus = EventBus()
    bridge = EventBusBridge(bus=bus)
    bridge.connect_bus()

    dash = DashboardTab(bridge=bridge)
    assert dash.kpi_threat.lbl_value.text().startswith("0")
    assert dash.lbl_inc_id.text() == "No Active Incident"

    # Simulate threat update
    dash.update_threat(80, "HIGH")
    assert "80 / 100 HIGH" in dash.kpi_threat.lbl_value.text()
    assert dash.threat_gauge.score == 80
    assert dash.threat_gauge.severity == "HIGH"

    # Simulate incident creation
    dossier = {
        "incident_id": "INC-TEST1234",
        "severity": "CRITICAL",
        "threat_score": 95,
        "summary": "Simulated ransomware mass encryption",
    }
    dash.on_incident_created(dossier)
    assert dash.lbl_inc_id.text() == "INC-TEST1234"
    assert dash.badge_inc_status.text() == "ATTACK DETECTED"
    assert dash.btn_resolve.isEnabled()

    # Simulate canary breach event
    canary_ev = Event(
        event_type="CANARY_SECURITY_ALERT",
        data={"path": "runtime/lab/finance/.canary_report.xlsx", "severity": "CRITICAL"},
        source="test",
    )
    bridge._on_bus_event(canary_ev)
    assert "BREACHED" in dash.kpi_canaries.lbl_value.text()

    # Simulate DLP interception event
    dlp_ev = Event(
        event_type="DLP_TRANSFER_BLOCKED",
        data={"posture": "STRICT", "rule_id": "DLP-001"},
        source="test",
    )
    bridge._on_bus_event(dlp_ev)
    assert dash.kpi_dlp.lbl_value.text() == "STRICT"

    # Simulate incident resolution resets canaries
    dash.on_incident_resolved("INC-TEST1234", "Unit test clean resolution")
    assert dash.lbl_inc_id.text() == "No Active Incident"
    assert dash.badge_inc_status.text() == "CLEAN"
    assert "ARMED" in dash.kpi_canaries.lbl_value.text()
    assert not dash.btn_resolve.isEnabled()

    # Simulate write gate change
    dash.on_write_gate_changed(True)
    assert dash.kpi_gate.lbl_value.text() == "LOCKED"
    dash.on_write_gate_changed(False)
    assert dash.kpi_gate.lbl_value.text() == "UNLOCKED"

    bridge.disconnect_bus()


def test_lab_tab(qapp):
    """Test LabTab environment validation, manifest metrics, and preset selection."""
    lab = LabTab()
    assert lab.lbl_marker_status.text() != ""
    assert "VALID" in lab.lbl_marker_status.text()
    assert "files" in lab.lbl_manifest_status.text()

    # Preset selection
    lab._set_preset(1000)
    assert lab.spin_files.value() == 1000
    lab._set_preset(10000)
    assert lab.spin_files.value() == 10000
    lab._set_preset(20000)
    assert lab.spin_files.value() == 20000


def test_containment_tab(qapp):
    """Test ContainmentTab gate toggle, process list, history loading, and bridge signals."""
    bus = EventBus()
    bridge = EventBusBridge(bus=bus)
    bridge.connect_bus()

    cont = ContainmentTab(bridge=bridge)
    assert cont.lbl_gate_status.text() != ""

    # Test gate lock & unlock
    cont._lock_gate()
    assert "LOCKED" in cont.lbl_gate_status.text()
    cont._unlock_gate()
    assert "UNLOCKED" in cont.lbl_gate_status.text()

    # Test bridge signal reactions
    bridge.write_gate_changed.emit(True)
    assert "LOCKED" in cont.lbl_gate_status.text()
    bridge.write_gate_changed.emit(False)
    assert "UNLOCKED" in cont.lbl_gate_status.text()

    # Process refresh
    cont.refresh_processes()
    # History refresh
    cont.refresh_history()

    bridge.disconnect_bus()


def test_vault_tab(qapp):
    """Test VaultTab RSA key metadata, Argon2id parameters, and snapshot listing."""
    vault = VaultTab()
    assert vault.lbl_key_id.text().startswith("KEY-")
    assert "Argon2id" in vault.lbl_envelope.text()

    # Snapshot list verification
    assert vault.table_snaps.rowCount() >= 1
    # Test snapshot inspection selection
    vault.table_snaps.selectRow(0)
    vault._inspect_selected()
    assert "snapshot_id" in vault.txt_console.toPlainText()
