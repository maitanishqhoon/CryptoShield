"""
Unit tests for Stage 10.3 Tabs: RecoveryTab, ExfiltrationTab, ForensicsTab.
"""

import os
import sys
import pytest

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication
from app.dlp.models import DLPProfile
from app.ui.tabs.recovery_tab import RecoveryTab
from app.ui.tabs.exfiltration_tab import ExfiltrationTab
from app.ui.tabs.forensics_tab import ForensicsTab


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


def test_recovery_tab(qapp):
    """Test RecoveryTab workspace management, preview, and controls."""
    tab = RecoveryTab()
    assert tab.table_ws is not None
    assert tab.combo_ws is not None
    assert tab.combo_snaps.count() >= 1

    # Create workspace
    tab._create_workspace()
    assert tab.table_ws.rowCount() >= 1
    new_ws_id = tab.combo_ws.currentText()
    assert new_ws_id.startswith("WKSP-")

    # Preview restoration
    tab.input_passphrase.setText("CryptoShieldVaultPassphrase2026!")
    tab._preview_restoration()
    assert "Restoration Plan Preview" in tab.txt_audit.toPlainText()

    # Clean up workspace
    tab._delete_workspace()


def test_exfiltration_tab(qapp):
    """Test ExfiltrationTab loopback receiver, posture selector, and rules."""
    tab = ExfiltrationTab()
    assert tab.table_rules.rowCount() >= 5
    assert tab.lbl_receiver_status.text().startswith("IDLE")

    # Test loopback receiver toggle
    tab._start_receiver()
    assert "LISTENING" in tab.lbl_receiver_status.text()
    assert "127.0.0.1" in tab.lbl_endpoint.text()

    tab._stop_receiver()
    assert "IDLE" in tab.lbl_receiver_status.text()

    # Test posture profile change
    tab.combo_profile.setCurrentText("STRICT")
    tab._apply_profile()
    assert tab.dlp_coord.get_status()["profile"] == "STRICT"

    # Reset profile
    tab.combo_profile.setCurrentText("DEFAULT")
    tab._apply_profile()
    assert tab.dlp_coord.get_status()["profile"] == "DEFAULT"

    # Refresh logs and approvals
    tab.refresh_approvals()
    tab.refresh_audit_log()


def test_forensics_tab(qapp):
    """Test ForensicsTab report loading, KPI metrics, timeline, and seal verification."""
    tab = ForensicsTab()
    assert tab.table_reports.rowCount() >= 1

    # Verify seal on first report
    tab.table_reports.selectRow(0)
    tab._verify_seal()
    assert "verified successfully" in tab.lbl_verify_status.text()

    # Check KPI metrics populated
    assert tab.kpi_protection.lbl_value.text() != "—"
    assert tab.kpi_leakage.lbl_value.text().startswith("0 BYTES")

    # Check timeline populated
    assert tab.table_timeline.rowCount() >= 1
