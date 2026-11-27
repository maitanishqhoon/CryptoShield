"""
Unit tests for Stage 10.3 Tabs: RecoveryTab, ExfiltrationTab, ForensicsTab.
"""

import os
import sys
import pytest

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication
from app.core.event_bus import Event, EventBus
from app.dlp.models import DLPAction, DLPEvaluationResult, DLPProfile
from app.ui.bridge import EventBusBridge
from app.ui.tabs.recovery_tab import RecoveryTab
from app.ui.tabs.exfiltration_tab import ExfiltrationTab
from app.ui.tabs.forensics_tab import ForensicsTab


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


def test_recovery_tab(qapp, isolated_runtime, monkeypatch):
    """Test RecoveryTab workspace management, assessment, passphrase resolution, preview, and controls."""
    bus = EventBus()
    bridge = EventBusBridge(bus=bus)
    bridge.connect_bus()

    tab = RecoveryTab(bridge=bridge)
    assert tab.table_ws is not None
    assert tab.combo_ws is not None
    assert tab.combo_snaps.count() >= 1

    # Test bridge recovery_progress signal
    bridge.recovery_progress.emit("Restoring isolated assets", 45, 100)
    assert tab.progress_bar.value() == 45
    assert "Restoring isolated assets [45/100]" in tab.txt_audit.toPlainText()

    # Create workspace
    tab._create_workspace()
    assert tab.table_ws.rowCount() >= 1
    new_ws_id = tab.combo_ws.currentText()
    assert new_ws_id.startswith("WKSP-")
    found_row = [r for r in range(tab.table_ws.rowCount()) if tab.table_ws.item(r, 0).text() == new_ws_id]
    assert len(found_row) == 1
    row_idx = found_row[0]
    assert "VALID" in tab.table_ws.item(row_idx, 3).text()

    # Seed workspace
    tab._seed_workspace()
    assert "Successfully seeded" in tab.txt_audit.toPlainText()
    assert int(tab.table_ws.item(row_idx, 2).text()) > 0

    # Assessment without passphrase and without env var aborts cleanly in offscreen mode
    monkeypatch.delenv("CRYPTOSHIELD_VAULT_PASSPHRASE", raising=False)
    tab.input_passphrase.clear()
    tab._run_assessment()
    assert "passphrase is required" in tab.lbl_assess_status.text()

    # Assessment resolves CRYPTOSHIELD_VAULT_PASSPHRASE automatically when field is empty
    monkeypatch.setenv("CRYPTOSHIELD_VAULT_PASSPHRASE", isolated_runtime["passphrase"])
    tab._run_assessment()
    assert tab.active_worker is not None
    tab.active_worker.wait(8000)
    qapp.processEvents()
    assert "[PASS] Assessed" in tab.lbl_assess_status.text()
    assert tab.input_passphrase.text() == isolated_runtime["passphrase"]

    # Preview restoration
    tab._preview_restoration()
    assert "Restoration Plan Preview" in tab.txt_audit.toPlainText()

    # Test restoration authorization gate
    tab.chk_authorize.setChecked(False)
    tab._execute_restoration()
    assert "Restoration requires explicit authorization" in tab.txt_audit.toPlainText()

    # Clean up workspace
    tab._delete_workspace()
    bridge.disconnect_bus()


def test_exfiltration_tab(qapp, isolated_runtime):
    """Test ExfiltrationTab loopback receiver, posture selector, approval queue, and bridge signals."""
    bus = EventBus()
    bridge = EventBusBridge(bus=bus)
    bridge.connect_bus()

    tab = ExfiltrationTab(bridge=bridge)
    assert tab.table_rules.rowCount() >= 5
    assert tab.lbl_receiver_status.text().startswith("IDLE")

    # 1. Test loopback receiver toggle
    tab._start_receiver()
    assert "LISTENING" in tab.lbl_receiver_status.text()
    assert "127.0.0.1" in tab.lbl_endpoint.text()

    tab._stop_receiver()
    assert "IDLE" in tab.lbl_receiver_status.text()

    # 2. Test posture profile change
    tab.combo_profile.setCurrentText("STRICT")
    tab._apply_profile()
    assert tab.dlp_coord.get_status()["profile"] == "STRICT"

    # Reset profile
    tab.combo_profile.setCurrentText("DEFAULT")
    tab._apply_profile()
    assert tab.dlp_coord.get_status()["profile"] == "DEFAULT"

    # 3. Test approval workflow with actual requests
    eval_1 = DLPEvaluationResult(
        evaluation_id="eval-test-approve",
        timestamp="2026-11-20T20:00:00",
        action=DLPAction.REQUIRE_APPROVAL,
        allowed=False,
        classifications_evaluated=["CONFIDENTIAL"],
        file_count=3,
    )
    req_1 = tab.approval_mgr.submit_request(eval_1)
    tab.refresh_approvals()
    assert tab.table_approvals.rowCount() >= 1

    # Approve transfer
    row_req1 = -1
    for r in range(tab.table_approvals.rowCount()):
        if tab.table_approvals.item(r, 0).text() == req_1.approval_token:
            row_req1 = r
            break
    assert row_req1 >= 0
    tab.table_approvals.selectRow(row_req1)
    tab._approve_transfer()
    assert tab.table_approvals.item(row_req1, 4).text() == "APPROVED"

    # Reject transfer
    eval_2 = DLPEvaluationResult(
        evaluation_id="eval-test-reject",
        timestamp="2026-11-20T20:01:00",
        action=DLPAction.REQUIRE_APPROVAL,
        allowed=False,
        classifications_evaluated=["RESTRICTED"],
        file_count=7,
    )
    req_2 = tab.approval_mgr.submit_request(eval_2)
    tab.refresh_approvals()

    row_req2 = -1
    for r in range(tab.table_approvals.rowCount()):
        if tab.table_approvals.item(r, 0).text() == req_2.approval_token:
            row_req2 = r
            break
    assert row_req2 >= 0
    tab.table_approvals.selectRow(row_req2)
    tab._reject_transfer()
    assert tab.table_approvals.item(row_req2, 4).text() == "REJECTED"

    # Test direct simulated sensitive transfer staging
    initial_approvals = tab.table_approvals.rowCount()
    tab._stage_test_transfer()
    assert tab.table_approvals.rowCount() == initial_approvals + 1

    # 4. Test bridge DLP interception signals
    bridge.dlp_interception.emit({"action": "BLOCK", "rule_id": "DLP-001"})
    dlp_bus_ev = Event(
        event_type="DLP_TRANSFER_BLOCKED",
        data={"rule_id": "DLP-001", "posture": "DEFAULT"},
        source="test",
    )
    bridge._on_bus_event(dlp_bus_ev)

    bridge.disconnect_bus()


def test_forensics_tab(qapp, isolated_runtime):
    """Test ForensicsTab report loading, KPI metrics, timeline, seal verification, and bridge signals."""
    bus = EventBus()
    bridge = EventBusBridge(bus=bus)
    bridge.connect_bus()

    tab = ForensicsTab(bridge=bridge)
    assert tab.table_reports.rowCount() >= 1

    # Test bridge incident events
    bridge.incident_created.emit({"incident_id": "INC-TEST-ACTIVE"})
    assert tab.input_inc_id.text() == "INC-TEST-ACTIVE"

    bridge.incident_resolved.emit("INC-TEST-RESOLVED", "Auto-resolved in unit test")
    assert tab.input_inc_id.text() == "INC-TEST-RESOLVED"

    # Verify seal on first report
    tab.table_reports.selectRow(0)
    tab._verify_seal()
    assert "verified successfully" in tab.lbl_verify_status.text()

    # Check KPI metrics populated
    assert tab.kpi_protection.lbl_value.text() != "—"
    assert tab.kpi_leakage.lbl_value.text().startswith("0 BYTES")

    # Check timeline populated
    assert tab.table_timeline.rowCount() >= 1

    # Check summary and JSON views
    assert tab.txt_summary.toPlainText() != "" or tab.txt_summary.toMarkdown() != ""
    assert tab.txt_json.toPlainText().startswith("{")

    bridge.disconnect_bus()
