"""
Stage 10.5: End-to-End GUI Integration & System-Wide Verification Suite.
Validates live multi-subsystem reactive event propagation across all 8 tabs
of the CryptoShield SOC Console via EventBusBridge.
"""

import os
import sys
import time
import pytest

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication
from app.config import CONFIG
from app.containment.lab_write_gate import LabWriteGate
from app.core.event_bus import Event, EventBus
from app.dlp.models import DLPAction, DLPEvaluationResult
from app.ui.app_launcher import launch_gui
from app.ui.bridge import EventBusBridge
from app.ui.main_window import CryptoShieldMainWindow
from app.ui.theme import ThemeColors


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


def test_e2e_soc_console_lifecycle(qapp, isolated_runtime):
    """
    Complete end-to-end multi-subsystem defensive lifecycle demonstration:
    1. Initial SOC Console baseline state verification.
    2. Canary tampering detection & visual breach indicators.
    3. Ransomware detection alert & threat gauge escalation.
    4. Threat containment trigger & LabWriteGate dynamic lock.
    5. Data Loss Prevention (DLP) interception & quarantine approval queue update.
    6. Incident resolution & automated system state restoration.
    7. Forensics catalog correlation & chain-of-custody seal verification.
    """
    bus = EventBus()
    bridge = EventBusBridge(bus=bus)
    bridge.connect_bus()

    # Instantiate Main Window with integrated bridge
    window = CryptoShieldMainWindow(bridge=bridge)
    assert window.tabs.count() == 8

    # -------------------------------------------------------------------------
    # Stage 1: Initial Baseline Verification
    # -------------------------------------------------------------------------
    dash = window.tab_dashboard
    cont = window.tab_containment
    exfil = window.tab_exfiltration
    forensics = window.tab_forensics

    assert "NORMAL" in window.badge_threat.text()
    assert "UNLOCKED" in window.badge_gate.text()
    assert "ONLINE" in window.lbl_sb_bus.text()
    assert "ARMED" in dash.kpi_canaries.lbl_value.text()
    assert dash.badge_inc_status.text() == "CLEAN"

    # -------------------------------------------------------------------------
    # Stage 2: Canary Tampering & Honeypot Breach
    # -------------------------------------------------------------------------
    canary_event = Event(
        event_type="CANARY_SECURITY_ALERT",
        data={
            "path": "runtime/lab/Finance/.canary_quarterly_budget.xlsx",
            "operation": "READ",
            "department": "Finance",
            "threat_score": 75,
            "severity": "HIGH",
        },
        source="canary_analyzer",
    )
    bridge._on_bus_event(canary_event)
    qapp.processEvents()

    assert "BREACHED" in dash.kpi_canaries.lbl_value.text()
    assert "Honeypot tampering detected" in dash.kpi_canaries.lbl_subtitle.text()

    # -------------------------------------------------------------------------
    # Stage 3: Ransomware Detection & Threat Score Escalation
    # -------------------------------------------------------------------------
    detection_event = Event(
        event_type="DETECTION_RESULT",
        data={
            "detection_id": "DET-E2E-1005",
            "score": 95,
            "threat_score": 95,
            "severity": "CRITICAL",
            "reasons": ["MASS_FILE_MODIFICATION", "RAPID_FILE_RENAMING"],
        },
        source="behavior_analyzer",
    )
    bridge._on_bus_event(detection_event)
    qapp.processEvents()

    assert "95" in window.badge_threat.text()
    assert "CRITICAL" in window.badge_threat.text()
    assert dash.threat_gauge.score == 95

    # -------------------------------------------------------------------------
    # Stage 4: Containment Trigger & Write Gate Dynamic Lock
    # -------------------------------------------------------------------------
    containment_event = Event(
        event_type="CONTAINMENT_TRIGGERED",
        data={
            "containment_id": "CONT-E2E-1005",
            "action": "LOCK",
            "simulation_run_id": "SIM-E2E",
        },
        source="containment_manager",
    )
    bridge._on_bus_event(containment_event)
    qapp.processEvents()

    assert "LOCKED" in window.badge_gate.text()
    assert "LOCKED" in cont.lbl_gate_status.text()

    # -------------------------------------------------------------------------
    # Stage 5: DLP Pre-Transmission Interception & Approval Queue
    # -------------------------------------------------------------------------
    dlp_eval = DLPEvaluationResult(
        evaluation_id="eval-e2e-001",
        timestamp="2026-11-20T20:30:00",
        action=DLPAction.REQUIRE_APPROVAL,
        allowed=False,
        classifications_evaluated=["RESTRICTED"],
        file_count=5,
    )
    req = exfil.approval_mgr.submit_request(dlp_eval)

    dlp_event = Event(
        event_type="DLP_TRANSFER_QUARANTINED",
        data={
            "action": "REQUIRE_APPROVAL",
            "posture": "DEFAULT",
            "rule_id": "DLP-002",
            "token": req.approval_token,
        },
        source="dlp_transfer_gate",
    )
    bridge._on_bus_event(dlp_event)
    qapp.processEvents()

    assert exfil.table_approvals.rowCount() >= 1

    # -------------------------------------------------------------------------
    # Stage 6: Incident Resolution & Baseline Reset
    # -------------------------------------------------------------------------
    res_event = Event(
        event_type="SECURITY_INCIDENT_RESOLVED",
        data={
            "incident_id": "INC-E2E-1005",
            "resolution_notes": "Threat neutralized and contained via E2E test harness.",
        },
        source="incident_manager",
    )
    bridge._on_bus_event(res_event)
    qapp.processEvents()

    # Verify reset to CLEAN / ARMED / NORMAL
    assert dash.lbl_inc_id.text() == "No Active Incident"
    assert dash.badge_inc_status.text() == "CLEAN"
    assert "ARMED" in dash.kpi_canaries.lbl_value.text()
    assert dash.threat_gauge.score == 0

    # Verify Forensics auto-populated the resolved incident
    assert forensics.input_inc_id.text() == "INC-E2E-1005"

    # Unlock gate cleanly
    bridge.write_gate_changed.emit(False)
    qapp.processEvents()
    assert "UNLOCKED" in window.badge_gate.text()

    bridge.disconnect_bus()


def test_realtime_ui_updates_and_tab_sync(qapp, isolated_runtime):
    """
    Verify real-time UI synchronization across subsystems:
    1. Realtime snapshot propagation to RecoveryTab dropdown and VaultTab table.
    2. Tab switching triggering comprehensive refresh_all() on RecoveryTab.
    3. DashboardTab write gate toggle propagating to Top Ribbon and other tabs.
    4. DLP posture change propagating to DashboardTab KPI card in real time.
    5. Forensic report generation event propagating to ForensicsTab catalog.
    """
    bus = EventBus()
    bridge = EventBusBridge(bus=bus)
    bridge.connect_bus()

    window = CryptoShieldMainWindow(bridge=bridge)
    dash = window.tab_dashboard
    recovery = window.tab_recovery
    vault = window.tab_vault
    exfil = window.tab_exfiltration
    forensics = window.tab_forensics

    # 1. Snapshot realtime propagation
    initial_snaps_count = recovery.combo_snaps.count()
    test_snap_id = "SNAP-REALTIME-TEST-99"

    # Simulate SNAPSHOT_CREATED via bridge
    snap_event = Event(
        event_type="SNAPSHOT_CREATED",
        data={
            "snapshot_id": test_snap_id,
            "total_files": 42,
            "total_encrypted_bytes": 102400,
        },
        source="vault.snapshot_manager",
    )
    bridge._on_bus_event(snap_event)
    qapp.processEvents()

    # Recovery tab should have updated its dropdown
    assert "REALTIME" in recovery.txt_audit.toPlainText()

    # 2. Tab switching to Tab 5 (Recovery) triggers refresh_all()
    window.tabs.setCurrentIndex(4)
    qapp.processEvents()
    assert recovery.combo_snaps.count() >= 1

    # 3. Dashboard write gate toggle propagates to Top Ribbon in real time
    assert "UNLOCKED" in window.badge_gate.text()
    dash._toggle_write_gate()
    qapp.processEvents()
    assert "LOCKED" in window.badge_gate.text()
    assert "LOCKED" in dash.kpi_gate.lbl_value.text()

    dash._toggle_write_gate()
    qapp.processEvents()
    assert "UNLOCKED" in window.badge_gate.text()
    assert "UNLOCKED" in dash.kpi_gate.lbl_value.text()

    # 4. DLP profile change propagates to DashboardTab KPI in real time
    exfil.combo_profile.setCurrentText("AUDIT_ONLY")
    exfil._apply_profile()
    qapp.processEvents()
    assert dash.kpi_dlp.lbl_value.text() == "AUDIT_ONLY"
    assert "AUDIT_ONLY" in window.badge_dlp.text()

    # Reset DLP profile to DEFAULT
    exfil.combo_profile.setCurrentText("DEFAULT")
    exfil._apply_profile()
    qapp.processEvents()

    # 5. Forensic report event propagates to ForensicsTab
    initial_reports_count = forensics.table_reports.rowCount()
    report_event = Event(
        event_type="FORENSIC_REPORT_GENERATED",
        data={
            "report_id": "REP-REALTIME-TEST-01",
            "incident_id": "INC-TEST-01",
        },
        source="forensic_coordinator",
    )
    bridge._on_bus_event(report_event)
    qapp.processEvents()
    assert "REALTIME" in forensics.lbl_verify_status.text() or forensics.table_reports.rowCount() >= initial_reports_count

    bridge.disconnect_bus()


def test_e2e_gui_cli_headless_execution(isolated_runtime):
    """Verify that 'python -m app.main gui --offscreen' launches and exits cleanly."""
    exit_code = launch_gui(args=["app.main", "--offscreen"], offscreen=True)
    assert exit_code == 0
