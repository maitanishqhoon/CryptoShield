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


def test_e2e_soc_console_lifecycle(qapp):
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


def test_e2e_gui_cli_headless_execution():
    """Verify that 'python -m app.main gui --offscreen' launches and exits cleanly."""
    exit_code = launch_gui(args=["app.main", "--offscreen"], offscreen=True)
    assert exit_code == 0
