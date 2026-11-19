"""
CryptoShield — SOC Dashboard & Telemetry Tab (Phase 10)
Central operational console visualizing real-time threat scores, active incidents,
honeypot canary states, LabWriteGate status, and high-throughput telemetry stream.
"""

from typing import Any, Dict, Optional
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.config import CONFIG
from app.containment.lab_write_gate import LabWriteGate
from app.core.event_bus import Event
from app.detection.incident_manager import IncidentManager
from app.ui.bridge import EventBusBridge
from app.ui.components.event_table import EventTable
from app.ui.components.kpi_card import KPICard
from app.ui.components.threat_gauge import ThreatGauge
from app.ui.theme import ThemeColors, create_section_header, get_severity_color


class DashboardTab(QWidget):
    """
    Primary SOC overview tab showing real-time threat scoring,
    containment write-gate status, active incidents, and live event telemetry.
    """

    def __init__(
        self,
        bridge: Optional[EventBusBridge] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.bridge = bridge
        self.incident_manager = IncidentManager()
        self.write_gate = LabWriteGate()

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(14)

        # 1. Top Section Header
        main_layout.addWidget(
            create_section_header(
                "Security Operations Center (SOC) Command Console",
                "Real-time telemetry, threat detection, and active containment telemetry",
            )
        )

        # 2. KPI Cards Row
        kpi_layout = QHBoxLayout()
        kpi_layout.setSpacing(12)

        self.kpi_threat = KPICard(
            title="Threat Status",
            initial_value="0 / 100 NORMAL",
            subtitle="All telemetry nominal",
            accent_color=ThemeColors.GREEN,
        )
        kpi_layout.addWidget(self.kpi_threat)

        self.kpi_gate = KPICard(
            title="Lab Write Gate",
            initial_value="UNLOCKED",
            subtitle="Cooperative writes permitted",
            accent_color=ThemeColors.GREEN,
        )
        kpi_layout.addWidget(self.kpi_gate)

        self.kpi_canaries = KPICard(
            title="Honeypot Canaries",
            initial_value="ARMED",
            subtitle="Active canary surveillance",
            accent_color=ThemeColors.CYAN,
        )
        kpi_layout.addWidget(self.kpi_canaries)

        self.kpi_dlp = KPICard(
            title="DLP Posture",
            initial_value="DEFAULT",
            subtitle="Active policy enforcement",
            accent_color=ThemeColors.BLUE,
        )
        kpi_layout.addWidget(self.kpi_dlp)

        main_layout.addLayout(kpi_layout)

        # 3. Middle Row: Threat Gauge + Active Incident Card
        middle_layout = QHBoxLayout()
        middle_layout.setSpacing(12)

        # Visual Threat Gauge (left)
        self.threat_gauge = ThreatGauge()
        middle_layout.addWidget(self.threat_gauge, 1)

        # Active Incident Panel (right)
        self.panel_incident = self._build_incident_panel()
        middle_layout.addWidget(self.panel_incident, 2)

        main_layout.addLayout(middle_layout)

        # 4. Telemetry Stream Table Group Box
        telemetry_group = QGroupBox("LIVE DEFENSIVE TELEMETRY & EVENT STREAM")
        group_layout = QVBoxLayout(telemetry_group)
        group_layout.setContentsMargins(10, 14, 10, 10)

        self.event_table = EventTable()
        group_layout.addWidget(self.event_table)

        main_layout.addWidget(telemetry_group, 1)

        # Connect bridge signals if provided
        if self.bridge:
            self._connect_bridge()

        # Initial state sync
        self.refresh_state()

    def _build_incident_panel(self) -> QFrame:
        """Construct the active security incident card."""
        panel = QFrame()
        panel.setObjectName("incident-panel")
        panel.setStyleSheet(f"""
            QFrame#incident-panel {{
                background-color: {ThemeColors.BG_CARD};
                border: 1px solid {ThemeColors.BORDER_DEFAULT};
                border-radius: 6px;
                padding: 10px;
            }}
        """)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)

        header_row = QHBoxLayout()
        lbl_inc_title = QLabel("ACTIVE SECURITY INCIDENT")
        lbl_inc_title.setStyleSheet(f"color: {ThemeColors.TEXT_SECONDARY}; font-size: 11px; font-weight: 700;")
        header_row.addWidget(lbl_inc_title)
        header_row.addStretch()

        self.badge_inc_status = QLabel("CLEAN")
        self.badge_inc_status.setStyleSheet(f"""
            color: {ThemeColors.GREEN};
            background-color: {ThemeColors.GREEN_BG};
            border-radius: 8px;
            padding: 2px 8px;
            font-size: 10px;
            font-weight: 700;
        """)
        header_row.addWidget(self.badge_inc_status)
        layout.addLayout(header_row)

        self.lbl_inc_id = QLabel("No Active Incident")
        self.lbl_inc_id.setStyleSheet(f"color: {ThemeColors.TEXT_PRIMARY}; font-size: 18px; font-weight: 800;")
        layout.addWidget(self.lbl_inc_id)

        self.lbl_inc_details = QLabel("Laboratory environment nominal; no ransomware behaviour detected.")
        self.lbl_inc_details.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-size: 12px;")
        layout.addWidget(self.lbl_inc_details)

        btn_row = QHBoxLayout()
        self.btn_toggle_gate = QPushButton("Emergency Lock Gate")
        self.btn_toggle_gate.setObjectName("btn-danger")
        self.btn_toggle_gate.clicked.connect(self._toggle_write_gate)
        btn_row.addWidget(self.btn_toggle_gate)

        self.btn_resolve = QPushButton("Resolve Incident")
        self.btn_resolve.setEnabled(False)
        self.btn_resolve.clicked.connect(self._resolve_active_incident)
        btn_row.addWidget(self.btn_resolve)
        btn_row.addStretch()

        layout.addLayout(btn_row)
        return panel

    def _connect_bridge(self) -> None:
        """Bind Qt signals from EventBusBridge to UI slots."""
        self.bridge.event_received.connect(self.event_table.add_event)
        self.bridge.threat_updated.connect(self.update_threat)
        self.bridge.incident_created.connect(self.on_incident_created)
        self.bridge.incident_resolved.connect(self.on_incident_resolved)
        self.bridge.write_gate_changed.connect(self.on_write_gate_changed)

    def refresh_state(self) -> None:
        """Query disk & controllers to ensure UI matches physical runtime state."""
        # Check write gate state
        is_locked = self.write_gate.is_locked()
        self.on_write_gate_changed(is_locked)

        # Check incidents
        try:
            active = self.incident_manager.get_active_incident()
            if active:
                self.on_incident_created(active.to_dict())
            else:
                self.on_incident_resolved("", "")
        except Exception:
            pass

    def update_threat(self, score: int, severity: str) -> None:
        """Update threat meter and KPI cards."""
        self.threat_gauge.set_threat(score, severity)
        color = get_severity_color(severity)
        self.kpi_threat.set_value(f"{score} / 100 {severity}", accent_color=color)
        if score > 0:
            self.kpi_threat.set_subtitle(f"Attack indicators detected ({severity})")
        else:
            self.kpi_threat.set_subtitle("All telemetry nominal")

    def on_incident_created(self, dossier: Dict[str, Any]) -> None:
        """Update incident card when a security incident is flagged."""
        inc_id = dossier.get("incident_id", "INC-UNKNOWN")
        severity = dossier.get("severity", "CRITICAL")
        color = get_severity_color(severity)

        self.lbl_inc_id.setText(inc_id)
        self.lbl_inc_id.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: 800;")

        summary = dossier.get("summary", "")
        self.lbl_inc_details.setText(f"Status: OPEN | Severity: {severity} | {summary}")

        self.badge_inc_status.setText("ATTACK DETECTED")
        self.badge_inc_status.setStyleSheet(f"""
            color: #ffffff;
            background-color: {ThemeColors.RED_BG};
            border: 1px solid {ThemeColors.RED};
            border-radius: 8px;
            padding: 2px 8px;
            font-size: 10px;
            font-weight: 700;
        """)
        self.btn_resolve.setEnabled(True)

    def on_incident_resolved(self, inc_id: str, notes: str) -> None:
        """Reset incident card when incident is marked resolved."""
        self.lbl_inc_id.setText("No Active Incident")
        self.lbl_inc_id.setStyleSheet(f"color: {ThemeColors.TEXT_PRIMARY}; font-size: 18px; font-weight: 800;")
        self.lbl_inc_details.setText("Laboratory environment nominal; no ransomware behaviour detected.")

        self.badge_inc_status.setText("CLEAN")
        self.badge_inc_status.setStyleSheet(f"""
            color: {ThemeColors.GREEN};
            background-color: {ThemeColors.GREEN_BG};
            border-radius: 8px;
            padding: 2px 8px;
            font-size: 10px;
            font-weight: 700;
        """)
        self.btn_resolve.setEnabled(False)
        self.update_threat(0, "NORMAL")

    def on_write_gate_changed(self, is_locked: bool) -> None:
        """Update LabWriteGate KPI card and button labels."""
        if is_locked:
            self.kpi_gate.set_value("LOCKED", accent_color=ThemeColors.RED)
            self.kpi_gate.set_subtitle("Cooperative writes blocked")
            self.btn_toggle_gate.setText("Unlock Write Gate")
            self.btn_toggle_gate.setObjectName("btn-success")
        else:
            self.kpi_gate.set_value("UNLOCKED", accent_color=ThemeColors.GREEN)
            self.kpi_gate.set_subtitle("Cooperative writes permitted")
            self.btn_toggle_gate.setText("Emergency Lock Gate")
            self.btn_toggle_gate.setObjectName("btn-danger")
        self.btn_toggle_gate.style().unpolish(self.btn_toggle_gate)
        self.btn_toggle_gate.style().polish(self.btn_toggle_gate)

    def _toggle_write_gate(self) -> None:
        """Toggles the state of LabWriteGate."""
        if self.write_gate.is_locked():
            self.write_gate.unlock()
            self.on_write_gate_changed(False)
        else:
            self.write_gate.lock("Operator Emergency Lock from SOC Dashboard")
            self.on_write_gate_changed(True)

    def _resolve_active_incident(self) -> None:
        """Resolves the currently open security incident."""
        try:
            active = self.incident_manager.get_active_incident()
            if active:
                self.incident_manager.resolve_incident(
                    active.incident_id,
                    "Resolved by SOC Operator via PySide6 Console",
                )
                self.on_incident_resolved(active.incident_id, "Operator Resolved")
        except Exception as e:
            self.lbl_inc_details.setText(f"Error resolving incident: {e}")
