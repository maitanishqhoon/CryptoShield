"""
CryptoShield — Main Application Window (Phase 10)
Hosts the top operational status ribbon, central multi-tab subsystem console,
and real-time event status bar.
"""

from datetime import datetime, timezone
from typing import Optional
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.config import CONFIG
from app.containment.lab_write_gate import LabWriteGate
from app.lab.lab_manager import LabManager
from app.ui.bridge import EventBusBridge
from app.ui.tabs.containment_tab import ContainmentTab
from app.ui.tabs.dashboard_tab import DashboardTab
from app.ui.tabs.exfiltration_tab import ExfiltrationTab
from app.ui.tabs.forensics_tab import ForensicsTab
from app.ui.tabs.lab_tab import LabTab
from app.ui.tabs.recovery_tab import RecoveryTab
from app.ui.tabs.simulation_tab import SimulationTab
from app.ui.tabs.vault_tab import VaultTab
from app.ui.theme import ThemeColors, create_status_badge, get_severity_color


class CryptoShieldMainWindow(QMainWindow):
    """
    Primary desktop application window integrating all 9 defensive subsystems
    into a unified Security Operations Center (SOC) console.
    """

    def __init__(
        self,
        bridge: Optional[EventBusBridge] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.bridge = bridge or EventBusBridge()
        self.lab_mgr = LabManager()
        self.write_gate = LabWriteGate.get_instance()

        self.setWindowTitle("CryptoShield — Double-Extortion Defensive Ransomware Framework")
        self.resize(1280, 850)
        self.setMinimumSize(1100, 720)

        # Central Widget & Main Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(14, 10, 14, 10)
        main_layout.setSpacing(10)

        # 1. Top Operational Ribbon
        main_layout.addWidget(self._build_top_ribbon())

        # 2. Main Tabbed Subsystem Console
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        # Initialize all 8 tabs
        self.tab_dashboard = DashboardTab(bridge=self.bridge)
        self.tab_lab = LabTab()
        self.tab_containment = ContainmentTab(bridge=self.bridge)
        self.tab_vault = VaultTab()
        self.tab_recovery = RecoveryTab(bridge=self.bridge)
        self.tab_exfiltration = ExfiltrationTab(bridge=self.bridge)
        self.tab_forensics = ForensicsTab(bridge=self.bridge)
        self.tab_simulation = SimulationTab(bridge=self.bridge)

        self.tabs.addTab(self.tab_dashboard, "1. Dashboard & Telemetry")
        self.tabs.addTab(self.tab_lab, "2. Lab & Dataset Engine")
        self.tabs.addTab(self.tab_containment, "3. Threat Containment")
        self.tabs.addTab(self.tab_vault, "4. Cryptographic Vault")
        self.tabs.addTab(self.tab_recovery, "5. Recovery & Restoration")
        self.tabs.addTab(self.tab_exfiltration, "6. Exfiltration & DLP")
        self.tabs.addTab(self.tab_forensics, "7. Forensic Reports")
        self.tabs.addTab(self.tab_simulation, "8. Simulation Testbed")

        self.tabs.currentChanged.connect(self._on_tab_changed)
        main_layout.addWidget(self.tabs, 1)

        # 3. Status Bar
        self._init_status_bar()

        # 4. Live Clock Timer (updates every 1000ms)
        self.clock_timer = QTimer(self)
        self.clock_timer.timeout.connect(self._update_clock)
        self.clock_timer.start(1000)

        # 5. Connect Bridge Signals
        self._connect_bridge()

        # Initial Ribbon Sync
        self.refresh_ribbon_status()

    def _build_top_ribbon(self) -> QFrame:
        """Top branding and real-time status ribbon."""
        ribbon = QFrame()
        ribbon.setObjectName("top-ribbon")
        ribbon.setStyleSheet(f"""
            QFrame#top-ribbon {{
                background-color: {ThemeColors.BG_CARD};
                border: 1px solid {ThemeColors.BORDER_DEFAULT};
                border-radius: 6px;
                padding: 6px 14px;
            }}
        """)
        layout = QHBoxLayout(ribbon)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(14)

        # Brand / Logo Title
        brand_layout = QVBoxLayout()
        brand_layout.setSpacing(1)
        lbl_brand = QLabel("CRYPTOSHIELD")
        lbl_brand.setStyleSheet(f"color: {ThemeColors.TEXT_PRIMARY}; font-size: 18px; font-weight: 900; letter-spacing: 1px;")
        lbl_sub = QLabel("DOUBLE-EXTORTION DEFENSE & FORENSIC RECOVERY PLATFORM")
        lbl_sub.setStyleSheet(f"color: {ThemeColors.TEXT_ACCENT}; font-size: 10px; font-weight: 700; letter-spacing: 0.5px;")
        brand_layout.addWidget(lbl_brand)
        brand_layout.addWidget(lbl_sub)
        layout.addLayout(brand_layout)

        layout.addStretch()

        # Status Badges
        self.badge_marker = create_status_badge("LAB: VALID", ThemeColors.GREEN, ThemeColors.GREEN_BG)
        layout.addWidget(self.badge_marker)

        self.badge_gate = create_status_badge("GATE: UNLOCKED", ThemeColors.GREEN, ThemeColors.GREEN_BG)
        layout.addWidget(self.badge_gate)

        self.badge_threat = create_status_badge("THREAT: 0 NORMAL", ThemeColors.GREEN, ThemeColors.GREEN_BG)
        layout.addWidget(self.badge_threat)

        self.badge_dlp = create_status_badge("DLP: DEFAULT", ThemeColors.BLUE, ThemeColors.BLUE_BG)
        layout.addWidget(self.badge_dlp)

        # Clock (Indian Standard Time - IST)
        self.lbl_clock = QLabel("IST: --:--:--")
        self.lbl_clock.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-family: monospace; font-size: 11px;")
        layout.addWidget(self.lbl_clock)

        return ribbon

    def _init_status_bar(self) -> None:
        """Configure bottom status bar."""
        sb = QStatusBar()
        self.setStatusBar(sb)

        self.lbl_sb_lab = QLabel(f"Laboratory: {CONFIG.LAB_DIR}")
        self.lbl_sb_lab.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-size: 11px;")
        sb.addWidget(self.lbl_sb_lab, 2)

        self.lbl_sb_bus = QLabel("EventBus Bridge: ONLINE")
        self.lbl_sb_bus.setStyleSheet(f"color: {ThemeColors.GREEN}; font-weight: 700; font-size: 11px;")
        sb.addPermanentWidget(self.lbl_sb_bus)

    def _update_clock(self) -> None:
        """Update the top ribbon IST clock display."""
        now_str = datetime.now(CONFIG.TIMEZONE).strftime("%Y-%m-%d %H:%M:%S IST")
        self.lbl_clock.setText(now_str)

    def _connect_bridge(self) -> None:
        """Listen to EventBusBridge signals for top ribbon updates."""
        self.bridge.threat_updated.connect(self._on_threat_updated)
        self.bridge.write_gate_changed.connect(self._on_gate_changed)

    def _on_threat_updated(self, score: int, severity: str) -> None:
        """Update top threat badge."""
        color = get_severity_color(severity)
        self.badge_threat.setText(f"THREAT: {score} {severity}")
        self.badge_threat.setStyleSheet(f"""
            QLabel {{
                color: {color};
                background-color: {ThemeColors.BG_CARD_ALT};
                border: 1px solid {color};
                border-radius: 10px;
                padding: 3px 10px;
                font-size: 11px;
                font-weight: 700;
            }}
        """)

    def _on_gate_changed(self, is_locked: bool) -> None:
        """Update top write gate badge."""
        if is_locked:
            self.badge_gate.setText("GATE: LOCKED")
            self.badge_gate.setStyleSheet(f"""
                QLabel {{
                    color: {ThemeColors.RED};
                    background-color: {ThemeColors.RED_BG};
                    border: 1px solid {ThemeColors.RED};
                    border-radius: 10px;
                    padding: 3px 10px;
                    font-size: 11px;
                    font-weight: 700;
                }}
            """)
        else:
            self.badge_gate.setText("GATE: UNLOCKED")
            self.badge_gate.setStyleSheet(f"""
                QLabel {{
                    color: {ThemeColors.GREEN};
                    background-color: {ThemeColors.GREEN_BG};
                    border: 1px solid {ThemeColors.GREEN};
                    border-radius: 10px;
                    padding: 3px 10px;
                    font-size: 11px;
                    font-weight: 700;
                }}
            """)

    def refresh_ribbon_status(self) -> None:
        """Synchronize top ribbon badges with physical runtime state."""
        # 1. Marker
        is_valid, _ = self.lab_mgr.validate_lab()
        if is_valid:
            self.badge_marker.setText("LAB: VALID")
        else:
            self.badge_marker.setText("LAB: UNINITIALIZED")
            self.badge_marker.setStyleSheet(f"color: {ThemeColors.AMBER}; border: 1px solid {ThemeColors.AMBER};")

        # 2. Gate
        self._on_gate_changed(self.write_gate.is_locked())

    def _on_tab_changed(self, index: int) -> None:
        """Refresh tab contents when switched into view."""
        if index == 0:
            self.tab_dashboard.refresh_state()
        elif index == 1:
            self.tab_lab.refresh_lab_info()
        elif index == 2:
            self.tab_containment.refresh_all()
        elif index == 3:
            self.tab_vault.refresh_all()
        elif index == 4:
            self.tab_recovery.refresh_workspaces()
        elif index == 5:
            self.tab_exfiltration.refresh_all()
        elif index == 6:
            self.tab_forensics.refresh_catalog()
