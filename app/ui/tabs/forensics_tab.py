"""
CryptoShield — Forensic Incident Reporting Tab (Phase 10)
Manages forensic dossiers, cryptographic chain-of-custody verification,
chronological multi-subsystem attack timelines, and academic evaluation metrics.
"""

import json
from typing import Any, Dict, List, Optional
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.config import CONFIG
from app.reporting.forensic_coordinator import FORENSIC_COORDINATOR, ForensicCoordinator
from app.reporting.models import ForensicDossier
from app.ui.components.kpi_card import KPICard
from app.ui.theme import ThemeColors, create_section_header


class ForensicsTab(QWidget):
    """
    Console for inspecting forensic incident reports, verifying SHA-256 seals,
    reviewing chronological attack timelines, and evaluating double-extortion defensive KPIs.
    """

    def __init__(self, bridge: Optional[Any] = None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.bridge = bridge
        self.coordinator = FORENSIC_COORDINATOR
        self._reports_meta: List[Any] = []
        self._current_dossier: Optional[ForensicDossier] = None

        if self.bridge:
            if hasattr(self.bridge, "incident_resolved"):
                self.bridge.incident_resolved.connect(self._on_bridge_incident_resolved)
            if hasattr(self.bridge, "incident_created"):
                self.bridge.incident_created.connect(self._on_bridge_incident_created)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(14)

        # Section Header
        main_layout.addWidget(
            create_section_header(
                "Forensic Incident Reporting Subsystem",
                "Chronological timeline fusion, cryptographic chain-of-custody seals, and academic defensive KPIs",
            )
        )

        # Splitter: Reports Catalog (Top) | Dossier Inspector (Bottom)
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self._build_catalog_panel())
        splitter.addWidget(self._build_inspector_panel())
        splitter.setSizes([320, 480])

        main_layout.addWidget(splitter, 1)

        # Initial refresh
        self.refresh_catalog()

    def _build_catalog_panel(self) -> QGroupBox:
        """Forensic reports catalog table and action controls."""
        group = QGroupBox("GENERATED FORENSIC REPORTS CATALOG (RUNTIME/REPORTS/)")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Action Buttons Row
        btn_row = QHBoxLayout()

        self.input_inc_id = QLineEdit()
        self.input_inc_id.setPlaceholderText("Enter Incident ID (e.g. INC-XXXXXXXX)...")
        self.input_inc_id.setFixedWidth(220)
        btn_row.addWidget(self.input_inc_id)

        self.btn_generate = QPushButton("Compile Report")
        self.btn_generate.setObjectName("btn-primary")
        self.btn_generate.clicked.connect(self._generate_report)
        btn_row.addWidget(self.btn_generate)

        self.btn_verify = QPushButton("Cryptographically Verify Seal")
        self.btn_verify.setObjectName("btn-success")
        self.btn_verify.clicked.connect(self._verify_seal)
        btn_row.addWidget(self.btn_verify)

        btn_row.addStretch()

        btn_refresh = QPushButton("Refresh Catalog")
        btn_refresh.clicked.connect(self.refresh_catalog)
        btn_row.addWidget(btn_refresh)

        layout.addLayout(btn_row)

        # Table of reports
        self.table_reports = QTableWidget()
        self.table_reports.setColumnCount(5)
        self.table_reports.setHorizontalHeaderLabels([
            "Report ID",
            "Incident ID",
            "Generated At",
            "Chain of Custody SHA-256 Seal",
            "Available Formats",
        ])
        self.table_reports.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_reports.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_reports.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_reports.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table_reports.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_reports.verticalHeader().setVisible(False)
        self.table_reports.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_reports.setAlternatingRowColors(True)
        self.table_reports.cellClicked.connect(self._on_report_selected)
        layout.addWidget(self.table_reports)

        # Verification Status Label
        self.lbl_verify_status = QLabel("Select a report and click 'Cryptographically Verify Seal' to audit integrity.")
        self.lbl_verify_status.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-size: 11px;")
        layout.addWidget(self.lbl_verify_status)

        return group

    def _build_inspector_panel(self) -> QGroupBox:
        """Tabbed inspector for selected dossier."""
        group = QGroupBox("FORENSIC DOSSIER & ATTACK TIMELINE INSPECTOR")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self.tabs_inspector = QTabWidget()

        # Tab 1: Academic KPIs
        self.tab_kpis = QWidget()
        kpi_layout = QVBoxLayout(self.tab_kpis)
        kpi_grid = QGridLayout()

        self.kpi_latency = KPICard("Detection Latency", "—", "Time to first detection", ThemeColors.CYAN)
        kpi_grid.addWidget(self.kpi_latency, 0, 0)

        self.kpi_containment = KPICard("Containment Duration", "—", "Time to isolate attack", ThemeColors.RED)
        kpi_grid.addWidget(self.kpi_containment, 0, 1)

        self.kpi_recovery = KPICard("Recovery Duration", "—", "Decryption & restore time", ThemeColors.PURPLE)
        kpi_grid.addWidget(self.kpi_recovery, 0, 2)

        self.kpi_protection = KPICard("Protection Rate", "—", "Preserved / total assets", ThemeColors.GREEN)
        kpi_grid.addWidget(self.kpi_protection, 1, 0)

        self.kpi_leakage = KPICard("Exfiltration Leakage", "—", "Zero-byte verification", ThemeColors.BLUE)
        kpi_grid.addWidget(self.kpi_leakage, 1, 1)

        self.kpi_hash_match = KPICard("Restoration Hash Match", "—", "SHA-256 match rate", ThemeColors.GREEN)
        kpi_grid.addWidget(self.kpi_hash_match, 1, 2)

        kpi_layout.addLayout(kpi_grid)
        self.tabs_inspector.addTab(self.tab_kpis, "Academic KPIs")

        # Tab 2: Chronological Timeline
        self.tab_timeline = QWidget()
        time_layout = QVBoxLayout(self.tab_timeline)
        self.table_timeline = QTableWidget()
        self.table_timeline.setColumnCount(4)
        self.table_timeline.setHorizontalHeaderLabels(["Timestamp", "Subsystem", "Event Type", "Description"])
        self.table_timeline.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_timeline.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_timeline.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_timeline.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table_timeline.verticalHeader().setVisible(False)
        self.table_timeline.setAlternatingRowColors(True)
        time_layout.addWidget(self.table_timeline)
        self.tabs_inspector.addTab(self.tab_timeline, "Chronological Attack Timeline")

        # Tab 3: Markdown / Formatted Summary
        self.tab_summary = QWidget()
        summary_layout = QVBoxLayout(self.tab_summary)
        self.txt_summary = QTextEdit()
        self.txt_summary.setReadOnly(True)
        summary_layout.addWidget(self.txt_summary)
        self.tabs_inspector.addTab(self.tab_summary, "Executive Summary")

        # Tab 4: Raw JSON Dossier
        self.tab_json = QWidget()
        json_layout = QVBoxLayout(self.tab_json)
        self.txt_json = QTextEdit()
        self.txt_json.setReadOnly(True)
        json_layout.addWidget(self.txt_json)
        self.tabs_inspector.addTab(self.tab_json, "Raw JSON Dossier")

        layout.addWidget(self.tabs_inspector)
        return group

    def refresh_catalog(self) -> None:
        """Query disk and populate reports catalog table."""
        try:
            self._reports_meta = self.coordinator.list_reports()
            self.table_reports.setRowCount(len(self._reports_meta))

            for row, r in enumerate(self._reports_meta):
                if hasattr(r, "export_files") and r.export_files:
                    formats = ", ".join(r.export_files.keys()).upper()
                else:
                    formats = "JSON, MD, CSV, HTML"
                seal = r.dossier_sha256 if r.dossier_sha256 else "UNSEALED"

                items = [
                    QTableWidgetItem(str(r.report_id)),
                    QTableWidgetItem(str(r.incident_id)),
                    QTableWidgetItem(str(r.generated_at)[:19]),
                    QTableWidgetItem(str(seal)),
                    QTableWidgetItem(str(formats)),
                ]
                items[0].setForeground(QColor(ThemeColors.CYAN))
                items[3].setForeground(QColor(ThemeColors.PURPLE))

                for col, itm in enumerate(items):
                    itm.setFlags(itm.flags() & ~Qt.ItemIsEditable)
                    self.table_reports.setItem(row, col, itm)

            if self._reports_meta:
                self.table_reports.selectRow(0)
                self._load_dossier(self._reports_meta[0].report_id)
        except Exception as e:
            self.lbl_verify_status.setText(f"[-] Failed to load reports: {e}")

    def _on_report_selected(self, row: int, col: int) -> None:
        """User clicked a row in the catalog table."""
        if 0 <= row < len(self._reports_meta):
            rep_id = self._reports_meta[row].report_id
            self._load_dossier(rep_id)

    def _load_dossier(self, report_id: str) -> None:
        """Loads and visualizes the full ForensicDossier."""
        try:
            dossier = self.coordinator.get_report(report_id)
            self._current_dossier = dossier

            # Populate KPIs
            m = dossier.metrics
            self.kpi_latency.set_value(f"{m.detection_latency_seconds:.4f}s")
            self.kpi_containment.set_value(f"{m.containment_duration_seconds:.4f}s")
            self.kpi_recovery.set_value(f"{m.recovery_duration_seconds:.2f}s")
            self.kpi_protection.set_value(f"{m.protection_success_rate:.1f}%")

            leak_str = "0 BYTES [PASS]" if m.zero_leakage_verified else f"{m.exfiltration_leakage_bytes}B [FAIL]"
            self.kpi_leakage.set_value(leak_str, accent_color=ThemeColors.GREEN if m.zero_leakage_verified else ThemeColors.RED)
            self.kpi_hash_match.set_value(f"{m.sha256_hash_match_rate:.1f}%")

            # Populate Timeline
            self.table_timeline.setRowCount(len(dossier.timeline))
            for row, t in enumerate(dossier.timeline):
                sub = t.subsystem.value if hasattr(t.subsystem, "value") else str(t.subsystem)
                action_name = getattr(t, "action", getattr(t, "event_type", "EVENT"))
                items = [
                    QTableWidgetItem(str(t.timestamp)[:19]),
                    QTableWidgetItem(str(sub)),
                    QTableWidgetItem(str(action_name)),
                    QTableWidgetItem(str(t.description)),
                ]
                # Color code
                if "CONTAINMENT" in sub or "BLOCKED" in str(action_name):
                    items[2].setForeground(QColor(ThemeColors.RED))
                elif "CANARY" in str(action_name):
                    items[2].setForeground(QColor(ThemeColors.ORANGE))
                elif "DLP" in sub:
                    items[2].setForeground(QColor(ThemeColors.AMBER))
                elif "RECOVERY" in sub:
                    items[2].setForeground(QColor(ThemeColors.GREEN))

                for c, itm in enumerate(items):
                    itm.setFlags(itm.flags() & ~Qt.ItemIsEditable)
                    self.table_timeline.setItem(row, c, itm)

            # Populate Markdown Summary
            md_path = CONFIG.REPORTS_DIR / f"{report_id}.md"
            if md_path.exists():
                self.txt_summary.setMarkdown(md_path.read_text(encoding="utf-8"))
            else:
                sev = getattr(dossier.detection, "peak_severity", getattr(dossier.detection, "severity", "NORMAL"))
                self.txt_summary.setPlainText(f"Executive Summary for {report_id}\nIncident: {dossier.incident_id}\nSeverity: {sev}")

            # Populate JSON Dossier
            data = dossier.to_dict() if hasattr(dossier, "to_dict") else vars(dossier)
            self.txt_json.setPlainText(json.dumps(data, indent=2))

        except Exception as e:
            self.lbl_verify_status.setText(f"[-] Error loading dossier: {e}")

    def _verify_seal(self) -> None:
        """Verifies SHA-256 chain-of-custody seal on the selected report."""
        row = self.table_reports.currentRow()
        if row < 0 or row >= len(self._reports_meta):
            self.lbl_verify_status.setText("[-] Please select a report from the table above.")
            return

        rep_id = self._reports_meta[row].report_id
        valid, msg = self.coordinator.verify_report(rep_id)

        color = ThemeColors.GREEN if valid else ThemeColors.RED
        self.lbl_verify_status.setText(f"Audit Result: {msg}")
        self.lbl_verify_status.setStyleSheet(f"color: {color}; font-weight: 700;")

    def _generate_report(self) -> None:
        """Generates a new forensic report for an incident ID."""
        inc_id = self.input_inc_id.text().strip()
        if not inc_id:
            self.lbl_verify_status.setText("[-] Enter an Incident ID (e.g. INC-XXXXXXXX) to compile report.")
            return

        try:
            dossier, paths = self.coordinator.generate_report(inc_id)
            self.lbl_verify_status.setText(f"[+] Successfully compiled report {dossier.report_id} across 4 formats!")
            self.lbl_verify_status.setStyleSheet(f"color: {ThemeColors.GREEN}; font-weight: 700;")
            self.refresh_catalog()
            self._load_dossier(dossier.report_id)
        except Exception as e:
            self.lbl_verify_status.setText(f"[-] Failed to generate report: {e}")
            self.lbl_verify_status.setStyleSheet(f"color: {ThemeColors.RED};")

    def _on_bridge_incident_resolved(self, incident_id: str, notes: str) -> None:
        """Auto-populate incident ID input and refresh catalog upon incident resolution."""
        if incident_id:
            self.input_inc_id.setText(incident_id)
        self.refresh_catalog()

    def _on_bridge_incident_created(self, incident_dict: Dict[str, Any]) -> None:
        """Auto-populate incident ID input when an incident starts."""
        inc_id = incident_dict.get("incident_id")
        if inc_id:
            self.input_inc_id.setText(str(inc_id))
