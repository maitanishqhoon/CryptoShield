"""
CryptoShield — Threat Containment Console Tab (Phase 10)
Manages application-level LabWriteGate enforcement, controlled simulation process
registries, and containment operation audit dossiers.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.config import CONFIG
from app.containment.containment_manager import ContainmentManager
from app.containment.lab_write_gate import LabWriteGate
from app.containment.process_registry import ControlledProcessRegistry
from app.core.models import (
    ContainmentRecord,
    ControlledProcessRecord,
    ProcessLifecycleStatus,
)
from app.ui.bridge import EventBusBridge
from app.ui.theme import ThemeColors, create_section_header


class ContainmentTab(QWidget):
    """
    Operator interface for threat containment:
    - Manual emergency lock/unlock of LabWriteGate
    - Surveillance and validation of registered simulation test processes
    - Inspection of historical containment audit dossiers (CONT-*)
    """

    def __init__(
        self,
        bridge: Optional[EventBusBridge] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.bridge = bridge
        self.write_gate = LabWriteGate.get_instance()
        self.registry = ControlledProcessRegistry.get_instance()
        self.containment_mgr = ContainmentManager.get_instance()
        self._history_records: List[ContainmentRecord] = []

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(14)

        # Section Header
        main_layout.addWidget(
            create_section_header(
                "Threat Containment Console & Active Interception",
                "Application-level write-gate enforcement, controlled process registry, and containment audit dossiers",
            )
        )

        # 1. LabWriteGate Panel
        main_layout.addWidget(self._build_gate_panel())

        # 2. Main Content Splitter (Process Registry & Containment History)
        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(self._build_process_panel())
        splitter.addWidget(self._build_history_panel())
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([300, 300])
        main_layout.addWidget(splitter, 1)

        # Connect Bridge signals if available
        if self.bridge:
            self.bridge.write_gate_changed.connect(self._on_bridge_gate_changed)
            self.bridge.containment_triggered.connect(self._on_bridge_containment_triggered)

        # Initial data population
        self.refresh_all()

    def _build_gate_panel(self) -> QGroupBox:
        """LabWriteGate emergency controls and active state indicator."""
        group = QGroupBox("LAB WRITE GATE CONTROL && ENFORCEMENT POSTURE")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        top_row.setSpacing(12)

        # Status badge
        self.lbl_gate_status = QLabel("GATE: UNLOCKED")
        self.lbl_gate_status.setAlignment(Qt.AlignCenter)
        self.lbl_gate_status.setFixedHeight(34)
        self.lbl_gate_status.setMinimumWidth(150)
        top_row.addWidget(self.lbl_gate_status)

        # Emergency Lock Button
        self.btn_lock = QPushButton("Emergency Lock Gate")
        self.btn_lock.setObjectName("btn-danger")
        self.btn_lock.setFixedHeight(34)
        self.btn_lock.setStyleSheet(f"""
            QPushButton {{
                background-color: {ThemeColors.RED_BG};
                color: {ThemeColors.RED};
                border: 1px solid {ThemeColors.RED};
                border-radius: 6px;
                padding: 6px 14px;
                font-weight: 700;
            }}
            QPushButton:hover {{
                background-color: {ThemeColors.RED};
                color: white;
            }}
        """)
        self.btn_lock.clicked.connect(self._lock_gate)
        top_row.addWidget(self.btn_lock)

        # Unlock Button
        self.btn_unlock = QPushButton("Unlock Gate")
        self.btn_unlock.setObjectName("btn-success")
        self.btn_unlock.setFixedHeight(34)
        self.btn_unlock.setStyleSheet(f"""
            QPushButton {{
                background-color: {ThemeColors.GREEN_BG};
                color: {ThemeColors.GREEN};
                border: 1px solid {ThemeColors.GREEN};
                border-radius: 6px;
                padding: 6px 14px;
                font-weight: 700;
            }}
            QPushButton:hover {{
                background-color: {ThemeColors.GREEN};
                color: white;
            }}
        """)
        self.btn_unlock.clicked.connect(self._unlock_gate)
        top_row.addWidget(self.btn_unlock)

        top_row.addStretch()
        layout.addLayout(top_row)

        # Gate details row: Active State File & Containment Target in a clean horizontal flow
        details_layout = QHBoxLayout()
        details_layout.setSpacing(28)

        state_box = QHBoxLayout()
        state_box.setSpacing(8)
        lbl_state_title = QLabel("Active State File:")
        lbl_state_title.setStyleSheet(f"color: {ThemeColors.TEXT_SECONDARY}; font-weight: 600; font-size: 11px;")
        state_box.addWidget(lbl_state_title)

        state_dir = getattr(CONFIG, "containment_dir", getattr(CONFIG, "CONTAINMENT_DIR", CONFIG.LAB_DIR))
        self.lbl_gate_file = QLabel(str(state_dir / ".write_gate_state"))
        self.lbl_gate_file.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-family: 'Consolas', monospace; font-size: 11px;")
        state_box.addWidget(self.lbl_gate_file)
        details_layout.addLayout(state_box)

        target_box = QHBoxLayout()
        target_box.setSpacing(8)
        lbl_target_title = QLabel("Containment Target:")
        lbl_target_title.setStyleSheet(f"color: {ThemeColors.TEXT_SECONDARY}; font-weight: 600; font-size: 11px;")
        target_box.addWidget(lbl_target_title)

        self.lbl_lab_dir = QLabel(str(CONFIG.LAB_DIR))
        self.lbl_lab_dir.setStyleSheet(f"color: {ThemeColors.TEXT_ACCENT}; font-family: 'Consolas', monospace; font-size: 11px;")
        target_box.addWidget(self.lbl_lab_dir)
        details_layout.addLayout(target_box)

        details_layout.addStretch()
        layout.addLayout(details_layout)

        # Safety boundary note
        lbl_safety = QLabel(
            "[SAFETY BOUNDARY] Application-level write gate intercepting operations during active containment. "
            "Guarantees laboratory containment without modifying host operating system ACLs."
        )
        lbl_safety.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-size: 11px; font-style: italic;")
        layout.addWidget(lbl_safety)

        return group

    def _build_process_panel(self) -> QGroupBox:
        """Controlled Process Registry table and monitoring."""
        group = QGroupBox("CONTROLLED TEST PROCESS REGISTRY (SAFETY BOUNDARY)")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Top action row
        top_row = QHBoxLayout()
        self.btn_refresh_proc = QPushButton("Refresh Processes")
        self.btn_refresh_proc.clicked.connect(self.refresh_processes)
        top_row.addWidget(self.btn_refresh_proc)

        lbl_invariant = QLabel(
            "[INVARIANT] Host OS processes are strictly protected. "
            "Only registered CryptoShield simulator processes may be contained."
        )
        lbl_invariant.setStyleSheet(f"color: {ThemeColors.CYAN}; font-size: 11px; font-weight: 600;")
        top_row.addWidget(lbl_invariant)
        top_row.addStretch()
        layout.addLayout(top_row)

        # Process table
        self.table_processes = QTableWidget()
        self.table_processes.setColumnCount(6)
        self.table_processes.setHorizontalHeaderLabels([
            "PID",
            "Simulation Run ID",
            "Expected Identity",
            "Lifecycle Status",
            "Executable Path",
            "Registered At",
        ])
        header = self.table_processes.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        header.setSectionResizeMode(3, QHeaderView.Interactive)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.Interactive)
        self.table_processes.setColumnWidth(0, 80)
        self.table_processes.setColumnWidth(1, 150)
        self.table_processes.setColumnWidth(2, 160)
        self.table_processes.setColumnWidth(3, 130)
        self.table_processes.setColumnWidth(5, 170)
        self.table_processes.verticalHeader().setVisible(False)
        self.table_processes.verticalHeader().setDefaultSectionSize(34)
        self.table_processes.verticalHeader().setMinimumSectionSize(28)
        self.table_processes.setMinimumHeight(130)
        self.table_processes.setShowGrid(True)
        self.table_processes.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_processes.setAlternatingRowColors(True)
        layout.addWidget(self.table_processes, 1)

        group.setMinimumHeight(190)
        return group

    def _build_history_panel(self) -> QGroupBox:
        """Recorded containment actions and JSON audit dossiers."""
        group = QGroupBox("RECORDED CONTAINMENT OPERATIONS && AUDIT DOSSIERS")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        top_row = QHBoxLayout()
        self.btn_refresh_hist = QPushButton("Refresh History")
        self.btn_refresh_hist.clicked.connect(self.refresh_history)
        top_row.addWidget(self.btn_refresh_hist)

        lbl_desc = QLabel("Select any containment record to inspect its full JSON cryptographic audit trail.")
        lbl_desc.setStyleSheet(f"color: {ThemeColors.TEXT_SECONDARY}; font-size: 11px;")
        top_row.addWidget(lbl_desc)
        top_row.addStretch()
        layout.addLayout(top_row)

        # Horizontal Splitter between History Table and Dossier Viewer
        h_splitter = QSplitter(Qt.Horizontal)
        h_splitter.setChildrenCollapsible(False)
        h_splitter.setMinimumHeight(120)

        # History table
        self.table_history = QTableWidget()
        self.table_history.setColumnCount(6)
        self.table_history.setHorizontalHeaderLabels([
            "Containment ID",
            "Simulation Run ID",
            "Actions Taken",
            "Initial Threat",
            "Final Status",
            "Start Timestamp",
        ])
        h_header = self.table_history.horizontalHeader()
        h_header.setSectionResizeMode(0, QHeaderView.Interactive)
        h_header.setSectionResizeMode(1, QHeaderView.Interactive)
        h_header.setSectionResizeMode(2, QHeaderView.Stretch)
        h_header.setSectionResizeMode(3, QHeaderView.Interactive)
        h_header.setSectionResizeMode(4, QHeaderView.Interactive)
        h_header.setSectionResizeMode(5, QHeaderView.Interactive)
        self.table_history.setColumnWidth(0, 140)
        self.table_history.setColumnWidth(1, 140)
        self.table_history.setColumnWidth(3, 140)
        self.table_history.setColumnWidth(4, 120)
        self.table_history.setColumnWidth(5, 170)
        self.table_history.verticalHeader().setVisible(False)
        self.table_history.verticalHeader().setDefaultSectionSize(34)
        self.table_history.verticalHeader().setMinimumSectionSize(28)
        self.table_history.setMinimumHeight(120)
        self.table_history.setShowGrid(True)
        self.table_history.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_history.setAlternatingRowColors(True)
        self.table_history.itemSelectionChanged.connect(self._on_history_selected)
        h_splitter.addWidget(self.table_history)

        # JSON Dossier viewer
        self.txt_dossier = QTextEdit()
        self.txt_dossier.setReadOnly(True)
        self.txt_dossier.setMinimumHeight(120)
        self.txt_dossier.setPlaceholderText("Select a containment record from the table to view complete JSON audit dossier...")
        self.txt_dossier.setStyleSheet(f"""
            QTextEdit {{
                background-color: {ThemeColors.BG_INPUT};
                color: {ThemeColors.TEXT_PRIMARY};
                font-family: "Consolas", monospace;
                font-size: 11px;
                border: 1px solid {ThemeColors.BORDER_DEFAULT};
                border-radius: 4px;
                padding: 6px;
            }}
        """)
        h_splitter.addWidget(self.txt_dossier)
        h_splitter.setSizes([550, 450])

        layout.addWidget(h_splitter, 1)
        group.setMinimumHeight(180)
        return group

    def _lock_gate(self) -> None:
        """Manually trigger emergency write gate lock."""
        self.write_gate.lock(reason="Manual Emergency Lock via UI Console")
        self.refresh_gate()
        if self.bridge:
            self.bridge.write_gate_changed.emit(True)

    def _unlock_gate(self) -> None:
        """Unlock write gate to restore standard laboratory writes."""
        self.write_gate.unlock()
        self.refresh_gate()
        if self.bridge:
            self.bridge.write_gate_changed.emit(False)

    def refresh_gate(self) -> None:
        """Update write gate indicator and state file status."""
        is_locked = self.write_gate.is_locked()
        if is_locked:
            self.lbl_gate_status.setText("GATE: LOCKED")
            self.lbl_gate_status.setStyleSheet(f"""
                QLabel {{
                    color: {ThemeColors.RED};
                    background-color: {ThemeColors.RED_BG};
                    border: 1px solid {ThemeColors.RED};
                    border-radius: 6px;
                    padding: 4px 12px;
                    font-weight: 800;
                    font-size: 13px;
                }}
            """)
        else:
            self.lbl_gate_status.setText("GATE: UNLOCKED")
            self.lbl_gate_status.setStyleSheet(f"""
                QLabel {{
                    color: {ThemeColors.GREEN};
                    background-color: {ThemeColors.GREEN_BG};
                    border: 1px solid {ThemeColors.GREEN};
                    border-radius: 6px;
                    padding: 4px 12px;
                    font-weight: 800;
                    font-size: 13px;
                }}
            """)

    def refresh_processes(self) -> None:
        """Inspect ControlledProcessRegistry and populate table."""
        try:
            records = self.registry.list_records()
            self.table_processes.setRowCount(len(records))
            for row, rec in enumerate(records):
                status_str = str(rec.lifecycle_status)
                reg_time = str(rec.registered_at)[:19].replace("T", " ")
                items = [
                    QTableWidgetItem(str(rec.pid)),
                    QTableWidgetItem(str(rec.simulation_run_id)),
                    QTableWidgetItem(str(rec.expected_identity)),
                    QTableWidgetItem(status_str),
                    QTableWidgetItem(str(rec.executable_path)),
                    QTableWidgetItem(reg_time),
                ]

                # Color code status
                if status_str == ProcessLifecycleStatus.RUNNING.value:
                    items[3].setForeground(QColor(ThemeColors.GREEN))
                elif status_str in (ProcessLifecycleStatus.TERMINATED.value, ProcessLifecycleStatus.EXITED.value):
                    items[3].setForeground(QColor(ThemeColors.TEXT_MUTED))
                else:
                    items[3].setForeground(QColor(ThemeColors.AMBER))

                items[0].setForeground(QColor(ThemeColors.CYAN))
                items[1].setForeground(QColor(ThemeColors.PURPLE))

                items[0].setToolTip(f"Process PID: {rec.pid}")
                items[4].setToolTip(str(rec.executable_path))

                for col, itm in enumerate(items):
                    itm.setFlags(itm.flags() & ~Qt.ItemIsEditable)
                    self.table_processes.setItem(row, col, itm)
        except Exception as e:
            if hasattr(self, "txt_dossier"):
                self.txt_dossier.setPlainText(f"[-] Error refreshing processes: {e}")

    def refresh_history(self) -> None:
        """Query ContainmentManager for containment dossiers."""
        try:
            self._history_records = self.containment_mgr.list_records()
            self._history_records.sort(
                key=lambda r: getattr(r, "start_timestamp", ""),
                reverse=True,
            )
            self.table_history.setRowCount(len(self._history_records))
            for row, rec in enumerate(self._history_records):
                actions_str = ", ".join(rec.actions_taken) if rec.actions_taken else "NONE"
                status_str = str(rec.final_status)
                score_str = f"{rec.initial_threat_score} ({rec.severity})"
                start_time = str(rec.start_timestamp)[:19].replace("T", " ")
                items = [
                    QTableWidgetItem(str(rec.containment_id)),
                    QTableWidgetItem(str(rec.simulation_run_id or "N/A")),
                    QTableWidgetItem(actions_str),
                    QTableWidgetItem(score_str),
                    QTableWidgetItem(status_str),
                    QTableWidgetItem(start_time),
                ]

                # Colors
                items[0].setForeground(QColor(ThemeColors.PURPLE))
                items[0].setToolTip(f"Containment ID: {rec.containment_id}")
                items[2].setToolTip(actions_str)
                if status_str == "CONTAINED":
                    items[4].setForeground(QColor(ThemeColors.GREEN))
                elif status_str == "FAILED":
                    items[4].setForeground(QColor(ThemeColors.RED))
                else:
                    items[4].setForeground(QColor(ThemeColors.AMBER))

                for col, itm in enumerate(items):
                    itm.setFlags(itm.flags() & ~Qt.ItemIsEditable)
                    self.table_history.setItem(row, col, itm)
        except Exception as e:
            if hasattr(self, "txt_dossier"):
                self.txt_dossier.setPlainText(f"[-] Error refreshing history: {e}")

    def _on_history_selected(self) -> None:
        """Display JSON audit dossier of selected containment operation."""
        row = self.table_history.currentRow()
        if row < 0 or row >= len(self._history_records):
            return
        rec = self._history_records[row]
        data = rec.to_dict() if hasattr(rec, "to_dict") else vars(rec)
        self.txt_dossier.setPlainText(json.dumps(data, indent=2))

    def refresh_all(self) -> None:
        """Refresh gate, processes, and containment history."""
        self.refresh_gate()
        self.refresh_processes()
        self.refresh_history()

    def _on_bridge_gate_changed(self, is_locked: bool) -> None:
        """Slot invoked when EventBusBridge reports a gate state change."""
        self.refresh_gate()

    def _on_bridge_containment_triggered(self, data: Dict[str, Any]) -> None:
        """Slot invoked when EventBusBridge reports containment execution."""
        self.refresh_all()
