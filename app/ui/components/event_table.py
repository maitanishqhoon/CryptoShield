"""
CryptoShield — Telemetry Event Table Component (Phase 10)
High-performance virtualized telemetry table displaying live file and security events.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.config import CONFIG
from app.core.event_bus import Event
from app.ui.theme import ThemeColors


class EventTable(QWidget):
    """
    Real-time security event table with live filtering, category selection,
    auto-scrolling, and bounded memory retention.
    """

    MAX_ROWS = 500

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Controls bar: Search, Filter, Auto-scroll, Clear
        controls_layout = QHBoxLayout()
        controls_layout.setContentsMargins(0, 0, 0, 0)

        # Search bar
        self.input_search = QLineEdit()
        self.input_search.setPlaceholderText("Filter by path, department, or token...")
        self.input_search.textChanged.connect(self._apply_filters)
        controls_layout.addWidget(self.input_search, 2)

        # Category filter combo
        self.combo_filter = QComboBox()
        self.combo_filter.addItems([
            "All Events",
            "Canary Breaches",
            "Filesystem (Write/Modify/Delete)",
            "Access & Reads",
            "Containment",
            "DLP Gate",
            "Incidents & Alerts",
        ])
        self.combo_filter.currentIndexChanged.connect(self._apply_filters)
        controls_layout.addWidget(self.combo_filter, 1)

        # Auto-scroll toggle
        self.chk_autoscroll = QCheckBox("Auto-scroll")
        self.chk_autoscroll.setChecked(True)
        controls_layout.addWidget(self.chk_autoscroll)

        # Clear button
        self.btn_clear = QPushButton("Clear")
        self.btn_clear.clicked.connect(self.clear_table)
        controls_layout.addWidget(self.btn_clear)

        layout.addLayout(controls_layout)

        # Table Widget
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Timestamp",
            "Event Type",
            "Classification",
            "Department",
            "Path / Details",
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        layout.addWidget(self.table)

        # Status footer
        self.lbl_status = QLabel("Events: 0")
        self.lbl_status.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-size: 11px;")
        layout.addWidget(self.lbl_status)

        self._all_records: List[Dict[str, Any]] = []

    def add_event(self, event: Event) -> None:
        """Add an EventBus Event to the table."""
        data = event.data or {}
        ts = event.timestamp
        if "T" in ts:
            try:
                # Format to HH:MM:SS.mmm in Indian Standard Time (IST)
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.tzinfo is not None:
                    dt = dt.astimezone(CONFIG.TIMEZONE)
                else:
                    dt = dt.replace(tzinfo=CONFIG.TIMEZONE)
                ts_str = dt.strftime("%H:%M:%S.%f")[:-3]
            except Exception:
                ts_str = ts[-12:]
        else:
            ts_str = ts

        record = {
            "timestamp": ts_str,
            "event_type": event.event_type,
            "classification": data.get("classification", data.get("file_classification", "—")),
            "department": data.get("department", "—"),
            "details": data.get("path", data.get("file_path", data.get("message", str(data)))),
            "is_canary": data.get("is_canary", False) or "CANARY" in event.event_type,
            "severity": data.get("severity", "NORMAL"),
        }
        self.add_record(record)

    def add_record(self, record: Dict[str, Any]) -> None:
        """Add a formatted record dictionary to the table."""
        self._all_records.append(record)
        if len(self._all_records) > self.MAX_ROWS:
            self._all_records.pop(0)

        # Check if record matches active filters
        if self._matches_filter(record):
            self._append_row(record)
            self._update_status()

    def _append_row(self, record: Dict[str, Any]) -> None:
        """Inserts a row into the QTableWidget with appropriate color styling."""
        row = self.table.rowCount()
        self.table.insertRow(row)

        items = [
            QTableWidgetItem(str(record.get("timestamp", ""))),
            QTableWidgetItem(str(record.get("event_type", ""))),
            QTableWidgetItem(str(record.get("classification", "—"))),
            QTableWidgetItem(str(record.get("department", "—"))),
            QTableWidgetItem(str(record.get("details", ""))),
        ]

        # Determine styling color based on event type and canary status
        et = record.get("event_type", "")
        is_canary = record.get("is_canary", False)

        if is_canary or "CANARY" in et:
            color = QColor(ThemeColors.ORANGE)
        elif "CONTAINMENT" in et or "BLOCKED" in et or record.get("severity") == "CRITICAL":
            color = QColor(ThemeColors.RED)
        elif "APPROVAL" in et or "QUARANTINE" in et or record.get("severity") in ("HIGH", "MEDIUM"):
            color = QColor(ThemeColors.AMBER)
        elif "RECOVERY" in et or "VERIFIED" in et:
            color = QColor(ThemeColors.GREEN)
        else:
            color = QColor(ThemeColors.TEXT_PRIMARY)

        for col, item in enumerate(items):
            item.setForeground(color)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self.table.setItem(row, col, item)

        if self.chk_autoscroll.isChecked():
            self.table.scrollToBottom()

    def _matches_filter(self, record: Dict[str, Any]) -> bool:
        """Evaluates whether a record matches the search query and category dropdown."""
        query = self.input_search.text().strip().lower()
        if query:
            match = False
            for val in record.values():
                if query in str(val).lower():
                    match = True
                    break
            if not match:
                return False

        cat = self.combo_filter.currentText()
        et = record.get("event_type", "").upper()

        if cat == "All Events":
            return True
        elif cat == "Canary Breaches":
            return record.get("is_canary", False) or "CANARY" in et
        elif cat == "Filesystem (Write/Modify/Delete)":
            return any(k in et for k in ("FILE_CREATED", "FILE_MODIFIED", "FILE_DELETED", "FILE_MOVED"))
        elif cat == "Access & Reads":
            return any(k in et for k in ("FILE_READ", "FILE_OPEN", "FILE_ACCESS", "BURST"))
        elif cat == "Containment":
            return "CONTAINMENT" in et
        elif cat == "DLP Gate":
            return "DLP" in et
        elif cat == "Incidents & Alerts":
            return any(k in et for k in ("INCIDENT", "ALERT", "DETECTION"))

        return True

    def _apply_filters(self) -> None:
        """Refreshes the table display based on current filters."""
        self.table.setRowCount(0)
        for record in self._all_records:
            if self._matches_filter(record):
                self._append_row(record)
        self._update_status()

    def clear_table(self) -> None:
        """Clears all records from the table and internal buffer."""
        self._all_records.clear()
        self.table.setRowCount(0)
        self._update_status()

    def _update_status(self) -> None:
        """Updates the status counter label."""
        total = len(self._all_records)
        visible = self.table.rowCount()
        self.lbl_status.setText(f"Showing {visible} of {total} events")
