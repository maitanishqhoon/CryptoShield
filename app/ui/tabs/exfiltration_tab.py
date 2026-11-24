"""
CryptoShield — Data Exfiltration Monitoring & DLP Center Tab (Phase 10)
Manages loopback mock receivers, DLP posture profiles (DEFAULT, STRICT, AUDIT_ONLY, PERMISSIVE),
policy rule matrix, live monitored outbound transfers, quarantined approval workflows, and pre-transmission interception logs.
"""

import json
from typing import Any, Dict, List, Optional
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
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
from app.dlp.approval_manager import DLPApprovalManager
from app.dlp.dlp_coordinator import DLP_COORDINATOR
from app.dlp.models import DLPAction, DLPProfile
from app.dlp.policy_engine import DLPPolicyEngine
from app.exfiltration.exfiltration_coordinator import EXFILTRATION_COORDINATOR
from app.exfiltration.mock_receiver import MockReceiver
from app.ui.theme import ThemeColors, create_section_header


class ExfiltrationTab(QWidget):
    """
    Console for monitoring exfiltration staging and network transfers,
    modifying DLP security posture profiles, managing approval queues,
    and auditing zero-leakage enforcement.
    """

    def __init__(self, bridge: Optional[Any] = None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.bridge = bridge
        self.dlp_coord = DLP_COORDINATOR
        self.policy_engine = getattr(self.dlp_coord, "policy_engine", DLPPolicyEngine())
        self.approval_mgr = getattr(self.dlp_coord, "approval_manager", DLPApprovalManager())
        self.mock_receiver: Optional[MockReceiver] = getattr(EXFILTRATION_COORDINATOR, "receiver", None)
        self._transfers: List[Dict[str, Any]] = []

        if self.bridge:
            if hasattr(self.bridge, "dlp_interception"):
                self.bridge.dlp_interception.connect(self._on_bridge_dlp_event)
            if hasattr(self.bridge, "exfiltration_activity"):
                self.bridge.exfiltration_activity.connect(self._on_bridge_exfil_event)
            if hasattr(self.bridge, "event_received"):
                self.bridge.event_received.connect(self._on_bridge_bus_event)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 12, 14, 12)
        main_layout.setSpacing(10)

        # Section Header
        main_layout.addWidget(
            create_section_header(
                "Data Exfiltration Monitoring & Data Loss Prevention (DLP) Center",
                "Loopback socket telemetry, priority rule matrix, and pre-transmission zero-byte interception gate",
            )
        )

        # Main Horizontal Splitter:
        # Left: Squeezed Mock Receiver (Top) + DLP Policy Matrix (Bottom)
        # Right: Expanded Live Outbound Transfers (Top) + Quarantined Approvals & Audit (Bottom)
        main_splitter = QSplitter(Qt.Horizontal)

        # Left Column Container
        left_container = QWidget()
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)
        left_layout.addWidget(self._build_receiver_panel())
        left_layout.addWidget(self._build_dlp_policy_panel(), 1)
        main_splitter.addWidget(left_container)

        # Right Column Splitter (Vertical)
        right_splitter = QSplitter(Qt.Vertical)
        right_splitter.addWidget(self._build_transfers_panel())
        right_splitter.addWidget(self._build_approvals_panel())
        right_splitter.setStretchFactor(0, 3)  # Transfers gets 60% of right height
        right_splitter.setStretchFactor(1, 2)  # Approvals gets 40% of right height
        right_splitter.setSizes([380, 240])
        main_splitter.addWidget(right_splitter)

        main_splitter.setStretchFactor(0, 4)
        main_splitter.setStretchFactor(1, 6)
        main_splitter.setSizes([450, 650])

        main_layout.addWidget(main_splitter, 1)

        # Initial refresh
        self.refresh_all()

    def _build_receiver_panel(self) -> QGroupBox:
        """Loopback mock socket receiver controls, squeezed horizontally into the left column."""
        group = QGroupBox("SAFE LOOPBACK MOCK RECEIVER (127.0.0.1)")
        layout = QGridLayout(group)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(6)

        # Row 0: Status & Endpoint
        layout.addWidget(QLabel("Status:"), 0, 0)
        self.lbl_receiver_status = QLabel("IDLE (Stopped)")
        self.lbl_receiver_status.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-weight: 700;")
        layout.addWidget(self.lbl_receiver_status, 0, 1)

        layout.addWidget(QLabel("Endpoint:"), 0, 2)
        self.lbl_endpoint = QLabel("None")
        self.lbl_endpoint.setStyleSheet(f"color: {ThemeColors.TEXT_ACCENT}; font-family: monospace;")
        layout.addWidget(self.lbl_endpoint, 0, 3)

        # Row 1: Metrics & Loopback Constraint
        layout.addWidget(QLabel("Payloads:"), 1, 0)
        self.lbl_receiver_metrics = QLabel("0 payloads | 0 bytes")
        layout.addWidget(self.lbl_receiver_metrics, 1, 1)

        lbl_safety = QLabel("[Loopback 127.0.0.1 Only]")
        lbl_safety.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-size: 11px;")
        layout.addWidget(lbl_safety, 1, 2, 1, 2)

        # Row 2: Control Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        self.btn_start_receiver = QPushButton("Start Mock Receiver")
        self.btn_start_receiver.setObjectName("btn-primary")
        self.btn_start_receiver.clicked.connect(self._start_receiver)
        btn_row.addWidget(self.btn_start_receiver)

        self.btn_stop_receiver = QPushButton("Stop Mock Receiver")
        self.btn_stop_receiver.setEnabled(False)
        self.btn_stop_receiver.clicked.connect(self._stop_receiver)
        btn_row.addWidget(self.btn_stop_receiver)

        btn_row.addStretch()
        layout.addLayout(btn_row, 2, 0, 1, 4)

        return group

    def _build_dlp_policy_panel(self) -> QGroupBox:
        """DLP Posture Profile selector and rule matrix."""
        group = QGroupBox("DLP SECURITY POSTURE & PRIORITY RULE MATRIX")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(6)

        # Profile Switcher Row
        prof_row = QHBoxLayout()
        prof_row.addWidget(QLabel("Active Posture:"))
        self.combo_profile = QComboBox()
        self.combo_profile.addItems(["DEFAULT", "STRICT", "AUDIT_ONLY", "PERMISSIVE"])
        prof_row.addWidget(self.combo_profile)

        self.btn_apply_profile = QPushButton("Apply Profile")
        self.btn_apply_profile.setObjectName("btn-primary")
        self.btn_apply_profile.clicked.connect(self._apply_profile)
        prof_row.addWidget(self.btn_apply_profile)

        prof_row.addStretch()
        layout.addLayout(prof_row)

        # Rules Table
        self.table_rules = QTableWidget()
        self.table_rules.setColumnCount(5)
        self.table_rules.setHorizontalHeaderLabels(["Pri", "Rule Name", "Classification", "Canary", "Action"])
        self.table_rules.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_rules.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_rules.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_rules.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_rules.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_rules.verticalHeader().setVisible(False)
        self.table_rules.setAlternatingRowColors(True)
        layout.addWidget(self.table_rules, 1)

        return group

    def _build_transfers_panel(self) -> QGroupBox:
        """Expanded live monitored outbound transfers and DLP interception table."""
        group = QGroupBox("LIVE MONITORED OUTBOUND TRANSFERS & DLP INTERCEPTION")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(6)

        self.table_transfers = QTableWidget()
        self.table_transfers.setColumnCount(7)
        self.table_transfers.setHorizontalHeaderLabels([
            "Transfer ID", "Time", "Destination", "Classification", "Canary", "Bytes", "DLP / Status"
        ])
        self.table_transfers.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_transfers.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_transfers.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_transfers.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_transfers.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_transfers.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table_transfers.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.table_transfers.verticalHeader().setVisible(False)
        self.table_transfers.setAlternatingRowColors(True)
        self.table_transfers.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_transfers.setMinimumHeight(200)
        layout.addWidget(self.table_transfers, 1)

        return group

    def _build_approvals_panel(self) -> QGroupBox:
        """Quarantined approval queue and audit log stream."""
        group = QGroupBox("QUARANTINED APPROVAL QUEUE & AUDIT STREAM")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(6)

        # Approvals Table
        self.table_approvals = QTableWidget()
        self.table_approvals.setColumnCount(5)
        self.table_approvals.setHorizontalHeaderLabels(["Token", "Created", "Classification", "Files", "Status"])
        self.table_approvals.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_approvals.verticalHeader().setVisible(False)
        self.table_approvals.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_approvals.setMinimumHeight(85)
        layout.addWidget(self.table_approvals, 1)

        # Action Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        self.btn_stage_test = QPushButton("Simulate Sensitive Transfer")
        self.btn_stage_test.setObjectName("btn-primary")
        self.btn_stage_test.setToolTip("Queue an outbound transfer of CONFIDENTIAL records to test the quarantine gate")
        self.btn_stage_test.clicked.connect(self._stage_test_transfer)
        btn_row.addWidget(self.btn_stage_test)

        self.btn_approve = QPushButton("Approve Selected Transfer")
        self.btn_approve.setObjectName("btn-success")
        self.btn_approve.clicked.connect(self._approve_transfer)
        btn_row.addWidget(self.btn_approve)

        self.btn_reject = QPushButton("Reject Selected Transfer")
        self.btn_reject.setObjectName("btn-danger")
        self.btn_reject.clicked.connect(self._reject_transfer)
        btn_row.addWidget(self.btn_reject)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Audit Log Viewer
        layout.addWidget(QLabel("DLP Policy Audit Log (runtime/dlp/audit.log):"))
        self.txt_audit_log = QTextEdit()
        self.txt_audit_log.setReadOnly(True)
        self.txt_audit_log.setFixedHeight(65)
        layout.addWidget(self.txt_audit_log)

        return group

    def refresh_all(self) -> None:
        """Refresh profile, rule matrix, approvals, audit log, transfers, and receiver."""
        self.refresh_profile_and_rules()
        self.refresh_approvals()
        self.refresh_audit_log()
        self.refresh_transfers()
        self.refresh_receiver_status()

    def refresh_profile_and_rules(self) -> None:
        """Query active DLP posture and populate rule matrix."""
        status = self.dlp_coord.get_status()
        active_prof = status.get("profile", "DEFAULT")
        idx = self.combo_profile.findText(active_prof)
        if idx >= 0:
            self.combo_profile.setCurrentIndex(idx)

        rules = self.policy_engine.get_rules()
        self.table_rules.setRowCount(len(rules))

        for row, r in enumerate(rules):
            action_str = r.action.value if hasattr(r.action, "value") else str(r.action)
            class_str = ", ".join(r.target_classifications) if r.target_classifications else ("CANARY" if r.block_canaries else "ANY")
            is_canary_str = "YES" if r.block_canaries else "—"

            items = [
                QTableWidgetItem(str(r.priority)),
                QTableWidgetItem(str(r.name)),
                QTableWidgetItem(class_str),
                QTableWidgetItem(is_canary_str),
                QTableWidgetItem(action_str),
            ]

            # Color action
            if action_str == "BLOCK":
                items[4].setForeground(QColor(ThemeColors.RED))
            elif action_str == "REQUIRE_APPROVAL":
                items[4].setForeground(QColor(ThemeColors.AMBER))
            elif action_str == "ALERT":
                items[4].setForeground(QColor(ThemeColors.ORANGE))
            else:
                items[4].setForeground(QColor(ThemeColors.GREEN))

            for col, itm in enumerate(items):
                itm.setFlags(itm.flags() & ~Qt.ItemIsEditable)
                self.table_rules.setItem(row, col, itm)

    def refresh_transfers(self) -> None:
        """Query recorded transfers from coordinator and persistent audit logs."""
        known_ids = {t.get("transfer_id") for t in self._transfers if isinstance(t, dict)}

        # 1. Check in-memory transfer monitor records
        try:
            records = EXFILTRATION_COORDINATOR.transfer_monitor.get_transfer_records()
            for rec in records:
                rec_dict = rec.to_dict() if hasattr(rec, "to_dict") else dict(rec)
                xid = rec_dict.get("transfer_id")
                if xid and xid not in known_ids:
                    self._transfers.append(rec_dict)
                    known_ids.add(xid)
        except Exception:
            pass

        # 2. If transfers list is empty (e.g. fresh launch), populate from recent audit.log entries
        if not self._transfers:
            log_file = CONFIG.DLP_DIR / "audit.log"
            if log_file.exists():
                try:
                    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
                    for line in lines[-12:]:
                        try:
                            record = json.loads(line)
                            ev_type = record.get("event_type", "")
                            if ev_type in ("DLP_TRANSFER_ALLOWED", "DLP_ALERT_TRIGGERED", "DLP_APPROVAL_REQUIRED", "DLP_TRANSFER_BLOCKED"):
                                details = record.get("details", {})
                                t_details = details.get("transfer_details", {}) if isinstance(details, dict) else {}
                                endpoint = details.get("destination_endpoint") or t_details.get("destination_endpoint", "127.0.0.1:8999")
                                xid = details.get("evaluation_id") or record.get("record_id", f"AUD-{len(self._transfers)+1:03d}")
                                if xid in known_ids:
                                    continue

                                classifications = details.get("classifications_evaluated") or t_details.get("classifications", ["CONFIDENTIAL"])
                                is_canary = details.get("contains_canary") or t_details.get("contains_canary", False)
                                b_val = details.get("bytes_requested") or t_details.get("bytes", 0)
                                act = record.get("action", details.get("action", "EVALUATE"))
                                status_str = act
                                if act == "BLOCK":
                                    status_str = "BLOCKED [DLP]"
                                elif act == "REQUIRE_APPROVAL":
                                    status_str = "QUARANTINED"
                                elif act == "ALLOW":
                                    status_str = "COMPLETED [ALLOWED]"

                                self._transfers.append({
                                    "transfer_id": xid,
                                    "timestamp": record.get("timestamp", ""),
                                    "destination_endpoint": endpoint,
                                    "classifications": classifications,
                                    "contains_canary": is_canary,
                                    "bytes_transferred": 0 if act in ("BLOCK", "REQUIRE_APPROVAL") else b_val,
                                    "status": status_str,
                                })
                                known_ids.add(xid)
                        except Exception:
                            continue
                except Exception:
                    pass

        self._repopulate_transfers_table()

    def _repopulate_transfers_table(self) -> None:
        """Render rows in table_transfers."""
        self.table_transfers.setRowCount(len(self._transfers))
        for row, t in enumerate(self._transfers):
            self._populate_transfer_row(row, t)

    def _populate_transfer_row(self, row: int, data: Dict[str, Any]) -> None:
        xfer_id = str(data.get("transfer_id", f"XFER-{row+1:04d}"))
        ts = str(data.get("timestamp", ""))
        time_str = ts[11:19] if len(ts) >= 19 else ts
        if not time_str:
            time_str = "--:--:--"
        endpoint = str(data.get("destination_endpoint", "127.0.0.1:8999"))

        classes = data.get("classifications_included", data.get("classifications", []))
        class_str = ", ".join(classes) if isinstance(classes, list) and classes else str(data.get("classification", "GENERAL"))
        if not class_str:
            class_str = "GENERAL"

        is_canary = bool(data.get("contains_canary", False))
        canary_str = "TRIPPED" if is_canary else "—"

        bytes_val = data.get("bytes_transferred", 0)
        bytes_str = f"{bytes_val:,} B" if bytes_val > 0 else "0 B (Zero-Leakage)"

        status_val = str(data.get("status", "UNKNOWN")).upper()
        meta = data.get("metadata", {})
        if isinstance(meta, dict) and meta.get("dlp_intercepted"):
            status_val = f"BLOCKED [{meta.get('dlp_action', 'DLP')}]"
        elif status_val == "COMPLETED":
            status_val = "COMPLETED [ALLOWED]"

        items = [
            QTableWidgetItem(xfer_id),
            QTableWidgetItem(time_str),
            QTableWidgetItem(endpoint),
            QTableWidgetItem(class_str),
            QTableWidgetItem(canary_str),
            QTableWidgetItem(bytes_str),
            QTableWidgetItem(status_val),
        ]

        if is_canary:
            items[4].setForeground(QColor(ThemeColors.RED))
        if "BLOCK" in status_val or status_val == "FAILED":
            items[6].setForeground(QColor(ThemeColors.RED))
        elif "QUARANTIN" in status_val or "APPROVAL" in status_val or status_val == "PENDING":
            items[6].setForeground(QColor(ThemeColors.AMBER))
        elif "ALERT" in status_val:
            items[6].setForeground(QColor(ThemeColors.ORANGE))
        else:
            items[6].setForeground(QColor(ThemeColors.GREEN))

        for col, itm in enumerate(items):
            itm.setFlags(itm.flags() & ~Qt.ItemIsEditable)
            self.table_transfers.setItem(row, col, itm)

    def _add_transfer_row(self, data: Dict[str, Any]) -> None:
        """Dynamically append a single transfer entry in real time."""
        xfer_id = data.get("transfer_id")
        if xfer_id and any(t.get("transfer_id") == xfer_id for t in self._transfers):
            return
        self._transfers.append(data)
        row = self.table_transfers.rowCount()
        self.table_transfers.insertRow(row)
        self._populate_transfer_row(row, data)
        self.table_transfers.scrollToBottom()

    def refresh_approvals(self) -> None:
        """Query quarantined approval queue."""
        requests = self.approval_mgr.get_all_requests()
        self.table_approvals.setRowCount(len(requests))
        self._current_requests: List[Any] = requests

        for row, req in enumerate(requests):
            status_str = req.status.value if hasattr(req.status, "value") else str(req.status)
            details = getattr(req, "transfer_details", getattr(req, "transfer_context", {}))
            classifications = details.get("classifications", [])
            class_str = ", ".join(classifications) if isinstance(classifications, list) else str(details.get("classification", "CONFIDENTIAL"))
            if not class_str:
                class_str = "CONFIDENTIAL"
            req_time = getattr(req, "requested_at", getattr(req, "created_at", ""))
            items = [
                QTableWidgetItem(str(req.approval_token)),
                QTableWidgetItem(str(req_time)[:19]),
                QTableWidgetItem(class_str),
                QTableWidgetItem(f"{details.get('file_count', 1):,}"),
                QTableWidgetItem(status_str),
            ]
            items[4].setForeground(QColor(ThemeColors.AMBER) if status_str == "PENDING" else QColor(ThemeColors.GREEN))
            for col, itm in enumerate(items):
                itm.setFlags(itm.flags() & ~Qt.ItemIsEditable)
                self.table_approvals.setItem(row, col, itm)

    def refresh_audit_log(self) -> None:
        """Read latest lines of runtime/dlp/audit.log."""
        log_file = CONFIG.DLP_DIR / "audit.log"
        if log_file.exists():
            try:
                lines = log_file.read_text(encoding="utf-8").strip().splitlines()
                self.txt_audit_log.setPlainText("\n".join(lines[-15:]))
            except Exception:
                pass

    def refresh_receiver_status(self) -> None:
        """Update receiver status and metrics display."""
        receiver = getattr(self, "mock_receiver", None) or EXFILTRATION_COORDINATOR.receiver
        if receiver and receiver.is_running():
            self.lbl_receiver_status.setText(f"LISTENING [127.0.0.1:{receiver.actual_port}]")
            self.lbl_receiver_status.setStyleSheet(f"color: {ThemeColors.CYAN}; font-weight: 700;")
            self.lbl_endpoint.setText(f"{receiver.host}:{receiver.actual_port}")
            self.btn_start_receiver.setEnabled(False)
            self.btn_stop_receiver.setEnabled(True)
        else:
            self.lbl_receiver_status.setText("IDLE (Stopped)")
            self.lbl_receiver_status.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-weight: 700;")
            self.lbl_endpoint.setText("None")
            self.btn_start_receiver.setEnabled(True)
            self.btn_stop_receiver.setEnabled(False)

        metrics = receiver.get_metrics() if receiver else {"payloads_received": 0, "bytes_received": 0}
        self.lbl_receiver_metrics.setText(
            f"{metrics.get('payloads_received', 0)} payloads | {metrics.get('bytes_received', 0):,} bytes"
        )

    def _ingest_dlp_event_data(self, data: Dict[str, Any]) -> None:
        """Extract transfer record fields from DLP event dict and add to table."""
        if not isinstance(data, dict):
            return
        t_details = data.get("transfer_details", {}) if isinstance(data.get("transfer_details"), dict) else {}
        endpoint = data.get("destination_endpoint") or t_details.get("destination_endpoint", "127.0.0.1:8999")
        xid = data.get("transfer_id") or data.get("evaluation_id") or data.get("approval_token") or f"DLP-{len(self._transfers)+1:03d}"
        classes = data.get("classifications_evaluated") or data.get("classifications") or t_details.get("classifications", ["CONFIDENTIAL"])
        is_canary = data.get("contains_canary") or t_details.get("contains_canary", False)
        b_val = data.get("bytes_transferred") or data.get("bytes_requested") or t_details.get("bytes", 0)
        action_val = data.get("action") or data.get("dlp_action") or data.get("status", "BLOCKED")
        if hasattr(action_val, "value"):
            action_val = action_val.value
        action_val = str(action_val).upper()

        if action_val in ("BLOCK", "BLOCKED"):
            status_val = "BLOCKED [DLP]"
            b_val = 0
        elif action_val in ("REQUIRE_APPROVAL", "PENDING", "QUARANTINED"):
            status_val = "QUARANTINED"
            b_val = 0
        elif action_val in ("ALLOW", "ALLOWED", "COMPLETED"):
            status_val = "COMPLETED [ALLOWED]"
        elif action_val == "ALERT":
            status_val = "ALERT [LOGGED]"
        else:
            status_val = action_val

        self._add_transfer_row({
            "transfer_id": xid,
            "timestamp": data.get("timestamp", data.get("requested_at", "")),
            "destination_endpoint": endpoint,
            "classifications": classes,
            "contains_canary": is_canary,
            "bytes_transferred": b_val,
            "status": status_val,
        })

    def _on_bridge_dlp_event(self, data: Dict[str, Any]) -> None:
        """Slot for bridge DLP interception signals."""
        self.refresh_approvals()
        self.refresh_audit_log()
        self.refresh_receiver_status()
        self._ingest_dlp_event_data(data)

    def _on_bridge_exfil_event(self, signal_dict: Dict[str, Any]) -> None:
        """Slot for bridge exfiltration signals."""
        ev_type = signal_dict.get("type", "")
        ev_data = signal_dict.get("data", {})
        if ev_type.startswith("EXFILTRATION_TRANSFER_"):
            self._add_transfer_row(ev_data)
        elif ev_type == "EXFILTRATION_CANARY_ALERT":
            canary_rec = {
                "transfer_id": f"CANARY-{len(self._transfers)+1:03d}",
                "timestamp": signal_dict.get("timestamp", ""),
                "destination_endpoint": "127.0.0.1:8999",
                "classifications": ["CANARY_HONEYPOT"],
                "contains_canary": True,
                "bytes_transferred": 0,
                "status": "BLOCKED [CANARY_TRIP]",
            }
            self._add_transfer_row(canary_rec)
        self.refresh_receiver_status()

    def _on_bridge_bus_event(self, event: Any) -> None:
        """Slot for raw EventBus events matching DLP & Exfiltration activity."""
        event_type = getattr(event, "event_type", "")
        event_data = getattr(event, "data", {})
        if event_type.startswith("DLP_"):
            self.refresh_approvals()
            self.refresh_audit_log()
            if isinstance(event_data, dict):
                ev_data = dict(event_data)
                ev_data["timestamp"] = ev_data.get("timestamp") or getattr(event, "timestamp", "")
                self._ingest_dlp_event_data(ev_data)
        elif event_type.startswith("EXFILTRATION_"):
            if isinstance(event_data, dict):
                if event_type.startswith("EXFILTRATION_TRANSFER_"):
                    self._add_transfer_row(event_data)
                elif event_type == "EXFILTRATION_CANARY_ALERT":
                    canary_rec = {
                        "transfer_id": f"CANARY-{len(self._transfers)+1:03d}",
                        "timestamp": getattr(event, "timestamp", ""),
                        "destination_endpoint": "127.0.0.1:8999",
                        "classifications": ["CANARY_HONEYPOT"],
                        "contains_canary": True,
                        "bytes_transferred": 0,
                        "status": "BLOCKED [CANARY_TRIP]",
                    }
                    self._add_transfer_row(canary_rec)
            self.refresh_receiver_status()

    def _start_receiver(self) -> None:
        """Start the loopback mock receiver."""
        try:
            self.mock_receiver = EXFILTRATION_COORDINATOR.receiver
            host, port = self.mock_receiver.start()
            self.lbl_receiver_status.setText(f"LISTENING [127.0.0.1:{port}]")
            self.lbl_receiver_status.setStyleSheet(f"color: {ThemeColors.CYAN}; font-weight: 700;")
            self.lbl_endpoint.setText(f"{host}:{port}")
            self.btn_start_receiver.setEnabled(False)
            self.btn_stop_receiver.setEnabled(True)
        except Exception as e:
            self.lbl_receiver_status.setText(f"Failed to start: {e}")

    def _stop_receiver(self) -> None:
        """Stop the loopback mock receiver."""
        if self.mock_receiver:
            self.mock_receiver.stop()
        self.lbl_receiver_status.setText("IDLE (Stopped)")
        self.lbl_receiver_status.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-weight: 700;")
        self.lbl_endpoint.setText("None")
        self.btn_start_receiver.setEnabled(True)
        self.btn_stop_receiver.setEnabled(False)

    def _apply_profile(self) -> None:
        """Switch active DLP posture profile."""
        prof_name = self.combo_profile.currentText()
        profile = DLPProfile[prof_name]
        self.dlp_coord.set_profile(profile)
        self.refresh_profile_and_rules()

    def _stage_test_transfer(self) -> None:
        """Simulate an outbound transfer of CONFIDENTIAL data to test the DLP gate & approval queue."""
        sample_payload = b'{"employee_records": [{"id": 101, "name": "Alice Smith", "salary": 145000}]}'
        eval_res = self.dlp_coord.evaluate_transfer(
            destination_endpoint="127.0.0.1:8999",
            payload_bytes=sample_payload,
            file_count=1,
            classifications=["CONFIDENTIAL"],
            departments=["Finance"],
            contains_canary=False,
        )
        self._add_transfer_row({
            "transfer_id": f"TEST-{len(self._transfers)+1:03d}",
            "timestamp": "",
            "destination_endpoint": "127.0.0.1:8999",
            "classifications": ["CONFIDENTIAL"],
            "contains_canary": False,
            "bytes_transferred": len(sample_payload) if eval_res.allowed else 0,
            "status": eval_res.action.value if hasattr(eval_res.action, "value") else str(eval_res.action),
            "metadata": {"dlp_action": eval_res.action.value if hasattr(eval_res.action, "value") else str(eval_res.action)},
        })
        self.refresh_approvals()
        self.refresh_audit_log()
        self.refresh_receiver_status()

    def _approve_transfer(self) -> None:
        """Approve selected quarantined transfer request."""
        row = self.table_approvals.currentRow()
        if row < 0 or row >= len(getattr(self, "_current_requests", [])):
            return
        req = self._current_requests[row]
        self.approval_mgr.approve(req.approval_token, decided_by="SOC Console Operator")
        self.refresh_approvals()
        self.refresh_audit_log()
        self.refresh_transfers()

    def _reject_transfer(self) -> None:
        """Reject selected quarantined transfer request."""
        row = self.table_approvals.currentRow()
        if row < 0 or row >= len(getattr(self, "_current_requests", [])):
            return
        req = self._current_requests[row]
        self.approval_mgr.reject(req.approval_token, decided_by="SOC Console Operator")
        self.refresh_approvals()
        self.refresh_audit_log()
        self.refresh_transfers()
