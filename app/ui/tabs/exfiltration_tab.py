"""
CryptoShield — Data Exfiltration Monitoring & DLP Center Tab (Phase 10)
Manages loopback mock receivers, DLP posture profiles (DEFAULT, STRICT, AUDIT_ONLY, PERMISSIVE),
policy rule matrix, quarantined approval workflows, and pre-transmission interception logs.
"""

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
        self.mock_receiver: Optional[MockReceiver] = None

        if self.bridge:
            if hasattr(self.bridge, "dlp_interception"):
                self.bridge.dlp_interception.connect(self._on_bridge_dlp_event)
            if hasattr(self.bridge, "event_received"):
                self.bridge.event_received.connect(self._on_bridge_bus_event)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(14)

        # Section Header
        main_layout.addWidget(
            create_section_header(
                "Data Exfiltration Monitoring & Data Loss Prevention (DLP) Center",
                "Loopback socket telemetry, priority rule matrix, and pre-transmission zero-byte interception gate",
            )
        )

        # 1. Mock Receiver Status & Controls
        main_layout.addWidget(self._build_receiver_panel())

        # Splitter: Rules & Posture (Left) | Approvals & Audit (Right)
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_dlp_policy_panel())
        splitter.addWidget(self._build_approvals_panel())
        splitter.setSizes([500, 500])

        main_layout.addWidget(splitter, 1)

        # Initial refresh
        self.refresh_all()

    def _build_receiver_panel(self) -> QGroupBox:
        """Loopback mock socket receiver controls."""
        group = QGroupBox("SAFE LOOPBACK MOCK EXFILTRATION RECEIVER (127.0.0.1)")
        layout = QGridLayout(group)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        layout.addWidget(QLabel("Receiver Status:"), 0, 0)
        self.lbl_receiver_status = QLabel("IDLE (Stopped)")
        self.lbl_receiver_status.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-weight: 700;")
        layout.addWidget(self.lbl_receiver_status, 0, 1)

        layout.addWidget(QLabel("Bound Endpoint:"), 0, 2)
        self.lbl_endpoint = QLabel("None")
        self.lbl_endpoint.setStyleSheet(f"color: {ThemeColors.TEXT_ACCENT}; font-family: monospace;")
        layout.addWidget(self.lbl_endpoint, 0, 3)

        layout.addWidget(QLabel("Payloads Received:"), 1, 0)
        self.lbl_receiver_metrics = QLabel("0 payloads | 0 bytes")
        layout.addWidget(self.lbl_receiver_metrics, 1, 1)

        # Invariant Notice
        lbl_safety = QLabel("[SAFETY] Binds strictly to loopback 127.0.0.1. External network transmission is strictly prohibited.")
        lbl_safety.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-size: 11px;")
        layout.addWidget(lbl_safety, 1, 2, 1, 2)

        btn_row = QHBoxLayout()
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
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Profile Switcher Row
        prof_row = QHBoxLayout()
        prof_row.addWidget(QLabel("Active Security Posture:"))
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
        layout.addWidget(self.table_rules)

        return group

    def _build_approvals_panel(self) -> QGroupBox:
        """Quarantined approval queue and audit log stream."""
        group = QGroupBox("QUARANTINED APPROVAL QUEUE & AUDIT STREAM")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Approvals Table
        self.table_approvals = QTableWidget()
        self.table_approvals.setColumnCount(5)
        self.table_approvals.setHorizontalHeaderLabels(["Token", "Created", "Classification", "Files", "Status"])
        self.table_approvals.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_approvals.verticalHeader().setVisible(False)
        self.table_approvals.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.table_approvals)

        # Action Buttons
        btn_row = QHBoxLayout()
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
        self.txt_audit_log.setFixedHeight(110)
        layout.addWidget(self.txt_audit_log)

        return group

    def refresh_all(self) -> None:
        """Refresh profile, rule matrix, approvals, and audit log."""
        self.refresh_profile_and_rules()
        self.refresh_approvals()
        self.refresh_audit_log()

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

    def _on_bridge_dlp_event(self, data: Dict[str, Any]) -> None:
        """Slot for bridge DLP interception signals."""
        self.refresh_approvals()
        self.refresh_audit_log()

    def _on_bridge_bus_event(self, event: Any) -> None:
        """Slot for raw EventBus events matching DLP activity."""
        event_type = getattr(event, "event_type", "")
        if event_type.startswith("DLP_"):
            self.refresh_approvals()
            self.refresh_audit_log()

    def _start_receiver(self) -> None:
        """Start the loopback mock receiver."""
        try:
            self.mock_receiver = MockReceiver()
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
            self.mock_receiver = None

    def _apply_profile(self) -> None:
        """Switch active DLP posture profile."""
        prof_name = self.combo_profile.currentText()
        profile = DLPProfile[prof_name]
        self.dlp_coord.set_profile(profile)
        self.refresh_profile_and_rules()

    def _approve_transfer(self) -> None:
        """Approve selected quarantined transfer request."""
        row = self.table_approvals.currentRow()
        if row < 0 or row >= len(getattr(self, "_current_requests", [])):
            return
        req = self._current_requests[row]
        self.approval_mgr.approve(req.approval_token, decided_by="SOC Console Operator")
        self.refresh_approvals()
        self.refresh_audit_log()

    def _reject_transfer(self) -> None:
        """Reject selected quarantined transfer request."""
        row = self.table_approvals.currentRow()
        if row < 0 or row >= len(getattr(self, "_current_requests", [])):
            return
        req = self._current_requests[row]
        self.approval_mgr.reject(req.approval_token, decided_by="SOC Console Operator")
        self.refresh_approvals()
        self.refresh_audit_log()
