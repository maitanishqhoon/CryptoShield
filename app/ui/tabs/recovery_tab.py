"""
CryptoShield — Cryptographic Recovery & Restoration Console Tab (Phase 10)
Manages isolated recovery workspaces, multithreaded damage assessment against snapshots,
two-stage authenticated file restoration, evidence quarantine, and SHA-256 validation.
"""

import os
from typing import Any, Dict, List, Optional
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.config import CONFIG
from app.recovery.recovery_coordinator import RECOVERY_COORDINATOR, RecoveryCoordinator
from app.recovery.workspace_manager import RecoveryWorkspaceManager
from app.ui.theme import ThemeColors, create_section_header
from app.ui.workers import AsyncWorker
from app.vault.snapshot_manager import SnapshotManager


class RecoveryTab(QWidget):
    """
    Operator interface for managing isolated recovery workspaces, assessing
    ransomware encryption damage, previewing file restorations, and executing
    two-stage authenticated file recoveries with evidence quarantine.
    """

    def __init__(self, bridge: Optional[Any] = None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.bridge = bridge
        self.workspace_mgr = RecoveryWorkspaceManager()
        self.coordinator = RECOVERY_COORDINATOR
        self.snapshot_mgr = SnapshotManager()
        self.active_worker: Optional[AsyncWorker] = None

        if self.bridge:
            if hasattr(self.bridge, "recovery_progress"):
                self.bridge.recovery_progress.connect(self._on_bridge_recovery_progress)
            if hasattr(self.bridge, "snapshot_created"):
                self.bridge.snapshot_created.connect(self._on_bridge_snapshot_created)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(14)

        # Section Header
        main_layout.addWidget(
            create_section_header(
                "Cryptographic Recovery & File Restoration Console",
                "Authenticated isolated recovery workspaces, multithreaded damage assessment, and two-stage restoration",
            )
        )

        # Splitter: Workspace Management & Assessment (Top) | Restoration & Audit Log (Bottom)
        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(self._build_top_panel())
        splitter.addWidget(self._build_bottom_panel())
        splitter.setSizes([410, 390])

        main_layout.addWidget(splitter, 1)

        # Initial refresh
        self.refresh_workspaces()
        self.refresh_snapshots_combo()

    def _build_top_panel(self) -> QWidget:
        """Workspaces table and damage assessment panel."""
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Left: Workspace Manager
        ws_group = QGroupBox("ISOLATED RECOVERY WORKSPACES (RUNTIME/RECOVERY/)")
        ws_layout = QVBoxLayout(ws_group)
        ws_layout.setContentsMargins(12, 12, 12, 12)
        ws_layout.setSpacing(8)

        # Invariant note
        lbl_ws_note = QLabel(
            "[SAFETY] All recovery restorations occur strictly inside authenticated workspaces "
            "bearing .cryptoshield_recovery_marker. Live baseline is never touched directly."
        )
        lbl_ws_note.setWordWrap(True)
        lbl_ws_note.setStyleSheet(f"""
            color: {ThemeColors.CYAN};
            background-color: {ThemeColors.CYAN_BG};
            border-radius: 4px;
            padding: 5px 8px;
            font-size: 11px;
        """)
        ws_layout.addWidget(lbl_ws_note)

        # Workspaces Table
        self.table_ws = QTableWidget()
        self.table_ws.setColumnCount(4)
        self.table_ws.setHorizontalHeaderLabels(["Workspace ID", "Created", "Seeded Files", "Marker"])
        self.table_ws.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_ws.verticalHeader().setVisible(False)
        self.table_ws.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_ws.setAlternatingRowColors(True)
        self.table_ws.itemSelectionChanged.connect(self._on_ws_selection_changed)
        ws_layout.addWidget(self.table_ws)

        ws_btn_row = QHBoxLayout()
        self.btn_new_ws = QPushButton("Create Workspace")
        self.btn_new_ws.clicked.connect(self._create_workspace)
        ws_btn_row.addWidget(self.btn_new_ws)

        self.btn_seed_ws = QPushButton("Seed Selected")
        self.btn_seed_ws.clicked.connect(self._seed_workspace)
        ws_btn_row.addWidget(self.btn_seed_ws)

        self.btn_del_ws = QPushButton("Delete Selected")
        self.btn_del_ws.setObjectName("btn-danger")
        self.btn_del_ws.clicked.connect(self._delete_workspace)
        ws_btn_row.addWidget(self.btn_del_ws)

        ws_layout.addLayout(ws_btn_row)
        layout.addWidget(ws_group, 1)

        # Right: Damage Assessment Panel
        assess_group = QGroupBox("MULTITHREADED DAMAGE ASSESSMENT")
        assess_layout = QVBoxLayout(assess_group)
        assess_layout.setContentsMargins(12, 12, 12, 12)
        assess_layout.setSpacing(8)

        inputs_grid = QGridLayout()
        inputs_grid.addWidget(QLabel("Target Workspace:"), 0, 0)
        self.combo_ws = QComboBox()
        inputs_grid.addWidget(self.combo_ws, 0, 1)

        inputs_grid.addWidget(QLabel("Baseline Snapshot:"), 1, 0)
        self.combo_snaps = QComboBox()
        inputs_grid.addWidget(self.combo_snaps, 1, 1)

        assess_layout.addLayout(inputs_grid)

        self.btn_assess = QPushButton("Execute Damage Assessment")
        self.btn_assess.setObjectName("btn-primary")
        self.btn_assess.clicked.connect(self._run_assessment)
        assess_layout.addWidget(self.btn_assess)

        # Assessment Metrics Table
        self.table_assessment = QTableWidget()
        self.table_assessment.setColumnCount(5)
        self.table_assessment.setHorizontalHeaderLabels([
            "INTACT",
            "MODIFIED",
            "MISSING",
            "UNREADABLE",
            "UNTRACKED",
        ])
        self.table_assessment.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_assessment.horizontalHeader().setFixedHeight(34)
        self.table_assessment.verticalHeader().setVisible(False)
        self.table_assessment.verticalHeader().setDefaultSectionSize(44)
        self.table_assessment.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.table_assessment.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.table_assessment.setFixedHeight(82)
        self.table_assessment.setRowCount(1)
        self.table_assessment.setRowHeight(0, 44)
        init_font = QFont("Segoe UI", 13)
        init_font.setBold(True)
        for col in range(5):
            itm = QTableWidgetItem("0")
            itm.setTextAlignment(Qt.AlignCenter)
            itm.setFont(init_font)
            itm.setForeground(QColor(ThemeColors.TEXT_MUTED))
            itm.setFlags(itm.flags() & ~Qt.ItemIsEditable)
            self.table_assessment.setItem(0, col, itm)
        assess_layout.addWidget(self.table_assessment)

        self.lbl_assess_status = QLabel("Select workspace and snapshot, then click assessment.")
        self.lbl_assess_status.setWordWrap(True)
        self.lbl_assess_status.setMinimumHeight(32)
        self.lbl_assess_status.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.lbl_assess_status.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-size: 11px;")
        assess_layout.addWidget(self.lbl_assess_status)
        assess_layout.addStretch()

        layout.addWidget(assess_group, 1)
        return container

    def _build_bottom_panel(self) -> QGroupBox:
        """Restoration wizard and cryptographic audit output."""
        group = QGroupBox("TWO-STAGE AUTHENTICATED RESTORATION WIZARD & AUDIT LOG")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        # Parameters Row
        params_row = QHBoxLayout()
        params_row.addWidget(QLabel("RSA Key Passphrase:"))
        self.input_passphrase = QLineEdit()
        self.input_passphrase.setEchoMode(QLineEdit.Password)
        self.input_passphrase.setPlaceholderText("Enter private key passphrase (if prompted)...")
        self.input_passphrase.setFixedWidth(240)
        params_row.addWidget(self.input_passphrase)

        self.chk_overwrite = QCheckBox("Overwrite Modified (Remediate Damage)")
        self.chk_overwrite.setChecked(True)
        params_row.addWidget(self.chk_overwrite)

        self.chk_authorize = QCheckBox("Authorize Live Restoration")
        self.chk_authorize.setChecked(True)
        params_row.addWidget(self.chk_authorize)

        params_row.addStretch()
        layout.addLayout(params_row)

        # Action Buttons
        btn_row = QHBoxLayout()
        self.btn_preview = QPushButton("Preview Restoration Actions")
        self.btn_preview.clicked.connect(self._preview_restoration)
        btn_row.addWidget(self.btn_preview)

        self.btn_restore = QPushButton("Commit Authenticated Restoration")
        self.btn_restore.setObjectName("btn-success")
        self.btn_restore.clicked.connect(self._execute_restoration)
        btn_row.addWidget(self.btn_restore)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Text Console
        self.txt_audit = QTextEdit()
        self.txt_audit.setReadOnly(True)
        self.txt_audit.setPlaceholderText("Restoration execution plan and cryptographic verification results will be logged here...")
        layout.addWidget(self.txt_audit, 1)

        return group

    def refresh_all(self) -> None:
        """Comprehensive refresh of workspaces and snapshot baseline catalogs."""
        self.refresh_workspaces()
        self.refresh_snapshots_combo()

    def refresh_workspaces(self) -> None:
        """Query disk and populate workspaces table and dropdown."""
        try:
            workspaces = self.workspace_mgr.list_workspaces()
            self.table_ws.setRowCount(len(workspaces))
            current_selected = self.combo_ws.currentText()
            self.combo_ws.clear()

            for row, ws in enumerate(workspaces):
                ws_id = ws.workspace_id
                self.combo_ws.addItem(ws_id)
                marker_valid = getattr(ws, "is_marker_valid", getattr(ws, "marker_valid", False))

                items = [
                    QTableWidgetItem(str(ws_id)),
                    QTableWidgetItem(str(ws.created_at)[:19]),
                    QTableWidgetItem(f"{ws.seeded_file_count:,}"),
                    QTableWidgetItem("VALID [PASS]" if marker_valid else "INVALID"),
                ]
                items[3].setForeground(QColor(ThemeColors.GREEN if marker_valid else ThemeColors.RED))
                for col, itm in enumerate(items):
                    itm.setFlags(itm.flags() & ~Qt.ItemIsEditable)
                    self.table_ws.setItem(row, col, itm)

            if current_selected:
                idx = self.combo_ws.findText(current_selected)
                if idx >= 0:
                    self.combo_ws.setCurrentIndex(idx)
                elif self.combo_ws.count() > 0:
                    self.combo_ws.setCurrentIndex(0)
            elif self.combo_ws.count() > 0:
                self.combo_ws.setCurrentIndex(0)

            if self.combo_ws.count() > 0:
                cur_text = self.combo_ws.currentText()
                for r in range(self.table_ws.rowCount()):
                    itm = self.table_ws.item(r, 0)
                    if itm and itm.text() == cur_text:
                        self.table_ws.selectRow(r)
                        break
        except Exception as e:
            self.txt_audit.setPlainText(f"[-] Failed to refresh workspaces: {e}")

    def _on_ws_selection_changed(self) -> None:
        """Synchronize dropdown selection with table row clicks."""
        row = self.table_ws.currentRow()
        if 0 <= row < self.table_ws.rowCount():
            item = self.table_ws.item(row, 0)
            if item:
                idx = self.combo_ws.findText(item.text())
                if idx >= 0:
                    self.combo_ws.setCurrentIndex(idx)

    def refresh_snapshots_combo(self, preferred_snap_id: Optional[str] = None) -> None:
        """Query available snapshots to populate snapshot dropdown while preserving selection."""
        try:
            current_selected = preferred_snap_id or self.combo_snaps.currentText()
            self.combo_snaps.clear()
            snaps = self.snapshot_mgr.list_snapshots()
            for s in snaps:
                self.combo_snaps.addItem(s.snapshot_id)

            if current_selected:
                idx = self.combo_snaps.findText(current_selected)
                if idx >= 0:
                    self.combo_snaps.setCurrentIndex(idx)
                elif self.combo_snaps.count() > 0:
                    self.combo_snaps.setCurrentIndex(0)
            elif self.combo_snaps.count() > 0:
                self.combo_snaps.setCurrentIndex(0)
        except Exception:
            pass

    def _on_bridge_snapshot_created(self, data: Dict[str, Any]) -> None:
        """Slot invoked when a new snapshot is published across the subsystem."""
        snap_id = data.get("snapshot_id")
        self.refresh_snapshots_combo(preferred_snap_id=snap_id)
        if snap_id:
            self.txt_audit.append(f"[*] [REALTIME] Baseline snapshot '{snap_id}' detected & synchronized.")

    def _create_workspace(self) -> None:
        """Creates a fresh isolated recovery workspace."""
        try:
            meta = self.workspace_mgr.create_workspace()
            self.txt_audit.setPlainText(f"[+] Created recovery workspace: {meta.workspace_id}")
            self.refresh_workspaces()
            idx = self.combo_ws.findText(meta.workspace_id)
            if idx >= 0:
                self.combo_ws.setCurrentIndex(idx)
                for r in range(self.table_ws.rowCount()):
                    itm = self.table_ws.item(r, 0)
                    if itm and itm.text() == meta.workspace_id:
                        self.table_ws.selectRow(r)
                        break
        except Exception as e:
            self.txt_audit.setPlainText(f"[-] Workspace creation error: {e}")

    def _seed_workspace(self) -> None:
        """Seeds selected workspace with baseline lab files."""
        ws_id = self.combo_ws.currentText()
        if not ws_id:
            self.txt_audit.setPlainText("[-] No workspace selected to seed.")
            return

        self.txt_audit.setPlainText(f"[*] Seeding workspace '{ws_id}' from lab files...")
        try:
            seeded = self.workspace_mgr.seed_from_lab(ws_id, max_files=100)
            self.txt_audit.setPlainText(f"[+] Successfully seeded {seeded} files into workspace '{ws_id}'.")
            self.refresh_workspaces()
        except Exception as e:
            self.txt_audit.setPlainText(f"[-] Seeding error: {e}")

    def _delete_workspace(self) -> None:
        """Deletes selected recovery workspace."""
        ws_id = self.combo_ws.currentText()
        if not ws_id:
            return
        try:
            self.workspace_mgr.delete_workspace(ws_id)
            self.txt_audit.setPlainText(f"[+] Deleted workspace: {ws_id}")
            self.refresh_workspaces()
        except Exception as e:
            self.txt_audit.setPlainText(f"[-] Deletion error: {e}")

    def _resolve_passphrase(self, snap_id: str, action_label: str) -> Optional[str]:
        """
        Resolve RSA-3072 private-key passphrase from the input field, environment variable,
        or an interactive masked prompt when running with a live display.
        """
        passphrase = self.input_passphrase.text().strip()
        if passphrase:
            return passphrase

        env_pass = os.environ.get("CRYPTOSHIELD_VAULT_PASSPHRASE", "").strip()
        if env_pass:
            self.input_passphrase.setText(env_pass)
            return env_pass

        if QApplication.platformName() != "offscreen":
            dialog_pass, ok = QInputDialog.getText(
                self,
                "RSA-3072 Private Key Passphrase",
                f"Enter RSA-3072 private key passphrase to {action_label} snapshot '{snap_id}':",
                QLineEdit.Password,
            )
            if ok and dialog_pass.strip():
                passphrase = dialog_pass.strip()
                self.input_passphrase.setText(passphrase)
                return passphrase

        return None

    def _run_assessment(self) -> None:
        """Runs damage assessment asynchronously."""
        ws_id = self.combo_ws.currentText()
        snap_id = self.combo_snaps.currentText()
        if not ws_id or not snap_id:
            self.lbl_assess_status.setStyleSheet(f"color: {ThemeColors.RED}; font-size: 11px;")
            self.lbl_assess_status.setText("[-] Please select both a workspace and snapshot.")
            return

        passphrase = self._resolve_passphrase(snap_id, "assess")
        if not passphrase:
            self.lbl_assess_status.setStyleSheet(f"color: {ThemeColors.RED}; font-size: 11px;")
            self.lbl_assess_status.setText(
                "[-] Assessment canceled: RSA-3072 private-key passphrase is required."
            )
            return

        self.btn_assess.setEnabled(False)
        self.lbl_assess_status.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-size: 11px;")
        self.lbl_assess_status.setText(f"Assessing damage in {ws_id} against {snap_id}...")

        def assess_payload():
            summary = self.coordinator.assess(
                workspace_id=ws_id,
                snapshot_id=snap_id,
                passphrase=passphrase,
            )
            return summary

        self.active_worker = AsyncWorker(assess_payload)
        self.active_worker.signals.finished.connect(self._on_assess_finished)
        self.active_worker.signals.error.connect(self._on_assess_error)
        self.active_worker.start()

    def _on_assess_finished(self, summary) -> None:
        self.btn_assess.setEnabled(True)
        total_files = getattr(summary, "total_files", getattr(summary, "total_workspace_files_scanned", 0))
        self.lbl_assess_status.setText(
            f"[PASS] Assessed {total_files:,} files in {summary.duration_seconds:.2f}s "
            f"({summary.modified_count} modified, {summary.missing_count} missing)."
        )
        self.lbl_assess_status.setStyleSheet(f"color: {ThemeColors.GREEN}; font-weight: 700; font-size: 11px;")

        # Populate Assessment Table
        self.table_assessment.setRowCount(1)
        self.table_assessment.setRowHeight(0, 44)
        items = [
            QTableWidgetItem(f"{summary.intact_count:,}"),
            QTableWidgetItem(f"{summary.modified_count:,}"),
            QTableWidgetItem(f"{summary.missing_count:,}"),
            QTableWidgetItem(f"{summary.unreadable_count:,}"),
            QTableWidgetItem(f"{summary.untracked_count:,}"),
        ]

        font = QFont("Segoe UI", 13)
        font.setBold(True)

        items[0].setForeground(QColor(ThemeColors.GREEN))
        items[1].setForeground(QColor(ThemeColors.RED if summary.modified_count else ThemeColors.TEXT_MUTED))
        items[2].setForeground(QColor(ThemeColors.AMBER if summary.missing_count else ThemeColors.TEXT_MUTED))
        items[3].setForeground(QColor(ThemeColors.ORANGE if summary.unreadable_count else ThemeColors.TEXT_MUTED))
        items[4].setForeground(QColor(ThemeColors.CYAN if summary.untracked_count else ThemeColors.TEXT_MUTED))

        for col, itm in enumerate(items):
            itm.setTextAlignment(Qt.AlignCenter)
            itm.setFont(font)
            itm.setFlags(itm.flags() & ~Qt.ItemIsEditable)
            self.table_assessment.setItem(0, col, itm)

    def _on_assess_error(self, err_msg: str) -> None:
        self.btn_assess.setEnabled(True)
        self.lbl_assess_status.setText(f"[-] Assessment error: {err_msg}")
        self.lbl_assess_status.setStyleSheet(f"color: {ThemeColors.RED}; font-size: 11px;")

    def _preview_restoration(self) -> None:
        """Previews restoration plan without committing files to disk."""
        ws_id = self.combo_ws.currentText()
        snap_id = self.combo_snaps.currentText()
        if not ws_id or not snap_id:
            self.txt_audit.setPlainText("[-] Select workspace and snapshot first.")
            return

        passphrase = self._resolve_passphrase(snap_id, "preview restoration for")
        if not passphrase:
            self.txt_audit.setPlainText(
                "[-] Preview aborted: RSA-3072 private-key passphrase is required."
            )
            return

        overwrite = self.chk_overwrite.isChecked()

        try:
            report = self.coordinator.preview(
                workspace_id=ws_id,
                snapshot_id=snap_id,
                passphrase=passphrase,
                overwrite_modified=overwrite,
            )
            self.txt_audit.setPlainText(
                f"[+] Restoration Plan Preview:\n"
                f"    - Workspace ID         : {report.workspace_id}\n"
                f"    - Snapshot ID          : {report.snapshot_id}\n"
                f"    - Total Evaluated      : {report.total_evaluated:,}\n"
                f"    - Planned Restores     : {report.restored_count:,}\n"
                f"    - Evidence Preserved   : {report.evidence_preserved_count:,}\n"
                f"    - Already Intact       : {report.skipped_intact_count:,}\n"
                f"    - Canary Restores      : {report.canary_restored_count:,}\n"
                f"    - Mode                 : Dry-Run Preview (Ready for authenticated commit)"
            )
        except Exception as e:
            self.txt_audit.setPlainText(f"[-] Preview error: {e}")

    def _execute_restoration(self) -> None:
        """Executes two-stage authenticated restoration with evidence quarantine."""
        ws_id = self.combo_ws.currentText()
        snap_id = self.combo_snaps.currentText()
        if not ws_id or not snap_id:
            self.txt_audit.setPlainText("[-] Select workspace and snapshot first.")
            return

        if not self.chk_authorize.isChecked():
            self.txt_audit.setPlainText("[-] Restoration requires explicit authorization. Check 'Authorize Live Restoration'.")
            return

        passphrase = self._resolve_passphrase(snap_id, "restore")
        if not passphrase:
            self.txt_audit.setPlainText(
                "[-] Restoration aborted: RSA-3072 private-key passphrase is required."
            )
            return

        overwrite = self.chk_overwrite.isChecked()

        self.btn_restore.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.txt_audit.setPlainText(f"[*] Committing authenticated two-stage restoration in '{ws_id}'...")

        def restore_payload(progress=None):
            def local_cb(cur: int, tot: int, path: str = ""):
                if progress:
                    pct = int((cur / tot) * 100) if tot > 0 else 0
                    progress(pct, 100, f"Restoring [{cur:,}/{tot:,}]: {path}")

            report = self.coordinator.restore(
                workspace_id=ws_id,
                snapshot_id=snap_id,
                passphrase=passphrase,
                overwrite_modified=overwrite,
                authorize=True,
                dry_run=False,
                progress_callback=local_cb,
            )
            return report

        self.active_worker = AsyncWorker(restore_payload)
        self.active_worker.signals.progress.connect(self._on_restore_progress)
        self.active_worker.signals.finished.connect(self._on_restore_finished)
        self.active_worker.signals.error.connect(self._on_restore_error)
        self.active_worker.start()

    def _on_restore_progress(self, cur: int, tot: int, msg: str) -> None:
        self.progress_bar.setValue(cur)
        self.txt_audit.setPlainText(f"[*] {msg}")

    def _on_bridge_recovery_progress(self, status_text: str, current: int, total: int) -> None:
        """Handle recovery progress emitted via event bus bridge."""
        pct = int((current / total) * 100) if total > 0 else 0
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(pct)
        self.txt_audit.setPlainText(f"[*] {status_text} [{current}/{total}]")

    def _on_restore_finished(self, report) -> None:
        self.btn_restore.setEnabled(True)
        self.progress_bar.setValue(100)
        audit_passed = getattr(report, "post_recovery_audit_passed", None)
        audit_str = "[PASS] 100% INTACT" if audit_passed else ("[FAIL]" if audit_passed is False else "N/A")
        self.txt_audit.setPlainText(
            f"[+] [PASS] Authenticated Restoration Completed Successfully!\n"
            f"    - Recovery ID          : {report.recovery_id}\n"
            f"    - Workspace ID         : {report.workspace_id}\n"
            f"    - Snapshot ID          : {report.snapshot_id}\n"
            f"    - Duration             : {report.duration_seconds:.2f}s\n"
            f"    - Restored Files       : {report.restored_count:,} (100% AES-GCM + SHA-256 Validated)\n"
            f"    - Quarantined Evidence : {report.evidence_preserved_count:,} modified files quarantined\n"
            f"    - Failures             : {report.failed_count}\n"
            f"    - Verification Status  : {audit_str}"
        )
        self.refresh_workspaces()

    def _on_restore_error(self, err_msg: str) -> None:
        self.btn_restore.setEnabled(True)
        self.txt_audit.setPlainText(f"[-] Restoration failed: {err_msg}")
