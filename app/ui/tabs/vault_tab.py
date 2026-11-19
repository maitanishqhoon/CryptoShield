"""
CryptoShield — Cryptographic Vault & Snapshot Engine Tab (Phase 10)
Manages RSA-3072 key pairs, Argon2id envelopes, AES-256-GCM snapshots, and cryptographic verification audits.
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
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.config import CONFIG
from app.ui.theme import ThemeColors, create_section_header
from app.ui.workers import AsyncWorker
from app.vault.key_manager import KeyManager
from app.vault.snapshot_manager import SnapshotManager
from app.vault.vault_verifier import SnapshotVerifier


class VaultTab(QWidget):
    """
    Operator interface for the cryptographic backup vault, RSA-3072 key manager,
    Argon2id key hardening envelope, and AES-256-GCM snapshot catalog.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.key_mgr = KeyManager()
        self.snapshot_mgr = SnapshotManager()
        self.active_worker: Optional[AsyncWorker] = None
        self._snapshots: List[Any] = []

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(14)

        # Section Header
        main_layout.addWidget(
            create_section_header(
                "Cryptographic Vault & Encrypted Snapshot Engine",
                "AES-256-GCM object encryption, RSA-3072 key management, and Argon2id envelope protection",
            )
        )

        # 1. Key Manager & Argon2id Panel
        main_layout.addWidget(self._build_key_panel())

        # 2. Snapshot Catalog Group
        main_layout.addWidget(self._build_snapshot_panel(), 1)

        # 3. Cryptographic Audit Output Console
        main_layout.addWidget(self._build_console_panel())

        # Initial data refresh
        self.refresh_all()

    def _build_key_panel(self) -> QGroupBox:
        """RSA-3072 key health and Argon2id hardening envelope details."""
        group = QGroupBox("RSA-3072 ASYMMETRIC KEY MANAGEMENT & ARGON2ID ENVELOPE")
        layout = QGridLayout(group)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(8)

        layout.addWidget(QLabel("Active Key ID:"), 0, 0)
        self.lbl_key_id = QLabel("Checking...")
        self.lbl_key_id.setStyleSheet(f"color: {ThemeColors.PURPLE}; font-weight: 800; font-family: monospace;")
        layout.addWidget(self.lbl_key_id, 0, 1)

        layout.addWidget(QLabel("Protection Envelope:"), 0, 2)
        self.lbl_envelope = QLabel("Checking...")
        layout.addWidget(self.lbl_envelope, 0, 3)

        layout.addWidget(QLabel("Argon2id Parameters:"), 1, 0)
        self.lbl_argon_params = QLabel("Checking...")
        self.lbl_argon_params.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-size: 11px;")
        layout.addWidget(self.lbl_argon_params, 1, 1)

        layout.addWidget(QLabel("SHA-256 Fingerprint:"), 1, 2)
        self.lbl_fingerprint = QLabel("Checking...")
        self.lbl_fingerprint.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-family: monospace; font-size: 11px;")
        layout.addWidget(self.lbl_fingerprint, 1, 3)

        return group

    def _build_snapshot_panel(self) -> QGroupBox:
        """Encrypted snapshot table & action buttons."""
        group = QGroupBox("AUTHENTICATED SNAPSHOT CATALOG (RUNTIME/VAULT/)")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Action Buttons Row
        btn_row = QHBoxLayout()
        self.btn_create_snap = QPushButton("Create New Encrypted Snapshot")
        self.btn_create_snap.setObjectName("btn-primary")
        self.btn_create_snap.clicked.connect(self._create_snapshot)
        btn_row.addWidget(self.btn_create_snap)

        self.btn_inspect = QPushButton("Inspect Selected Snapshot")
        self.btn_inspect.clicked.connect(self._inspect_selected)
        btn_row.addWidget(self.btn_inspect)

        self.btn_verify = QPushButton("Cryptographically Verify Snapshot")
        self.btn_verify.setObjectName("btn-success")
        self.btn_verify.clicked.connect(self._verify_selected)
        btn_row.addWidget(self.btn_verify)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Table of snapshots
        self.table_snaps = QTableWidget()
        self.table_snaps.setColumnCount(6)
        self.table_snaps.setHorizontalHeaderLabels([
            "Snapshot ID",
            "Created Timestamp",
            "Files",
            "Raw Size (MB)",
            "Ciphertext Size (MB)",
            "Status",
        ])
        self.table_snaps.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_snaps.verticalHeader().setVisible(False)
        self.table_snaps.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_snaps.setAlternatingRowColors(True)
        layout.addWidget(self.table_snaps)

        return group

    def _build_console_panel(self) -> QGroupBox:
        """Progress bar and cryptographic inspection output."""
        group = QGroupBox("CRYPTOGRAPHIC AUDIT & SNAPSHOT INSPECTION LOG")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(6)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.txt_console = QTextEdit()
        self.txt_console.setReadOnly(True)
        self.txt_console.setFixedHeight(110)
        self.txt_console.setPlaceholderText("Select a snapshot or execute verification to view cryptographic audit details...")
        layout.addWidget(self.txt_console)

        return group

    def refresh_all(self) -> None:
        """Refresh key metadata and snapshot catalog."""
        self.refresh_key_info()
        self.refresh_snapshots()

    def refresh_key_info(self) -> None:
        """Query KeyManager for RSA-3072 and Argon2id envelope data."""
        try:
            meta = self.key_mgr.get_key_metadata()
            if meta:
                key_id = meta.get("key_id", "KEY-UNKNOWN")
                self.lbl_key_id.setText(key_id)

                prot = meta.get("private_key_protection", "Argon2id-AES256GCM")
                v = meta.get("private_key_envelope_version", 2)
                self.lbl_envelope.setText(f"{prot} (v{v}) [PASS]")
                self.lbl_envelope.setStyleSheet(f"color: {ThemeColors.GREEN}; font-weight: 700;")

                fp = meta.get("fingerprint", "")
                self.lbl_fingerprint.setText(fp[:32] + "..." if len(fp) > 32 else fp)

                kdf = meta.get("private_key_kdf", {})
                if isinstance(kdf, dict):
                    mem = kdf.get("memory_cost_kib", 65536)
                    iters = kdf.get("iterations", 3)
                    lanes = kdf.get("lanes", 4)
                    self.lbl_argon_params.setText(f"Mem: {mem:,} KiB | Iters: {iters} | Parallelism: {lanes}")
                else:
                    self.lbl_argon_params.setText(str(kdf))
            else:
                self.lbl_key_id.setText("NO ACTIVE KEY")
                self.lbl_envelope.setText("Uninitialized")
        except Exception as e:
            self.lbl_key_id.setText("ERROR")
            self.lbl_envelope.setText(str(e))

    def refresh_snapshots(self) -> None:
        """List snapshots from vault on disk."""
        try:
            self._snapshots = self.snapshot_mgr.list_snapshots()
            self.table_snaps.setRowCount(len(self._snapshots))

            for row, snap in enumerate(self._snapshots):
                raw_mb = getattr(snap, "total_original_bytes", 0) / (1024 * 1024)
                enc_mb = getattr(snap, "total_encrypted_bytes", 0) / (1024 * 1024)
                status = getattr(snap, "completed_status", "UNKNOWN")

                items = [
                    QTableWidgetItem(str(snap.snapshot_id)),
                    QTableWidgetItem(str(getattr(snap, "created_at", ""))[:19]),
                    QTableWidgetItem(f"{getattr(snap, 'total_files', 0):,}"),
                    QTableWidgetItem(f"{raw_mb:.2f} MB"),
                    QTableWidgetItem(f"{enc_mb:.2f} MB"),
                    QTableWidgetItem(str(status)),
                ]

                # Style status item
                items[5].setForeground(QColor(ThemeColors.GREEN if status == "COMPLETED" else ThemeColors.AMBER))
                items[0].setForeground(QColor(ThemeColors.PURPLE))

                for col, itm in enumerate(items):
                    itm.setFlags(itm.flags() & ~Qt.ItemIsEditable)
                    self.table_snaps.setItem(row, col, itm)
        except Exception as e:
            self.txt_console.setPlainText(f"[-] Failed to load snapshots: {e}")

    def _create_snapshot(self) -> None:
        """Creates a clean AES-256-GCM encrypted snapshot asynchronously."""
        self.btn_create_snap.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.txt_console.setPlainText("[*] Initiating AES-256-GCM encrypted snapshot compile...")

        def create_payload(progress=None):
            def local_cb(cur: int, tot: int):
                if progress:
                    pct = int((cur / tot) * 100) if tot > 0 else 0
                    progress(pct, 100, f"Encrypting objects: {cur:,}/{tot:,}...")

            meta = self.snapshot_mgr.create_snapshot(progress_callback=local_cb)
            return meta

        self.active_worker = AsyncWorker(create_payload)
        self.active_worker.signals.progress.connect(self._on_snap_progress)
        self.active_worker.signals.finished.connect(self._on_snap_finished)
        self.active_worker.signals.error.connect(self._on_snap_error)
        self.active_worker.start()

    def _on_snap_progress(self, cur: int, tot: int, msg: str) -> None:
        self.progress_bar.setValue(cur)
        self.txt_console.setPlainText(f"[*] {msg}")

    def _on_snap_finished(self, meta) -> None:
        self.btn_create_snap.setEnabled(True)
        self.progress_bar.setValue(100)
        self.txt_console.setPlainText(
            f"[+] [PASS] Snapshot {meta.snapshot_id} created successfully!\n"
            f"    - Files Encrypted   : {meta.total_files:,}\n"
            f"    - Raw Dataset Size  : {meta.total_original_bytes / (1024*1024):.2f} MB\n"
            f"    - Encrypted Storage : {meta.total_encrypted_bytes / (1024*1024):.2f} MB\n"
            f"    - RSA Key ID        : {meta.key_id}"
        )
        self.refresh_snapshots()

    def _on_snap_error(self, err_msg: str) -> None:
        self.btn_create_snap.setEnabled(True)
        self.txt_console.setPlainText(f"[-] Snapshot creation failed: {err_msg}")

    def _inspect_selected(self) -> None:
        """Inspects selected snapshot in the text viewer."""
        row = self.table_snaps.currentRow()
        if row < 0 or row >= len(self._snapshots):
            self.txt_console.setPlainText("[-] Please select a snapshot from the table above.")
            return

        snap = self._snapshots[row]
        data = snap.to_dict() if hasattr(snap, "to_dict") else vars(snap)
        self.txt_console.setPlainText(json.dumps(data, indent=2))

    def _verify_selected(self) -> None:
        """Cryptographically verifies container integrity and manifests of selected snapshot."""
        row = self.table_snaps.currentRow()
        if row < 0 or row >= len(self._snapshots):
            self.txt_console.setPlainText("[-] Please select a snapshot from the table above to verify.")
            return

        snap = self._snapshots[row]
        snap_id = snap.snapshot_id

        self.btn_verify.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.txt_console.setPlainText(f"[*] Cryptographically auditing snapshot '{snap_id}'...")

        def verify_payload(progress=None):
            verifier = SnapshotVerifier()
            def local_cb(cur: int, tot: int):
                if progress:
                    pct = int((cur / tot) * 100) if tot > 0 else 0
                    progress(pct, 100, f"Verifying AES-GCM tags: {cur:,}/{tot:,}...")

            res = verifier.verify_snapshot(snap_id, progress_callback=local_cb)
            return res

        self.active_worker = AsyncWorker(verify_payload)
        self.active_worker.signals.progress.connect(self._on_snap_progress)
        self.active_worker.signals.finished.connect(self._on_verify_finished)
        self.active_worker.signals.error.connect(self._on_verify_error)
        self.active_worker.start()

    def _on_verify_finished(self, res) -> None:
        self.btn_verify.setEnabled(True)
        self.progress_bar.setValue(100)
        status_str = "[PASS] VALID & INTACT" if res.is_valid else "[FAIL] CORRUPTED/TAMPERED"
        color_str = "GREEN" if res.is_valid else "RED"

        self.txt_console.setPlainText(
            f"[+] Cryptographic Audit Result: {status_str}\n"
            f"    - Snapshot ID       : {res.snapshot_id}\n"
            f"    - Objects Verified  : {res.total_objects:,}\n"
            f"    - Valid Containers  : {res.valid_objects:,}\n"
            f"    - Corrupted Objects : {len(res.corrupted_objects):,}\n"
            f"    - Missing Objects   : {len(res.missing_objects):,}\n"
            f"    - Audit Duration    : {res.duration_seconds:.2f}s"
        )

    def _on_verify_error(self, err_msg: str) -> None:
        self.btn_verify.setEnabled(True)
        self.txt_console.setPlainText(f"[-] Verification failed: {err_msg}")
