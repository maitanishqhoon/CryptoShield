"""
CryptoShield — Laboratory Baseline & Dataset Engine Tab (Phase 10)
Manages synthetic enterprise dataset generation, baseline manifests, and SHA-256 integrity auditing.
"""

import time
from typing import Any, Optional
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.config import CONFIG
from app.core.models import DatasetPreset
from app.lab.dataset_generator import SyntheticDatasetGenerator
from app.lab.lab_manager import LabManager
from app.lab.manifest import ManifestManager
from app.ui.theme import ThemeColors, create_section_header
from app.ui.workers import AsyncWorker


class LabTab(QWidget):
    """
    Console for generating synthetic enterprise files across 9 departments,
    inspecting baseline manifest metrics, and executing parallel SHA-256 integrity audits.
    """

    def __init__(self, bridge: Optional[Any] = None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.bridge = bridge
        self.lab_mgr = LabManager()
        self.manifest_mgr = ManifestManager()
        self.active_worker: Optional[AsyncWorker] = None

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(14)

        # Section Header
        main_layout.addWidget(
            create_section_header(
                "Laboratory Environment & Synthetic Dataset Engine",
                "Deterministic dataset synthesizer and baseline manifest SHA-256 integrity auditing",
            )
        )

        # 1. Environment Status Panel
        main_layout.addWidget(self._build_environment_panel())

        # 2. Dataset Synthesizer Controls
        main_layout.addWidget(self._build_generator_panel())

        # 3. Integrity Audit Panel
        main_layout.addWidget(self._build_audit_panel(), 1)

        # Initial refresh
        self.refresh_lab_info()

    def _build_environment_panel(self) -> QGroupBox:
        """Laboratory workspace health and marker status."""
        group = QGroupBox("LABORATORY WORKSPACE & SAFETY BOUNDARY")
        layout = QGridLayout(group)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        # Lab Directory Path
        layout.addWidget(QLabel("Lab Directory:"), 0, 0)
        self.lbl_lab_path = QLabel(str(CONFIG.LAB_DIR))
        self.lbl_lab_path.setStyleSheet(f"color: {ThemeColors.TEXT_ACCENT}; font-family: monospace;")
        layout.addWidget(self.lbl_lab_path, 0, 1)

        # Marker Status
        layout.addWidget(QLabel("Safety Marker:"), 0, 2)
        self.lbl_marker_status = QLabel("Checking...")
        layout.addWidget(self.lbl_marker_status, 0, 3)

        # Baseline Manifest Status
        layout.addWidget(QLabel("Baseline Manifest:"), 1, 0)
        self.lbl_manifest_status = QLabel("Checking...")
        layout.addWidget(self.lbl_manifest_status, 1, 1)

        # Active Canaries
        layout.addWidget(QLabel("Active Honeypots:"), 1, 2)
        self.lbl_canary_count = QLabel("Checking...")
        layout.addWidget(self.lbl_canary_count, 1, 3)

        return group

    def _build_generator_panel(self) -> QGroupBox:
        """Synthetic dataset synthesizer configuration & execution."""
        group = QGroupBox("SYNTHETIC ENTERPRISE DATASET SYNTHESIZER")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        # Presets Row
        preset_row = QHBoxLayout()
        preset_row.addWidget(QLabel("Quick Presets:"))

        btn_quick = QPushButton("Quick (1,000 files)")
        btn_quick.clicked.connect(lambda: self._set_preset(1000))
        preset_row.addWidget(btn_quick)

        btn_default = QPushButton("Default (10,000 files)")
        btn_default.clicked.connect(lambda: self._set_preset(10000))
        preset_row.addWidget(btn_default)

        btn_stress = QPushButton("Stress (20,000 files)")
        btn_stress.clicked.connect(lambda: self._set_preset(20000))
        preset_row.addWidget(btn_stress)

        preset_row.addStretch()
        layout.addLayout(preset_row)

        # Custom Parameters Row
        params_row = QHBoxLayout()
        params_row.addWidget(QLabel("Target Files:"))
        self.spin_files = QSpinBox()
        self.spin_files.setRange(10, 50000)
        self.spin_files.setValue(1000)
        self.spin_files.setSingleStep(500)
        params_row.addWidget(self.spin_files)

        params_row.addWidget(QLabel("Random Seed:"))
        self.spin_seed = QSpinBox()
        self.spin_seed.setRange(1, 999999)
        self.spin_seed.setValue(42)
        params_row.addWidget(self.spin_seed)

        self.chk_clean = QCheckBox("Clean Lab Before Generate")
        self.chk_clean.setChecked(False)
        params_row.addWidget(self.chk_clean)

        self.btn_generate = QPushButton("Generate Dataset")
        self.btn_generate.setObjectName("btn-primary")
        self.btn_generate.clicked.connect(self._run_generation)
        params_row.addWidget(self.btn_generate)

        layout.addLayout(params_row)

        # Progress Row
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.lbl_gen_status = QLabel("")
        self.lbl_gen_status.setStyleSheet(f"color: {ThemeColors.TEXT_MUTED}; font-size: 11px;")
        layout.addWidget(self.lbl_gen_status)

        return group

    def _build_audit_panel(self) -> QGroupBox:
        """SHA-256 Manifest Integrity Auditor."""
        group = QGroupBox("BASELINE MANIFEST SHA-256 INTEGRITY AUDITOR")
        layout = QVBoxLayout(group)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        self.btn_audit = QPushButton("Execute Integrity Audit")
        self.btn_audit.setObjectName("btn-success")
        self.btn_audit.clicked.connect(self._run_integrity_audit)
        top_row.addWidget(self.btn_audit)

        self.lbl_audit_summary = QLabel("Audit not yet performed in this session.")
        self.lbl_audit_summary.setStyleSheet(f"color: {ThemeColors.TEXT_SECONDARY};")
        top_row.addWidget(self.lbl_audit_summary, 1)

        layout.addLayout(top_row)

        # Audit Metrics Table
        self.audit_table = QTableWidget()
        self.audit_table.setColumnCount(6)
        self.audit_table.setHorizontalHeaderLabels([
            "Audit Status",
            "Matched (100%)",
            "Modified Files",
            "Missing Files",
            "Untracked Files",
            "Canary Tampering",
        ])
        self.audit_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.audit_table.verticalHeader().setVisible(False)
        self.audit_table.setFixedHeight(65)
        layout.addWidget(self.audit_table)

        return group

    def refresh_lab_info(self) -> None:
        """Inspects disk and updates laboratory health and manifest metrics."""
        is_valid, msg = self.lab_mgr.validate_lab()
        if is_valid:
            self.lbl_marker_status.setText("VALID [HMAC-SHA256 Authenticated]")
            self.lbl_marker_status.setStyleSheet(f"color: {ThemeColors.GREEN}; font-weight: 700;")
        else:
            self.lbl_marker_status.setText(f"INVALID ({msg})")
            self.lbl_marker_status.setStyleSheet(f"color: {ThemeColors.RED}; font-weight: 700;")

        manifest = self.manifest_mgr.load_manifest()
        if manifest:
            self.lbl_manifest_status.setText(f"{manifest.total_files:,} files ({manifest.total_size_bytes / (1024*1024):.2f} MB)")
            self.lbl_manifest_status.setStyleSheet(f"color: {ThemeColors.TEXT_PRIMARY};")
            self.lbl_canary_count.setText(f"{manifest.canary_count:,} honeypots registered")
            self.lbl_canary_count.setStyleSheet(f"color: {ThemeColors.CYAN}; font-weight: 700;")
        else:
            self.lbl_manifest_status.setText("Manifest Missing (Generate Required)")
            self.lbl_manifest_status.setStyleSheet(f"color: {ThemeColors.AMBER};")
            self.lbl_canary_count.setText("0")

    def _set_preset(self, count: int) -> None:
        """Applies a preset file count to the spin box."""
        self.spin_files.setValue(count)

    def _run_generation(self) -> None:
        """Launches synthetic dataset generation asynchronously."""
        file_count = self.spin_files.value()
        seed = self.spin_seed.value()
        clean = self.chk_clean.isChecked()

        self.btn_generate.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.lbl_gen_status.setText(f"Generating {file_count:,} synthetic enterprise files...")

        def generate_payload(progress=None):
            if clean:
                self.lab_mgr.clean_lab(preserve_marker=True)
            self.lab_mgr.initialize_lab()
            generator = SyntheticDatasetGenerator(seed=seed)

            def local_prog(current: int, total: int):
                if progress:
                    pct = int((current / total) * 100)
                    progress(pct, 100, f"Writing {current:,} / {total:,} files...")

            manifest = generator.generate_dataset(file_count=file_count, progress_callback=local_prog)
            return manifest

        self.active_worker = AsyncWorker(generate_payload)
        self.active_worker.signals.progress.connect(self._on_gen_progress)
        self.active_worker.signals.finished.connect(self._on_gen_finished)
        self.active_worker.signals.error.connect(self._on_gen_error)
        self.active_worker.start()

    def _on_gen_progress(self, current: int, total: int, msg: str) -> None:
        self.progress_bar.setValue(current)
        self.lbl_gen_status.setText(msg)

    def _on_gen_finished(self, manifest) -> None:
        self.btn_generate.setEnabled(True)
        self.progress_bar.setValue(100)
        self.lbl_gen_status.setText(
            f"[PASS] Successfully generated {manifest.total_files:,} files "
            f"({manifest.canary_count} canaries) in {manifest.total_size_bytes / (1024*1024):.2f} MB"
        )
        self.refresh_lab_info()
        try:
            from app.core.event_bus import BUS, Event
            BUS.publish(
                Event(
                    event_type="DATASET_GENERATED",
                    data={
                        "total_files": manifest.total_files,
                        "canary_count": manifest.canary_count,
                        "total_bytes": manifest.total_size_bytes,
                    },
                    source="lab.dataset_generator",
                )
            )
        except Exception:
            pass

    def _on_gen_error(self, err_msg: str) -> None:
        self.btn_generate.setEnabled(True)
        self.lbl_gen_status.setText(f"[-] Generation error: {err_msg}")
        self.lbl_gen_status.setStyleSheet(f"color: {ThemeColors.RED};")

    def _run_integrity_audit(self) -> None:
        """Executes full SHA-256 laboratory baseline audit asynchronously."""
        self.btn_audit.setEnabled(False)
        self.lbl_audit_summary.setText("Auditing SHA-256 hashes across files on disk...")

        def audit_payload():
            start_t = time.perf_counter()
            result = ManifestManager.verify_integrity(CONFIG.LAB_DIR)
            return result

        self.active_worker = AsyncWorker(audit_payload)
        self.active_worker.signals.finished.connect(self._on_audit_finished)
        self.active_worker.signals.error.connect(self._on_audit_error)
        self.active_worker.start()

    def _on_audit_finished(self, result) -> None:
        self.btn_audit.setEnabled(True)
        status_text = "[PASS] INTACT" if result.is_valid else "[FAIL] ALTERED"
        color = ThemeColors.GREEN if result.is_valid else ThemeColors.RED
        self.lbl_audit_summary.setText(
            f"{status_text}: Scanned {result.total_disk_files:,} files in {result.duration_seconds:.2f}s "
            f"({result.matched_files:,} matched)."
        )
        self.lbl_audit_summary.setStyleSheet(f"color: {color}; font-weight: 700;")

        # Populate audit table
        self.audit_table.setRowCount(1)
        items = [
            QTableWidgetItem(status_text),
            QTableWidgetItem(f"{result.matched_files:,}"),
            QTableWidgetItem(f"{len(result.modified_files):,}"),
            QTableWidgetItem(f"{len(result.missing_files):,}"),
            QTableWidgetItem(f"{len(result.untracked_files):,}"),
            QTableWidgetItem(f"{len(result.canary_tampered_files):,}"),
        ]

        # Colors
        items[0].setForeground(QColor(color))
        items[1].setForeground(QColor(ThemeColors.GREEN))
        items[2].setForeground(QColor(ThemeColors.RED if result.modified_files else ThemeColors.TEXT_MUTED))
        items[3].setForeground(QColor(ThemeColors.AMBER if result.missing_files else ThemeColors.TEXT_MUTED))
        items[4].setForeground(QColor(ThemeColors.CYAN if result.untracked_files else ThemeColors.TEXT_MUTED))
        items[5].setForeground(QColor(ThemeColors.ORANGE if result.canary_tampered_files else ThemeColors.TEXT_MUTED))

        for col, itm in enumerate(items):
            itm.setTextAlignment(Qt.AlignCenter)
            itm.setFlags(itm.flags() & ~Qt.ItemIsEditable)
            self.audit_table.setItem(0, col, itm)

    def _on_audit_error(self, err_msg: str) -> None:
        self.btn_audit.setEnabled(True)
        self.lbl_audit_summary.setText(f"[-] Audit failed: {err_msg}")
        self.lbl_audit_summary.setStyleSheet(f"color: {ThemeColors.RED};")
