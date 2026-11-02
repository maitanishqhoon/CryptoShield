"""
Central Configuration for CryptoShield.

Defines all filesystem paths, laboratory safety parameters, dataset generation
rules, limits, and departmental taxonomy.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from app.core.models import DataClassification, DatasetPreset


@dataclass(frozen=True)
class CryptoShieldConfig:
    """Immutable configuration holding all paths and operational constraints."""

    # Base project paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    RUNTIME_DIR: Path = BASE_DIR / "runtime"

    # Laboratory and subsystem directories
    LAB_DIR: Path = RUNTIME_DIR / "lab"
    VAULT_DIR: Path = RUNTIME_DIR / "vault"
    SNAPSHOTS_DIR: Path = RUNTIME_DIR / "snapshots"
    LOGS_DIR: Path = RUNTIME_DIR / "logs"
    REPORTS_DIR: Path = RUNTIME_DIR / "reports"

    # Identification & Safety
    LAB_MARKER_FILENAME: str = ".cryptoshield_lab_marker"
    MANIFEST_FILENAME: str = "baseline_manifest.json"
    LOG_FILENAME: str = "cryptoshield.log"
    JSON_LOG_FILENAME: str = "cryptoshield.json.log"

    # Supported enterprise departments
    DEPARTMENTS: List[str] = field(
        default_factory=lambda: [
            "Finance",
            "Human Resources",
            "Legal",
            "Sales",
            "Customers",
            "Operations",
            "Research",
            "IT",
            "Public Documents",
        ]
    )

    # Supported file extensions
    FILE_FORMATS: List[str] = field(
        default_factory=lambda: [
            "txt",
            "csv",
            "json",
            "xml",
            "md",
            "html",
            "log",
        ]
    )

    # Department classification guidelines
    DEPARTMENT_CLASSIFICATIONS: Dict[str, List[DataClassification]] = field(
        default_factory=lambda: {
            "Finance": [DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED],
            "Human Resources": [DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED],
            "Legal": [DataClassification.RESTRICTED, DataClassification.CONFIDENTIAL],
            "Sales": [DataClassification.INTERNAL, DataClassification.CONFIDENTIAL],
            "Customers": [DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED],
            "Operations": [DataClassification.INTERNAL, DataClassification.PUBLIC],
            "Research": [DataClassification.CONFIDENTIAL, DataClassification.INTERNAL],
            "IT": [DataClassification.RESTRICTED, DataClassification.INTERNAL],
            "Public Documents": [DataClassification.PUBLIC],
        }
    )

    # Safety and dataset limits
    MAX_FILE_SIZE_BYTES: int = 128 * 1024        # 128 KB max single synthetic file
    MAX_DATASET_TOTAL_BYTES: int = 500 * 1024 * 1024  # 500 MB safety cap
    CANARY_RATIO: float = 0.02                   # 2% of files as canaries
    MIN_CANARY_COUNT: int = 5                    # Minimum canaries generated
    MAX_CANARY_COUNT: int = 250                  # Cap to avoid excessive canaries
    IO_BUFFER_SIZE_BYTES: int = 64 * 1024        # 64 KB buffer for streaming SHA256

    # Presets
    PRESET_COUNTS: Dict[str, int] = field(
        default_factory=lambda: {
            "quick": DatasetPreset.QUICK.value,
            "default": DatasetPreset.DEFAULT.value,
            "stress": DatasetPreset.STRESS.value,
        }
    )

    # Telemetry and Monitoring Parameters (Phase 2)
    MONITORING_ENABLED: bool = True
    MONITOR_EVENT_QUEUE_CAPACITY: int = 10000
    MONITOR_DEBOUNCE_SECONDS: float = 0.05
    MONITOR_OBSERVER_TIMEOUT_SECONDS: float = 0.05
    PROCESS_POLL_INTERVAL_SECONDS: float = 1.0
    CANARY_EVENT_PRIORITY: str = "HIGH"
    MONITOR_IGNORED_DIRS: List[str] = field(
        default_factory=lambda: [".git", "__pycache__", ".pytest_cache", ".demo_tmp"]
    )
    MONITOR_IGNORED_FILENAMES: List[str] = field(
        default_factory=lambda: [".cryptoshield_lab_marker", "baseline_manifest.json"]
    )

    @property
    def lab_marker_path(self) -> Path:
        return self.LAB_DIR / self.LAB_MARKER_FILENAME

    @property
    def manifest_path(self) -> Path:
        return self.LAB_DIR / self.MANIFEST_FILENAME

    @property
    def log_path(self) -> Path:
        return self.LOGS_DIR / self.LOG_FILENAME

    @property
    def json_log_path(self) -> Path:
        return self.LOGS_DIR / self.JSON_LOG_FILENAME


# Global singleton instance
CONFIG = CryptoShieldConfig()
