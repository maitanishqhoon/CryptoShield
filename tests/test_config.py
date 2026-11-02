"""Unit tests for CryptoShield configuration."""

from pathlib import Path
from app.config import CONFIG, CryptoShieldConfig
from app.core.models import DataClassification, DatasetPreset


def test_config_paths():
    assert isinstance(CONFIG.BASE_DIR, Path)
    assert CONFIG.RUNTIME_DIR == CONFIG.BASE_DIR / "runtime"
    assert CONFIG.LAB_DIR == CONFIG.RUNTIME_DIR / "lab"
    assert CONFIG.VAULT_DIR == CONFIG.RUNTIME_DIR / "vault"
    assert CONFIG.SNAPSHOTS_DIR == CONFIG.RUNTIME_DIR / "snapshots"
    assert CONFIG.LOGS_DIR == CONFIG.RUNTIME_DIR / "logs"
    assert CONFIG.REPORTS_DIR == CONFIG.RUNTIME_DIR / "reports"


def test_config_presets():
    assert CONFIG.PRESET_COUNTS["quick"] == 1000
    assert CONFIG.PRESET_COUNTS["default"] == 10000
    assert CONFIG.PRESET_COUNTS["stress"] == 20000


def test_config_departments_and_formats():
    assert len(CONFIG.DEPARTMENTS) == 9
    assert "Finance" in CONFIG.DEPARTMENTS
    assert "Human Resources" in CONFIG.DEPARTMENTS
    assert "Legal" in CONFIG.DEPARTMENTS

    for fmt in ["txt", "csv", "json", "xml", "md", "html", "log"]:
        assert fmt in CONFIG.FILE_FORMATS


def test_config_safety_limits():
    assert CONFIG.MAX_FILE_SIZE_BYTES > 0
    assert CONFIG.MAX_DATASET_TOTAL_BYTES > 0
    assert 0.0 < CONFIG.CANARY_RATIO < 0.5
