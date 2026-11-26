"""Unit tests for CryptoShield configuration."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

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


def test_runtime_dir_env_override_and_ensure_directories(tmp_path: Path, monkeypatch):
    custom_runtime = tmp_path / "custom_runtime"
    monkeypatch.setenv("CRYPTOSHIELD_RUNTIME_DIR", str(custom_runtime))

    cfg = CryptoShieldConfig()
    assert cfg.RUNTIME_DIR == custom_runtime.resolve()
    assert cfg.EXFILTRATION_DIR == custom_runtime.resolve() / "exfiltration"

    cfg.ensure_directories()
    for path in [
        cfg.RUNTIME_DIR,
        cfg.LAB_DIR,
        cfg.VAULT_DIR,
        cfg.KEYS_DIR,
        cfg.SNAPSHOTS_DIR,
        cfg.LOGS_DIR,
        cfg.REPORTS_DIR,
        cfg.INCIDENTS_DIR,
        cfg.CONTAINMENT_DIR,
        cfg.RECOVERY_DIR,
        cfg.RECOVERY_WORKSPACES_DIR,
        cfg.RECOVERY_STAGING_DIR,
        cfg.RECOVERY_REPORTS_DIR,
        cfg.EXFILTRATION_DIR,
        cfg.DLP_DIR,
    ]:
        assert path.is_dir(), f"Expected runtime directory to exist: {path}"


def test_cli_initializes_runtime_directories_on_fresh_path(tmp_path: Path):
    fresh_runtime = tmp_path / "fresh_cli_runtime"
    assert not fresh_runtime.exists()

    env = {**os.environ, "CRYPTOSHIELD_RUNTIME_DIR": str(fresh_runtime)}
    proc = subprocess.run(
        [sys.executable, "-m", "app.main", "vault", "status"],
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0
    assert (fresh_runtime / "lab").is_dir()
    assert (fresh_runtime / "keys").is_dir()
    assert (fresh_runtime / "vault").is_dir()
    assert (fresh_runtime / "recovery" / "workspaces").is_dir()
    assert (fresh_runtime / "exfiltration").is_dir()
    assert (fresh_runtime / "dlp").is_dir()


def test_recovery_demo_requires_passphrase_without_hardcoded_fallback(isolated_runtime, monkeypatch):
    from app.recovery.models import RecoveryError

    monkeypatch.delenv("CRYPTOSHIELD_VAULT_PASSPHRASE", raising=False)
    coordinator = isolated_runtime["recovery_coordinator"]

    with pytest.raises(RecoveryError, match="passphrase is required"):
        coordinator.run_recovery_demo(
            file_count=5,
            snapshot_id=isolated_runtime["snapshot_id"],
            passphrase=None,
            cleanup=True,
        )
