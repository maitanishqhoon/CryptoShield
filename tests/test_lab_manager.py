"""Unit tests for LabManager lifecycle, validation, and safe cleanup."""

from pathlib import Path
import pytest

from app.config import CONFIG
from app.core.safety import SafetyViolationError
from app.lab.lab_manager import LabManager


def test_lab_manager_init(tmp_path: Path):
    lab_dir = tmp_path / "lab"
    mgr = LabManager(base_lab_dir=lab_dir)

    # Initialize lab
    marker = mgr.initialize_lab()
    assert mgr.marker_path.exists()
    assert marker.authorized_root == str(lab_dir.resolve())

    # Validate lab
    is_valid, msg = mgr.validate_lab()
    assert is_valid is True

    # Check status
    status = mgr.get_status()
    assert status["is_valid"] is True
    assert status["has_marker"] is True
    assert status["total_files"] == 0


def test_lab_manager_clean(tmp_path: Path):
    lab_dir = tmp_path / "lab"
    mgr = LabManager(base_lab_dir=lab_dir)
    mgr.initialize_lab()

    # Add mock files
    test_sub = lab_dir / "Finance"
    test_sub.mkdir()
    (test_sub / "test1.txt").write_text("sample data")
    (test_sub / "test2.csv").write_text("a,b,c")

    status_before = mgr.get_status()
    assert status_before["total_files"] == 2

    # Clean preserving marker
    deleted = mgr.clean_lab(preserve_marker=True)
    assert deleted > 0
    assert mgr.marker_path.exists()

    status_after = mgr.get_status()
    assert status_after["total_files"] == 0
    assert status_after["has_marker"] is True


def test_lab_manager_clean_uninitialized_fails(tmp_path: Path):
    """Attempting to clean an uninitialized directory must fail safety check."""
    lab_dir = tmp_path / "lab"
    lab_dir.mkdir()
    mgr = LabManager(base_lab_dir=lab_dir)

    with pytest.raises(SafetyViolationError, match="Missing safety marker"):
        mgr.clean_lab()
