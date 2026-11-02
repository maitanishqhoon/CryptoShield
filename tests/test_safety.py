"""Unit tests for CryptoShield safety controls and boundary enforcement."""

import json
import os
from pathlib import Path
import pytest

from app.core.safety import (
    SafetyViolationError,
    generate_lab_marker,
    is_path_safe_for_containment,
    validate_lab_path,
    validate_process_for_containment,
    verify_lab_marker,
)
from app.config import CONFIG


def test_validate_lab_path_inside(tmp_path: Path):
    """Ensure paths inside the laboratory root pass validation."""
    lab_root = tmp_path / "lab"
    lab_root.mkdir()
    child = lab_root / "Finance" / "doc.txt"
    child.parent.mkdir()
    child.touch()

    validated = validate_lab_path(child, base_lab_dir=lab_root)
    assert validated == child.resolve()


def test_validate_lab_path_outside(tmp_path: Path):
    """Ensure paths outside the laboratory root raise SafetyViolationError."""
    lab_root = tmp_path / "lab"
    lab_root.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_file = outside_dir / "secret.txt"
    outside_file.touch()

    with pytest.raises(SafetyViolationError, match="outside authorized laboratory"):
        validate_lab_path(outside_file, base_lab_dir=lab_root)


def test_validate_lab_path_traversal(tmp_path: Path):
    """Ensure directory traversal attacks are rejected."""
    lab_root = tmp_path / "lab"
    lab_root.mkdir()
    traversal_path = lab_root / ".." / "evil.txt"

    with pytest.raises(SafetyViolationError):
        validate_lab_path(traversal_path, base_lab_dir=lab_root)


def test_verify_lab_marker_valid(tmp_path: Path):
    """Verify that a freshly generated marker passes verification."""
    lab_root = tmp_path / "lab"
    lab_root.mkdir()

    marker = generate_lab_marker(base_lab_dir=lab_root)
    marker_file = lab_root / CONFIG.LAB_MARKER_FILENAME
    with open(marker_file, "w", encoding="utf-8") as f:
        json.dump(marker.to_dict(), f)

    verified = verify_lab_marker(base_lab_dir=lab_root)
    assert verified.lab_id == marker.lab_id
    assert verified.authorized_root == str(lab_root.resolve())


def test_verify_lab_marker_missing(tmp_path: Path):
    """Missing marker must raise SafetyViolationError."""
    lab_root = tmp_path / "lab"
    lab_root.mkdir()

    with pytest.raises(SafetyViolationError, match="Missing safety marker"):
        verify_lab_marker(base_lab_dir=lab_root)


def test_verify_lab_marker_tampered(tmp_path: Path):
    """Tampered signature must raise SafetyViolationError."""
    lab_root = tmp_path / "lab"
    lab_root.mkdir()

    marker = generate_lab_marker(base_lab_dir=lab_root)
    data = marker.to_dict()
    data["marker_signature"] = "tampered_signature_0000000000000000000000"

    marker_file = lab_root / CONFIG.LAB_MARKER_FILENAME
    with open(marker_file, "w", encoding="utf-8") as f:
        json.dump(data, f)

    with pytest.raises(SafetyViolationError, match="signature validation failed"):
        verify_lab_marker(base_lab_dir=lab_root)


def test_is_path_safe_for_containment(tmp_path: Path):
    lab_root = tmp_path / "lab"
    lab_root.mkdir()
    child = lab_root / "file.txt"
    outside = tmp_path / "file.txt"

    assert is_path_safe_for_containment(child, base_lab_dir=lab_root) is True
    assert is_path_safe_for_containment(outside, base_lab_dir=lab_root) is False


def test_validate_process_for_containment():
    """Ensure only registered attack simulation PIDs can be contained."""
    allowed = {1234, 5678}
    assert validate_process_for_containment(1234, allowed) is True
    assert validate_process_for_containment(9999, allowed) is False
    assert validate_process_for_containment(0, allowed) is False  # System idle
    assert validate_process_for_containment(4, allowed) is False  # System kernel
    assert validate_process_for_containment(os.getpid(), allowed) is False  # Self
