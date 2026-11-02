"""
Safety verification and boundary enforcement engine for CryptoShield.

Guarantees that all laboratory operations, scans, and simulated activities
remain strictly isolated within the designated laboratory directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Set, Union

from app.core.models import LabMarker


DEFAULT_MARKER_FILENAME = ".cryptoshield_lab_marker"


def _get_default_lab_dir() -> Path:
    from app.config import CONFIG
    return CONFIG.LAB_DIR


class SafetyViolationError(RuntimeError):
    """Raised when an operation attempts to breach laboratory safety boundaries."""
    pass


_MARKER_SALT = "CRYPTOSHIELD_SAFETY_SECRET_SALT_2026"


def _compute_marker_signature(lab_id: str, authorized_root: str) -> str:
    """Compute deterministic SHA-256 signature for marker tamper-detection."""
    content = f"{lab_id}:{authorized_root}:{_MARKER_SALT}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def generate_lab_marker(base_lab_dir: Optional[Path] = None) -> LabMarker:
    """Create a new authenticated laboratory marker instance."""
    root_path = (base_lab_dir or _get_default_lab_dir()).resolve()
    lab_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    hostname = socket.gethostname()
    platform_name = platform.platform()
    sig = _compute_marker_signature(lab_id, str(root_path))

    return LabMarker(
        lab_id=lab_id,
        created_at=now_iso,
        version="1.0.0",
        authorized_root=str(root_path),
        system_hostname=hostname,
        platform=platform_name,
        marker_signature=sig,
    )


def validate_lab_path(
    path: Union[str, Path],
    base_lab_dir: Optional[Path] = None,
    allow_marker: bool = True,
) -> Path:
    """
    Strictly validate that a given path resides inside the authorized laboratory directory.

    Raises:
        SafetyViolationError: If path is outside laboratory or touches unauthorized areas.
    """
    lab_root = (base_lab_dir or _get_default_lab_dir()).resolve()
    target = Path(path).resolve()

    # Verify target path is child of laboratory root
    try:
        target.relative_to(lab_root)
    except ValueError:
        raise SafetyViolationError(
            f"[CRITICAL SAFETY BREACH] Path '{target}' is outside authorized laboratory directory '{lab_root}'!"
        )

    # Disallow targeting the lab root directly as a file modification
    if target == lab_root:
        raise SafetyViolationError(
            f"[SAFETY VIOLATION] Target path cannot be the laboratory root directory itself."
        )

    # Check for marker file protection unless specifically allowed
    if not allow_marker and target.name == DEFAULT_MARKER_FILENAME:
        raise SafetyViolationError(
            f"[SAFETY VIOLATION] Modification of safety marker '{target.name}' is prohibited."
        )

    return target


def verify_lab_marker(base_lab_dir: Optional[Path] = None) -> LabMarker:
    """
    Verify that the laboratory root contains a valid, untampered safety marker.

    Raises:
        SafetyViolationError: If marker is missing, corrupted, or does not match authorized root.
    """
    lab_root = (base_lab_dir or _get_default_lab_dir()).resolve()
    marker_path = lab_root / DEFAULT_MARKER_FILENAME

    if not marker_path.exists():
        raise SafetyViolationError(
            f"[SAFETY VIOLATION] Missing safety marker at '{marker_path}'. "
            "Laboratory directory has not been properly initialized."
        )

    try:
        with open(marker_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        marker = LabMarker.from_dict(data)
    except Exception as e:
        raise SafetyViolationError(
            f"[SAFETY VIOLATION] Failed to read or parse laboratory marker: {e}"
        )

    # Verify authorized root matches current resolved directory
    marker_root = Path(marker.authorized_root).resolve()
    if marker_root != lab_root:
        raise SafetyViolationError(
            f"[SAFETY VIOLATION] Marker authorized root '{marker_root}' does not match current lab root '{lab_root}'."
        )

    # Verify integrity signature
    expected_sig = _compute_marker_signature(marker.lab_id, str(marker_root))
    if marker.marker_signature != expected_sig:
        raise SafetyViolationError(
            "[SAFETY VIOLATION] Laboratory marker signature validation failed. Marker may have been tampered with."
        )

    return marker


def is_path_safe_for_containment(
    path: Union[str, Path], base_lab_dir: Optional[Path] = None
) -> bool:
    """Non-throwing query to test whether a path is safely inside the laboratory."""
    try:
        validate_lab_path(path, base_lab_dir)
        return True
    except SafetyViolationError:
        return False


def validate_process_for_containment(pid: int, allowed_pids: Set[int]) -> bool:
    """
    Ensure only processes explicitly launched/registered by the test framework
    can be stopped or contained by CryptoShield.
    """
    if pid <= 4:  # System / idle / init processes
        return False
    if pid == os.getpid():  # CryptoShield's own process
        return False
    return pid in allowed_pids
