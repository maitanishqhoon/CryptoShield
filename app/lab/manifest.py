"""
Baseline manifest management and cryptographic integrity auditing.

Computes SHA-256 hashes, records file metadata, serializes/deserializes
manifest files, and verifies lab directory integrity against the baseline.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from app.config import CONFIG
from app.core.logger import get_logger
from app.core.models import IntegrityVerificationResult, Manifest, ManifestEntry
from app.core.safety import validate_lab_path

logger = get_logger("manifest")


def compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file using streaming 64 KB blocks."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CONFIG.IO_BUFFER_SIZE_BYTES):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def compute_bytes_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of in-memory bytes."""
    return hashlib.sha256(data).hexdigest().lower()


class ManifestManager:
    """Handles saving, loading, and auditing of baseline manifests."""

    @staticmethod
    def save_manifest(
        manifest: Manifest,
        target_path: Optional[Path] = None,
        base_lab_dir: Optional[Path] = None,
    ) -> Path:
        """Serialize baseline manifest to disk as JSON."""
        dest = target_path or CONFIG.manifest_path
        lab_root = base_lab_dir or (dest.parent if target_path else CONFIG.LAB_DIR)
        validate_lab_path(dest, base_lab_dir=lab_root)
        dest.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f"Saving baseline manifest with {manifest.total_files} files to {dest}")
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(manifest.to_dict(), f, indent=2)

        return dest

    @staticmethod
    def load_manifest(
        source_path: Optional[Path] = None,
        base_lab_dir: Optional[Path] = None,
    ) -> Manifest:
        """Load manifest from JSON file."""
        src = source_path or CONFIG.manifest_path
        lab_root = base_lab_dir or (src.parent if source_path else CONFIG.LAB_DIR)
        validate_lab_path(src, base_lab_dir=lab_root)

        if not src.exists():
            raise FileNotFoundError(f"Baseline manifest not found at: {src}")

        with open(src, "r", encoding="utf-8") as f:
            data = json.load(f)

        return Manifest.from_dict(data)

    @staticmethod
    def verify_integrity(
        base_lab_dir: Optional[Path] = None,
        manifest: Optional[Manifest] = None,
    ) -> IntegrityVerificationResult:
        """
        Audit the current state of the lab directory against the baseline manifest.

        Identifies:
        - Matched files (intact SHA-256)
        - Modified files (SHA-256 mismatch)
        - Missing files (in manifest, absent on disk)
        - Untracked files (on disk, not in manifest)
        - Canary tampering (any modification/deletion of canaries)
        """
        start_time = time.perf_counter()
        lab_root = (base_lab_dir or CONFIG.LAB_DIR).resolve()

        if manifest is None:
            manifest = ManifestManager.load_manifest(lab_root / CONFIG.MANIFEST_FILENAME)

        matched = 0
        modified_files: List[str] = []
        missing_files: List[str] = []
        untracked_files: List[str] = []
        canary_tampered: List[str] = []

        # Fast directory scan using os.walk
        disk_files: Dict[str, Path] = {}
        for root, _, files in os.walk(lab_root):
            root_path = Path(root)
            for f in files:
                if f in {
                    CONFIG.LAB_MARKER_FILENAME,
                    CONFIG.MANIFEST_FILENAME,
                    ".write_gate_state",
                    ".gitkeep",
                }:
                    continue
                full_path = root_path / f
                try:
                    rel = full_path.relative_to(lab_root).as_posix()
                    disk_files[rel] = full_path
                except Exception:
                    continue

        # Fast parallel hashing
        def _check_entry(item: Tuple[str, ManifestEntry]) -> Tuple[str, str, bool]:
            rel_path, entry = item
            if rel_path not in disk_files:
                return rel_path, "missing", entry.is_canary

            current_hash = compute_file_sha256(disk_files[rel_path])
            if current_hash == entry.sha256.lower():
                return rel_path, "matched", entry.is_canary
            else:
                return rel_path, "modified", entry.is_canary

        workers = min(32, max(4, (os.cpu_count() or 4) * 2))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            check_results = list(executor.map(_check_entry, manifest.entries.items(), chunksize=50))

        for rel_path, status, is_canary in check_results:
            if status == "matched":
                matched += 1
            elif status == "modified":
                modified_files.append(rel_path)
                if is_canary:
                    canary_tampered.append(rel_path)
            elif status == "missing":
                missing_files.append(rel_path)
                if is_canary:
                    canary_tampered.append(rel_path)

        # Check for untracked files on disk
        for rel_path in disk_files:
            if rel_path not in manifest.entries:
                untracked_files.append(rel_path)

        duration = time.perf_counter() - start_time
        is_valid = (
            len(modified_files) == 0
            and len(missing_files) == 0
            and len(untracked_files) == 0
        )

        result = IntegrityVerificationResult(
            is_valid=is_valid,
            total_manifest_files=len(manifest.entries),
            total_disk_files=len(disk_files),
            matched_files=matched,
            modified_files=modified_files,
            missing_files=missing_files,
            untracked_files=untracked_files,
            canary_tampered_files=canary_tampered,
            duration_seconds=round(duration, 4),
        )

        logger.info(
            f"Integrity audit finished: valid={is_valid}, matched={matched}/{len(manifest.entries)}, "
            f"modified={len(modified_files)}, missing={len(missing_files)}, "
            f"untracked={len(untracked_files)} ({duration:.2f}s)"
        )
        return result
