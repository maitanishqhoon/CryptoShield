"""
Snapshot Manager for CryptoShield Vault (Phase 5).

Coordinates safe, atomic snapshot creation, encrypted storage, and snapshot lifecycle
management.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.config import CONFIG
from app.containment.process_registry import REGISTRY, ControlledProcessRegistry
from app.core.logger import get_logger
from app.core.models import Manifest, ManifestEntry, ProcessLifecycleStatus
from app.core.safety import SafetyViolationError, validate_lab_path, verify_lab_marker
from app.lab.manifest import ManifestManager
from app.vault.crypto_engine import CRYPTO_ENGINE, CryptoEngine
from app.vault.key_manager import KEY_MGR, KeyManager
from app.vault.models import (
    EncryptedObjectRecord,
    PublicSnapshotMetadata,
    SnapshotManifest,
    SnapshotStatus,
)
from app.vault.snapshot_manifest import (
    MANIFEST_SCHEMA_VERSION,
    SNAPSHOT_MANIFEST_MGR,
    SnapshotManifestManager,
)

logger = get_logger("vault.snapshot_manager")


class SnapshotCreationError(RuntimeError):
    """Raised when snapshot creation fails."""
    pass


class BaselineIntegrityError(SnapshotCreationError):
    """Raised when source baseline fails integrity verification before snapshot."""
    pass


class ActiveSimulationError(SnapshotCreationError):
    """Raised when an active simulation process is running in the lab."""
    pass


class SnapshotManager:
    """
    Coordinates creation and lifecycle of encrypted laboratory snapshots.
    """

    _instance_lock = threading.Lock()
    _instance: Optional[SnapshotManager] = None

    def __init__(
        self,
        vault_dir: Optional[Path] = None,
        base_lab_dir: Optional[Path] = None,
        key_manager: Optional[KeyManager] = None,
        crypto_engine: Optional[CryptoEngine] = None,
        manifest_manager: Optional[SnapshotManifestManager] = None,
        process_registry: Optional[ControlledProcessRegistry] = None,
    ) -> None:
        self.vault_dir = (vault_dir or CONFIG.vault_dir).resolve()
        self.lab_dir = (base_lab_dir or CONFIG.LAB_DIR).resolve()
        self.key_manager = key_manager or KEY_MGR
        self.crypto_engine = crypto_engine or CRYPTO_ENGINE
        self.manifest_manager = manifest_manager or SNAPSHOT_MANIFEST_MGR
        self.process_registry = process_registry or REGISTRY
        self._lock = threading.RLock()

    @classmethod
    def get_instance(cls) -> SnapshotManager:
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = SnapshotManager()
            return cls._instance

    def initialize_vault_directory(self) -> None:
        """Ensure vault directory exists."""
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        gitkeep = self.vault_dir / ".gitkeep"
        if not gitkeep.exists() and not any(self.vault_dir.iterdir()):
            gitkeep.touch()

    def create_snapshot(
        self,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        max_workers: int = 8,
    ) -> PublicSnapshotMetadata:
        """
        Create a clean, cryptographically authenticated snapshot of the laboratory.

        Enforces:
        1. Lab marker validation.
        2. Strict baseline manifest audit (refuses corrupted/modified datasets).
        3. Active simulation process detection (refuses concurrent simulator runs).
        4. Independent 256-bit AES session key.
        5. Atomic staging and publication.
        6. Zero modification to original files.
        """
        with self._lock:
            t_total_start = time.perf_counter()
            self.initialize_vault_directory()

            # 1. Validate laboratory marker
            logger.info("Validating laboratory safety marker before snapshot...")
            lab_marker = verify_lab_marker(self.lab_dir)

            # 2. Check for active simulation runs
            active_runs = [
                rec.simulation_run_id
                for rec in self.process_registry.list_records()
                if rec.lifecycle_status == ProcessLifecycleStatus.RUNNING.value
            ]
            if active_runs:
                raise ActiveSimulationError(
                    f"Refusing snapshot: Active simulation run(s) detected: {active_runs}. "
                    "Laboratory filesystem must be quiescent."
                )

            # 3. Load baseline manifest and run strict integrity audit
            manifest_path = self.lab_dir / CONFIG.MANIFEST_FILENAME
            if not manifest_path.exists():
                raise BaselineIntegrityError(
                    f"Baseline manifest not found at '{manifest_path}'. Initialize lab first."
                )

            logger.info("Auditing baseline laboratory integrity before snapshot creation...")
            t_audit_start = time.perf_counter()
            baseline_manifest = ManifestManager.load_manifest(manifest_path, base_lab_dir=self.lab_dir)
            audit_result = ManifestManager.verify_integrity(
                base_lab_dir=self.lab_dir,
                manifest=baseline_manifest,
            )
            audit_duration = time.perf_counter() - t_audit_start

            if not audit_result.is_valid:
                raise BaselineIntegrityError(
                    f"Refusing snapshot: Baseline integrity audit failed! "
                    f"Modified: {len(audit_result.modified_files)}, "
                    f"Missing: {len(audit_result.missing_files)}, "
                    f"Untracked: {len(audit_result.untracked_files)}, "
                    f"Canary Tampered: {len(audit_result.canary_tampered_files)}."
                )

            # 4. Ensure RSA keys are provisioned
            if not self.key_manager.has_keys():
                raise SnapshotCreationError(
                    "Cryptographic key pair not initialized. Run 'cryptoshield vault init' first."
                )

            public_key = self.key_manager.load_public_key()
            key_meta = self.key_manager.get_key_metadata()
            key_id = key_meta.get("key_id", "UNKNOWN")

            # 5. Generate snapshot identity and AES session key
            snapshot_id = f"SNAP-{uuid.uuid4().hex[:8].upper()}"
            final_snapshot_dir = self.vault_dir / snapshot_id
            staging_dir = self.vault_dir / f".staging_{snapshot_id}"

            if final_snapshot_dir.exists():
                raise SnapshotCreationError(f"Snapshot directory '{final_snapshot_dir}' already exists.")

            aes_session_key = self.key_manager.generate_snapshot_aes_key()
            staging_dir.mkdir(parents=True, exist_ok=True)
            staging_objects_dir = staging_dir / "objects"
            staging_objects_dir.mkdir(parents=True, exist_ok=True)

            logger.info(
                f"Initiating snapshot creation {snapshot_id} for {len(baseline_manifest.entries):,} files..."
            )

            # 6. Stream encrypt all registered manifest files
            encrypted_records: Dict[str, EncryptedObjectRecord] = {}
            opaque_id_map: Dict[str, str] = {}
            total_files = len(baseline_manifest.entries)
            processed_count = 0
            total_encrypted_bytes = 0

            # Progress tracking lock
            progress_lock = threading.Lock()

            def _encrypt_single_entry(entry: ManifestEntry) -> EncryptedObjectRecord:
                nonlocal processed_count
                rel_path = entry.relative_path
                src_path = self.lab_dir / rel_path
                opaque_id = CRYPTO_ENGINE.generate_opaque_id(snapshot_id, rel_path)
                dest_file = staging_objects_dir / f"{opaque_id}{CONFIG.VAULT_OBJECT_EXT}"

                rec = self.crypto_engine.encrypt_file(
                    source_path=src_path,
                    dest_path=dest_file,
                    key=aes_session_key,
                    snapshot_id=snapshot_id,
                    opaque_id=opaque_id,
                    entry=entry,
                    base_lab_dir=self.lab_dir,
                )

                with progress_lock:
                    processed_count += 1
                    if progress_callback:
                        progress_callback(processed_count, total_files)

                return rec

            start_encrypt_time = time.perf_counter()

            try:
                workers = min(max_workers, max(1, (os.cpu_count() or 4)))
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    results = list(
                        executor.map(_encrypt_single_entry, baseline_manifest.entries.values())
                    )

                encryption_duration = time.perf_counter() - start_encrypt_time

                for rec in results:
                    encrypted_records[rec.relative_path] = rec
                    opaque_id_map[rec.opaque_id] = rec.relative_path
                    total_encrypted_bytes += rec.encrypted_size_bytes

                # 7. Build SnapshotManifest
                now_iso = datetime.now(CONFIG.TIMEZONE).isoformat()
                snap_manifest = SnapshotManifest(
                    snapshot_id=snapshot_id,
                    format_version=str(CONFIG.VAULT_FORMAT_VERSION),
                    created_at=now_iso,
                    lab_id=lab_marker.lab_id,
                    total_files=total_files,
                    total_original_bytes=baseline_manifest.total_size_bytes,
                    canary_count=baseline_manifest.canary_count,
                    department_counts=dict(baseline_manifest.department_counts),
                    classification_counts=dict(baseline_manifest.classification_counts),
                    entries=encrypted_records,
                    opaque_id_map=opaque_id_map,
                )

                # 8. Encrypt manifest to staging_dir / "manifest.enc"
                t_manifest_start = time.perf_counter()
                manifest_enc_path = staging_dir / "manifest.enc"
                manifest_nonce, manifest_tag, manifest_enc_size = self.manifest_manager.encrypt_manifest(
                    manifest=snap_manifest,
                    dest_path=manifest_enc_path,
                    key=aes_session_key,
                )
                manifest_duration = time.perf_counter() - t_manifest_start
                total_encrypted_bytes += manifest_enc_size

                # 9. Wrap AES session key with RSA public key
                t_wrap_start = time.perf_counter()
                wrapped_aes_key = self.key_manager.wrap_aes_key(
                    public_key=public_key,
                    aes_key=aes_session_key,
                    snapshot_id=snapshot_id,
                )
                key_wrapping_duration = time.perf_counter() - t_wrap_start

                # 10. Write public snapshot.json metadata
                total_objects_bytes = sum(r.encrypted_size_bytes for r in results)
                total_creation_duration = time.perf_counter() - t_total_start

                metadata = PublicSnapshotMetadata(
                    snapshot_id=snapshot_id,
                    format_version=str(CONFIG.VAULT_FORMAT_VERSION),
                    created_at=now_iso,
                    completed_status=SnapshotStatus.COMPLETED.value,
                    total_files=total_files,
                    total_original_bytes=baseline_manifest.total_size_bytes,
                    total_encrypted_bytes=total_encrypted_bytes,
                    key_id=key_id,
                    wrapped_aes_key_b64=base64.b64encode(wrapped_aes_key).decode("ascii"),
                    manifest_nonce_b64=base64.b64encode(manifest_nonce).decode("ascii"),
                    manifest_tag_b64=base64.b64encode(manifest_tag).decode("ascii"),
                    manifest_encrypted_size=manifest_enc_size,
                    source_lab_id=lab_marker.lab_id,
                    metadata={
                        "creation_duration_seconds": round(encryption_duration, 4),
                        "encryption_algorithm": "AES-256-GCM",
                        "key_wrapping_algorithm": "RSA-OAEP-SHA256",
                        "phase_durations": {
                            "audit_duration_seconds": round(audit_duration, 4),
                            "encryption_duration_seconds": round(encryption_duration, 4),
                            "manifest_duration_seconds": round(manifest_duration, 4),
                            "key_wrapping_duration_seconds": round(key_wrapping_duration, 4),
                            "publication_duration_seconds": 0.0,
                            "total_creation_duration_seconds": round(total_creation_duration, 4),
                        },
                        "storage_accounting": {
                            "original_logical_bytes": baseline_manifest.total_size_bytes,
                            "encrypted_objects_bytes": total_objects_bytes,
                            "manifest_encrypted_bytes": manifest_enc_size,
                            "object_overhead_bytes": total_objects_bytes - baseline_manifest.total_size_bytes,
                            "object_overhead_percentage": round(
                                ((total_objects_bytes - baseline_manifest.total_size_bytes) / baseline_manifest.total_size_bytes) * 100,
                                4,
                            ) if baseline_manifest.total_size_bytes > 0 else 0.0,
                            "total_vault_overhead_bytes": total_encrypted_bytes - baseline_manifest.total_size_bytes,
                            "total_vault_overhead_percentage": round(
                                ((total_encrypted_bytes - baseline_manifest.total_size_bytes) / baseline_manifest.total_size_bytes) * 100,
                                4,
                            ) if baseline_manifest.total_size_bytes > 0 else 0.0,
                        },
                    },
                )

                meta_path = staging_dir / "snapshot.json"
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(metadata.to_dict(), f, indent=2)

                # 11. Atomic verification before publication: ensure every object exists on disk
                disk_objects = set(p.name for p in staging_objects_dir.glob(f"*{CONFIG.VAULT_OBJECT_EXT}"))
                expected_objects = set(f"{rec.opaque_id}{CONFIG.VAULT_OBJECT_EXT}" for rec in results)

                if disk_objects != expected_objects:
                    diff = expected_objects.symmetric_difference(disk_objects)
                    raise SnapshotCreationError(f"Staging object mismatch before atomic publication: {diff}")

                # 12. Atomically publish snapshot directory
                t_pub_start = time.perf_counter()
                staging_dir.replace(final_snapshot_dir)
                pub_duration = time.perf_counter() - t_pub_start

                metadata.metadata["phase_durations"]["publication_duration_seconds"] = round(pub_duration, 4)
                metadata.metadata["phase_durations"]["total_creation_duration_seconds"] = round(
                    time.perf_counter() - t_total_start, 4
                )

                # Update snapshot.json in published location
                with open(final_snapshot_dir / "snapshot.json", "w", encoding="utf-8") as f:
                    json.dump(metadata.to_dict(), f, indent=2)

                logger.info(
                    f"Snapshot {snapshot_id} successfully created and atomically published to '{final_snapshot_dir}'!"
                )
                return metadata

            except Exception as e:
                logger.error(f"Snapshot creation failed for {snapshot_id}: {e}")
                # Safe cleanup of incomplete staging directory
                if staging_dir.exists():
                    try:
                        shutil.rmtree(staging_dir, ignore_errors=True)
                        logger.info(f"Cleaned up incomplete staging directory '{staging_dir}'.")
                    except Exception as clean_err:
                        logger.warning(f"Failed to remove staging directory: {clean_err}")
                raise

    def list_snapshots(self) -> List[PublicSnapshotMetadata]:
        """List all valid snapshots in the vault sorted by creation date."""
        self.initialize_vault_directory()
        snapshots: List[PublicSnapshotMetadata] = []

        for item in self.vault_dir.iterdir():
            if not item.is_dir() or item.name.startswith("."):
                continue

            meta_file = item / "snapshot.json"
            if meta_file.exists():
                try:
                    with open(meta_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    snapshots.append(PublicSnapshotMetadata.from_dict(data))
                except Exception as e:
                    logger.warning(f"Could not read metadata for snapshot in '{item.name}': {e}")

        # Sort descending by creation timestamp
        snapshots.sort(key=lambda s: s.created_at, reverse=True)
        return snapshots

    def get_snapshot_metadata(self, snapshot_id: str) -> Optional[PublicSnapshotMetadata]:
        """Load public metadata for a specific snapshot."""
        target_dir = self.vault_dir / snapshot_id
        meta_file = target_dir / "snapshot.json"
        if not meta_file.exists():
            return None

        try:
            with open(meta_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return PublicSnapshotMetadata.from_dict(data)
        except Exception as e:
            logger.error(f"Failed to load snapshot metadata for {snapshot_id}: {e}")
            return None


# Global manager singleton
SNAPSHOT_MGR = SnapshotManager.get_instance()

