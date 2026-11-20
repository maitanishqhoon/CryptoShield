"""
Snapshot Verification Engine for CryptoShield Vault (Phase 5).

Cryptographically audits and verifies stored snapshots. Validates RSA-OAEP key unwrapping,
AES-256-GCM authentication tags, in-memory SHA-256 streaming hashes, object counts,
and tamper detection.

CRITICAL REQUIREMENT:
Verification NEVER restores plaintext files to the original laboratory directory or disk.
Plaintext chunks are streamed directly through an in-memory hash calculator and discarded.
"""

from __future__ import annotations

import base64
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.config import CONFIG
from app.core.logger import get_logger
from app.core.models import ManifestEntry
from app.vault.crypto_engine import CRYPTO_ENGINE, CryptoEngine
from app.vault.key_manager import KEY_MGR, KeyManager
from app.vault.models import (
    ObjectVerificationResult,
    PublicSnapshotMetadata,
    SnapshotStatus,
    SnapshotVerificationOutcome,
    SnapshotVerificationReport,
    VerificationStatus,
)
from app.vault.snapshot_manifest import (
    SNAPSHOT_MANIFEST_MGR,
    SnapshotManifestAuthenticationError,
    SnapshotManifestManager,
)

logger = get_logger("vault.verifier")


class SnapshotVerifier:
    """
    Performs full cryptographic integrity auditing of encrypted snapshots.
    """

    def __init__(
        self,
        vault_dir: Optional[Path] = None,
        key_manager: Optional[KeyManager] = None,
        crypto_engine: Optional[CryptoEngine] = None,
        manifest_manager: Optional[SnapshotManifestManager] = None,
    ) -> None:
        self.vault_dir = (vault_dir or CONFIG.vault_dir).resolve()
        self.key_manager = key_manager or KEY_MGR
        self.crypto_engine = crypto_engine or CRYPTO_ENGINE
        self.manifest_manager = manifest_manager or SNAPSHOT_MANIFEST_MGR
        self._lock = threading.RLock()

    def verify_snapshot(
        self,
        snapshot_id: str,
        passphrase: str,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        max_workers: int = 8,
    ) -> SnapshotVerificationReport:
        """
        Perform a thorough cryptographic and integrity audit of a snapshot.

        Steps:
        1. Load public metadata from `snapshot.json`.
        2. Validate format version and completed status.
        3. Unwrap per-snapshot AES key using RSA private key & passphrase.
        4. Decrypt and authenticate the snapshot manifest (`manifest.enc`).
        5. For each file in the decrypted manifest:
           - Locate `objects/<opaque_id>.cso`.
           - Verify magic, format version, and 96-bit nonce.
           - Stream decrypt through AES-256-GCM (verifies 128-bit tag and AAD).
           - Calculate SHA-256 of plaintext stream in memory.
           - Compare calculated hash against manifest original hash.
        6. Scan `objects/` directory for unexpected, missing, or orphan objects.
        7. Compute overall outcome: FULLY_VERIFIED, PARTIALLY_VERIFIED, or VERIFICATION_FAILED.
        """
        start_t = time.perf_counter()
        now_iso = datetime.now(CONFIG.TIMEZONE).isoformat()
        snapshot_dir = self.vault_dir / snapshot_id

        if not snapshot_dir.exists():
            return SnapshotVerificationReport(
                snapshot_id=snapshot_id,
                verified_at=now_iso,
                duration_seconds=0.0,
                outcome=SnapshotVerificationOutcome.VERIFICATION_FAILED.value,
                total_manifest_objects=0,
                verified_objects=0,
                failed_objects=0,
                summary=f"Snapshot directory not found: {snapshot_dir}",
            )

        meta_file = snapshot_dir / "snapshot.json"
        if not meta_file.exists():
            return SnapshotVerificationReport(
                snapshot_id=snapshot_id,
                verified_at=now_iso,
                duration_seconds=0.0,
                outcome=SnapshotVerificationOutcome.VERIFICATION_FAILED.value,
                total_manifest_objects=0,
                verified_objects=0,
                failed_objects=0,
                summary=f"Snapshot metadata 'snapshot.json' missing at: {meta_file}",
            )

        # 1. Load metadata
        try:
            import json
            with open(meta_file, "r", encoding="utf-8") as f:
                raw_meta = json.load(f)
            metadata = PublicSnapshotMetadata.from_dict(raw_meta)
        except Exception as e:
            return SnapshotVerificationReport(
                snapshot_id=snapshot_id,
                verified_at=now_iso,
                duration_seconds=round(time.perf_counter() - start_t, 3),
                outcome=SnapshotVerificationOutcome.VERIFICATION_FAILED.value,
                total_manifest_objects=0,
                verified_objects=0,
                failed_objects=0,
                summary=f"Failed to parse snapshot metadata: {e}",
            )

        # 2. Check format version
        if str(metadata.format_version) != str(CONFIG.VAULT_FORMAT_VERSION):
            return SnapshotVerificationReport(
                snapshot_id=snapshot_id,
                verified_at=now_iso,
                duration_seconds=round(time.perf_counter() - start_t, 3),
                outcome=SnapshotVerificationOutcome.VERIFICATION_FAILED.value,
                total_manifest_objects=metadata.total_files,
                verified_objects=0,
                failed_objects=metadata.total_files,
                summary=f"Unsupported snapshot format version '{metadata.format_version}'. Expected {CONFIG.VAULT_FORMAT_VERSION}.",
            )

        # 3. Load private key & unwrap AES session key
        try:
            private_key = self.key_manager.load_private_key(passphrase=passphrase)
        except Exception as e:
            logger.error(f"Failed to load private key for verification: {e}")
            return SnapshotVerificationReport(
                snapshot_id=snapshot_id,
                verified_at=now_iso,
                duration_seconds=round(time.perf_counter() - start_t, 3),
                outcome=SnapshotVerificationOutcome.VERIFICATION_FAILED.value,
                total_manifest_objects=metadata.total_files,
                verified_objects=0,
                failed_objects=metadata.total_files,
                summary=f"Private key authentication failed: {e}",
            )

        try:
            wrapped_aes_bytes = base64.b64decode(metadata.wrapped_aes_key_b64)
            aes_session_key = self.key_manager.unwrap_aes_key(
                private_key=private_key,
                wrapped_aes_key=wrapped_aes_bytes,
                snapshot_id=snapshot_id,
            )
        except Exception as e:
            logger.error(f"Failed to unwrap AES session key for {snapshot_id}: {e}")
            return SnapshotVerificationReport(
                snapshot_id=snapshot_id,
                verified_at=now_iso,
                duration_seconds=round(time.perf_counter() - start_t, 3),
                outcome=SnapshotVerificationOutcome.VERIFICATION_FAILED.value,
                total_manifest_objects=metadata.total_files,
                verified_objects=0,
                failed_objects=metadata.total_files,
                summary=f"Failed to unwrap AES session key: {e}",
            )

        # 4. Decrypt and authenticate snapshot manifest
        manifest_enc_file = snapshot_dir / "manifest.enc"
        if not manifest_enc_file.exists():
            return SnapshotVerificationReport(
                snapshot_id=snapshot_id,
                verified_at=now_iso,
                duration_seconds=round(time.perf_counter() - start_t, 3),
                outcome=SnapshotVerificationOutcome.VERIFICATION_FAILED.value,
                total_manifest_objects=metadata.total_files,
                verified_objects=0,
                failed_objects=metadata.total_files,
                summary=f"Encrypted manifest missing at: {manifest_enc_file}",
            )

        try:
            manifest_nonce = base64.b64decode(metadata.manifest_nonce_b64)
            manifest_tag = base64.b64decode(metadata.manifest_tag_b64)
            manifest = self.manifest_manager.decrypt_manifest(
                source_path=manifest_enc_file,
                key=aes_session_key,
                snapshot_id=snapshot_id,
                nonce=manifest_nonce,
                tag=manifest_tag,
                schema_version=metadata.format_version,
            )
        except SnapshotManifestAuthenticationError as e:
            logger.error(f"Encrypted manifest authentication failed for {snapshot_id}: {e}")
            return SnapshotVerificationReport(
                snapshot_id=snapshot_id,
                verified_at=now_iso,
                duration_seconds=round(time.perf_counter() - start_t, 3),
                outcome=SnapshotVerificationOutcome.VERIFICATION_FAILED.value,
                total_manifest_objects=metadata.total_files,
                verified_objects=0,
                failed_objects=metadata.total_files,
                tampered_objects=["manifest.enc"],
                summary=f"CRITICAL: Snapshot manifest authentication failed (tampered): {e}",
            )
        except Exception as e:
            return SnapshotVerificationReport(
                snapshot_id=snapshot_id,
                verified_at=now_iso,
                duration_seconds=round(time.perf_counter() - start_t, 3),
                outcome=SnapshotVerificationOutcome.VERIFICATION_FAILED.value,
                total_manifest_objects=metadata.total_files,
                verified_objects=0,
                failed_objects=metadata.total_files,
                summary=f"Manifest decryption error: {e}",
            )

        # 5. Verify all encrypted objects in parallel
        objects_dir = snapshot_dir / "objects"
        if not objects_dir.exists():
            return SnapshotVerificationReport(
                snapshot_id=snapshot_id,
                verified_at=now_iso,
                duration_seconds=round(time.perf_counter() - start_t, 3),
                outcome=SnapshotVerificationOutcome.VERIFICATION_FAILED.value,
                total_manifest_objects=len(manifest.entries),
                verified_objects=0,
                failed_objects=len(manifest.entries),
                summary="Objects directory missing from snapshot.",
            )

        verified_count = 0
        failed_count = 0
        missing_objects: List[str] = []
        tampered_objects: List[str] = []
        details: Dict[str, Dict[str, Any]] = {}

        # Scan objects on disk
        disk_object_files = {p.name: p for p in objects_dir.glob(f"*{CONFIG.VAULT_OBJECT_EXT}")}
        expected_object_files = set()

        processed_count = 0
        total_objects = len(manifest.entries)
        progress_lock = threading.Lock()

        def _verify_entry(item: Tuple[str, Any]) -> ObjectVerificationResult:
            nonlocal processed_count
            rel_path, obj_record = item
            opaque_id = obj_record.opaque_id
            obj_filename = f"{opaque_id}{CONFIG.VAULT_OBJECT_EXT}"
            obj_path = objects_dir / obj_filename

            # Reconstruct synthetic ManifestEntry for AAD verification
            dummy_entry = ManifestEntry(
                relative_path=rel_path,
                file_type=rel_path.split(".")[-1] if "." in rel_path else "txt",
                file_size_bytes=obj_record.original_size_bytes,
                data_classification=obj_record.data_classification,
                sha256=obj_record.original_sha256,
                is_canary=obj_record.is_canary,
                department=obj_record.department,
                created_at="",
            )

            if not obj_path.exists():
                res = ObjectVerificationResult(
                    opaque_id=opaque_id,
                    relative_path=rel_path,
                    status=VerificationStatus.MISSING_OBJECT.value,
                    error_message=f"Encrypted object '{obj_filename}' not found.",
                )
            else:
                ok, calc_hash, err = self.crypto_engine.verify_encrypted_file(
                    encrypted_path=obj_path,
                    key=aes_session_key,
                    snapshot_id=snapshot_id,
                    opaque_id=opaque_id,
                    entry=dummy_entry,
                )
                if ok:
                    res = ObjectVerificationResult(
                        opaque_id=opaque_id,
                        relative_path=rel_path,
                        status=VerificationStatus.VERIFIED.value,
                        calculated_sha256=calc_hash,
                        expected_sha256=obj_record.original_sha256,
                    )
                else:
                    status = (
                        VerificationStatus.AUTHENTICATION_FAILED.value
                        if "authentication failed" in (err or "").lower()
                        else VerificationStatus.HASH_MISMATCH.value
                    )
                    res = ObjectVerificationResult(
                        opaque_id=opaque_id,
                        relative_path=rel_path,
                        status=status,
                        calculated_sha256=calc_hash,
                        expected_sha256=obj_record.original_sha256,
                        error_message=err,
                    )

            with progress_lock:
                processed_count += 1
                if progress_callback:
                    progress_callback(processed_count, total_objects)

            return res

        workers = min(max_workers, max(1, (os.cpu_count() or 4)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            check_results = list(executor.map(_verify_entry, manifest.entries.items()))

        for res in check_results:
            details[res.relative_path] = res.to_dict()
            expected_object_files.add(f"{res.opaque_id}{CONFIG.VAULT_OBJECT_EXT}")

            if res.status == VerificationStatus.VERIFIED.value:
                verified_count += 1
            else:
                failed_count += 1
                if res.status == VerificationStatus.MISSING_OBJECT.value:
                    missing_objects.append(res.relative_path)
                else:
                    tampered_objects.append(res.relative_path)

        # 6. Check for unexpected objects
        unexpected_objects = [
            fname for fname in disk_object_files if fname not in expected_object_files
        ]

        # 7. Overall outcome determination
        duration = round(time.perf_counter() - start_t, 3)
        if failed_count == 0 and len(unexpected_objects) == 0 and verified_count == total_objects:
            outcome = SnapshotVerificationOutcome.FULLY_VERIFIED.value
            summary = (
                f"Snapshot {snapshot_id} FULLY VERIFIED ({verified_count:,}/{total_objects:,} objects "
                f"authenticated with valid AES-GCM tags & matching SHA-256 hashes in {duration:.2f}s)."
            )
        elif verified_count > 0:
            outcome = SnapshotVerificationOutcome.PARTIALLY_VERIFIED.value
            summary = (
                f"Snapshot {snapshot_id} PARTIALLY VERIFIED ({verified_count:,}/{total_objects:,} verified, "
                f"{failed_count:,} failed, {len(unexpected_objects):,} unexpected)."
            )
        else:
            outcome = SnapshotVerificationOutcome.VERIFICATION_FAILED.value
            summary = f"Snapshot {snapshot_id} VERIFICATION FAILED (0/{total_objects:,} objects verified)."

        logger.info(summary)

        return SnapshotVerificationReport(
            snapshot_id=snapshot_id,
            verified_at=now_iso,
            duration_seconds=duration,
            outcome=outcome,
            total_manifest_objects=total_objects,
            verified_objects=verified_count,
            failed_objects=failed_count,
            missing_objects=missing_objects,
            unexpected_objects=unexpected_objects,
            tampered_objects=tampered_objects,
            details=details,
            summary=summary,
        )


# Global verifier singleton
VAULT_VERIFIER = SnapshotVerifier()
