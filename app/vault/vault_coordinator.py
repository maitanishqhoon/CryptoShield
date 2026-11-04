"""
Vault Coordinator for CryptoShield (Phase 5).

Provides a unified facade integrating the KeyManager, CryptoEngine,
SnapshotManager, and VaultVerifier for CLI and programmatic callers.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from app.config import CONFIG
from app.core.logger import get_logger
from app.vault.crypto_engine import CRYPTO_ENGINE, CryptoEngine
from app.vault.key_manager import KEY_MGR, KeyManager
from app.vault.models import (
    PublicSnapshotMetadata,
    SnapshotVerificationOutcome,
    SnapshotVerificationReport,
)
from app.vault.snapshot_manager import SNAPSHOT_MGR, SnapshotManager
from app.vault.vault_verifier import VAULT_VERIFIER, SnapshotVerifier

logger = get_logger("vault.coordinator")


class VaultCoordinator:
    """
    Central orchestration facade for all cryptographic vault operations.
    """

    _instance_lock = threading.Lock()
    _instance: Optional[VaultCoordinator] = None

    def __init__(
        self,
        vault_dir: Optional[Path] = None,
        key_manager: Optional[KeyManager] = None,
        snapshot_manager: Optional[SnapshotManager] = None,
        verifier: Optional[SnapshotVerifier] = None,
        crypto_engine: Optional[CryptoEngine] = None,
    ) -> None:
        self.vault_dir = (vault_dir or CONFIG.vault_dir).resolve()
        self.key_manager = key_manager or KEY_MGR
        self.snapshot_manager = snapshot_manager or SNAPSHOT_MGR
        self.verifier = verifier or VAULT_VERIFIER
        self.crypto_engine = crypto_engine or CRYPTO_ENGINE
        self._lock = threading.RLock()

    @classmethod
    def get_instance(cls) -> VaultCoordinator:
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = VaultCoordinator()
            return cls._instance

    def initialize_vault(
        self,
        passphrase: str,
        key_size: int = CONFIG.RSA_KEY_SIZE_BITS,
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        Initialize the cryptographic vault, provisioning a new RSA key pair encrypted with passphrase.
        """
        with self._lock:
            self.snapshot_manager.initialize_vault_directory()
            priv_path, pub_path, key_id = self.key_manager.generate_key_pair(
                passphrase=passphrase,
                key_size=key_size,
                force=force,
            )
            meta = self.key_manager.get_key_metadata()
            return {
                "status": "INITIALIZED",
                "key_id": key_id,
                "algorithm": meta.get("algorithm", "RSA-OAEP-SHA256"),
                "key_size_bits": meta.get("key_size_bits", key_size),
                "private_key_path": str(priv_path),
                "public_key_path": str(pub_path),
                "created_at": meta.get("created_at"),
            }

    def create_snapshot(
        self,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        max_workers: int = 8,
    ) -> PublicSnapshotMetadata:
        """
        Create a clean, cryptographically authenticated snapshot of the laboratory.
        """
        with self._lock:
            return self.snapshot_manager.create_snapshot(
                progress_callback=progress_callback,
                max_workers=max_workers,
            )

    def list_snapshots(self) -> List[PublicSnapshotMetadata]:
        """List all valid snapshots in descending order of creation time."""
        with self._lock:
            return self.snapshot_manager.list_snapshots()

    def inspect_snapshot(
        self,
        snapshot_id: str,
        passphrase: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve snapshot details. If passphrase is provided, decrypts and includes
        departmental summary and canary counts from the confidential manifest.
        """
        with self._lock:
            metadata = self.snapshot_manager.get_snapshot_metadata(snapshot_id)
            if not metadata:
                raise FileNotFoundError(f"Snapshot '{snapshot_id}' not found in vault.")

            res: Dict[str, Any] = {
                "snapshot_id": metadata.snapshot_id,
                "format_version": metadata.format_version,
                "created_at": metadata.created_at,
                "status": metadata.completed_status,
                "total_files": metadata.total_files,
                "total_original_bytes": metadata.total_original_bytes,
                "total_original_mb": round(metadata.total_original_bytes / (1024 * 1024), 2),
                "total_encrypted_bytes": metadata.total_encrypted_bytes,
                "total_encrypted_mb": round(metadata.total_encrypted_bytes / (1024 * 1024), 2),
                "key_id": metadata.key_id,
                "source_lab_id": metadata.source_lab_id,
                "metadata": metadata.metadata,
            }

            if passphrase:
                try:
                    import base64
                    private_key = self.key_manager.load_private_key(passphrase=passphrase)
                    wrapped_aes = base64.b64decode(metadata.wrapped_aes_key_b64)
                    aes_key = self.key_manager.unwrap_aes_key(
                        private_key=private_key,
                        wrapped_aes_key=wrapped_aes,
                        snapshot_id=snapshot_id,
                    )
                    manifest_enc_file = self.vault_dir / snapshot_id / "manifest.enc"
                    manifest_nonce = base64.b64decode(metadata.manifest_nonce_b64)
                    manifest_tag = base64.b64decode(metadata.manifest_tag_b64)
                    manifest = self.snapshot_manager.manifest_manager.decrypt_manifest(
                        source_path=manifest_enc_file,
                        key=aes_key,
                        snapshot_id=snapshot_id,
                        nonce=manifest_nonce,
                        tag=manifest_tag,
                    )
                    res["confidential_manifest"] = {
                        "canary_count": manifest.canary_count,
                        "department_counts": manifest.department_counts,
                        "classification_counts": manifest.classification_counts,
                    }
                except Exception as e:
                    res["confidential_manifest_error"] = str(e)

            return res

    def verify_snapshot(
        self,
        snapshot_id: str,
        passphrase: str,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        max_workers: int = 8,
    ) -> SnapshotVerificationReport:
        """
        Verify the cryptographic validity and integrity of a stored snapshot.
        """
        with self._lock:
            return self.verifier.verify_snapshot(
                snapshot_id=snapshot_id,
                passphrase=passphrase,
                progress_callback=progress_callback,
                max_workers=max_workers,
            )

    def get_vault_status(self) -> Dict[str, Any]:
        """
        Query general vault health, key status, and storage metrics.
        """
        with self._lock:
            has_keys = self.key_manager.has_keys()
            key_id = None
            key_algo = None
            if has_keys:
                try:
                    meta = self.key_manager.get_key_metadata()
                    key_id = meta.get("key_id")
                    key_algo = meta.get("algorithm")
                except Exception:
                    pass

            snapshots = self.list_snapshots()
            total_encrypted_bytes = sum(s.total_encrypted_bytes for s in snapshots)

            return {
                "vault_dir": str(self.vault_dir),
                "keys_dir": str(self.key_manager.keys_dir),
                "has_keys": has_keys,
                "key_id": key_id,
                "key_algorithm": key_algo,
                "total_snapshots": len(snapshots),
                "total_encrypted_bytes": total_encrypted_bytes,
                "total_encrypted_mb": round(total_encrypted_bytes / (1024 * 1024), 2),
                "snapshots": [
                    {
                        "snapshot_id": s.snapshot_id,
                        "created_at": s.created_at,
                        "total_files": s.total_files,
                        "total_encrypted_mb": round(s.total_encrypted_bytes / (1024 * 1024), 2),
                        "status": s.completed_status,
                    }
                    for s in snapshots
                ],
            }


# Global coordinator singleton
VAULT_COORDINATOR = VaultCoordinator.get_instance()

