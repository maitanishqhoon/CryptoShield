"""
Encrypted Snapshot Manifest Manager for CryptoShield Vault (Phase 5).

Handles serialization, AES-256-GCM encryption, decryption, and integrity
verification of the confidential snapshot manifest.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.config import CONFIG
from app.core.logger import get_logger
from app.vault.crypto_engine import NonceTracker
from app.vault.models import SnapshotManifest

logger = get_logger("vault.snapshot_manifest")

MANIFEST_SCHEMA_VERSION = "1.0.0"


class SnapshotManifestError(RuntimeError):
    """Base exception for snapshot manifest failures."""
    pass


class SnapshotManifestAuthenticationError(SnapshotManifestError):
    """Raised when manifest ciphertext, tag, or AAD authentication fails."""
    pass


class SnapshotManifestManager:
    """
    Manages encrypted snapshot manifests.
    """

    def __init__(self, nonce_tracker: Optional[NonceTracker] = None) -> None:
        self.nonce_tracker = nonce_tracker or NonceTracker()

    @staticmethod
    def build_manifest_aad(snapshot_id: str, schema_version: str = MANIFEST_SCHEMA_VERSION) -> bytes:
        """Construct canonical AAD binding for manifest encryption."""
        aad_dict = {
            "schema_version": schema_version,
            "snapshot_id": snapshot_id,
        }
        canonical_str = json.dumps(aad_dict, sort_keys=True, separators=(",", ":"))
        return canonical_str.encode("utf-8")

    def encrypt_manifest(
        self,
        manifest: SnapshotManifest,
        dest_path: Path,
        key: bytes,
    ) -> Tuple[bytes, bytes, int]:
        """
        Encrypt SnapshotManifest with AES-256-GCM and save to dest_path (`manifest.enc`).

        Returns:
            Tuple of (nonce, tag, encrypted_bytes_length).
        """
        if len(key) != CONFIG.AES_KEY_SIZE_BYTES:
            raise ValueError(f"AES key must be exactly {CONFIG.AES_KEY_SIZE_BYTES} bytes.")

        nonce = self.nonce_tracker.generate_unique_nonce()
        aad = self.build_manifest_aad(manifest.snapshot_id, manifest.format_version)

        raw_json_bytes = json.dumps(manifest.to_dict(), indent=2).encode("utf-8")

        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(aad)

        ciphertext = encryptor.update(raw_json_bytes) + encryptor.finalize()
        tag = encryptor.tag

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(ciphertext)

        logger.info(
            f"Encrypted manifest written to '{dest_path.name}' "
            f"({len(ciphertext)} bytes, {manifest.total_files} files)."
        )
        return nonce, tag, len(ciphertext)

    def decrypt_manifest(
        self,
        source_path: Path,
        key: bytes,
        snapshot_id: str,
        nonce: bytes,
        tag: bytes,
        schema_version: str = MANIFEST_SCHEMA_VERSION,
    ) -> SnapshotManifest:
        """
        Decrypt and authenticate `manifest.enc` using AES-256-GCM.

        Raises:
            SnapshotManifestAuthenticationError: If tag, ciphertext, or AAD validation fails.
            SnapshotManifestError: If deserialization or schema validation fails.
        """
        if not source_path.exists():
            raise FileNotFoundError(f"Encrypted manifest not found at: {source_path}")

        if len(key) != CONFIG.AES_KEY_SIZE_BYTES:
            raise ValueError(f"AES key must be exactly {CONFIG.AES_KEY_SIZE_BYTES} bytes.")

        ciphertext = source_path.read_bytes()
        aad = self.build_manifest_aad(snapshot_id, schema_version)

        try:
            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(aad)
            plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag:
            raise SnapshotManifestAuthenticationError(
                "Failed to authenticate encrypted snapshot manifest. Ciphertext, tag, or AAD tampered."
            )
        except Exception as e:
            raise SnapshotManifestError(f"Error during manifest decryption: {e}")

        try:
            data = json.loads(plaintext_bytes.decode("utf-8"))
            manifest = SnapshotManifest.from_dict(data)
        except Exception as e:
            raise SnapshotManifestError(f"Failed to parse decrypted manifest JSON: {e}")

        if manifest.snapshot_id != snapshot_id:
            raise SnapshotManifestAuthenticationError(
                f"Manifest snapshot_id mismatch: Decrypted {manifest.snapshot_id} != expected {snapshot_id}."
            )

        return manifest


# Global manager instance
SNAPSHOT_MANIFEST_MGR = SnapshotManifestManager()

