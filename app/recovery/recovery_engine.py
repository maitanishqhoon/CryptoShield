"""
Cryptographic Recovery Engine for CryptoShield (Phase 6).

Performs authenticated snapshot key unwrapping, manifest decryption, and streaming
Two-Gate AES-256-GCM object decryption into restricted staging with guaranteed
cleanup on verification failure.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import struct
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.config import CONFIG
from app.core.logger import get_logger
from app.recovery.models import (
    RecoveryAuthenticationError,
    RecoveryError,
    RecoveryIntegrityError,
    StagedObjectResult,
)
from app.vault.crypto_engine import (
    HEADER_MAGIC,
    HEADER_SIZE,
    HEADER_STRUCT_FMT,
    HEADER_VERSION,
)
from app.vault.key_manager import (
    KEY_MGR,
    EnvelopeTamperedError,
    InvalidPassphraseError,
    KeyManager,
    KeyManagerError,
    KeyNotFoundError,
)
from app.vault.models import EncryptedObjectRecord, SnapshotManifest
from app.vault.snapshot_manifest import (
    SNAPSHOT_MANIFEST_MGR,
    SnapshotManifestAuthenticationError,
    SnapshotManifestError,
    SnapshotManifestManager,
)

logger = get_logger("recovery.engine")


class RecoveryEngine:
    """
    Authenticated cryptographic decryption engine for CryptoShield recovery.
    Enforces strict Two-Gate verification and zero plaintext leakage on disk.
    """

    def __init__(
        self,
        vault_dir: Optional[Path] = None,
        staging_dir: Optional[Path] = None,
        key_manager: Optional[KeyManager] = None,
        manifest_manager: Optional[SnapshotManifestManager] = None,
        chunk_size: int = CONFIG.STREAMING_CHUNK_SIZE_BYTES,
    ) -> None:
        self.vault_dir = (vault_dir or CONFIG.VAULT_DIR).resolve()
        self.staging_dir = (staging_dir or CONFIG.RECOVERY_STAGING_DIR).resolve()
        self.key_manager = key_manager or KEY_MGR
        self.manifest_manager = manifest_manager or SNAPSHOT_MANIFEST_MGR
        self.chunk_size = chunk_size

        # Ensure staging root exists
        self.staging_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def build_record_aad(
        snapshot_id: str,
        record: EncryptedObjectRecord,
        format_version: str = "1.0.0",
    ) -> bytes:
        """
        Build byte-for-byte canonical AAD JSON string binding ciphertext to file metadata.
        Matches exactly the structure constructed during Phase 5 encryption.
        """
        aad_dict = {
            "canary": bool(record.is_canary),
            "classification": str(record.data_classification),
            "department": str(record.department),
            "format_version": str(format_version),
            "opaque_id": str(record.opaque_id),
            "original_path": str(record.relative_path),
            "original_sha256": str(record.original_sha256).lower(),
            "original_size": int(record.original_size_bytes),
            "snapshot_id": str(snapshot_id),
        }
        canonical_str = json.dumps(aad_dict, sort_keys=True, separators=(",", ":"))
        return canonical_str.encode("utf-8")

    def unlock_snapshot(
        self,
        snapshot_id: str,
        passphrase: str,
        private_key_path: Optional[Path] = None,
    ) -> Tuple[bytes, SnapshotManifest, Dict[str, Any]]:
        """
        Authenticate and unlock a cryptographic snapshot from the vault.

        Args:
            snapshot_id: Unique snapshot identifier.
            passphrase: Password protecting the RSA private key envelope.
            private_key_path: Optional explicit path to the private key file.

        Returns:
            Tuple of (unwrapped_32_byte_aes_key, decrypted_SnapshotManifest, metadata_dict).

        Raises:
            RecoveryAuthenticationError: On wrong passphrase, envelope tampering,
                                         unwrapping failure, or manifest GCM tag failure.
            RecoveryError: On missing files or path safety errors.
        """
        # Step 1: Validate snapshot ID and locate directory
        if not snapshot_id or not isinstance(snapshot_id, str):
            raise RecoveryError("A valid snapshot_id string is required.")
        if ".." in snapshot_id or "/" in snapshot_id or "\\" in snapshot_id:
            raise RecoveryError(f"Path traversal detected in snapshot_id: '{snapshot_id}'")

        snapshot_dir = (self.vault_dir / snapshot_id).resolve()
        try:
            snapshot_dir.relative_to(self.vault_dir)
        except ValueError:
            raise RecoveryError(f"Snapshot directory '{snapshot_dir}' is outside vault.")

        if not snapshot_dir.exists() or not snapshot_dir.is_dir():
            raise RecoveryError(f"Snapshot directory not found: '{snapshot_dir}'")

        # Locate metadata file (supports snapshot.json or snapshot_metadata.json)
        meta_path = snapshot_dir / "snapshot.json"
        if not meta_path.exists():
            meta_path = snapshot_dir / "snapshot_metadata.json"
        if not meta_path.exists():
            raise RecoveryError(f"Snapshot metadata file not found at: '{snapshot_dir}'")

        manifest_enc_path = snapshot_dir / "manifest.enc"
        if not manifest_enc_path.exists():
            raise RecoveryError(f"Encrypted manifest not found at: '{manifest_enc_path}'")

        # Step 2: Load and verify metadata
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                metadata_dict = json.load(f)
        except Exception as e:
            raise RecoveryError(f"Failed to read snapshot metadata: {e}")

        status = metadata_dict.get("completed_status") or metadata_dict.get("status")
        if status != "COMPLETED":
            raise RecoveryError(
                f"Snapshot '{snapshot_id}' status is not COMPLETED (found: '{status}')"
            )

        if metadata_dict.get("snapshot_id") != snapshot_id:
            raise RecoveryError(
                f"Snapshot metadata ID mismatch: '{metadata_dict.get('snapshot_id')}' != '{snapshot_id}'"
            )

        format_version = metadata_dict.get("format_version", "1.0.0")

        # Step 3: Load RSA private key
        try:
            private_key = self.key_manager.load_private_key(
                passphrase=passphrase,
                key_path=private_key_path,
            )
        except (InvalidPassphraseError, EnvelopeTamperedError, KeyNotFoundError, KeyManagerError) as exc:
            raise RecoveryAuthenticationError(
                f"Private key authentication failed for snapshot '{snapshot_id}'"
            ) from exc
        except Exception as exc:
            raise RecoveryAuthenticationError(
                f"Failed to load private key for snapshot '{snapshot_id}': {exc}"
            ) from exc

        # Step 4: Unwrap AES session key
        try:
            wrapped_aes_key = base64.b64decode(metadata_dict["wrapped_aes_key_b64"])
            aes_key = self.key_manager.unwrap_aes_key(
                private_key=private_key,
                wrapped_aes_key=wrapped_aes_key,
                snapshot_id=snapshot_id,
            )
        except (KeyManagerError, ValueError, KeyError) as exc:
            raise RecoveryAuthenticationError(
                f"AES key unwrapping failed for snapshot '{snapshot_id}'"
            ) from exc

        # Step 5: Decrypt and authenticate manifest.enc
        try:
            manifest_nonce = base64.b64decode(metadata_dict["manifest_nonce_b64"])
            manifest_tag = base64.b64decode(metadata_dict["manifest_tag_b64"])

            snapshot_manifest = self.manifest_manager.decrypt_manifest(
                source_path=manifest_enc_path,
                key=aes_key,
                snapshot_id=snapshot_id,
                nonce=manifest_nonce,
                tag=manifest_tag,
                schema_version=format_version,
            )
        except (SnapshotManifestAuthenticationError, SnapshotManifestError) as exc:
            raise RecoveryAuthenticationError(
                f"Manifest decryption or authentication failed for snapshot '{snapshot_id}'"
            ) from exc
        except Exception as exc:
            raise RecoveryAuthenticationError(
                f"Error decrypting manifest for snapshot '{snapshot_id}': {exc}"
            ) from exc

        logger.info(
            f"Successfully authenticated and unlocked snapshot '{snapshot_id}' "
            f"({snapshot_manifest.total_files} files)."
        )

        return aes_key, snapshot_manifest, metadata_dict

    def create_staging_session(self, session_id: Optional[str] = None) -> Path:
        """
        Create an isolated staging session directory for unverified file decryption.

        Returns:
            Resolved Path to the new session staging directory.
        """
        sid = session_id or uuid.uuid4().hex[:8].upper()
        if ".." in sid or "/" in sid or "\\" in sid:
            raise RecoveryError(f"Invalid staging session ID: {sid}")

        session_dir = (self.staging_dir / f".stage_{sid}").resolve()
        session_dir.mkdir(parents=True, exist_ok=True)
        return session_dir

    def cleanup_staging_session(self, session_staging_dir: Path) -> None:
        """Safely remove a staging session directory."""
        target = session_staging_dir.resolve()
        try:
            target.relative_to(self.staging_dir)
        except ValueError:
            raise RecoveryError(f"Target '{target}' is outside staging root '{self.staging_dir}'")

        if target == self.staging_dir:
            raise RecoveryError("Cannot delete root staging directory.")

        shutil.rmtree(target, ignore_errors=True)

    def stage_decrypted_object(
        self,
        snapshot_id: str,
        aes_key: bytes,
        record: EncryptedObjectRecord,
        session_staging_dir: Path,
        format_version: str = "1.0.0",
    ) -> StagedObjectResult:
        """
        Stream decrypt a .cso vault object into a restricted staging .part file.
        Enforces Two-Gate Verification:
          Gate 1: AES-256-GCM authentication tag finalization.
          Gate 2: SHA-256 digest & byte size verification against manifest.

        Guarantees that on ANY failure, the staging .part file is immediately unlinked.

        Returns:
            StagedObjectResult with verification flags and staged file path.

        Raises:
            RecoveryAuthenticationError: On GCM authentication failure or header tampering.
            RecoveryIntegrityError: On SHA-256 hash or size mismatch.
            RecoveryError: On general I/O or boundary failures.
        """
        # Step 1: Validate staging boundary and object existence
        resolved_staging = session_staging_dir.resolve()
        try:
            resolved_staging.relative_to(self.staging_dir)
        except ValueError:
            raise RecoveryError(
                f"Staging directory '{resolved_staging}' is outside staging root '{self.staging_dir}'"
            )

        cso_path = (self.vault_dir / snapshot_id / "objects" / f"{record.opaque_id}.cso").resolve()
        if not cso_path.is_file():
            raise RecoveryAuthenticationError(
                f"Missing encrypted object {record.opaque_id} ({record.relative_path}) at '{cso_path}'"
            )

        # Step 2: Parse and validate 34-byte .cso header
        try:
            with open(cso_path, "rb") as in_f:
                header_bytes = in_f.read(HEADER_SIZE)
        except Exception as e:
            raise RecoveryError(f"Failed to read .cso header for {record.opaque_id}: {e}")

        if len(header_bytes) < HEADER_SIZE:
            raise RecoveryAuthenticationError(f"Truncated .cso header for {record.opaque_id}")

        magic, version, header_nonce, header_tag = struct.unpack(HEADER_STRUCT_FMT, header_bytes)

        if magic != HEADER_MAGIC or version != HEADER_VERSION:
            raise RecoveryAuthenticationError(
                f"Invalid .cso header magic or version for {record.opaque_id}: magic={magic!r}, version={version}"
            )

        expected_nonce = bytes.fromhex(record.nonce_hex)
        expected_tag = bytes.fromhex(record.tag_hex)

        if header_nonce != expected_nonce or header_tag != expected_tag:
            raise RecoveryAuthenticationError(
                f"Header nonce/tag mismatch against authenticated manifest for {record.opaque_id}"
            )

        # Step 3: Build Canonical AAD & Initialize AES-256-GCM Decryptor
        aad = self.build_record_aad(
            snapshot_id=snapshot_id,
            record=record,
            format_version=format_version,
        )

        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(header_nonce, header_tag),
            backend=default_backend(),
        ).decryptor()
        decryptor.authenticate_additional_data(aad)

        # Step 4: Stream Decrypt to Restricted .part File & Hash Simultaneously
        staged_file_path = (resolved_staging / f"{record.opaque_id}.part").resolve()
        hasher = hashlib.sha256()
        bytes_written = 0

        try:
            with open(cso_path, "rb") as in_f:
                in_f.seek(HEADER_SIZE)
                with open(staged_file_path, "wb") as out_f:
                    while chunk := in_f.read(self.chunk_size):
                        plaintext_chunk = decryptor.update(chunk)
                        if plaintext_chunk:
                            out_f.write(plaintext_chunk)
                            hasher.update(plaintext_chunk)
                            bytes_written += len(plaintext_chunk)

                    # GATE 1: GCM Tag Finalization
                    final_plaintext = decryptor.finalize()
                    if final_plaintext:
                        out_f.write(final_plaintext)
                        hasher.update(final_plaintext)
                        bytes_written += len(final_plaintext)

                    out_f.flush()

            # GATE 2: SHA-256 and size verification
            computed_sha256 = hasher.hexdigest().lower()
            expected_sha256 = record.original_sha256.lower()

            if computed_sha256 != expected_sha256 or bytes_written != record.original_size_bytes:
                staged_file_path.unlink(missing_ok=True)
                raise RecoveryIntegrityError(
                    f"SHA-256 or size mismatch for {record.relative_path}: "
                    f"computed {computed_sha256} ({bytes_written}B) != expected {expected_sha256} ({record.original_size_bytes}B)"
                )

        except InvalidTag as exc:
            staged_file_path.unlink(missing_ok=True)
            raise RecoveryAuthenticationError(
                f"GCM authentication failed for {record.opaque_id} ({record.relative_path})"
            ) from exc
        except RecoveryIntegrityError:
            staged_file_path.unlink(missing_ok=True)
            raise
        except RecoveryAuthenticationError:
            staged_file_path.unlink(missing_ok=True)
            raise
        except Exception as exc:
            staged_file_path.unlink(missing_ok=True)
            raise RecoveryError(f"Staging decryption failed for {record.opaque_id}: {exc}") from exc

        # Step 5: Return Verified Staged Result
        return StagedObjectResult(
            relative_path=record.relative_path,
            opaque_id=record.opaque_id,
            staged_path=staged_file_path,
            gcm_authenticated=True,
            sha256_verified=True,
            computed_sha256=computed_sha256,
            expected_sha256=expected_sha256,
            decrypted_size_bytes=bytes_written,
            is_canary=record.is_canary,
        )
