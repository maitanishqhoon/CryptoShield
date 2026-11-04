"""
Cryptographic File Encryption Engine for CryptoShield Vault (Phase 5).

Implements streaming AES-256-GCM encryption and verification, chunked I/O,
unique 96-bit nonces, 128-bit authentication tags, and Additional Authenticated Data (AAD)
binding.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.config import CONFIG
from app.core.logger import get_logger
from app.core.models import ManifestEntry
from app.core.safety import SafetyViolationError, validate_lab_path
from app.vault.models import EncryptedObjectRecord

logger = get_logger("vault.crypto_engine")

HEADER_MAGIC = b"CSO1"
HEADER_VERSION = 1
HEADER_STRUCT_FMT = ">4sH12s16s"  # 4s magic, H version, 12s nonce, 16s tag = 34 bytes
HEADER_SIZE = struct.calcsize(HEADER_STRUCT_FMT)  # 34 bytes


class CryptoEngineError(RuntimeError):
    """Base exception for cryptographic engine failures."""
    pass


class AuthenticationFailedError(CryptoEngineError):
    """Raised when GCM authentication tag verification fails (ciphertext or AAD tampered)."""
    pass


class FileTamperedError(CryptoEngineError):
    """Raised when source file hash or metadata mismatch is detected during encryption."""
    pass


class NonceTracker:
    """Thread-safe tracker to enforce unique nonces under a given AES key."""

    def __init__(self) -> None:
        self._seen_nonces: Set[bytes] = set()
        self._lock = threading.Lock()

    def generate_unique_nonce(self) -> bytes:
        """Generate a cryptographically secure 12-byte nonce that hasn't been used yet."""
        with self._lock:
            while True:
                nonce = os.urandom(CONFIG.AES_GCM_NONCE_SIZE_BYTES)
                if nonce not in self._seen_nonces:
                    self._seen_nonces.add(nonce)
                    return nonce

    def clear(self) -> None:
        with self._lock:
            self._seen_nonces.clear()


class CryptoEngine:
    """
    AES-256-GCM streaming encryption and verification engine.
    """

    def __init__(self, chunk_size: int = CONFIG.STREAMING_CHUNK_SIZE_BYTES) -> None:
        self.chunk_size = chunk_size
        self.nonce_tracker = NonceTracker()

    @staticmethod
    def build_aad(
        snapshot_id: str,
        opaque_id: str,
        entry: ManifestEntry,
        format_version: str = "1.0.0",
    ) -> bytes:
        """
        Build canonically serialized Additional Authenticated Data (AAD) bytes.
        Binds cryptographic ciphertext directly to snapshot and file metadata.
        """
        aad_dict = {
            "canary": bool(entry.is_canary),
            "classification": entry.data_classification,
            "department": entry.department,
            "format_version": format_version,
            "opaque_id": opaque_id,
            "original_path": entry.relative_path,
            "original_sha256": entry.sha256.lower(),
            "original_size": entry.file_size_bytes,
            "snapshot_id": snapshot_id,
        }
        # Canonical JSON: sorted keys, no whitespace
        canonical_str = json.dumps(aad_dict, sort_keys=True, separators=(",", ":"))
        return canonical_str.encode("utf-8")

    @staticmethod
    def generate_opaque_id(snapshot_id: str, relative_path: str) -> str:
        """Generate a deterministic or opaque object ID for storage."""
        h = hashlib.sha256(f"{snapshot_id}:{relative_path}".encode("utf-8")).hexdigest()
        return f"OBJ-{h[:16].upper()}"

    def encrypt_file(
        self,
        source_path: Path,
        dest_path: Path,
        key: bytes,
        snapshot_id: str,
        opaque_id: str,
        entry: ManifestEntry,
        base_lab_dir: Optional[Path] = None,
    ) -> EncryptedObjectRecord:
        """
        Encrypt a registered source file using AES-256-GCM with streaming I/O.

        Validates:
        - Source path is safely inside the laboratory directory.
        - File is a regular file without symbolic link escapes.
        - Source file stats are unchanged across read.
        - Calculated original SHA-256 matches baseline manifest entry.
        """
        if len(key) != CONFIG.AES_KEY_SIZE_BYTES:
            raise ValueError(f"AES key must be exactly {CONFIG.AES_KEY_SIZE_BYTES} bytes.")

        lab_root = (base_lab_dir or CONFIG.LAB_DIR).resolve()
        validated_src = validate_lab_path(source_path, base_lab_dir=lab_root)

        if not validated_src.is_file():
            raise FileNotFoundError(f"Source path '{validated_src}' is not a regular file.")

        # Reject symlink escapes
        if validated_src.is_symlink():
            resolved = validated_src.resolve()
            try:
                resolved.relative_to(lab_root)
            except ValueError:
                raise SafetyViolationError(
                    f"Symlink '{validated_src}' points outside authorized lab: '{resolved}'."
                )

        # Pre-read metadata capture
        pre_stat = validated_src.stat()
        pre_size = pre_stat.st_size
        pre_mtime = pre_stat.st_mtime

        # Generate unique nonce
        nonce = self.nonce_tracker.generate_unique_nonce()
        aad = self.build_aad(
            snapshot_id=snapshot_id,
            opaque_id=opaque_id,
            entry=entry,
            format_version=str(CONFIG.VAULT_FORMAT_VERSION),
        )

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        temp_dest = dest_path.with_suffix(f"{CONFIG.VAULT_OBJECT_EXT}.tmp")

        hasher = hashlib.sha256()
        total_read = 0
        total_encrypted_body = 0

        try:
            encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
            encryptor.authenticate_additional_data(aad)

            with open(validated_src, "rb") as f_in, open(temp_dest, "wb") as f_out:
                # Write placeholder 34-byte header: Magic, Version, Nonce, blank 16-byte Tag
                dummy_tag = b"\x00" * CONFIG.AES_GCM_TAG_SIZE_BYTES
                header = struct.pack(
                    HEADER_STRUCT_FMT,
                    HEADER_MAGIC,
                    HEADER_VERSION,
                    nonce,
                    dummy_tag,
                )
                f_out.write(header)

                # Stream file contents
                while chunk := f_in.read(self.chunk_size):
                    total_read += len(chunk)
                    hasher.update(chunk)
                    ciphertext_chunk = encryptor.update(chunk)
                    if ciphertext_chunk:
                        f_out.write(ciphertext_chunk)
                        total_encrypted_body += len(ciphertext_chunk)

                # Finalize encryption
                final_chunk = encryptor.finalize()
                if final_chunk:
                    f_out.write(final_chunk)
                    total_encrypted_body += len(final_chunk)

                tag = encryptor.tag

                # Seek back and write real GCM authentication tag
                f_out.seek(0)
                final_header = struct.pack(
                    HEADER_STRUCT_FMT,
                    HEADER_MAGIC,
                    HEADER_VERSION,
                    nonce,
                    tag,
                )
                f_out.write(final_header)

            # Post-read verification: Concurrent modification detection
            post_stat = validated_src.stat()
            if post_stat.st_mtime != pre_mtime or post_stat.st_size != pre_size:
                raise FileTamperedError(
                    f"File '{validated_src}' was concurrently modified during snapshot creation."
                )

            # Verify computed SHA-256 against baseline manifest
            calc_hash = hasher.hexdigest().lower()
            if calc_hash != entry.sha256.lower():
                raise FileTamperedError(
                    f"Hash mismatch for '{entry.relative_path}': calculated {calc_hash} != manifest {entry.sha256}."
                )

            # Atomically replace destination
            if dest_path.exists():
                dest_path.unlink()
            temp_dest.replace(dest_path)

            total_encrypted_size = HEADER_SIZE + total_encrypted_body

            return EncryptedObjectRecord(
                opaque_id=opaque_id,
                relative_path=entry.relative_path,
                original_size_bytes=total_read,
                original_sha256=calc_hash,
                department=entry.department,
                data_classification=entry.data_classification,
                is_canary=entry.is_canary,
                encrypted_size_bytes=total_encrypted_size,
                nonce_hex=nonce.hex(),
                tag_hex=tag.hex(),
            )

        except Exception as e:
            if temp_dest.exists():
                try:
                    temp_dest.unlink()
                except OSError:
                    pass
            logger.error(f"Failed to encrypt '{entry.relative_path}': {e}")
            raise

    def verify_encrypted_file(
        self,
        encrypted_path: Path,
        key: bytes,
        snapshot_id: str,
        opaque_id: str,
        entry: ManifestEntry,
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Cryptographically verify an encrypted `.cso` object using streaming decryption.

        CRITICAL SECURITY REQUIREMENT:
        Plaintext chunks are NEVER written to disk. They are fed into an in-memory
        SHA-256 hasher and immediately discarded.

        Returns:
            Tuple of (is_valid, calculated_sha256, error_message).
        """
        if not encrypted_path.exists():
            return False, "", f"Encrypted object '{encrypted_path.name}' not found."

        aad = self.build_aad(
            snapshot_id=snapshot_id,
            opaque_id=opaque_id,
            entry=entry,
            format_version=str(CONFIG.VAULT_FORMAT_VERSION),
        )

        try:
            with open(encrypted_path, "rb") as f_in:
                header_bytes = f_in.read(HEADER_SIZE)
                if len(header_bytes) != HEADER_SIZE:
                    return False, "", "Invalid encrypted object: header truncated."

                magic, version, nonce, tag = struct.unpack(HEADER_STRUCT_FMT, header_bytes)

                if magic != HEADER_MAGIC:
                    return False, "", f"Invalid magic header: expected {HEADER_MAGIC!r}, got {magic!r}."

                if version != HEADER_VERSION:
                    return False, "", f"Unsupported format version: {version}."

                # Create GCM decryptor with tag
                decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
                decryptor.authenticate_additional_data(aad)

                hasher = hashlib.sha256()
                total_plaintext_bytes = 0

                # Stream ciphertext through decryptor into in-memory hasher
                while chunk := f_in.read(self.chunk_size):
                    plaintext_chunk = decryptor.update(chunk)
                    if plaintext_chunk:
                        hasher.update(plaintext_chunk)
                        total_plaintext_bytes += len(plaintext_chunk)

                # Finalize verifies GCM authentication tag
                try:
                    final_plaintext = decryptor.finalize()
                    if final_plaintext:
                        hasher.update(final_plaintext)
                        total_plaintext_bytes += len(final_plaintext)
                except InvalidTag:
                    return False, "", "AES-GCM authentication failed: Ciphertext, tag, or AAD has been tampered with."

                # Verify calculated hash against expected baseline hash
                calc_sha256 = hasher.hexdigest().lower()
                if calc_sha256 != entry.sha256.lower():
                    return False, calc_sha256, (
                        f"SHA-256 hash mismatch: Decrypted {calc_sha256} != expected {entry.sha256}."
                    )

                # Verify plaintext size
                if total_plaintext_bytes != entry.file_size_bytes:
                    return False, calc_sha256, (
                        f"Plaintext size mismatch: Decrypted {total_plaintext_bytes} != expected {entry.file_size_bytes}."
                    )

                return True, calc_sha256, None

        except Exception as e:
            return False, "", f"Decryption failure: {e}"


# Global CryptoEngine singleton
CRYPTO_ENGINE = CryptoEngine()
