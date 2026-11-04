"""
Cryptographic Key Manager for CryptoShield Vault (Phase 5).

Manages RSA-3072 key-pair generation, encrypted PEM serialization,
secure passphrase handling, public-key fingerprinting, 256-bit AES session-key
generation, and RSA-OAEP key wrapping/unwrapping.

SECURITY NOTICE:
In this academic prototype, the private key is stored locally in `runtime/keys/`
encrypted with a user-provided passphrase. While this protects against offline
plaintext extraction, storing the private key on the same host machine does NOT
provide production-grade hardware isolation (such as an HSM or KMS) against an
adversary with full host-level administrative compromise.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from app.config import CONFIG
from app.core.logger import get_logger

logger = get_logger("vault.key_manager")


class KeyManagerError(RuntimeError):
    """Base exception for KeyManager failures."""
    pass


class InvalidPassphraseError(KeyManagerError):
    """Raised when an incorrect passphrase is supplied for private-key decryption."""
    pass


class KeyNotFoundError(KeyManagerError):
    """Raised when an expected cryptographic key file is missing."""
    pass


class EnvelopeTamperedError(KeyManagerError):
    """Raised when the private-key protection envelope exhibits tampering, corruption, or authentication tag mismatch."""
    pass


class KeyManager:
    """
    Manages RSA key pairs and AES session keys for the CryptoShield Vault.
    """

    _instance_lock = threading.Lock()
    _instance: Optional[KeyManager] = None

    def __init__(self, keys_dir: Optional[Path] = None) -> None:
        self.keys_dir = (keys_dir or CONFIG.keys_dir).resolve()
        self.private_key_path = self.keys_dir / CONFIG.PRIVATE_KEY_FILENAME
        self.public_key_path = self.keys_dir / CONFIG.PUBLIC_KEY_FILENAME
        self.key_metadata_path = self.keys_dir / CONFIG.KEY_METADATA_FILENAME
        self._lock = threading.RLock()

    @classmethod
    def get_instance(cls) -> KeyManager:
        """Singleton accessor."""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = KeyManager()
            return cls._instance

    def initialize_keys_directory(self) -> None:
        """Ensure keys directory exists and has a .gitkeep if empty."""
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        gitkeep = self.keys_dir / ".gitkeep"
        if not gitkeep.exists() and not any(self.keys_dir.iterdir()):
            gitkeep.touch()

    @staticmethod
    def _compute_v2_envelope_aad(
        envelope_version: int,
        key_id: str,
        kdf_params: Dict[str, Any],
        verifier_tag_b64: str,
        cipher: str,
    ) -> bytes:
        """
        Build deterministic canonical JSON bytes representing the Additional Authenticated Data (AAD)
        for AES-256-GCM private-key envelope encryption.
        """
        canonical = {
            "cipher": cipher,
            "envelope_version": envelope_version,
            "format": "CryptoShield-Hardened-PrivateKey",
            "kdf": {
                "algorithm": kdf_params["algorithm"],
                "iterations": kdf_params["iterations"],
                "lanes": kdf_params["lanes"],
                "memory_cost_kib": kdf_params["memory_cost_kib"],
                "salt_b64": kdf_params["salt_b64"],
            },
            "key_id": key_id,
            "verifier_tag_b64": verifier_tag_b64,
        }
        return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _build_v2_envelope(
        self,
        private_key: rsa.RSAPrivateKey,
        passphrase: str,
        key_id: str,
        iterations: int = CONFIG.ARGON2_ITERATIONS,
        memory_cost_kib: int = CONFIG.ARGON2_MEMORY_COST_KIB,
        lanes: int = CONFIG.ARGON2_LANES,
        salt_bytes_len: int = CONFIG.ARGON2_SALT_BYTES,
    ) -> Dict[str, Any]:
        """
        Build a versioned Argon2id + AES-256-GCM protection envelope for an RSA private key.
        Derives 64 bytes via Argon2id (32B AES key + 32B HMAC verifier key).
        """
        salt = os.urandom(salt_bytes_len)
        salt_b64 = base64.b64encode(salt).decode("ascii")

        kdf = Argon2id(
            salt=salt,
            length=CONFIG.ARGON2_KEY_LENGTH_BYTES,
            iterations=iterations,
            lanes=lanes,
            memory_cost=memory_cost_kib,
        )
        derived = kdf.derive(passphrase.encode("utf-8"))
        aes_key = derived[:CONFIG.AES_KEY_SIZE_BYTES]
        verifier_key = derived[CONFIG.AES_KEY_SIZE_BYTES:]

        verifier_tag = hmac.new(
            verifier_key,
            f"CryptoShield-Passphrase-Check:{key_id}".encode("utf-8"),
            hashlib.sha256,
        ).digest()
        verifier_tag_b64 = base64.b64encode(verifier_tag).decode("ascii")

        kdf_params = {
            "algorithm": "Argon2id",
            "salt_b64": salt_b64,
            "iterations": iterations,
            "memory_cost_kib": memory_cost_kib,
            "lanes": lanes,
            "key_length_bytes": CONFIG.ARGON2_KEY_LENGTH_BYTES,
        }

        aad = self._compute_v2_envelope_aad(
            envelope_version=CONFIG.KEY_ENVELOPE_VERSION,
            key_id=key_id,
            kdf_params=kdf_params,
            verifier_tag_b64=verifier_tag_b64,
            cipher=CONFIG.ARGON2_CIPHER,
        )

        nonce = secrets.token_bytes(CONFIG.AES_GCM_NONCE_SIZE_BYTES)
        der_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        aesgcm = AESGCM(aes_key)
        encrypted_blob = aesgcm.encrypt(nonce, der_bytes, aad)
        tag_len = CONFIG.AES_GCM_TAG_SIZE_BYTES
        ciphertext = encrypted_blob[:-tag_len]
        tag = encrypted_blob[-tag_len:]

        return {
            "format": "CryptoShield-Hardened-PrivateKey",
            "envelope_version": CONFIG.KEY_ENVELOPE_VERSION,
            "key_id": key_id,
            "algorithm": "RSA-OAEP-SHA256",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "kdf": kdf_params,
            "passphrase_verifier": {
                "algorithm": "HMAC-SHA256",
                "verifier_tag_b64": verifier_tag_b64,
            },
            "encryption": {
                "cipher": CONFIG.ARGON2_CIPHER,
                "nonce_b64": base64.b64encode(nonce).decode("ascii"),
                "tag_b64": base64.b64encode(tag).decode("ascii"),
                "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            },
        }

    def generate_key_pair(
        self,
        passphrase: str,
        key_size: int = CONFIG.RSA_KEY_SIZE_BITS,
        force: bool = False,
        envelope_version: int = CONFIG.KEY_ENVELOPE_VERSION,
    ) -> Tuple[Path, Path, str]:
        """
        Generate a new RSA key pair, serializing the private key encrypted with passphrase.

        Args:
            passphrase: User-provided passphrase to encrypt private key.
            key_size: Bit length of RSA modulus (default: 3072).
            force: If True, overwrite existing keys.
            envelope_version: Protection format (default: 2 for Argon2id + AES-256-GCM; 1 for legacy PKCS#8).

        Returns:
            Tuple of (private_key_path, public_key_path, key_id).
        """
        if not passphrase or not isinstance(passphrase, str):
            raise ValueError("Passphrase must be a non-empty string.")

        if len(passphrase) < 6:
            raise ValueError("Passphrase must be at least 6 characters long for security.")

        if key_size < 2048:
            raise ValueError("RSA key size must be at least 2048 bits.")

        with self._lock:
            self.initialize_keys_directory()

            if self.private_key_path.exists() and not force:
                raise KeyManagerError(
                    f"Private key already exists at '{self.private_key_path}'. Use force=True to overwrite."
                )

            logger.info(f"Generating new RSA-{key_size} key pair (Envelope v{envelope_version})...")
            private_key = rsa.generate_private_key(
                public_exponent=CONFIG.RSA_PUBLIC_EXPONENT,
                key_size=key_size,
            )
            public_key = private_key.public_key()

            # Serialize public key unencrypted in SubjectPublicKeyInfo PEM format
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            # Compute deterministic public-key fingerprint / key ID
            der_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            fingerprint = hashlib.sha256(der_bytes).hexdigest()
            key_id = f"KEY-{fingerprint[:16].upper()}"

            # Serialize private key according to envelope version
            if envelope_version == 2:
                envelope = self._build_v2_envelope(private_key, passphrase, key_id)
                private_bytes = json.dumps(envelope, indent=2).encode("utf-8")
                protection_algorithm = "Argon2id-AES256GCM"
            elif envelope_version == 1:
                private_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(
                        passphrase.encode("utf-8")
                    ),
                )
                protection_algorithm = "PKCS8-PBES2"
            else:
                raise ValueError(f"Unsupported envelope version: {envelope_version}")

            # Atomically write key files
            temp_priv = self.private_key_path.with_suffix(".tmp")
            temp_pub = self.public_key_path.with_suffix(".tmp")
            temp_meta = self.key_metadata_path.with_suffix(".tmp")

            try:
                temp_priv.write_bytes(private_bytes)
                temp_pub.write_bytes(public_pem)

                metadata = {
                    "key_id": key_id,
                    "fingerprint": fingerprint,
                    "algorithm": "RSA-OAEP-SHA256",
                    "key_size_bits": key_size,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "public_exponent": CONFIG.RSA_PUBLIC_EXPONENT,
                    "private_key_file": self.private_key_path.name,
                    "public_key_file": self.public_key_path.name,
                    "private_key_envelope_version": envelope_version,
                    "private_key_protection": protection_algorithm,
                }
                if envelope_version == 2:
                    metadata["private_key_kdf"] = envelope["kdf"]
                    metadata["private_key_cipher"] = envelope["encryption"]["cipher"]
                with open(temp_meta, "w", encoding="utf-8") as f:
                    json.dump(metadata, f, indent=2)

                # Rename to final destinations
                if self.private_key_path.exists():
                    self.private_key_path.unlink()
                temp_priv.replace(self.private_key_path)

                if self.public_key_path.exists():
                    self.public_key_path.unlink()
                temp_pub.replace(self.public_key_path)

                if self.key_metadata_path.exists():
                    self.key_metadata_path.unlink()
                temp_meta.replace(self.key_metadata_path)

            finally:
                if temp_priv.exists():
                    temp_priv.unlink()
                if temp_pub.exists():
                    temp_pub.unlink()
                if temp_meta.exists():
                    temp_meta.unlink()

            logger.info(f"Cryptographic key pair successfully generated. Key ID: {key_id}")
            return self.private_key_path, self.public_key_path, key_id

    def load_public_key(self, key_path: Optional[Path] = None) -> rsa.RSAPublicKey:
        """
        Load RSA public key from PEM file.
        """
        target = (key_path or self.public_key_path).resolve()
        if not target.exists():
            raise KeyNotFoundError(f"Public key file not found at: {target}")

        with open(target, "rb") as f:
            data = f.read()

        try:
            pub = serialization.load_pem_public_key(data)
            if not isinstance(pub, rsa.RSAPublicKey):
                raise KeyManagerError(f"Key at {target} is not an RSA public key.")
            return pub
        except Exception as e:
            raise KeyManagerError(f"Failed to load public key from {target}: {e}")

    def load_private_key(
        self,
        passphrase: str,
        key_path: Optional[Path] = None,
    ) -> rsa.RSAPrivateKey:
        """
        Load RSA private key from encrypted file (supports both v2 Argon2id envelope and v1 PKCS#8 PEM).
        """
        if not passphrase or not isinstance(passphrase, str):
            raise InvalidPassphraseError("A valid passphrase is required to decrypt the private key.")

        target = (key_path or self.private_key_path).resolve()
        if not target.exists():
            raise KeyNotFoundError(f"Private key file not found at: {target}")

        with open(target, "rb") as f:
            data = f.read()

        # Legacy PKCS#8 PEM detection (v1)
        if data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----") or data.startswith(b"-----BEGIN RSA PRIVATE KEY-----"):
            try:
                priv = serialization.load_pem_private_key(
                    data,
                    password=passphrase.encode("utf-8"),
                )
                if not isinstance(priv, rsa.RSAPrivateKey):
                    raise KeyManagerError(f"Key at {target} is not an RSA private key.")
                return priv
            except (ValueError, TypeError):
                raise InvalidPassphraseError(f"Incorrect passphrase for private key at {target}.")
            except Exception as e:
                raise KeyManagerError(f"Failed to decrypt private key from {target}: {e}")

        # Versioned Hardened Envelope (v2)
        try:
            envelope = json.loads(data.decode("utf-8"))
        except Exception as e:
            raise KeyManagerError(f"Unrecognized private key format at {target}: {e}")

        if not isinstance(envelope, dict) or envelope.get("format") != "CryptoShield-Hardened-PrivateKey":
            raise KeyManagerError(f"Invalid private key envelope format at {target}.")

        envelope_version = envelope.get("envelope_version")
        if envelope_version != 2:
            raise KeyManagerError(f"Unsupported private key envelope version: {envelope_version}")

        try:
            key_id = envelope["key_id"]
            kdf_dict = envelope["kdf"]
            enc_dict = envelope["encryption"]
            ver_dict = envelope["passphrase_verifier"]

            salt = base64.b64decode(kdf_dict["salt_b64"])
            iterations = int(kdf_dict["iterations"])
            memory_cost_kib = int(kdf_dict["memory_cost_kib"])
            lanes = int(kdf_dict["lanes"])
            key_length_bytes = int(kdf_dict.get("key_length_bytes", CONFIG.ARGON2_KEY_LENGTH_BYTES))

            stored_verifier = base64.b64decode(ver_dict["verifier_tag_b64"])
            nonce = base64.b64decode(enc_dict["nonce_b64"])
            tag = base64.b64decode(enc_dict["tag_b64"])
            ciphertext = base64.b64decode(enc_dict["ciphertext_b64"])
            cipher_name = enc_dict.get("cipher", "AES-256-GCM")
        except Exception as e:
            raise EnvelopeTamperedError(f"Corrupted private key envelope structure at {target}: {e}")

        # Derive AES key and verifier key via Argon2id
        try:
            kdf = Argon2id(
                salt=salt,
                length=key_length_bytes,
                iterations=iterations,
                lanes=lanes,
                memory_cost=memory_cost_kib,
            )
            derived = kdf.derive(passphrase.encode("utf-8"))
            aes_key = derived[:CONFIG.AES_KEY_SIZE_BYTES]
            verifier_key = derived[CONFIG.AES_KEY_SIZE_BYTES:]
        except Exception as e:
            raise KeyManagerError(f"Argon2id key derivation failed: {e}")

        # Verify passphrase against HMAC tag
        expected_verifier = hmac.new(
            verifier_key,
            f"CryptoShield-Passphrase-Check:{key_id}".encode("utf-8"),
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(expected_verifier, stored_verifier):
            raise InvalidPassphraseError(f"Incorrect passphrase for private key at {target}.")

        # Reconstruct canonical AAD
        aad = self._compute_v2_envelope_aad(
            envelope_version=envelope_version,
            key_id=key_id,
            kdf_params=kdf_dict,
            verifier_tag_b64=ver_dict["verifier_tag_b64"],
            cipher=cipher_name,
        )

        # Authenticated AES-256-GCM decryption
        try:
            aesgcm = AESGCM(aes_key)
            der_bytes = aesgcm.decrypt(nonce, ciphertext + tag, aad)
        except InvalidTag:
            raise EnvelopeTamperedError(
                f"Private key envelope at {target} has been tampered with or corrupted: AES-GCM tag verification failed."
            )
        except Exception as e:
            raise KeyManagerError(f"Decryption error for private key envelope at {target}: {e}")

        try:
            priv = serialization.load_der_private_key(der_bytes, password=None)
            if not isinstance(priv, rsa.RSAPrivateKey):
                raise KeyManagerError(f"Decrypted payload at {target} is not an RSA private key.")
            return priv
        except Exception as e:
            raise KeyManagerError(f"Failed to parse decrypted private key DER from {target}: {e}")

    def migrate_private_key(
        self,
        passphrase: str,
        new_passphrase: Optional[str] = None,
        backup_suffix: str = ".v1.bak",
    ) -> Dict[str, Any]:
        """
        Migrate an existing private key to the versioned Argon2id + AES-256-GCM envelope (v2).
        Preserves the RSA key pair, public key, key ID, and public fingerprint.
        Employs atomic migration and retains a recoverable backup.
        """
        with self._lock:
            target = self.private_key_path.resolve()
            if not target.exists():
                raise KeyNotFoundError(f"Private key file not found at: {target}")

            old_data = target.read_bytes()
            if old_data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----") or old_data.startswith(b"-----BEGIN RSA PRIVATE KEY-----"):
                current_format = "PKCS8-PBES2-v1"
            elif b'"format": "CryptoShield-Hardened-PrivateKey"' in old_data:
                current_format = "Argon2id-AES256GCM-v2"
            else:
                current_format = "UNKNOWN"

            # 1. Decrypt existing private key with current passphrase
            logger.info(f"Decrypting existing private key ({current_format}) for migration...")
            current_priv = self.load_private_key(passphrase=passphrase)

            # 2. Verify key pair integrity against public key on disk
            pub_key = self.load_public_key()
            if current_priv.public_key().public_numbers() != pub_key.public_numbers():
                raise KeyManagerError("Private key does not match corresponding public key on disk.")

            # 3. Retrieve metadata to preserve key_id and fingerprint
            meta = self.get_key_metadata()
            key_id = meta.get("key_id")
            fingerprint = meta.get("fingerprint")

            if not key_id or not fingerprint:
                der_bytes = pub_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                fingerprint = hashlib.sha256(der_bytes).hexdigest()
                key_id = f"KEY-{fingerprint[:16].upper()}"

            # 4. Create recoverable backup of the original private key file
            backup_path = target.with_name(target.name + backup_suffix)
            logger.info(f"Creating recoverable backup of original private key at '{backup_path}'...")
            backup_temp = backup_path.with_suffix(".tmp")
            try:
                backup_temp.write_bytes(old_data)
                if backup_path.exists():
                    backup_path.unlink()
                backup_temp.replace(backup_path)
            finally:
                if backup_temp.exists():
                    backup_temp.unlink()

            # 5. Build new v2 envelope using effective passphrase
            effective_passphrase = new_passphrase if new_passphrase is not None else passphrase
            new_envelope = self._build_v2_envelope(current_priv, effective_passphrase, key_id)
            new_bytes = json.dumps(new_envelope, indent=2).encode("utf-8")

            # 6. Atomically replace the private key file
            temp_target = target.with_suffix(".tmp")
            try:
                temp_target.write_bytes(new_bytes)
                if target.exists():
                    target.unlink()
                temp_target.replace(target)
            finally:
                if temp_target.exists():
                    temp_target.unlink()

            # 7. Update metadata JSON (preserving key_id, fingerprint, public key)
            meta["private_key_envelope_version"] = 2
            meta["private_key_protection"] = "Argon2id-AES256GCM"
            meta["private_key_kdf"] = new_envelope["kdf"]
            meta["private_key_cipher"] = new_envelope["encryption"]["cipher"]
            meta["migrated_at"] = datetime.now(timezone.utc).isoformat()
            temp_meta = self.key_metadata_path.with_suffix(".tmp")
            try:
                with open(temp_meta, "w", encoding="utf-8") as f:
                    json.dump(meta, f, indent=2)
                if self.key_metadata_path.exists():
                    self.key_metadata_path.unlink()
                temp_meta.replace(self.key_metadata_path)
            finally:
                if temp_meta.exists():
                    temp_meta.unlink()

            # 8. Immediate self-test validation
            try:
                verified_priv = self.load_private_key(passphrase=effective_passphrase)
                if verified_priv.public_key().public_numbers() != pub_key.public_numbers():
                    raise KeyManagerError("Verification check failed: loaded key public numbers mismatch.")
            except Exception as e:
                # Immediate automatic recovery from backup
                logger.error(f"Migration self-test verification failed: {e}. Restoring from backup...")
                target.write_bytes(backup_path.read_bytes())
                raise KeyManagerError(f"Migration verification failed: {e}. Restored original key from backup.")

            logger.info(f"Private key successfully migrated to Argon2id envelope v2. Key ID: {key_id}")
            return {
                "status": "MIGRATED_SUCCESSFULLY",
                "key_id": key_id,
                "fingerprint": fingerprint,
                "previous_format": current_format,
                "new_format": "Argon2id-AES256GCM-v2",
                "envelope_version": 2,
                "kdf": new_envelope["kdf"],
                "cipher": new_envelope["encryption"]["cipher"],
                "backup_path": str(backup_path),
                "migrated_at": meta["migrated_at"],
            }

    def get_envelope_info(self, key_path: Optional[Path] = None) -> Dict[str, Any]:
        """
        Inspect the private key file format and envelope parameters without needing passphrase.
        """
        target = (key_path or self.private_key_path).resolve()
        if not target.exists():
            raise KeyNotFoundError(f"Private key file not found at: {target}")

        with open(target, "rb") as f:
            data = f.read()

        if data.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----") or data.startswith(b"-----BEGIN RSA PRIVATE KEY-----"):
            return {
                "format": "PKCS8-PBES2-v1",
                "envelope_version": 1,
                "encryption": "AES-256-CBC (PKCS#8)",
                "kdf": "PBKDF2-HMAC-SHA256 (2048 iterations)",
                "target_path": str(target),
            }

        try:
            envelope = json.loads(data.decode("utf-8"))
            if envelope.get("format") == "CryptoShield-Hardened-PrivateKey":
                return {
                    "format": "Argon2id-AES256GCM-v2",
                    "envelope_version": envelope.get("envelope_version", 2),
                    "key_id": envelope.get("key_id"),
                    "algorithm": envelope.get("algorithm"),
                    "kdf": envelope.get("kdf", {}),
                    "cipher": envelope.get("encryption", {}).get("cipher"),
                    "created_at": envelope.get("created_at"),
                    "target_path": str(target),
                }
        except Exception:
            pass

        return {
            "format": "UNKNOWN",
            "envelope_version": 0,
            "target_path": str(target),
        }

    def get_key_metadata(self) -> Dict[str, Any]:
        """
        Retrieve public key metadata.
        """
        if not self.key_metadata_path.exists():
            # If public key exists but metadata is absent, reconstruct metadata
            if self.public_key_path.exists():
                pub = self.load_public_key()
                der_bytes = pub.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                fingerprint = hashlib.sha256(der_bytes).hexdigest()
                return {
                    "key_id": f"KEY-{fingerprint[:16].upper()}",
                    "fingerprint": fingerprint,
                    "algorithm": "RSA-OAEP-SHA256",
                    "key_size_bits": pub.key_size,
                    "created_at": "UNKNOWN",
                    "public_exponent": pub.public_numbers().e,
                    "private_key_file": self.private_key_path.name,
                    "public_key_file": self.public_key_path.name,
                }
            raise KeyNotFoundError(f"Key metadata not found at: {self.key_metadata_path}")

        try:
            with open(self.key_metadata_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            raise KeyManagerError(f"Failed to read key metadata: {e}")

    def generate_snapshot_aes_key(self) -> bytes:
        """
        Generate a cryptographically secure 256-bit AES key.
        Always returns 32 cryptographically random bytes.
        """
        return os.urandom(CONFIG.AES_KEY_SIZE_BYTES)

    def wrap_aes_key(
        self,
        public_key: rsa.RSAPublicKey,
        aes_key: bytes,
        snapshot_id: str,
    ) -> bytes:
        """
        Wrap (encrypt) a 256-bit AES key using RSA-OAEP with SHA-256 and snapshot-specific label.
        """
        if len(aes_key) != CONFIG.AES_KEY_SIZE_BYTES:
            raise ValueError(f"AES key must be exactly {CONFIG.AES_KEY_SIZE_BYTES} bytes.")

        if not snapshot_id:
            raise ValueError("snapshot_id is required for OAEP label binding.")

        label = snapshot_id.encode("utf-8")
        oaep_padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=label,
        )

        return public_key.encrypt(aes_key, oaep_padding)

    def unwrap_aes_key(
        self,
        private_key: rsa.RSAPrivateKey,
        wrapped_aes_key: bytes,
        snapshot_id: str,
    ) -> bytes:
        """
        Unwrap (decrypt) an AES key using RSA-OAEP with SHA-256 and snapshot-specific label.
        """
        if not snapshot_id:
            raise ValueError("snapshot_id is required for OAEP label binding.")

        label = snapshot_id.encode("utf-8")
        oaep_padding = padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=label,
        )

        try:
            aes_key = private_key.decrypt(wrapped_aes_key, oaep_padding)
            if len(aes_key) != CONFIG.AES_KEY_SIZE_BYTES:
                raise KeyManagerError("Unwrapped key has invalid length.")
            return aes_key
        except Exception as e:
            raise KeyManagerError(f"Failed to unwrap AES session key: {e}")

    def has_keys(self) -> bool:
        """Check whether both public and private keys are present on disk."""
        return self.private_key_path.exists() and self.public_key_path.exists()


# Global KeyManager singleton
KEY_MGR = KeyManager.get_instance()

