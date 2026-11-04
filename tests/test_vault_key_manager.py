"""
Unit tests for KeyManager in CryptoShield Vault (Phase 5).
"""

from __future__ import annotations

import base64
import copy
import json
import tempfile
from pathlib import Path
import pytest
from unittest.mock import patch

from app.vault.key_manager import (
    EnvelopeTamperedError,
    InvalidPassphraseError,
    KeyManager,
    KeyManagerError,
    KeyNotFoundError,
)


@pytest.fixture
def temp_keys_dir():
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


def test_keypair_generation_and_loading(temp_keys_dir: Path):
    mgr = KeyManager(keys_dir=temp_keys_dir)
    passphrase = "SecretVaultPassphrase123!"

    priv_path, pub_path, key_id = mgr.generate_key_pair(passphrase=passphrase, key_size=2048)

    assert priv_path.exists()
    assert pub_path.exists()
    assert key_id.startswith("KEY-")

    # Load public key
    pub_key = mgr.load_public_key()
    assert pub_key.key_size == 2048

    # Load private key
    priv_key = mgr.load_private_key(passphrase=passphrase)
    assert priv_key.key_size == 2048

    # Metadata check
    meta = mgr.get_key_metadata()
    assert meta["key_id"] == key_id
    assert meta["algorithm"] == "RSA-OAEP-SHA256"


def test_incorrect_passphrase_rejected(temp_keys_dir: Path):
    mgr = KeyManager(keys_dir=temp_keys_dir)
    mgr.generate_key_pair(passphrase="CorrectPassphrase123!", key_size=2048)

    with pytest.raises(InvalidPassphraseError):
        mgr.load_private_key(passphrase="WrongPassword456!")

    with pytest.raises(InvalidPassphraseError):
        mgr.load_private_key(passphrase="")


def test_missing_key_files_raise_not_found(temp_keys_dir: Path):
    mgr = KeyManager(keys_dir=temp_keys_dir)
    assert not mgr.has_keys()

    with pytest.raises(KeyNotFoundError):
        mgr.load_public_key()

    with pytest.raises(KeyNotFoundError):
        mgr.load_private_key("some_pass")


def test_aes_session_key_generation(temp_keys_dir: Path):
    mgr = KeyManager(keys_dir=temp_keys_dir)
    k1 = mgr.generate_snapshot_aes_key()
    k2 = mgr.generate_snapshot_aes_key()

    assert len(k1) == 32
    assert len(k2) == 32
    assert k1 != k2  # Cryptographically random & unique


def test_rsa_oaep_key_wrapping_and_unwrapping(temp_keys_dir: Path):
    mgr = KeyManager(keys_dir=temp_keys_dir)
    passphrase = "WrappingTestPassphrase999!"
    mgr.generate_key_pair(passphrase=passphrase, key_size=2048)

    pub_key = mgr.load_public_key()
    priv_key = mgr.load_private_key(passphrase=passphrase)

    aes_key = mgr.generate_snapshot_aes_key()
    snapshot_id = "SNAP-TEST-OAEP-01"

    wrapped = mgr.wrap_aes_key(pub_key, aes_key, snapshot_id=snapshot_id)
    assert len(wrapped) > 0
    assert wrapped != aes_key

    unwrapped = mgr.unwrap_aes_key(priv_key, wrapped, snapshot_id=snapshot_id)
    assert unwrapped == aes_key


def test_rsa_oaep_wrong_label_fails_unwrap(temp_keys_dir: Path):
    mgr = KeyManager(keys_dir=temp_keys_dir)
    passphrase = "WrappingTestPassphrase999!"
    mgr.generate_key_pair(passphrase=passphrase, key_size=2048)

    pub_key = mgr.load_public_key()
    priv_key = mgr.load_private_key(passphrase=passphrase)

    aes_key = mgr.generate_snapshot_aes_key()
    wrapped = mgr.wrap_aes_key(pub_key, aes_key, snapshot_id="SNAP-ORIGINAL")

    with pytest.raises(KeyManagerError):
        mgr.unwrap_aes_key(priv_key, wrapped, snapshot_id="SNAP-DIFFERENT")


def test_hardened_envelope_v2_structure_and_parameters(temp_keys_dir: Path):
    """Verify that version 2 envelope uses Argon2id, random salt >= 16 bytes, AES-256-GCM, and 96-bit nonce."""
    mgr = KeyManager(keys_dir=temp_keys_dir)
    passphrase = "HardenedVaultPassphrase2026!"

    priv_path, pub_path, key_id = mgr.generate_key_pair(passphrase=passphrase, key_size=2048, envelope_version=2)

    with open(priv_path, "r", encoding="utf-8") as f:
        env = json.load(f)

    assert env["format"] == "CryptoShield-Hardened-PrivateKey"
    assert env["envelope_version"] == 2
    assert env["key_id"] == key_id
    assert env["algorithm"] == "RSA-OAEP-SHA256"

    # Verify KDF parameters
    kdf = env["kdf"]
    assert kdf["algorithm"] == "Argon2id"
    salt = base64.b64decode(kdf["salt_b64"])
    assert len(salt) >= 16
    assert kdf["iterations"] == 3
    assert kdf["memory_cost_kib"] == 65536
    assert kdf["lanes"] == 4

    # Verify Cipher parameters
    enc = env["encryption"]
    assert enc["cipher"] == "AES-256-GCM"
    nonce = base64.b64decode(enc["nonce_b64"])
    tag = base64.b64decode(enc["tag_b64"])
    ct = base64.b64decode(enc["ciphertext_b64"])
    assert len(nonce) == 12  # 96 bits
    assert len(tag) == 16    # 128 bits
    assert len(ct) > 0

    # Successful load with correct passphrase
    priv_key = mgr.load_private_key(passphrase=passphrase)
    assert priv_key.key_size == 2048


def test_v2_incorrect_passphrase_raises_invalid_passphrase(temp_keys_dir: Path):
    """Confirm wrong passphrase fails authentication cleanly."""
    mgr = KeyManager(keys_dir=temp_keys_dir)
    passphrase = "CorrectHardenedPassphrase1!"
    mgr.generate_key_pair(passphrase=passphrase, key_size=2048, envelope_version=2)

    with pytest.raises(InvalidPassphraseError):
        mgr.load_private_key(passphrase="WrongHardenedPassphrase2!")


def test_v2_tampered_ciphertext_detected(temp_keys_dir: Path):
    """Confirm tampering with encrypted private-key bytes triggers EnvelopeTamperedError."""
    mgr = KeyManager(keys_dir=temp_keys_dir)
    passphrase = "TamperTestPassphrase123!"
    priv_path, _, _ = mgr.generate_key_pair(passphrase=passphrase, key_size=2048, envelope_version=2)

    with open(priv_path, "r", encoding="utf-8") as f:
        env = json.load(f)

    ct = bytearray(base64.b64decode(env["encryption"]["ciphertext_b64"]))
    ct[10] ^= 0x55
    env["encryption"]["ciphertext_b64"] = base64.b64encode(ct).decode("ascii")

    with open(priv_path, "w", encoding="utf-8") as f:
        json.dump(env, f, indent=2)

    with pytest.raises(EnvelopeTamperedError):
        mgr.load_private_key(passphrase=passphrase)


def test_v2_tampered_tag_detected(temp_keys_dir: Path):
    """Confirm tampering with GCM authentication tag triggers EnvelopeTamperedError."""
    mgr = KeyManager(keys_dir=temp_keys_dir)
    passphrase = "TagTamperPassphrase123!"
    priv_path, _, _ = mgr.generate_key_pair(passphrase=passphrase, key_size=2048, envelope_version=2)

    with open(priv_path, "r", encoding="utf-8") as f:
        env = json.load(f)

    tag = bytearray(base64.b64decode(env["encryption"]["tag_b64"]))
    tag[0] ^= 0x01
    env["encryption"]["tag_b64"] = base64.b64encode(tag).decode("ascii")

    with open(priv_path, "w", encoding="utf-8") as f:
        json.dump(env, f, indent=2)

    with pytest.raises(EnvelopeTamperedError):
        mgr.load_private_key(passphrase=passphrase)


def test_v2_tampered_nonce_detected(temp_keys_dir: Path):
    """Confirm tampering with nonce triggers EnvelopeTamperedError."""
    mgr = KeyManager(keys_dir=temp_keys_dir)
    passphrase = "NonceTamperPassphrase123!"
    priv_path, _, _ = mgr.generate_key_pair(passphrase=passphrase, key_size=2048, envelope_version=2)

    with open(priv_path, "r", encoding="utf-8") as f:
        env = json.load(f)

    nonce = bytearray(base64.b64decode(env["encryption"]["nonce_b64"]))
    nonce[0] ^= 0xFF
    env["encryption"]["nonce_b64"] = base64.b64encode(nonce).decode("ascii")

    with open(priv_path, "w", encoding="utf-8") as f:
        json.dump(env, f, indent=2)

    with pytest.raises(EnvelopeTamperedError):
        mgr.load_private_key(passphrase=passphrase)


def test_v2_tampered_kdf_parameters_detected(temp_keys_dir: Path):
    """Confirm tampering with KDF parameters in envelope metadata is detected."""
    mgr = KeyManager(keys_dir=temp_keys_dir)
    passphrase = "KdfTamperPassphrase123!"
    priv_path, _, _ = mgr.generate_key_pair(passphrase=passphrase, key_size=2048, envelope_version=2)

    with open(priv_path, "r", encoding="utf-8") as f:
        env = json.load(f)

    # Attempt parameter downgrade attack
    env["kdf"]["iterations"] = 1

    with open(priv_path, "w", encoding="utf-8") as f:
        json.dump(env, f, indent=2)

    with pytest.raises(KeyManagerError):
        mgr.load_private_key(passphrase=passphrase)


def test_backward_compatibility_load_legacy_v1_pkcs8(temp_keys_dir: Path):
    """Confirm reading existing PKCS#8 encrypted PEM keys remains fully supported."""
    mgr = KeyManager(keys_dir=temp_keys_dir)
    passphrase = "LegacyV1Passphrase123!"
    priv_path, pub_path, key_id = mgr.generate_key_pair(passphrase=passphrase, key_size=2048, envelope_version=1)

    raw_pem = priv_path.read_bytes()
    assert b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in raw_pem

    # Load legacy key
    priv_key = mgr.load_private_key(passphrase=passphrase)
    assert priv_key.key_size == 2048

    # Wrong passphrase rejected on legacy key
    with pytest.raises(InvalidPassphraseError):
        mgr.load_private_key(passphrase="WrongLegacyPassphrase!")


def test_atomic_migration_v1_to_v2(temp_keys_dir: Path):
    """Confirm atomic migration from legacy v1 to hardened v2 envelope preserves keypair and wraps."""
    mgr = KeyManager(keys_dir=temp_keys_dir)
    passphrase = "MigrationSourcePassphrase1!"
    priv_path, pub_path, original_key_id = mgr.generate_key_pair(
        passphrase=passphrase, key_size=2048, envelope_version=1
    )

    pub_key_before = mgr.load_public_key()
    pub_pem_before = pub_path.read_bytes()

    # Wrap a session key using the pre-migration public key
    aes_key = mgr.generate_snapshot_aes_key()
    wrapped_before = mgr.wrap_aes_key(pub_key_before, aes_key, snapshot_id="SNAP-PRE-MIGRATION")

    # Perform atomic migration
    report = mgr.migrate_private_key(passphrase=passphrase)

    assert report["status"] == "MIGRATED_SUCCESSFULLY"
    assert report["key_id"] == original_key_id
    assert report["envelope_version"] == 2
    assert report["previous_format"] == "PKCS8-PBES2-v1"
    assert report["new_format"] == "Argon2id-AES256GCM-v2"

    # Confirm backup file created
    backup_file = Path(report["backup_path"])
    assert backup_file.exists()
    assert b"-----BEGIN ENCRYPTED PRIVATE KEY-----" in backup_file.read_bytes()

    # Confirm public key file was NOT modified/regenerated
    assert pub_path.read_bytes() == pub_pem_before

    # Confirm newly migrated private key loads cleanly
    migrated_priv = mgr.load_private_key(passphrase=passphrase)
    assert migrated_priv.key_size == 2048

    # Confirm migrated private key unwrap session keys generated prior to migration
    unwrapped = mgr.unwrap_aes_key(migrated_priv, wrapped_before, snapshot_id="SNAP-PRE-MIGRATION")
    assert unwrapped == aes_key


def test_migration_incorrect_passphrase_aborts_without_modifications(temp_keys_dir: Path):
    """Confirm migration with wrong passphrase raises InvalidPassphraseError without modifying files."""
    mgr = KeyManager(keys_dir=temp_keys_dir)
    passphrase = "RealPassphrase123!"
    priv_path, pub_path, _ = mgr.generate_key_pair(passphrase=passphrase, key_size=2048, envelope_version=1)

    original_bytes = priv_path.read_bytes()

    with pytest.raises(InvalidPassphraseError):
        mgr.migrate_private_key(passphrase="WrongPassphrase456!")

    assert priv_path.read_bytes() == original_bytes
    backup_file = priv_path.with_name(priv_path.name + ".v1.bak")
    assert not backup_file.exists()


def test_migration_failure_restores_original_key(temp_keys_dir: Path):
    """Confirm that if self-test verification fails during migration, the original key is restored."""
    mgr = KeyManager(keys_dir=temp_keys_dir)
    passphrase = "RollbackTestPassphrase1!"
    priv_path, _, _ = mgr.generate_key_pair(passphrase=passphrase, key_size=2048, envelope_version=1)

    original_bytes = priv_path.read_bytes()

    # Mock load_private_key to simulate verification failure on the self-test step
    orig_load = mgr.load_private_key
    call_count = 0

    def mock_load(passphrase, key_path=None):
        nonlocal call_count
        call_count += 1
        if call_count > 1:
            raise RuntimeError("Simulated self-test verification failure")
        return orig_load(passphrase, key_path)

    with patch.object(mgr, "load_private_key", side_effect=mock_load):
        with pytest.raises(KeyManagerError, match="Migration verification failed"):
            mgr.migrate_private_key(passphrase=passphrase)

    # Verify original file was restored
    assert priv_path.read_bytes() == original_bytes


def test_get_envelope_info(temp_keys_dir: Path):
    """Confirm get_envelope_info reports format details accurately."""
    mgr = KeyManager(keys_dir=temp_keys_dir)
    mgr.generate_key_pair(passphrase="InfoTestPassphrase1!", key_size=2048, envelope_version=1)
    info_v1 = mgr.get_envelope_info()
    assert info_v1["envelope_version"] == 1
    assert info_v1["format"] == "PKCS8-PBES2-v1"

    mgr.migrate_private_key(passphrase="InfoTestPassphrase1!")
    info_v2 = mgr.get_envelope_info()
    assert info_v2["envelope_version"] == 2
    assert info_v2["format"] == "Argon2id-AES256GCM-v2"
    assert info_v2["kdf"]["algorithm"] == "Argon2id"
    assert info_v2["cipher"] == "AES-256-GCM"

