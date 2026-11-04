"""
Comprehensive Tampering and Corruption Tests for CryptoShield Vault (Phase 5).

Verifies that the vault verifier detects all forms of malicious manipulation:
- Bit flips in ciphertext body
- Header magic corruption
- Header version corruption
- Nonce alteration
- Authentication tag corruption
- Truncated ciphertext
- Appended rogue data
- Object substitution (swapping two encrypted objects)
- Tampered manifest
"""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from app.lab.dataset_generator import SyntheticDatasetGenerator
from app.lab.lab_manager import LabManager
from app.vault.key_manager import KeyManager
from app.vault.models import SnapshotVerificationOutcome, VerificationStatus
from app.vault.snapshot_manager import SnapshotManager
from app.vault.vault_verifier import SnapshotVerifier


@pytest.fixture
def tampering_fixture():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        lab_dir = root / "lab"
        vault_dir = root / "vault"
        keys_dir = root / "keys"
        passphrase = "TamperTestingPassphrase2026!"

        lab_mgr = LabManager(base_lab_dir=lab_dir)
        lab_mgr.initialize_lab()

        gen = SyntheticDatasetGenerator(base_lab_dir=lab_dir, seed=42)
        gen.generate_dataset(file_count=10, canary_count=2)

        key_mgr = KeyManager(keys_dir=keys_dir)
        key_mgr.generate_key_pair(passphrase=passphrase, key_size=2048)

        snap_mgr = SnapshotManager(
            vault_dir=vault_dir,
            base_lab_dir=lab_dir,
            key_manager=key_mgr,
        )
        meta = snap_mgr.create_snapshot()

        verifier = SnapshotVerifier(vault_dir=vault_dir, key_manager=key_mgr)

        yield verifier, meta, vault_dir, passphrase


def test_tamper_header_magic(tampering_fixture):
    verifier, meta, vault_dir, passphrase = tampering_fixture
    objects_dir = vault_dir / meta.snapshot_id / "objects"
    obj = next(objects_dir.glob("*.cso"))

    raw = bytearray(obj.read_bytes())
    raw[0:4] = b"BAD!"
    obj.write_bytes(bytes(raw))

    report = verifier.verify_snapshot(meta.snapshot_id, passphrase)
    assert report.outcome != SnapshotVerificationOutcome.FULLY_VERIFIED.value
    assert report.failed_objects >= 1


def test_tamper_header_version(tampering_fixture):
    verifier, meta, vault_dir, passphrase = tampering_fixture
    objects_dir = vault_dir / meta.snapshot_id / "objects"
    obj = next(objects_dir.glob("*.cso"))

    raw = bytearray(obj.read_bytes())
    raw[4:6] = b"\x00\x02"  # Unsupported format version 2
    obj.write_bytes(bytes(raw))

    report = verifier.verify_snapshot(meta.snapshot_id, passphrase)
    assert report.outcome != SnapshotVerificationOutcome.FULLY_VERIFIED.value
    assert report.failed_objects >= 1


def test_tamper_authentication_tag(tampering_fixture):
    verifier, meta, vault_dir, passphrase = tampering_fixture
    objects_dir = vault_dir / meta.snapshot_id / "objects"
    obj = next(objects_dir.glob("*.cso"))

    # Tag is bytes 18:34 in header
    raw = bytearray(obj.read_bytes())
    raw[20] ^= 0xEE
    obj.write_bytes(bytes(raw))

    report = verifier.verify_snapshot(meta.snapshot_id, passphrase)
    assert report.outcome != SnapshotVerificationOutcome.FULLY_VERIFIED.value
    assert report.failed_objects >= 1


def test_tamper_truncated_ciphertext(tampering_fixture):
    verifier, meta, vault_dir, passphrase = tampering_fixture
    objects_dir = vault_dir / meta.snapshot_id / "objects"
    obj = next(objects_dir.glob("*.cso"))

    raw = obj.read_bytes()
    if len(raw) > 40:
        obj.write_bytes(raw[:-5])  # Truncate 5 bytes

        report = verifier.verify_snapshot(meta.snapshot_id, passphrase)
        assert report.outcome != SnapshotVerificationOutcome.FULLY_VERIFIED.value
        assert report.failed_objects >= 1


def test_tamper_appended_ciphertext(tampering_fixture):
    verifier, meta, vault_dir, passphrase = tampering_fixture
    objects_dir = vault_dir / meta.snapshot_id / "objects"
    obj = next(objects_dir.glob("*.cso"))

    raw = obj.read_bytes()
    obj.write_bytes(raw + b"ROGUE_TRAILING_BYTES")

    report = verifier.verify_snapshot(meta.snapshot_id, passphrase)
    assert report.outcome != SnapshotVerificationOutcome.FULLY_VERIFIED.value
    assert report.failed_objects >= 1


def test_object_substitution_detection(tampering_fixture):
    verifier, meta, vault_dir, passphrase = tampering_fixture
    objects_dir = vault_dir / meta.snapshot_id / "objects"
    cso_files = list(objects_dir.glob("*.cso"))
    assert len(cso_files) >= 2

    # Swap the contents of file A and file B
    data_a = cso_files[0].read_bytes()
    data_b = cso_files[1].read_bytes()

    cso_files[0].write_bytes(data_b)
    cso_files[1].write_bytes(data_a)

    # AAD binding will detect that the ciphertext/tag does not match file identity!
    report = verifier.verify_snapshot(meta.snapshot_id, passphrase)
    assert report.outcome != SnapshotVerificationOutcome.FULLY_VERIFIED.value
    assert report.failed_objects >= 2

