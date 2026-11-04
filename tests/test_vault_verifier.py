"""
Unit tests for SnapshotVerifier in CryptoShield Vault (Phase 5).
"""

from __future__ import annotations

import os
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
def verifier_fixture():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        lab_dir = root / "lab"
        vault_dir = root / "vault"
        keys_dir = root / "keys"
        passphrase = "VerifierTestPassphrase2026!"

        # Initialize lab
        lab_mgr = LabManager(base_lab_dir=lab_dir)
        lab_mgr.initialize_lab()

        gen = SyntheticDatasetGenerator(base_lab_dir=lab_dir, seed=123)
        gen.generate_dataset(file_count=15, canary_count=2)

        # Initialize keys
        key_mgr = KeyManager(keys_dir=keys_dir)
        key_mgr.generate_key_pair(passphrase=passphrase, key_size=2048)

        # Create a valid snapshot
        snap_mgr = SnapshotManager(
            vault_dir=vault_dir,
            base_lab_dir=lab_dir,
            key_manager=key_mgr,
        )
        meta = snap_mgr.create_snapshot()

        verifier = SnapshotVerifier(
            vault_dir=vault_dir,
            key_manager=key_mgr,
        )

        yield verifier, meta, vault_dir, lab_dir, passphrase, key_mgr


def test_full_valid_snapshot_verification(verifier_fixture):
    verifier, meta, _, _, passphrase, _ = verifier_fixture

    report = verifier.verify_snapshot(
        snapshot_id=meta.snapshot_id,
        passphrase=passphrase,
    )

    assert report.outcome == SnapshotVerificationOutcome.FULLY_VERIFIED.value
    assert report.total_manifest_objects == 15
    assert report.verified_objects == 15
    assert report.failed_objects == 0
    assert len(report.missing_objects) == 0
    assert len(report.unexpected_objects) == 0
    assert len(report.tampered_objects) == 0


def test_verification_detects_tampered_ciphertext(verifier_fixture):
    verifier, meta, vault_dir, _, passphrase, _ = verifier_fixture

    objects_dir = vault_dir / meta.snapshot_id / "objects"
    sample_cso = next(objects_dir.glob("*.cso"))

    # Flip 1 byte in the ciphertext body
    raw = bytearray(sample_cso.read_bytes())
    raw[35] ^= 0xAA
    sample_cso.write_bytes(bytes(raw))

    report = verifier.verify_snapshot(
        snapshot_id=meta.snapshot_id,
        passphrase=passphrase,
    )

    assert report.outcome in {
        SnapshotVerificationOutcome.PARTIALLY_VERIFIED.value,
        SnapshotVerificationOutcome.VERIFICATION_FAILED.value,
    }
    assert report.failed_objects >= 1
    assert len(report.tampered_objects) >= 1


def test_verification_detects_missing_object(verifier_fixture):
    verifier, meta, vault_dir, _, passphrase, _ = verifier_fixture

    objects_dir = vault_dir / meta.snapshot_id / "objects"
    sample_cso = next(objects_dir.glob("*.cso"))
    sample_cso.unlink()

    report = verifier.verify_snapshot(
        snapshot_id=meta.snapshot_id,
        passphrase=passphrase,
    )

    assert report.outcome in {
        SnapshotVerificationOutcome.PARTIALLY_VERIFIED.value,
        SnapshotVerificationOutcome.VERIFICATION_FAILED.value,
    }
    assert report.failed_objects >= 1
    assert len(report.missing_objects) >= 1


def test_verification_detects_unexpected_object(verifier_fixture):
    verifier, meta, vault_dir, _, passphrase, _ = verifier_fixture

    objects_dir = vault_dir / meta.snapshot_id / "objects"
    rogue_file = objects_dir / "OBJ-ROGUE-UNTRACKED.cso"
    rogue_file.write_bytes(b"CSO1" + b"\x00" * 30 + b"random rogue data")

    report = verifier.verify_snapshot(
        snapshot_id=meta.snapshot_id,
        passphrase=passphrase,
    )

    assert report.outcome != SnapshotVerificationOutcome.FULLY_VERIFIED.value
    assert "OBJ-ROGUE-UNTRACKED.cso" in report.unexpected_objects


def test_verification_fails_on_wrong_passphrase(verifier_fixture):
    verifier, meta, _, _, _, _ = verifier_fixture

    report = verifier.verify_snapshot(
        snapshot_id=meta.snapshot_id,
        passphrase="IncorrectPassword999!",
    )

    assert report.outcome == SnapshotVerificationOutcome.VERIFICATION_FAILED.value
    assert report.verified_objects == 0
    assert "authentication failed" in report.summary.lower()


def test_verification_does_not_write_plaintext_to_disk(verifier_fixture):
    verifier, meta, vault_dir, lab_dir, passphrase, _ = verifier_fixture

    # Count files in lab before
    lab_files_before = set(lab_dir.rglob("*"))
    vault_files_before = set(vault_dir.rglob("*"))

    report = verifier.verify_snapshot(
        snapshot_id=meta.snapshot_id,
        passphrase=passphrase,
    )

    assert report.outcome == SnapshotVerificationOutcome.FULLY_VERIFIED.value

    # Verify no new files were created in lab or vault
    lab_files_after = set(lab_dir.rglob("*"))
    vault_files_after = set(vault_dir.rglob("*"))

    assert lab_files_before == lab_files_after
    assert vault_files_before == vault_files_after

