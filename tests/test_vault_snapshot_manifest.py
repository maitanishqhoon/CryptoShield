"""
Unit tests for SnapshotManifestManager in CryptoShield Vault (Phase 5).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
import pytest

from app.vault.models import EncryptedObjectRecord, SnapshotManifest
from app.vault.snapshot_manifest import (
    SnapshotManifestAuthenticationError,
    SnapshotManifestManager,
)


@pytest.fixture
def temp_manifest_dir():
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


def test_manifest_encryption_and_decryption_roundtrip(temp_manifest_dir: Path):
    mgr = SnapshotManifestManager()
    key = os.urandom(32)
    snapshot_id = "SNAP-MAN-01"

    entry1 = EncryptedObjectRecord(
        opaque_id="OBJ-01",
        relative_path="Finance/ledger.csv",
        original_size_bytes=512,
        original_sha256="abc123def456",
        department="Finance",
        data_classification="CONFIDENTIAL",
        is_canary=False,
        encrypted_size_bytes=546,
        nonce_hex="00" * 12,
        tag_hex="11" * 16,
    )
    entry2 = EncryptedObjectRecord(
        opaque_id="OBJ-02",
        relative_path="HR/canary_hr.txt",
        original_size_bytes=128,
        original_sha256="999888777666",
        department="Human Resources",
        data_classification="RESTRICTED",
        is_canary=True,
        encrypted_size_bytes=162,
        nonce_hex="22" * 12,
        tag_hex="33" * 16,
    )

    manifest = SnapshotManifest(
        snapshot_id=snapshot_id,
        format_version="1.0.0",
        created_at="2026-11-04T12:00:00Z",
        lab_id="lab-1234",
        total_files=2,
        total_original_bytes=640,
        canary_count=1,
        department_counts={"Finance": 1, "Human Resources": 1},
        classification_counts={"CONFIDENTIAL": 1, "RESTRICTED": 1},
        entries={"Finance/ledger.csv": entry1, "HR/canary_hr.txt": entry2},
        opaque_id_map={"OBJ-01": "Finance/ledger.csv", "OBJ-02": "HR/canary_hr.txt"},
    )

    dest_file = temp_manifest_dir / "manifest.enc"
    nonce, tag, enc_size = mgr.encrypt_manifest(manifest, dest_file, key)

    assert dest_file.exists()
    assert enc_size > 0
    assert len(nonce) == 12
    assert len(tag) == 16

    # Decrypt
    decrypted = mgr.decrypt_manifest(
        source_path=dest_file,
        key=key,
        snapshot_id=snapshot_id,
        nonce=nonce,
        tag=tag,
    )

    assert decrypted.snapshot_id == snapshot_id
    assert decrypted.total_files == 2
    assert decrypted.canary_count == 1
    assert "Finance/ledger.csv" in decrypted.entries
    assert decrypted.entries["HR/canary_hr.txt"].is_canary is True


def test_manifest_tampering_detected(temp_manifest_dir: Path):
    mgr = SnapshotManifestManager()
    key = os.urandom(32)
    snapshot_id = "SNAP-MAN-TAMPER"

    manifest = SnapshotManifest(
        snapshot_id=snapshot_id,
        format_version="1.0.0",
        created_at="2026-11-04T12:00:00Z",
        lab_id="lab-1234",
        total_files=0,
        total_original_bytes=0,
        canary_count=0,
    )

    dest_file = temp_manifest_dir / "manifest.enc"
    nonce, tag, _ = mgr.encrypt_manifest(manifest, dest_file, key)

    # Tamper with ciphertext in manifest.enc
    raw = bytearray(dest_file.read_bytes())
    raw[10] ^= 0x55
    dest_file.write_bytes(bytes(raw))

    with pytest.raises(SnapshotManifestAuthenticationError):
        mgr.decrypt_manifest(
            source_path=dest_file,
            key=key,
            snapshot_id=snapshot_id,
            nonce=nonce,
            tag=tag,
        )


def test_manifest_snapshot_id_mismatch_rejected(temp_manifest_dir: Path):
    mgr = SnapshotManifestManager()
    key = os.urandom(32)

    manifest = SnapshotManifest(
        snapshot_id="SNAP-ORIGINAL-ID",
        format_version="1.0.0",
        created_at="2026-11-04T12:00:00Z",
        lab_id="lab-1234",
        total_files=0,
        total_original_bytes=0,
        canary_count=0,
    )

    dest_file = temp_manifest_dir / "manifest.enc"
    nonce, tag, _ = mgr.encrypt_manifest(manifest, dest_file, key)

    with pytest.raises(SnapshotManifestAuthenticationError):
        mgr.decrypt_manifest(
            source_path=dest_file,
            key=key,
            snapshot_id="SNAP-DIFFERENT-ID",  # Wrong snapshot ID in AAD
            nonce=nonce,
            tag=tag,
        )

