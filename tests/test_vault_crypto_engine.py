"""
Unit tests for CryptoEngine in CryptoShield Vault (Phase 5).
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
import pytest

from app.core.models import ManifestEntry
from app.lab.lab_manager import LabManager
from app.vault.crypto_engine import (
    CryptoEngine,
    FileTamperedError,
    HEADER_SIZE,
)


@pytest.fixture
def crypto_lab_workspace():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        lab_dir = root / "lab"
        dest_dir = root / "objects"
        lab_mgr = LabManager(base_lab_dir=lab_dir)
        lab_mgr.initialize_lab()
        yield lab_dir, dest_dir


def test_roundtrip_file_encryption_and_verification(crypto_lab_workspace):
    lab_dir, dest_dir = crypto_lab_workspace
    engine = CryptoEngine(chunk_size=1024)

    src_file = lab_dir / "Finance" / "q3_report.txt"
    src_file.parent.mkdir(parents=True, exist_ok=True)
    content = b"Confidential financial statement data line.\n" * 50
    src_file.write_bytes(content)
    expected_hash = hashlib.sha256(content).hexdigest().lower()

    entry = ManifestEntry(
        relative_path="Finance/q3_report.txt",
        file_type="txt",
        file_size_bytes=len(content),
        data_classification="CONFIDENTIAL",
        sha256=expected_hash,
        is_canary=False,
        department="Finance",
        created_at="",
    )

    key = os.urandom(32)
    snapshot_id = "SNAP-TEST-ROUNDTRIP-01"
    opaque_id = "OBJ-0001"
    dest_file = dest_dir / f"{opaque_id}.cso"

    rec = engine.encrypt_file(
        source_path=src_file,
        dest_path=dest_file,
        key=key,
        snapshot_id=snapshot_id,
        opaque_id=opaque_id,
        entry=entry,
        base_lab_dir=lab_dir,
    )

    assert dest_file.exists()
    assert rec.original_size_bytes == len(content)
    assert rec.original_sha256 == expected_hash
    assert rec.encrypted_size_bytes > len(content)  # Header + tag overhead

    # Verify
    ok, calc_hash, err = engine.verify_encrypted_file(
        encrypted_path=dest_file,
        key=key,
        snapshot_id=snapshot_id,
        opaque_id=opaque_id,
        entry=entry,
    )
    assert ok is True
    assert calc_hash == expected_hash
    assert err is None


def test_empty_file_encryption_and_verification(crypto_lab_workspace):
    lab_dir, dest_dir = crypto_lab_workspace
    engine = CryptoEngine(chunk_size=1024)

    src_file = lab_dir / "Public Documents" / "empty_notice.txt"
    src_file.parent.mkdir(parents=True, exist_ok=True)
    content = b""
    src_file.write_bytes(content)
    expected_hash = hashlib.sha256(content).hexdigest().lower()

    entry = ManifestEntry(
        relative_path="Public Documents/empty_notice.txt",
        file_type="txt",
        file_size_bytes=0,
        data_classification="PUBLIC",
        sha256=expected_hash,
        is_canary=False,
        department="Public Documents",
        created_at="",
    )

    key = os.urandom(32)
    snapshot_id = "SNAP-TEST-EMPTY-01"
    opaque_id = "OBJ-EMPTY-01"
    dest_file = dest_dir / f"{opaque_id}.cso"

    rec = engine.encrypt_file(
        source_path=src_file,
        dest_path=dest_file,
        key=key,
        snapshot_id=snapshot_id,
        opaque_id=opaque_id,
        entry=entry,
        base_lab_dir=lab_dir,
    )

    assert dest_file.exists()
    assert rec.original_size_bytes == 0
    assert rec.encrypted_size_bytes == HEADER_SIZE  # Exactly header size (34 bytes)

    ok, calc_hash, err = engine.verify_encrypted_file(
        encrypted_path=dest_file,
        key=key,
        snapshot_id=snapshot_id,
        opaque_id=opaque_id,
        entry=entry,
    )
    assert ok is True
    assert calc_hash == expected_hash


def test_large_file_streaming_across_chunks(crypto_lab_workspace):
    lab_dir, dest_dir = crypto_lab_workspace
    # Use small chunk size (16 KB) with a 256 KB file to force multiple streaming chunks
    engine = CryptoEngine(chunk_size=16 * 1024)

    src_file = lab_dir / "IT" / "server_backup.log"
    src_file.parent.mkdir(parents=True, exist_ok=True)
    content = b"ABCDEF0123456789" * 16384  # 256 KB
    src_file.write_bytes(content)
    expected_hash = hashlib.sha256(content).hexdigest().lower()

    entry = ManifestEntry(
        relative_path="IT/server_backup.log",
        file_type="log",
        file_size_bytes=len(content),
        data_classification="INTERNAL",
        sha256=expected_hash,
        is_canary=False,
        department="IT",
        created_at="",
    )

    key = os.urandom(32)
    snapshot_id = "SNAP-TEST-STREAM-01"
    opaque_id = "OBJ-LARGE-01"
    dest_file = dest_dir / f"{opaque_id}.cso"

    rec = engine.encrypt_file(
        source_path=src_file,
        dest_path=dest_file,
        key=key,
        snapshot_id=snapshot_id,
        opaque_id=opaque_id,
        entry=entry,
        base_lab_dir=lab_dir,
    )

    ok, calc_hash, err = engine.verify_encrypted_file(
        encrypted_path=dest_file,
        key=key,
        snapshot_id=snapshot_id,
        opaque_id=opaque_id,
        entry=entry,
    )
    assert ok is True
    assert calc_hash == expected_hash


def test_ciphertext_tampering_detected(crypto_lab_workspace):
    lab_dir, dest_dir = crypto_lab_workspace
    engine = CryptoEngine()

    src_file = lab_dir / "HR" / "contracts.txt"
    src_file.parent.mkdir(parents=True, exist_ok=True)
    content = b"Strictly confidential employee employment contract.\n"
    src_file.write_bytes(content)
    expected_hash = hashlib.sha256(content).hexdigest().lower()

    entry = ManifestEntry(
        relative_path="HR/contracts.txt",
        file_type="txt",
        file_size_bytes=len(content),
        data_classification="RESTRICTED",
        sha256=expected_hash,
        is_canary=False,
        department="Human Resources",
        created_at="",
    )

    key = os.urandom(32)
    snapshot_id = "SNAP-TAMPER-01"
    opaque_id = "OBJ-HR-01"
    dest_file = dest_dir / f"{opaque_id}.cso"

    engine.encrypt_file(
        source_path=src_file,
        dest_path=dest_file,
        key=key,
        snapshot_id=snapshot_id,
        opaque_id=opaque_id,
        entry=entry,
        base_lab_dir=lab_dir,
    )

    # Tamper with 1 byte in ciphertext body (after 34-byte header)
    data = bytearray(dest_file.read_bytes())
    data[35] ^= 0xFF
    dest_file.write_bytes(bytes(data))

    ok, _, err = engine.verify_encrypted_file(
        encrypted_path=dest_file,
        key=key,
        snapshot_id=snapshot_id,
        opaque_id=opaque_id,
        entry=entry,
    )
    assert ok is False
    assert "authentication failed" in (err or "").lower()


def test_aad_mismatch_detected(crypto_lab_workspace):
    lab_dir, dest_dir = crypto_lab_workspace
    engine = CryptoEngine()

    src_file = lab_dir / "Legal" / "nda.txt"
    src_file.parent.mkdir(parents=True, exist_ok=True)
    content = b"Legal non-disclosure agreement.\n"
    src_file.write_bytes(content)
    expected_hash = hashlib.sha256(content).hexdigest().lower()

    entry = ManifestEntry(
        relative_path="Legal/nda.txt",
        file_type="txt",
        file_size_bytes=len(content),
        data_classification="CONFIDENTIAL",
        sha256=expected_hash,
        is_canary=False,
        department="Legal",
        created_at="",
    )

    key = os.urandom(32)
    snapshot_id = "SNAP-AAD-01"
    opaque_id = "OBJ-LEGAL-01"
    dest_file = dest_dir / f"{opaque_id}.cso"

    engine.encrypt_file(
        source_path=src_file,
        dest_path=dest_file,
        key=key,
        snapshot_id=snapshot_id,
        opaque_id=opaque_id,
        entry=entry,
        base_lab_dir=lab_dir,
    )

    # Attempt to verify with modified metadata (e.g. changed data classification)
    tampered_entry = ManifestEntry(
        relative_path="Legal/nda.txt",
        file_type="txt",
        file_size_bytes=len(content),
        data_classification="PUBLIC",  # Tampered classification in AAD!
        sha256=expected_hash,
        is_canary=False,
        department="Legal",
        created_at="",
    )

    ok, _, err = engine.verify_encrypted_file(
        encrypted_path=dest_file,
        key=key,
        snapshot_id=snapshot_id,
        opaque_id=opaque_id,
        entry=tampered_entry,
    )
    assert ok is False
    assert "authentication failed" in (err or "").lower()

