"""Unit tests for ManifestManager, SHA-256 computation, and integrity verification."""

from pathlib import Path
import pytest

from app.config import CONFIG
from app.core.models import Manifest, ManifestEntry
from app.lab.lab_manager import LabManager
from app.lab.manifest import (
    ManifestManager,
    compute_bytes_sha256,
    compute_file_sha256,
)


def test_compute_sha256(tmp_path: Path):
    data = b"CryptoShield Security Benchmark 2026"
    test_file = tmp_path / "sample.txt"
    test_file.write_bytes(data)

    hash_from_bytes = compute_bytes_sha256(data)
    hash_from_file = compute_file_sha256(test_file)

    assert len(hash_from_bytes) == 64
    assert hash_from_bytes == hash_from_file


def test_manifest_serialization_roundtrip():
    entry = ManifestEntry(
        relative_path="Finance/invoices/inv_001.csv",
        file_type="csv",
        file_size_bytes=1024,
        data_classification="CONFIDENTIAL",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        is_canary=False,
        department="Finance",
        created_at="2026-03-01T12:00:00Z",
    )
    manifest = Manifest(
        manifest_version="1.0.0",
        lab_id="test-lab-uuid",
        generated_at="2026-03-01T12:00:00Z",
        total_files=1,
        total_size_bytes=1024,
        canary_count=0,
        seed=42,
        department_counts={"Finance": 1},
        type_counts={"csv": 1},
        classification_counts={"CONFIDENTIAL": 1},
        entries={"Finance/invoices/inv_001.csv": entry},
    )

    data = manifest.to_dict()
    restored = Manifest.from_dict(data)

    assert restored.lab_id == manifest.lab_id
    assert restored.total_files == 1
    assert "Finance/invoices/inv_001.csv" in restored.entries
    assert restored.entries["Finance/invoices/inv_001.csv"].sha256 == entry.sha256


def test_verify_integrity_intact(tmp_path: Path):
    lab_dir = tmp_path / "lab"
    mgr = LabManager(base_lab_dir=lab_dir)
    mgr.initialize_lab()

    file_a = lab_dir / "doc_a.txt"
    file_a.write_bytes(b"content A")
    hash_a = compute_file_sha256(file_a)

    file_b = lab_dir / "doc_b.json"
    file_b.write_bytes(b'{"key": "value"}')
    hash_b = compute_file_sha256(file_b)

    manifest = Manifest(
        manifest_version="1.0.0",
        lab_id="test-lab",
        generated_at="2026-03-01T12:00:00Z",
        total_files=2,
        total_size_bytes=len(b"content A") + len(b'{"key": "value"}'),
        canary_count=0,
        seed=42,
        entries={
            "doc_a.txt": ManifestEntry("doc_a.txt", "txt", len(b"content A"), "INTERNAL", hash_a, False, "IT", ""),
            "doc_b.json": ManifestEntry("doc_b.json", "json", len(b'{"key": "value"}'), "INTERNAL", hash_b, False, "IT", ""),
        },
    )

    result = ManifestManager.verify_integrity(base_lab_dir=lab_dir, manifest=manifest)
    assert result.is_valid is True
    assert result.matched_files == 2
    assert len(result.modified_files) == 0
    assert len(result.missing_files) == 0


def test_verify_integrity_tampered(tmp_path: Path):
    lab_dir = tmp_path / "lab"
    mgr = LabManager(base_lab_dir=lab_dir)
    mgr.initialize_lab()

    # Create file A (will be modified)
    file_a = lab_dir / "doc_a.txt"
    file_a.write_bytes(b"original content")
    original_hash = compute_file_sha256(file_a)

    # Create file C (canary that will be modified)
    file_c = lab_dir / "canary.json"
    file_c.write_bytes(b"canary content")
    canary_hash = compute_file_sha256(file_c)

    manifest = Manifest(
        manifest_version="1.0.0",
        lab_id="test-lab",
        generated_at="2026-03-01T12:00:00Z",
        total_files=3,
        total_size_bytes=100,
        canary_count=1,
        seed=42,
        entries={
            "doc_a.txt": ManifestEntry("doc_a.txt", "txt", 16, "INTERNAL", original_hash, False, "IT", ""),
            "missing.txt": ManifestEntry("missing.txt", "txt", 10, "INTERNAL", "fakehash", False, "IT", ""),
            "canary.json": ManifestEntry("canary.json", "json", 14, "RESTRICTED", canary_hash, True, "IT", ""),
        },
    )

    # Tamper with file A and canary C
    file_a.write_bytes(b"ENCRYPTED_RANSOMWARE_PAYLOAD")
    file_c.write_bytes(b"CANARY_TAMPERED")

    # Add an untracked file
    untracked = lab_dir / "ransom_note.txt"
    untracked.write_bytes(b"YOUR FILES ARE ENCRYPTED")

    result = ManifestManager.verify_integrity(base_lab_dir=lab_dir, manifest=manifest)
    assert result.is_valid is False
    assert "doc_a.txt" in result.modified_files
    assert "missing.txt" in result.missing_files
    assert "ransom_note.txt" in result.untracked_files
    assert "canary.json" in result.canary_tampered_files
