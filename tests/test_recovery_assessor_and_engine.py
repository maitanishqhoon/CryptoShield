"""
Unit and cryptographic tamper tests for CryptoShield Recovery Assessor and Engine (Phase 6, Task 2).

Tests:
1. 5-state integrity assessments (INTACT, MODIFIED, MISSING, UNREADABLE, UNTRACKED) and canary tracking.
2. Scoping and filtering (target_relative_path, target_directory).
3. Authenticated snapshot unlocking with RSA-OAEP key unwrapping and AES-GCM manifest authentication.
4. Two-Gate verified streaming decryption (empty, small, multi-chunk).
5. Tamper detection and guaranteed unverified plaintext cleanup across ciphertext, AAD, header, and SHA-256 gates.
6. Real vault snapshot integration (SNAP-266B3E3E) in read-only mode.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import pytest

from app.config import CONFIG
from app.core.models import ManifestEntry
from app.core.safety import generate_lab_marker
from app.recovery.models import (
    FileAssessmentStatus,
    PlannedRecoveryAction,
    RecoveryAuthenticationError,
    RecoveryError,
    RecoveryIntegrityError,
)
from app.recovery.recovery_assessor import RecoveryAssessor
from app.recovery.recovery_engine import RecoveryEngine
from app.recovery.workspace_manager import RecoveryWorkspaceManager
from app.vault.crypto_engine import (
    CryptoEngine,
    HEADER_MAGIC,
    HEADER_SIZE,
    HEADER_STRUCT_FMT,
    HEADER_VERSION,
)
from app.vault.key_manager import KeyManager
from app.vault.models import EncryptedObjectRecord, SnapshotManifest
from app.vault.snapshot_manifest import SnapshotManifestManager


@pytest.fixture
def test_vault_and_lab(tmp_path: Path):
    """Fixture providing a mock lab, mock vault, and isolated staging directory."""
    lab_dir = tmp_path / "lab"
    vault_dir = tmp_path / "vault"
    keys_dir = tmp_path / "keys"
    staging_dir = tmp_path / "staging"
    workspaces_root = tmp_path / "workspaces"

    lab_dir.mkdir(parents=True, exist_ok=True)
    vault_dir.mkdir(parents=True, exist_ok=True)
    keys_dir.mkdir(parents=True, exist_ok=True)
    staging_dir.mkdir(parents=True, exist_ok=True)
    workspaces_root.mkdir(parents=True, exist_ok=True)

    # Initialize authentic lab marker in lab_dir
    marker = generate_lab_marker(base_lab_dir=lab_dir)
    with open(lab_dir / CONFIG.LAB_MARKER_FILENAME, "w", encoding="utf-8") as f:
        json.dump(marker.to_dict(), f, indent=2)

    # Initialize RSA key pair (Envelope v2)
    km = KeyManager(keys_dir=keys_dir)
    km.generate_key_pair("TestVaultPassphrase2026!", key_size=2048)
    pub_key = km.load_public_key()

    ws_mgr = RecoveryWorkspaceManager(workspaces_root=workspaces_root, lab_dir=lab_dir)
    assessor = RecoveryAssessor(workspace_manager=ws_mgr, chunk_size=4096)
    smm = SnapshotManifestManager()
    engine = RecoveryEngine(
        vault_dir=vault_dir,
        staging_dir=staging_dir,
        key_manager=km,
        manifest_manager=smm,
        chunk_size=4096,
    )

    return {
        "lab_dir": lab_dir,
        "vault_dir": vault_dir,
        "keys_dir": keys_dir,
        "staging_dir": staging_dir,
        "workspaces_root": workspaces_root,
        "key_manager": km,
        "manifest_manager": smm,
        "workspace_manager": ws_mgr,
        "assessor": assessor,
        "engine": engine,
        "public_key": pub_key,
        "passphrase": "TestVaultPassphrase2026!",
    }


def _create_mock_snapshot_with_files(
    env: Dict[str, Any],
    snapshot_id: str,
    file_specs: Dict[str, bytes],
    canary_paths: Set[str],
) -> Tuple[bytes, SnapshotManifest]:
    """Helper to encrypt test files and build an authenticated snapshot directory."""
    lab_dir = env["lab_dir"]
    vault_dir = env["vault_dir"]
    km: KeyManager = env["key_manager"]
    smm: SnapshotManifestManager = env["manifest_manager"]
    pub_key = env["public_key"]

    snap_dir = vault_dir / snapshot_id
    objects_dir = snap_dir / "objects"
    objects_dir.mkdir(parents=True, exist_ok=True)

    aes_key = km.generate_snapshot_aes_key()
    wrapped_key = km.wrap_aes_key(pub_key, aes_key, snapshot_id)

    crypto_engine = CryptoEngine(chunk_size=4096)
    records: Dict[str, EncryptedObjectRecord] = {}
    opaque_map: Dict[str, str] = {}

    idx = 1
    total_bytes = 0
    for rel_path, data in file_specs.items():
        src_path = lab_dir / rel_path
        src_path.parent.mkdir(parents=True, exist_ok=True)
        src_path.write_bytes(data)

        total_bytes += len(data)
        file_hash = hashlib.sha256(data).hexdigest().lower()
        is_canary = rel_path in canary_paths
        dept = rel_path.split("/")[0]

        entry = ManifestEntry(
            relative_path=rel_path,
            file_type=rel_path.split(".")[-1],
            file_size_bytes=len(data),
            data_classification="CONFIDENTIAL" if is_canary else "INTERNAL",
            sha256=file_hash,
            is_canary=is_canary,
            department=dept,
            created_at="2026-11-16T00:00:00Z",
        )

        opaque_id = f"OBJ-{idx:04d}"
        dest_cso = objects_dir / f"{opaque_id}.cso"
        rec = crypto_engine.encrypt_file(
            source_path=src_path,
            dest_path=dest_cso,
            key=aes_key,
            snapshot_id=snapshot_id,
            opaque_id=opaque_id,
            entry=entry,
            base_lab_dir=lab_dir,
        )
        records[rel_path] = rec
        opaque_map[opaque_id] = rel_path
        idx += 1

    manifest = SnapshotManifest(
        snapshot_id=snapshot_id,
        format_version="1.0.0",
        created_at="2026-11-16T00:00:00Z",
        lab_id="mock-lab-id",
        total_files=len(records),
        total_original_bytes=total_bytes,
        canary_count=len(canary_paths),
        entries=records,
        opaque_id_map=opaque_map,
    )

    nonce, tag, enc_size = smm.encrypt_manifest(
        manifest=manifest,
        dest_path=snap_dir / "manifest.enc",
        key=aes_key,
    )

    metadata = {
        "snapshot_id": snapshot_id,
        "format_version": "1.0.0",
        "completed_status": "COMPLETED",
        "total_files": len(records),
        "total_original_bytes": total_bytes,
        "total_encrypted_bytes": enc_size + sum(r.encrypted_size_bytes for r in records.values()),
        "key_id": "KEY-MOCK",
        "wrapped_aes_key_b64": base64.b64encode(wrapped_key).decode("utf-8"),
        "manifest_nonce_b64": base64.b64encode(nonce).decode("utf-8"),
        "manifest_tag_b64": base64.b64encode(tag).decode("utf-8"),
        "manifest_encrypted_size": enc_size,
        "source_lab_id": "mock-lab-id",
    }
    with open(snap_dir / "snapshot.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return aes_key, manifest


# ============================================================================
# 1. Assessor 5-State Taxonomy & Canary Tracking
# ============================================================================

def test_assessor_all_five_statuses_and_canary_tracking(test_vault_and_lab, monkeypatch):
    env = test_vault_and_lab
    assessor: RecoveryAssessor = env["assessor"]
    ws_mgr: RecoveryWorkspaceManager = env["workspace_manager"]

    files_data = {
        "Finance/invoices/inv1.txt": b"Invoice 1 data",
        "Finance/invoices/inv2.txt": b"Invoice 2 data",
        "Finance/canary_banking.json": b'{"canary": "token1"}',
        "HR/employees/emp1.csv": b"id,name\n1,Alice",
        "HR/canary_salaries.csv": b"salaries canary data",
        "IT/configs/srv1.xml": b"<config>1</config>",
        "Legal/contracts/doc1.md": b"# Contract 1",
    }
    canary_paths = {"Finance/canary_banking.json", "HR/canary_salaries.csv"}

    _, manifest = _create_mock_snapshot_with_files(
        env, "SNAP-ASSESS-01", files_data, canary_paths
    )

    # Create workspace seeded from lab
    meta = ws_mgr.create_workspace("WKSP-ASSESS-01", seed_from_lab=True)
    ws_dir = meta.workspace_path

    # Set up scenarios:
    # 1. INTACT: "Finance/invoices/inv1.txt" and "HR/employees/emp1.csv"
    # 2. MODIFIED: "Finance/canary_banking.json" (canary) and "IT/configs/srv1.xml"
    (ws_dir / "Finance/canary_banking.json").write_bytes(b"CORRUPTED CANARY DATA")
    (ws_dir / "IT/configs/srv1.xml").write_bytes(b"<config>TAMPERED</config>")

    # 3. MISSING: "HR/canary_salaries.csv" (canary) and "Legal/contracts/doc1.md"
    (ws_dir / "HR/canary_salaries.csv").unlink()
    (ws_dir / "Legal/contracts/doc1.md").unlink()

    # 4. UNTRACKED: Two new files not in manifest
    (ws_dir / "UNTRACKED_001.txt").write_bytes(b"Artifact 1")
    (ws_dir / "Finance/untracked_memo.txt").write_bytes(b"Artifact 2")

    # 5. UNREADABLE: Simulate permission error on "Finance/invoices/inv2.txt"
    orig_compute = assessor.compute_file_sha256

    def mock_compute(path: Path):
        if "inv2.txt" in path.name:
            raise PermissionError("Access denied simulated")
        return orig_compute(path)

    monkeypatch.setattr(assessor, "compute_file_sha256", mock_compute)

    # Ensure evidence quarantine and recovery marker exist in workspace
    (ws_dir / CONFIG.RECOVERY_EVIDENCE_DIRNAME / "test.evd").write_bytes(b"evidence")

    # Assess with overwrite_modified=False
    summary_no_overwrite = assessor.assess_workspace(
        workspace_id="WKSP-ASSESS-01",
        manifest=manifest,
        overwrite_modified=False,
    )

    assert summary_no_overwrite.intact_count == 2
    assert summary_no_overwrite.modified_count == 2
    assert summary_no_overwrite.missing_count == 2
    assert summary_no_overwrite.unreadable_count == 1
    assert summary_no_overwrite.untracked_count == 2
    # Canaries affected: Finance/canary_banking.json (MODIFIED) + HR/canary_salaries.csv (MISSING) = 2
    assert summary_no_overwrite.canary_affected_count == 2

    # Verify planned actions when overwrite_modified=False
    mod_canary = summary_no_overwrite.records["Finance/canary_banking.json"]
    assert mod_canary.status == FileAssessmentStatus.MODIFIED
    assert mod_canary.planned_action == PlannedRecoveryAction.SKIP_MODIFIED_NO_OVERWRITE_AUTH
    assert mod_canary.is_canary is True

    miss_canary = summary_no_overwrite.records["HR/canary_salaries.csv"]
    assert miss_canary.status == FileAssessmentStatus.MISSING
    assert miss_canary.planned_action == PlannedRecoveryAction.RESTORE_MISSING
    assert miss_canary.is_canary is True

    unread_rec = summary_no_overwrite.records["Finance/invoices/inv2.txt"]
    assert unread_rec.status == FileAssessmentStatus.UNREADABLE
    assert unread_rec.planned_action == PlannedRecoveryAction.MANUAL_REVIEW_UNREADABLE
    assert "PermissionError" in str(unread_rec.error_detail)

    untracked_rec = summary_no_overwrite.records["UNTRACKED_001.txt"]
    assert untracked_rec.status == FileAssessmentStatus.UNTRACKED
    assert untracked_rec.planned_action == PlannedRecoveryAction.PRESERVE_UNTRACKED
    assert untracked_rec.is_canary is False

    # Reserved marker and evidence quarantine MUST NOT be flagged as UNTRACKED
    assert CONFIG.RECOVERY_MARKER_FILENAME not in summary_no_overwrite.records
    assert f"{CONFIG.RECOVERY_EVIDENCE_DIRNAME}/test.evd" not in summary_no_overwrite.records

    # Assess with overwrite_modified=True
    summary_overwrite = assessor.assess_workspace(
        workspace_id="WKSP-ASSESS-01",
        manifest=manifest,
        overwrite_modified=True,
    )
    assert (
        summary_overwrite.records["Finance/canary_banking.json"].planned_action
        == PlannedRecoveryAction.RESTORE_MODIFIED_PRESERVE_EVIDENCE
    )


# ============================================================================
# 2. Assessor Selective Scoping (File & Directory)
# ============================================================================

def test_assessor_selective_file_and_directory_scoping(test_vault_and_lab):
    env = test_vault_and_lab
    assessor: RecoveryAssessor = env["assessor"]
    ws_mgr: RecoveryWorkspaceManager = env["workspace_manager"]

    files_data = {
        "Finance/invoices/inv1.txt": b"Invoice 1",
        "Finance/invoices/inv2.txt": b"Invoice 2",
        "HR/employees/emp1.csv": b"Employee 1",
    }
    _, manifest = _create_mock_snapshot_with_files(
        env, "SNAP-SCOPE-01", files_data, set()
    )
    ws_mgr.create_workspace("WKSP-SCOPE-01", seed_from_lab=True)

    # 1. Single file filter
    summary_file = assessor.assess_workspace(
        "WKSP-SCOPE-01",
        manifest,
        target_relative_path="Finance/invoices/inv1.txt",
    )
    assert len(summary_file.records) == 1
    assert "Finance/invoices/inv1.txt" in summary_file.records
    assert summary_file.total_manifest_files == 1

    # Single non-existent relative path raises RecoveryError
    with pytest.raises(RecoveryError, match="not found in manifest"):
        assessor.assess_workspace(
            "WKSP-SCOPE-01",
            manifest,
            target_relative_path="Finance/nonexistent.txt",
        )

    # 2. Directory prefix filter
    summary_dept = assessor.assess_workspace(
        "WKSP-SCOPE-01",
        manifest,
        target_directory="Finance",
    )
    assert len(summary_dept.records) == 2
    assert "Finance/invoices/inv1.txt" in summary_dept.records
    assert "Finance/invoices/inv2.txt" in summary_dept.records
    assert "HR/employees/emp1.csv" not in summary_dept.records

    # Directory with no entries raises RecoveryError
    with pytest.raises(RecoveryError, match="no matching entries"):
        assessor.assess_workspace(
            "WKSP-SCOPE-01",
            manifest,
            target_directory="Legal",
        )


# ============================================================================
# 3. Engine Snapshot Unlock Rejects Wrong Passphrase
# ============================================================================

def test_engine_unlock_snapshot_wrong_passphrase_rejected(test_vault_and_lab):
    env = test_vault_and_lab
    engine: RecoveryEngine = env["engine"]

    files_data = {"Finance/doc.txt": b"Some content"}
    _create_mock_snapshot_with_files(env, "SNAP-PASS-01", files_data, set())

    with pytest.raises(RecoveryAuthenticationError, match="Private key authentication failed"):
        engine.unlock_snapshot("SNAP-PASS-01", "WrongPassphrase123!")


# ============================================================================
# 4. Engine Snapshot Unlock Rejects Corrupted Manifest
# ============================================================================

def test_engine_unlock_snapshot_corrupted_manifest_rejected(test_vault_and_lab):
    env = test_vault_and_lab
    engine: RecoveryEngine = env["engine"]
    vault_dir = env["vault_dir"]

    files_data = {"Finance/doc.txt": b"Some content"}
    _create_mock_snapshot_with_files(env, "SNAP-CORRUPT-MAN-01", files_data, set())

    # Flip byte in manifest.enc
    manifest_enc_path = vault_dir / "SNAP-CORRUPT-MAN-01" / "manifest.enc"
    enc_data = bytearray(manifest_enc_path.read_bytes())
    enc_data[10] ^= 0xFF
    manifest_enc_path.write_bytes(bytes(enc_data))

    with pytest.raises(RecoveryAuthenticationError, match="Manifest decryption or authentication failed"):
        engine.unlock_snapshot("SNAP-CORRUPT-MAN-01", env["passphrase"])


# ============================================================================
# 5. Engine Stage Empty, Small, and Multi-Chunk Files
# ============================================================================

def test_engine_stage_empty_small_and_multichunk_large_files(test_vault_and_lab):
    env = test_vault_and_lab
    engine: RecoveryEngine = env["engine"]

    empty_content = b""
    small_content = b"Small payload for single chunk encryption test."
    # Multi-chunk content: 200 KiB crossing multiple 4 KiB chunk boundaries
    large_content = os.urandom(200 * 1024)

    files_data = {
        "Finance/empty.txt": empty_content,
        "HR/small.txt": small_content,
        "IT/large.bin": large_content,
    }
    aes_key, manifest = _create_mock_snapshot_with_files(
        env, "SNAP-CHUNK-01", files_data, set()
    )

    stage_dir = engine.create_staging_session("sess_chunks")

    try:
        for rel, content in files_data.items():
            rec = manifest.entries[rel]
            res = engine.stage_decrypted_object("SNAP-CHUNK-01", aes_key, rec, stage_dir)

            assert res.gcm_authenticated is True
            assert res.sha256_verified is True
            assert res.computed_sha256 == hashlib.sha256(content).hexdigest().lower()
            assert res.decrypted_size_bytes == len(content)
            assert res.staged_path.is_file()
            assert res.staged_path.read_bytes() == content
    finally:
        engine.cleanup_staging_session(stage_dir)
        assert not stage_dir.exists()


# ============================================================================
# 6. Ciphertext Tampering Deletes Unverified Staged File
# ============================================================================

def test_engine_ciphertext_tampering_deletes_unverified_staged_file(test_vault_and_lab):
    env = test_vault_and_lab
    engine: RecoveryEngine = env["engine"]
    vault_dir = env["vault_dir"]

    # Multi-chunk file to ensure streaming writes occur before finalize()
    content = os.urandom(64 * 1024)
    files_data = {"Finance/tamper_test.bin": content}
    aes_key, manifest = _create_mock_snapshot_with_files(
        env, "SNAP-TAMPER-CIPH-01", files_data, set()
    )

    rec = manifest.entries["Finance/tamper_test.bin"]
    cso_path = vault_dir / "SNAP-TAMPER-CIPH-01" / "objects" / f"{rec.opaque_id}.cso"

    # Flip 1 bit in the last 16 bytes of ciphertext
    cso_bytes = bytearray(cso_path.read_bytes())
    cso_bytes[-10] ^= 0x01
    cso_path.write_bytes(bytes(cso_bytes))

    stage_dir = engine.create_staging_session("sess_ciph_tamper")
    staged_part_path = stage_dir / f"{rec.opaque_id}.part"

    try:
        with pytest.raises(RecoveryAuthenticationError, match="GCM authentication failed"):
            engine.stage_decrypted_object("SNAP-TAMPER-CIPH-01", aes_key, rec, stage_dir)

        # Zero plaintext leakage: .part file MUST NOT exist on disk
        assert not staged_part_path.exists()
    finally:
        engine.cleanup_staging_session(stage_dir)


# ============================================================================
# 7. AAD Tampering Rejected & Staged File Cleaned Up
# ============================================================================

def test_engine_aad_tampering_rejected_and_cleaned_up(test_vault_and_lab):
    env = test_vault_and_lab
    engine: RecoveryEngine = env["engine"]

    files_data = {"Finance/aad_test.txt": b"AAD binding test content."}
    aes_key, manifest = _create_mock_snapshot_with_files(
        env, "SNAP-TAMPER-AAD-01", files_data, set()
    )

    rec = manifest.entries["Finance/aad_test.txt"]

    # Tamper with metadata on record (e.g. department)
    tampered_rec = EncryptedObjectRecord.from_dict(rec.to_dict())
    tampered_rec.department = "HackedDepartment"

    stage_dir = engine.create_staging_session("sess_aad_tamper")
    staged_part_path = stage_dir / f"{rec.opaque_id}.part"

    try:
        with pytest.raises(RecoveryAuthenticationError, match="GCM authentication failed"):
            engine.stage_decrypted_object("SNAP-TAMPER-AAD-01", aes_key, tampered_rec, stage_dir)

        assert not staged_part_path.exists()
    finally:
        engine.cleanup_staging_session(stage_dir)


# ============================================================================
# 8. Header Magic or Nonce Tampering Rejected
# ============================================================================

def test_engine_header_magic_or_nonce_tampering_rejected(test_vault_and_lab):
    env = test_vault_and_lab
    engine: RecoveryEngine = env["engine"]
    vault_dir = env["vault_dir"]

    files_data = {"Finance/header_test.txt": b"Header validation test content."}
    aes_key, manifest = _create_mock_snapshot_with_files(
        env, "SNAP-TAMPER-HDR-01", files_data, set()
    )

    rec = manifest.entries["Finance/header_test.txt"]
    cso_path = vault_dir / "SNAP-TAMPER-HDR-01" / "objects" / f"{rec.opaque_id}.cso"
    original_cso_bytes = cso_path.read_bytes()

    stage_dir = engine.create_staging_session("sess_hdr_tamper")
    staged_part_path = stage_dir / f"{rec.opaque_id}.part"

    try:
        # Case A: Corrupt magic bytes b"CSO1" -> b"BAD1"
        tampered_cso = bytearray(original_cso_bytes)
        tampered_cso[0:4] = b"BAD1"
        cso_path.write_bytes(bytes(tampered_cso))

        with pytest.raises(RecoveryAuthenticationError, match="Invalid .cso header magic or version"):
            engine.stage_decrypted_object("SNAP-TAMPER-HDR-01", aes_key, rec, stage_dir)
        assert not staged_part_path.exists()

        # Case B: Corrupt nonce in header
        tampered_cso = bytearray(original_cso_bytes)
        tampered_cso[7] ^= 0xFF  # Inside 12-byte nonce
        cso_path.write_bytes(bytes(tampered_cso))

        with pytest.raises(RecoveryAuthenticationError, match="Header nonce/tag mismatch"):
            engine.stage_decrypted_object("SNAP-TAMPER-HDR-01", aes_key, rec, stage_dir)
        assert not staged_part_path.exists()

    finally:
        engine.cleanup_staging_session(stage_dir)


# ============================================================================
# 9. Gate 2 SHA-256 Mismatch Deletes Staged File
# ============================================================================

def test_engine_sha256_mismatch_gate_deletes_staged_file(test_vault_and_lab, monkeypatch):
    env = test_vault_and_lab
    engine: RecoveryEngine = env["engine"]

    files_data = {"Finance/sha256_gate.txt": b"Integrity gate test payload."}
    aes_key, manifest = _create_mock_snapshot_with_files(
        env, "SNAP-SHA-GATE-01", files_data, set()
    )

    rec = manifest.entries["Finance/sha256_gate.txt"]
    stage_dir = engine.create_staging_session("sess_sha_gate")
    staged_part_path = stage_dir / f"{rec.opaque_id}.part"

    # Monkeypatch hashlib.sha256 so Gate 1 (GCM) succeeds but Gate 2 detects hash mismatch
    orig_sha256 = hashlib.sha256

    class SpoofedHasher:
        def __init__(self, *args, **kwargs):
            self.real = orig_sha256(*args, **kwargs)

        def update(self, data):
            self.real.update(data)

        def hexdigest(self):
            return "0" * 64  # Mismatched hash

    monkeypatch.setattr(hashlib, "sha256", SpoofedHasher)

    try:
        with pytest.raises(RecoveryIntegrityError, match="SHA-256 or size mismatch"):
            engine.stage_decrypted_object("SNAP-SHA-GATE-01", aes_key, rec, stage_dir)

        # Zero plaintext leakage: .part file MUST be deleted immediately
        assert not staged_part_path.exists()
    finally:
        engine.cleanup_staging_session(stage_dir)


# ============================================================================
# 10. Real Vault Snapshot Integration (SNAP-266B3E3E, Read-Only)
# ============================================================================

def test_real_vault_snapshot_unlock_and_canary_staging_readonly(tmp_path: Path):
    real_snapshot_id = "SNAP-266B3E3E"
    real_snap_dir = CONFIG.VAULT_DIR / real_snapshot_id

    if not real_snap_dir.exists():
        pytest.skip(f"Real vault snapshot '{real_snapshot_id}' not found in runtime/vault/")

    engine = RecoveryEngine(
        vault_dir=CONFIG.VAULT_DIR,
        staging_dir=tmp_path / "staging",
        key_manager=KeyManager(keys_dir=CONFIG.KEYS_DIR),
        manifest_manager=SnapshotManifestManager(),
        chunk_size=64 * 1024,
    )

    passphrase = "CryptoShieldVaultPassphrase2026!"
    aes_key, manifest, metadata = engine.unlock_snapshot(real_snapshot_id, passphrase)

    assert len(aes_key) == 32
    assert manifest.snapshot_id == real_snapshot_id
    assert manifest.total_files > 0
    assert metadata["completed_status"] == "COMPLETED"

    stage_dir = engine.create_staging_session("sess_real_vault")

    try:
        # Find 4 normal files and 1 canary file
        canary_recs = [r for r in manifest.entries.values() if r.is_canary]
        normal_recs = [r for r in manifest.entries.values() if not r.is_canary]

        assert len(canary_recs) >= 1
        assert len(normal_recs) >= 4

        selected = [canary_recs[0]] + normal_recs[:4]

        for rec in selected:
            staged = engine.stage_decrypted_object(
                real_snapshot_id,
                aes_key,
                rec,
                stage_dir,
            )
            assert staged.gcm_authenticated is True
            assert staged.sha256_verified is True
            assert staged.computed_sha256 == rec.original_sha256.lower()
            assert staged.decrypted_size_bytes == rec.original_size_bytes
            assert staged.staged_path.is_file()
            assert staged.is_canary == rec.is_canary

    finally:
        engine.cleanup_staging_session(stage_dir)
        assert not stage_dir.exists()
