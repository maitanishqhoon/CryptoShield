"""
Unit tests for CryptoShield Recovery Workspace Management (Phase 6, Task 1).

Tests isolated, marker-authenticated recovery workspaces under runtime/recovery/workspaces/
guaranteeing that the protected runtime/lab/ baseline is never altered or targeted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import pytest

from app.config import CONFIG
from app.core.models import Manifest, ManifestEntry
from app.core.safety import generate_lab_marker, verify_lab_marker
from app.recovery.models import (
    FileAssessmentRecord,
    FileAssessmentStatus,
    FileRestorationOutcome,
    FileRestorationRecord,
    PlannedRecoveryAction,
    RecoveryAuthenticationError,
    RecoveryError,
    RecoveryIntegrityError,
    RecoveryMode,
    RecoveryOperationReport,
    RecoveryWorkspaceMarker,
    RestorationPolicyError,
    StagedObjectResult,
    WorkspaceAssessmentSummary,
    WorkspaceMetadata,
    WorkspaceNotFoundError,
    WorkspaceSafetyError,
)
from app.recovery.workspace_manager import RecoveryWorkspaceManager


@pytest.fixture
def recovery_env(tmp_path: Path):
    """Fixture providing isolated mock workspaces_root and lab_dir."""
    workspaces_root = tmp_path / "recovery" / "workspaces"
    lab_dir = tmp_path / "lab"
    workspaces_root.mkdir(parents=True, exist_ok=True)
    lab_dir.mkdir(parents=True, exist_ok=True)

    # Initialize authentic lab marker in lab_dir
    marker = generate_lab_marker(base_lab_dir=lab_dir)
    marker_file = lab_dir / CONFIG.LAB_MARKER_FILENAME
    with open(marker_file, "w", encoding="utf-8") as f:
        json.dump(marker.to_dict(), f, indent=2)

    mgr = RecoveryWorkspaceManager(
        workspaces_root=workspaces_root,
        lab_dir=lab_dir,
    )
    return {
        "manager": mgr,
        "workspaces_root": workspaces_root,
        "lab_dir": lab_dir,
        "lab_marker": marker,
    }


def _create_mock_lab_dataset(lab_dir: Path, marker_id: str) -> Dict[str, str]:
    """Helper to populate mock lab with normal and canary files alongside baseline manifest."""
    files_data = {
        "Finance/invoices/inv_001.txt": "Invoice 001 content",
        "Finance/invoices/inv_002.txt": "Invoice 002 content",
        "Finance/canary_banking_credentials.json": '{"canary": true, "key": "secret"}',
        "HR/employees/emp_001.csv": "id,name,role\n1,Alice,Engineer",
        "HR/canary_salaries_2026.csv": "canary_token_salaries_data",
        "IT/configs/server.xml": "<config><host>localhost</host></config>",
        "Legal/contracts/contract_001.md": "# Mutual NDA Contract",
        "Operations/logs/service.log": "2026-11-16 system healthy",
    }

    entries = {}
    for rel, content in files_data.items():
        p = lab_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        is_canary = "canary" in rel.lower()
        entries[rel] = ManifestEntry(
            relative_path=rel,
            file_type=rel.split(".")[-1],
            file_size_bytes=len(content.encode("utf-8")),
            data_classification="CONFIDENTIAL" if is_canary else "INTERNAL",
            sha256="dummy_sha256",
            is_canary=is_canary,
            department=rel.split("/")[0],
            created_at="2026-11-16T00:00:00Z",
        )

    manifest = Manifest(
        manifest_version="1.0.0",
        lab_id=marker_id,
        generated_at="2026-11-16T00:00:00Z",
        total_files=len(entries),
        total_size_bytes=sum(e.file_size_bytes for e in entries.values()),
        canary_count=sum(1 for e in entries.values() if e.is_canary),
        seed=42,
        entries=entries,
    )

    manifest_file = lab_dir / CONFIG.MANIFEST_FILENAME
    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest.to_dict(), f, indent=2)

    return files_data


# ============================================================================
# 1. Empty Workspace Creation & Marker Verification
# ============================================================================

def test_create_empty_workspace_and_verify_marker(recovery_env):
    mgr = recovery_env["manager"]
    workspaces_root = recovery_env["workspaces_root"]

    meta = mgr.create_workspace()
    assert meta.workspace_id.startswith("WKSP-")
    assert meta.marker_valid is True
    assert meta.seeded_file_count == 0
    assert meta.workspace_path.is_dir()
    assert meta.workspace_path.parent == workspaces_root

    # Verify evidence quarantine directory exists
    quarantine_dir = meta.workspace_path / CONFIG.RECOVERY_EVIDENCE_DIRNAME
    assert quarantine_dir.is_dir()

    # Verify marker
    marker = mgr.verify_workspace_marker(meta.workspace_id)
    assert marker.workspace_id == meta.workspace_id
    assert marker.authorized_root == str(meta.workspace_path.resolve())
    assert marker.seeded_file_count == 0
    assert len(marker.signature) == 64  # SHA-256 HMAC


# ============================================================================
# 2. Seeded Workspace Creation Preserving Canaries and Lab Baseline
# ============================================================================

def test_create_seeded_workspace_preserves_canaries_and_lab_baseline(recovery_env):
    mgr = recovery_env["manager"]
    lab_dir = recovery_env["lab_dir"]
    marker_id = recovery_env["lab_marker"].lab_id

    files_data = _create_mock_lab_dataset(lab_dir, marker_id)

    # Capture initial lab state
    initial_lab_files = {p: p.read_bytes() for p in lab_dir.rglob("*") if p.is_file()}

    # Seed with max_seed_files=4: total 8 files in lab, 2 are canaries
    meta = mgr.create_workspace(
        workspace_id="WKSP-SEED0001",
        seed_from_lab=True,
        max_seed_files=4,
        source_snapshot_id="SNAP-TEST-001",
    )

    assert meta.workspace_id == "WKSP-SEED0001"
    assert meta.seeded_file_count == 4
    assert meta.source_snapshot_id == "SNAP-TEST-001"

    ws_path = meta.workspace_path
    # Both canaries MUST be prioritized and present in the seeded workspace
    assert (ws_path / "Finance/canary_banking_credentials.json").exists()
    assert (ws_path / "HR/canary_salaries_2026.csv").exists()

    # Reserved lab marker and manifest MUST NOT be copied into workspace files
    assert not (ws_path / CONFIG.LAB_MARKER_FILENAME).exists()
    assert not (ws_path / CONFIG.MANIFEST_FILENAME).exists()

    # Recovery marker exists and is valid
    assert (ws_path / CONFIG.RECOVERY_MARKER_FILENAME).exists()
    marker = mgr.verify_workspace_marker(meta.workspace_id)
    assert marker.seeded_file_count == 4

    # Lab directory MUST remain 100% untouched
    current_lab_files = {p: p.read_bytes() for p in lab_dir.rglob("*") if p.is_file()}
    assert initial_lab_files == current_lab_files
    assert verify_lab_marker(lab_dir).lab_id == marker_id


# ============================================================================
# 3. Marker Tampering Detection
# ============================================================================

def test_marker_tampering_raises_workspace_safety_error(recovery_env):
    mgr = recovery_env["manager"]
    meta = mgr.create_workspace("WKSP-TAMPER01")
    marker_path = meta.workspace_path / CONFIG.RECOVERY_MARKER_FILENAME

    # Read authentic marker data
    with open(marker_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Case A: Tamper authorized_root
    tampered_data = dict(data)
    tampered_data["authorized_root"] = "C:\\some\\other\\path"
    with open(marker_path, "w", encoding="utf-8") as f:
        json.dump(tampered_data, f)
    with pytest.raises(WorkspaceSafetyError, match="does not match current workspace"):
        mgr.verify_workspace_marker("WKSP-TAMPER01")

    # Case B: Tamper seeded_file_count (signature mismatch)
    tampered_data = dict(data)
    tampered_data["seeded_file_count"] = 9999
    with open(marker_path, "w", encoding="utf-8") as f:
        json.dump(tampered_data, f)
    with pytest.raises(WorkspaceSafetyError, match="signature validation failed"):
        mgr.verify_workspace_marker("WKSP-TAMPER01")

    # Case C: Tamper signature directly
    tampered_data = dict(data)
    tampered_data["signature"] = "0" * 64
    with open(marker_path, "w", encoding="utf-8") as f:
        json.dump(tampered_data, f)
    with pytest.raises(WorkspaceSafetyError, match="signature validation failed"):
        mgr.verify_workspace_marker("WKSP-TAMPER01")

    # Case D: Corrupt JSON syntax
    with open(marker_path, "w", encoding="utf-8") as f:
        f.write("{invalid_json:")
    with pytest.raises(WorkspaceSafetyError, match="Failed to read or parse"):
        mgr.verify_workspace_marker("WKSP-TAMPER01")


# ============================================================================
# 4. Rejection of Laboratory Directory as Recovery Workspace
# ============================================================================

def test_reject_lab_directory_as_recovery_workspace(recovery_env):
    mgr = recovery_env["manager"]
    lab_dir = recovery_env["lab_dir"]

    # Attempt to verify lab_dir as a workspace
    with pytest.raises(WorkspaceSafetyError, match="protected laboratory directory"):
        mgr.verify_workspace_marker(lab_dir)

    # Attempt to validate path targeting lab_dir
    with pytest.raises(WorkspaceSafetyError):
        mgr.validate_workspace_path(str(lab_dir), "Finance/file.txt")

    # Attempt to delete lab_dir via workspace manager
    with pytest.raises(WorkspaceSafetyError):
        mgr.delete_workspace(str(lab_dir))

    # Attempt to simulate damage on lab_dir
    with pytest.raises(WorkspaceSafetyError):
        mgr.simulate_workspace_damage(str(lab_dir))

    # Attempt to create workspace with traversal ID
    with pytest.raises(WorkspaceSafetyError):
        mgr.create_workspace("../lab")
    with pytest.raises(WorkspaceSafetyError):
        mgr.create_workspace("..")


# ============================================================================
# 5. Path Traversal & Reserved File Protection
# ============================================================================

def test_path_traversal_and_reserved_file_protection(recovery_env, tmp_path: Path):
    mgr = recovery_env["manager"]
    meta = mgr.create_workspace("WKSP-TRAV0001")
    ws_id = meta.workspace_id

    # 1. Directory traversal via ".."
    with pytest.raises(WorkspaceSafetyError, match="[Pp]ath traversal"):
        mgr.validate_workspace_path(ws_id, "../outside.txt")
    with pytest.raises(WorkspaceSafetyError, match="[Pp]ath traversal"):
        mgr.validate_workspace_path(ws_id, "sub/../../escape.txt")

    # 2. Absolute path outside workspace
    outside = tmp_path / "outside_file.txt"
    outside.touch()
    with pytest.raises(WorkspaceSafetyError, match="outside authorized workspace"):
        mgr.validate_workspace_path(ws_id, outside)

    # 3. Workspace root targeting
    with pytest.raises(WorkspaceSafetyError, match="cannot be the workspace root"):
        mgr.validate_workspace_path(ws_id, ".")

    # 4. Reserved recovery marker protection
    with pytest.raises(WorkspaceSafetyError, match="reserved recovery file"):
        mgr.validate_workspace_path(ws_id, CONFIG.RECOVERY_MARKER_FILENAME)

    # 5. Evidence quarantine directory protection
    with pytest.raises(WorkspaceSafetyError, match="reserved recovery file"):
        mgr.validate_workspace_path(ws_id, f"{CONFIG.RECOVERY_EVIDENCE_DIRNAME}/item.evd")

    # 6. Explicit allow_reserved=True permits reading marker
    allowed_path = mgr.validate_workspace_path(
        ws_id, CONFIG.RECOVERY_MARKER_FILENAME, allow_reserved=True
    )
    assert allowed_path == meta.workspace_path / CONFIG.RECOVERY_MARKER_FILENAME


# ============================================================================
# 6. Symlink Escape Rejection
# ============================================================================

def test_symlink_escape_rejected(recovery_env, tmp_path: Path, monkeypatch):
    mgr = recovery_env["manager"]
    meta = mgr.create_workspace("WKSP-SYMLINK1")
    ws_path = meta.workspace_path

    outside_file = tmp_path / "secret.txt"
    outside_file.write_text("outside confidential data", encoding="utf-8")
    symlink_path = ws_path / "link_escape.txt"

    try:
        symlink_path.symlink_to(outside_file)
        with pytest.raises(WorkspaceSafetyError, match="[Ss]ymlink"):
            mgr.validate_workspace_path("WKSP-SYMLINK1", "link_escape.txt")
    except OSError:
        # On Windows environments where unprivileged symlink creation is denied:
        dummy_file = ws_path / "mock_symlink.txt"
        dummy_file.write_text("mocked", encoding="utf-8")
        orig_is_symlink = Path.is_symlink
        monkeypatch.setattr(
            Path,
            "is_symlink",
            lambda self: True if self.name == "mock_symlink.txt" else orig_is_symlink(self),
        )
        with pytest.raises(WorkspaceSafetyError, match="[Ss]ymlink"):
            mgr.validate_workspace_path("WKSP-SYMLINK1", "mock_symlink.txt")


# ============================================================================
# 7. Controlled Damage Simulation Bounded Strictly to Workspace
# ============================================================================

def test_simulate_workspace_damage_bounded_to_workspace(recovery_env):
    mgr = recovery_env["manager"]
    lab_dir = recovery_env["lab_dir"]
    marker_id = recovery_env["lab_marker"].lab_id

    _create_mock_lab_dataset(lab_dir, marker_id)
    initial_lab_hashes = {
        p.relative_to(lab_dir).as_posix(): p.read_bytes()
        for p in lab_dir.rglob("*")
        if p.is_file()
    }

    # Create workspace seeded with all lab files
    meta = mgr.create_workspace("WKSP-DAMAG001", seed_from_lab=True)
    ws_dir = meta.workspace_path

    damage = mgr.simulate_workspace_damage(
        workspace_id="WKSP-DAMAG001",
        modify_count=2,
        delete_count=2,
        untracked_count=2,
        include_canary=True,
    )

    assert len(damage["modified"]) == 2
    assert len(damage["deleted"]) == 2
    assert len(damage["untracked"]) == 2
    assert len(damage["canaries_affected"]) >= 2
    assert any(f in damage["canaries_affected"] for f in damage["modified"])
    assert any(f in damage["canaries_affected"] for f in damage["deleted"])

    # Verify modified and deleted sets are disjoint
    assert set(damage["modified"]).isdisjoint(set(damage["deleted"]))

    # Verify modifications applied
    for rel in damage["modified"]:
        p = ws_dir / rel
        assert p.is_file()
        content = p.read_bytes()
        assert b"# CRYPTOSHIELD_SIMULATED_CORRUPTION_MARKER" in content

    # Verify deletions applied
    for rel in damage["deleted"]:
        p = ws_dir / rel
        assert not p.exists()

    # Verify untracked artifacts created
    for name in damage["untracked"]:
        p = ws_dir / name
        assert p.is_file()
        assert "UNTRACKED_ARTIFACT_" in name

    # Verify laboratory baseline was completely untouched
    current_lab_hashes = {
        p.relative_to(lab_dir).as_posix(): p.read_bytes()
        for p in lab_dir.rglob("*")
        if p.is_file()
    }
    assert initial_lab_hashes == current_lab_hashes


# ============================================================================
# 8. List & Delete Workspace Lifecycle
# ============================================================================

def test_list_and_delete_workspace(recovery_env):
    mgr = recovery_env["manager"]

    meta_a = mgr.create_workspace("WKSP-ALPHA01")
    meta_b = mgr.create_workspace("WKSP-BETA002")

    workspaces = mgr.list_workspaces()
    assert len(workspaces) == 2
    ids = [w.workspace_id for w in workspaces]
    assert "WKSP-ALPHA01" in ids
    assert "WKSP-BETA002" in ids
    assert all(w.marker_valid for w in workspaces)

    # Tamper with BETA's marker signature
    beta_marker_file = meta_b.workspace_path / CONFIG.RECOVERY_MARKER_FILENAME
    with open(beta_marker_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    data["signature"] = "deadbeef" * 8
    with open(beta_marker_file, "w", encoding="utf-8") as f:
        json.dump(data, f)

    # list_workspaces must not crash; it reports marker_valid=False for BETA
    refreshed = mgr.list_workspaces()
    beta_meta = next(w for w in refreshed if w.workspace_id == "WKSP-BETA002")
    alpha_meta = next(w for w in refreshed if w.workspace_id == "WKSP-ALPHA01")
    assert alpha_meta.marker_valid is True
    assert beta_meta.marker_valid is False

    # Delete ALPHA workspace
    deleted = mgr.delete_workspace("WKSP-ALPHA01")
    assert deleted is True
    assert not meta_a.workspace_path.exists()

    with pytest.raises(WorkspaceNotFoundError):
        mgr.verify_workspace_marker("WKSP-ALPHA01")


# ============================================================================
# 9. Models & Enums Serialization Roundtrip
# ============================================================================

def test_models_serialization_roundtrip(tmp_path: Path):
    # 1. RecoveryWorkspaceMarker
    marker = RecoveryWorkspaceMarker(
        workspace_id="WKSP-TEST1234",
        workspace_uuid="uuid-1234-5678",
        authorized_root=str(tmp_path / "wksp"),
        source_snapshot_id="SNAP-001",
        seeded_file_count=42,
        created_at="2026-11-16T12:00:00Z",
        host_platform="Windows-11",
        signature="a" * 64,
    )
    marker_dict = marker.to_dict()
    marker_restored = RecoveryWorkspaceMarker.from_dict(marker_dict)
    assert marker == marker_restored

    # 2. WorkspaceMetadata
    meta = WorkspaceMetadata(
        workspace_id="WKSP-TEST1234",
        workspace_path=tmp_path / "wksp",
        created_at="2026-11-16T12:00:00Z",
        seeded_file_count=42,
        source_snapshot_id="SNAP-001",
        marker_valid=True,
    )
    meta_dict = meta.to_dict()
    meta_restored = WorkspaceMetadata.from_dict(meta_dict)
    assert meta == meta_restored

    # 3. FileAssessmentRecord
    far = FileAssessmentRecord(
        relative_path="Finance/ledger.csv",
        status=FileAssessmentStatus.MODIFIED,
        planned_action=PlannedRecoveryAction.RESTORE_MODIFIED_PRESERVE_EVIDENCE,
        expected_sha256="expectedhash123",
        current_sha256="currenthash456",
        expected_size_bytes=1024,
        current_size_bytes=2048,
        opaque_id="OBJ-9999",
        department="Finance",
        data_classification="CONFIDENTIAL",
        is_canary=False,
        error_detail=None,
    )
    far_dict = far.to_dict()
    far_restored = FileAssessmentRecord.from_dict(far_dict)
    assert far == far_restored

    # 4. WorkspaceAssessmentSummary
    summary = WorkspaceAssessmentSummary(
        assessment_id="ASSESS-12345678",
        workspace_id="WKSP-TEST1234",
        snapshot_id="SNAP-001",
        assessed_at="2026-11-16T12:00:00Z",
        total_manifest_files=10,
        total_workspace_files_scanned=10,
        intact_count=8,
        modified_count=1,
        missing_count=1,
        unreadable_count=0,
        untracked_count=0,
        canary_affected_count=0,
        duration_seconds=0.15,
        records={"Finance/ledger.csv": far},
    )
    summary_dict = summary.to_dict()
    summary_restored = WorkspaceAssessmentSummary.from_dict(summary_dict)
    assert summary == summary_restored

    # 5. StagedObjectResult
    staged = StagedObjectResult(
        relative_path="HR/staff.json",
        opaque_id="OBJ-1111",
        staged_path=tmp_path / "staging" / "OBJ-1111.dec",
        gcm_authenticated=True,
        sha256_verified=True,
        computed_sha256="hash123",
        expected_sha256="hash123",
        decrypted_size_bytes=512,
        is_canary=True,
        error_message=None,
    )
    staged_dict = staged.to_dict()
    staged_restored = StagedObjectResult.from_dict(staged_dict)
    assert staged == staged_restored

    # 6. FileRestorationRecord
    frr = FileRestorationRecord(
        relative_path="IT/server.xml",
        status_before=FileAssessmentStatus.MISSING,
        outcome=FileRestorationOutcome.RESTORED,
        opaque_id="OBJ-2222",
        restored_sha256="restoredhash",
        evidence_backup_path=None,
        is_canary=False,
        error_detail=None,
    )
    frr_dict = frr.to_dict()
    frr_restored = FileRestorationRecord.from_dict(frr_dict)
    assert frr == frr_restored

    # 7. RecoveryOperationReport
    report = RecoveryOperationReport(
        recovery_id="REC-12345678",
        workspace_id="WKSP-TEST1234",
        snapshot_id="SNAP-001",
        mode=RecoveryMode.FULL_WORKSPACE,
        dry_run=False,
        authorized=True,
        overwrite_modified=True,
        started_at="2026-11-16T12:00:00Z",
        completed_at="2026-11-16T12:00:05Z",
        duration_seconds=5.0,
        target_filter=None,
        total_evaluated=1,
        restored_count=1,
        skipped_intact_count=0,
        evidence_preserved_count=0,
        untracked_preserved_count=0,
        manual_review_count=0,
        failed_count=0,
        canary_restored_count=0,
        post_recovery_audit_passed=True,
        file_records=[frr],
    )
    report_dict = report.to_dict()
    report_restored = RecoveryOperationReport.from_dict(report_dict)
    assert report == report_restored

    # 8. Enums string inheritance & values
    assert issubclass(FileAssessmentStatus, str)
    assert issubclass(PlannedRecoveryAction, str)
    assert issubclass(RecoveryMode, str)
    assert issubclass(FileRestorationOutcome, str)

    assert FileAssessmentStatus.INTACT == "INTACT"
    assert PlannedRecoveryAction.RESTORE_MISSING == "RESTORE_MISSING"
    assert RecoveryMode.FULL_WORKSPACE == "FULL_WORKSPACE"
    assert FileRestorationOutcome.RESTORED == "RESTORED"

    # 9. Exception hierarchy
    assert issubclass(WorkspaceSafetyError, RecoveryError)
    assert issubclass(WorkspaceNotFoundError, RecoveryError)
    assert issubclass(RecoveryAuthenticationError, RecoveryError)
    assert issubclass(RecoveryIntegrityError, RecoveryError)
    assert issubclass(RestorationPolicyError, RecoveryError)
