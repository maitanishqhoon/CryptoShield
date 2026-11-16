"""
Unit and integration tests for CryptoShield Restoration Manager, Coordinator, and CLI (Phase 6, Task 3).

Tests:
1. Preview safety: Dry-run preview plans restorations without modifying workspace or leaking plaintexts.
2. Authorization gate: Non-dry-run without explicit authorize=True raises RestorationPolicyError.
3. Forensic evidence preservation: Overwritten modified files are quarantined with timestamps.
4. Intact and untracked files preserved: Intact files not re-decrypted, untracked files untouched.
5. Selective recovery: Targeting single files or directory subtrees leaves out-of-scope files untouched.
6. Full recovery & Canary verification: Full recovery emits EventBus telemetry and passes post-recovery audit.
7. Cancellation & error cleanup: Staging sessions and temporary files are purged on cancellation or failure.
8. Recovery coordinator & CLI workflow: End-to-end integration across workspaces, reports, and CLI commands.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import pytest

from app.config import CONFIG
from app.core.event_bus import Event, EventBus
from app.core.models import ManifestEntry
from app.core.safety import generate_lab_marker
from app.recovery.models import (
    FileAssessmentStatus,
    FileRestorationOutcome,
    PlannedRecoveryAction,
    RecoveryAuthenticationError,
    RecoveryError,
    RecoveryIntegrityError,
    RecoveryMode,
    RestorationPolicyError,
)
from app.recovery.recovery_assessor import RecoveryAssessor
from app.recovery.recovery_coordinator import RecoveryCoordinator
from app.recovery.recovery_engine import RecoveryEngine
from app.recovery.recovery_reporter import RecoveryReporter
from app.recovery.restoration_manager import RestorationManager
from app.recovery.workspace_manager import RecoveryWorkspaceManager
from app.vault.crypto_engine import CryptoEngine
from app.vault.key_manager import KeyManager
from app.vault.models import EncryptedObjectRecord, SnapshotManifest
from app.vault.snapshot_manifest import SnapshotManifestManager


@pytest.fixture
def recovery_env(tmp_path: Path):
    """Fixture providing isolated lab, vault, keys, workspaces, staging, and reports directories."""
    lab_dir = tmp_path / "lab"
    vault_dir = tmp_path / "vault"
    keys_dir = tmp_path / "keys"
    staging_dir = tmp_path / "staging"
    workspaces_root = tmp_path / "workspaces"
    reports_dir = tmp_path / "reports"

    for d in (lab_dir, vault_dir, keys_dir, staging_dir, workspaces_root, reports_dir):
        d.mkdir(parents=True, exist_ok=True)

    # Initialize authentic lab marker in lab_dir
    marker = generate_lab_marker(base_lab_dir=lab_dir)
    with open(lab_dir / CONFIG.LAB_MARKER_FILENAME, "w", encoding="utf-8") as f:
        json.dump(marker.to_dict(), f, indent=2)

    # Initialize RSA key pair (Envelope v2)
    km = KeyManager(keys_dir=keys_dir)
    passphrase = "RecoveryTestPassphrase2026!"
    km.generate_key_pair(passphrase, key_size=2048)
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
    rest_mgr = RestorationManager(
        workspace_manager=ws_mgr,
        recovery_engine=engine,
        recovery_assessor=assessor,
    )
    reporter = RecoveryReporter(reports_dir=reports_dir)
    event_bus = EventBus()

    coordinator = RecoveryCoordinator(
        workspace_manager=ws_mgr,
        assessor=assessor,
        engine=engine,
        restoration_manager=rest_mgr,
        reporter=reporter,
        event_bus=event_bus,
    )

    return {
        "lab_dir": lab_dir,
        "vault_dir": vault_dir,
        "keys_dir": keys_dir,
        "staging_dir": staging_dir,
        "workspaces_root": workspaces_root,
        "reports_dir": reports_dir,
        "key_manager": km,
        "manifest_manager": smm,
        "workspace_manager": ws_mgr,
        "assessor": assessor,
        "engine": engine,
        "restoration_manager": rest_mgr,
        "reporter": reporter,
        "coordinator": coordinator,
        "event_bus": event_bus,
        "public_key": pub_key,
        "passphrase": passphrase,
    }


def _create_mock_snapshot_and_workspace(
    env: Dict[str, Any],
    snapshot_id: str,
    file_specs: Dict[str, bytes],
    canary_paths: Set[str],
    workspace_id: str,
) -> Tuple[SnapshotManifest, RecoveryWorkspaceManager]:
    """Helper to encrypt test files into vault and seed an authentic recovery workspace."""
    lab_dir = env["lab_dir"]
    vault_dir = env["vault_dir"]
    km: KeyManager = env["key_manager"]
    smm: SnapshotManifestManager = env["manifest_manager"]
    pub_key = env["public_key"]
    ws_mgr: RecoveryWorkspaceManager = env["workspace_manager"]

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

    # Seed workspace from lab
    ws_mgr.create_workspace(
        workspace_id=workspace_id,
        source_snapshot_id=snapshot_id,
        seed_from_lab=True,
    )

    return manifest, ws_mgr


# ============================================================================
# 1. Preview Safety: Dry-Run Never Modifies Files or Staging
# ============================================================================

def test_restoration_preview_safety_no_files_written(recovery_env):
    """Verify dry_run=True preview schedules actions without modifying workspace or leaking plaintexts."""
    env = recovery_env
    files = {
        "finance/q1.csv": b"revenue,100\nexpenses,50\n",
        "hr/contracts/alice.txt": b"Confidential Contract Alice\n",
        "engineering/canary_src.py": b"# CANARY FILE INTEGRITY CHECK\n",
    }
    canaries = {"engineering/canary_src.py"}
    snap_id = "SNAP-PREVIEW-01"
    ws_id = "ws_preview_01"

    manifest, ws_mgr = _create_mock_snapshot_and_workspace(env, snap_id, files, canaries, ws_id)
    ws_dir = ws_mgr.get_workspace_path(ws_id)

    # Corrupt one file, delete another
    corrupted_content = b"CORRUPTED CONTENT BY TEST\n"
    (ws_dir / "finance/q1.csv").write_bytes(corrupted_content)
    (ws_dir / "hr/contracts/alice.txt").unlink()

    rest_mgr: RestorationManager = env["restoration_manager"]
    engine: RecoveryEngine = env["engine"]
    aes_key, manifest, _ = engine.unlock_snapshot(snap_id, passphrase=env["passphrase"])

    report = rest_mgr.execute_restoration(
        workspace_id=ws_id,
        snapshot_id=snap_id,
        manifest=manifest,
        aes_key=aes_key,
        dry_run=True,
        authorize=False,
        overwrite_modified=True,
    )

    assert report.dry_run is True
    assert report.authorized is False
    assert report.restored_count == 2
    assert report.evidence_preserved_count == 1
    assert report.skipped_intact_count == 1

    # Verify workspace files were NOT modified on disk
    assert (ws_dir / "finance/q1.csv").read_bytes() == corrupted_content
    assert not (ws_dir / "hr/contracts/alice.txt").exists()
    assert len(list((ws_dir / CONFIG.RECOVERY_EVIDENCE_DIRNAME).iterdir())) == 0

    # Verify staging directory has zero lingering files
    assert len(list(engine.staging_dir.iterdir())) == 0


# ============================================================================
# 2. Authorization Gate: Explicit Authorize Required for Live Commit
# ============================================================================

def test_restoration_authorization_gate(recovery_env):
    """Verify live restoration without authorize=True is blocked by RestorationPolicyError."""
    env = recovery_env
    files = {"docs/spec.txt": b"Specification content\n"}
    snap_id = "SNAP-GATE-01"
    ws_id = "ws_gate_01"

    manifest, _ = _create_mock_snapshot_and_workspace(env, snap_id, files, set(), ws_id)
    rest_mgr: RestorationManager = env["restoration_manager"]
    engine: RecoveryEngine = env["engine"]
    aes_key, manifest, _ = engine.unlock_snapshot(snap_id, passphrase=env["passphrase"])

    with pytest.raises(RestorationPolicyError) as exc_info:
        rest_mgr.execute_restoration(
            workspace_id=ws_id,
            snapshot_id=snap_id,
            manifest=manifest,
            aes_key=aes_key,
            dry_run=False,
            authorize=False,
        )
    assert "explicit authorization" in str(exc_info.value)


# ============================================================================
# 3. Forensic Evidence Preservation: Modified Files Quarantined
# ============================================================================

def test_forensic_evidence_preservation(recovery_env):
    """Verify modified files are preserved in .evidence_quarantine/ with timestamps before commit."""
    env = recovery_env
    orig_content = b"Original Finance Report Q1 2026\n"
    files = {"finance/report.txt": orig_content}
    snap_id = "SNAP-EVD-01"
    ws_id = "ws_evd_01"

    manifest, ws_mgr = _create_mock_snapshot_and_workspace(env, snap_id, files, set(), ws_id)
    ws_dir = ws_mgr.get_workspace_path(ws_id)

    # Modify file
    tampered_bytes = b"TAMPERED DATA INSERTED BY RANSOMWARE\n"
    (ws_dir / "finance/report.txt").write_bytes(tampered_bytes)

    rest_mgr: RestorationManager = env["restoration_manager"]
    engine: RecoveryEngine = env["engine"]
    aes_key, manifest, _ = engine.unlock_snapshot(snap_id, passphrase=env["passphrase"])

    report = rest_mgr.execute_restoration(
        workspace_id=ws_id,
        snapshot_id=snap_id,
        manifest=manifest,
        aes_key=aes_key,
        dry_run=False,
        authorize=True,
        overwrite_modified=True,
    )

    assert report.restored_count == 1
    assert report.evidence_preserved_count == 1

    # Verify workspace file has been restored to original baseline
    assert (ws_dir / "finance/report.txt").read_bytes() == orig_content

    # Verify evidence quarantine exists and contains the tampered bytes
    quarantine_root = ws_dir / CONFIG.RECOVERY_EVIDENCE_DIRNAME / "finance"
    assert quarantine_root.exists()
    evd_files = list(quarantine_root.glob("report.txt.*.evd"))
    assert len(evd_files) == 1
    assert evd_files[0].read_bytes() == tampered_bytes


# ============================================================================
# 4. Intact and Untracked Files Preserved
# ============================================================================

def test_intact_and_untracked_files_preserved(recovery_env):
    """Verify INTACT files are not modified and UNTRACKED files are kept untouched."""
    env = recovery_env
    files = {
        "intact.txt": b"Intact verified content\n",
        "missing.txt": b"Missing file content\n",
    }
    snap_id = "SNAP-PRESERVE-01"
    ws_id = "ws_preserve_01"

    manifest, ws_mgr = _create_mock_snapshot_and_workspace(env, snap_id, files, set(), ws_id)
    ws_dir = ws_mgr.get_workspace_path(ws_id)

    # Delete missing.txt to force restoration of missing.txt only
    (ws_dir / "missing.txt").unlink()

    # Create untracked file
    untracked_content = b"Operator manual notes 2026\n"
    (ws_dir / "operator_notes.txt").write_bytes(untracked_content)

    rest_mgr: RestorationManager = env["restoration_manager"]
    engine: RecoveryEngine = env["engine"]
    aes_key, manifest, _ = engine.unlock_snapshot(snap_id, passphrase=env["passphrase"])

    report = rest_mgr.execute_restoration(
        workspace_id=ws_id,
        snapshot_id=snap_id,
        manifest=manifest,
        aes_key=aes_key,
        dry_run=False,
        authorize=True,
        overwrite_modified=True,
    )

    assert report.restored_count == 1
    assert report.skipped_intact_count == 1
    assert report.untracked_preserved_count == 1

    # Verify intact file was preserved
    assert (ws_dir / "intact.txt").read_bytes() == b"Intact verified content\n"

    # Verify missing file was restored
    assert (ws_dir / "missing.txt").read_bytes() == b"Missing file content\n"

    # Verify untracked file was NOT deleted or altered
    assert (ws_dir / "operator_notes.txt").read_bytes() == untracked_content


# ============================================================================
# 5. Selective Recovery: Target File and Subtree Scoping
# ============================================================================

def test_selective_file_and_directory_restoration(recovery_env):
    """Verify targeted selective recovery for a single file and a departmental directory subtree."""
    env = recovery_env
    files = {
        "finance/budget.xlsx": b"Budget data\n",
        "hr/records/emp1.csv": b"Employee 1\n",
        "engineering/code.py": b"print('Hello world')\n",
    }
    snap_id = "SNAP-SELECTIVE-01"
    ws_id = "ws_selective_01"

    manifest, ws_mgr = _create_mock_snapshot_and_workspace(env, snap_id, files, set(), ws_id)
    ws_dir = ws_mgr.get_workspace_path(ws_id)

    # Corrupt all three files
    for p in files.keys():
        (ws_dir / p).write_bytes(b"CORRUPTED\n")

    rest_mgr: RestorationManager = env["restoration_manager"]
    engine: RecoveryEngine = env["engine"]

    # 1. Restore ONLY finance/budget.xlsx
    aes_key1, manifest, _ = engine.unlock_snapshot(snap_id, passphrase=env["passphrase"])
    report_file = rest_mgr.execute_restoration(
        workspace_id=ws_id,
        snapshot_id=snap_id,
        manifest=manifest,
        aes_key=aes_key1,
        dry_run=False,
        authorize=True,
        overwrite_modified=True,
        target_relative_path="finance/budget.xlsx",
    )
    assert report_file.mode == RecoveryMode.SELECTIVE_FILE
    assert report_file.restored_count == 1
    assert (ws_dir / "finance/budget.xlsx").read_bytes() == files["finance/budget.xlsx"]
    assert (ws_dir / "hr/records/emp1.csv").read_bytes() == b"CORRUPTED\n"
    assert (ws_dir / "engineering/code.py").read_bytes() == b"CORRUPTED\n"

    # 2. Restore ONLY hr/ subtree
    aes_key2, manifest, _ = engine.unlock_snapshot(snap_id, passphrase=env["passphrase"])
    report_dir = rest_mgr.execute_restoration(
        workspace_id=ws_id,
        snapshot_id=snap_id,
        manifest=manifest,
        aes_key=aes_key2,
        dry_run=False,
        authorize=True,
        overwrite_modified=True,
        target_directory="hr",
    )
    assert report_dir.mode == RecoveryMode.DIRECTORY
    assert report_dir.restored_count == 1
    assert (ws_dir / "hr/records/emp1.csv").read_bytes() == files["hr/records/emp1.csv"]
    assert (ws_dir / "engineering/code.py").read_bytes() == b"CORRUPTED\n"


# ============================================================================
# 6. Full Recovery & Canary Verification with EventBus Telemetry
# ============================================================================

def test_full_recovery_and_canary_restoration(recovery_env):
    """Verify full recovery restores canaries, emits EventBus telemetry, and passes post-audit."""
    env = recovery_env
    files = {
        "finance/ledger.dat": b"Ledger entry 2026\n",
        "canary_alpha.token": b"SECRET CANARY TOKEN ALPHA\n",
        "dept/notes.txt": b"General department notes\n",
    }
    canaries = {"canary_alpha.token"}
    snap_id = "SNAP-FULL-01"
    ws_id = "ws_full_01"

    _, ws_mgr = _create_mock_snapshot_and_workspace(env, snap_id, files, canaries, ws_id)
    ws_dir = ws_mgr.get_workspace_path(ws_id)

    # Damage files
    (ws_dir / "canary_alpha.token").write_bytes(b"TAMPERED CANARY\n")
    (ws_dir / "finance/ledger.dat").unlink()

    coordinator: RecoveryCoordinator = env["coordinator"]
    event_bus: EventBus = env["event_bus"]

    captured_events: List[Event] = []
    def handler(evt: Event) -> None:
        captured_events.append(evt)

    event_bus.subscribe("RECOVERY_COMPLETED", handler)
    event_bus.subscribe("CANARY_FILE_RESTORED", handler)

    report = coordinator.restore(
        workspace_id=ws_id,
        snapshot_id=snap_id,
        passphrase=env["passphrase"],
        overwrite_modified=True,
        dry_run=False,
        authorize=True,
    )

    assert report.restored_count == 2
    assert report.canary_restored_count == 1
    assert report.post_recovery_audit_passed is True

    # Check EventBus events
    rec_completed_events = [e for e in captured_events if e.event_type == "RECOVERY_COMPLETED"]
    canary_restored_events = [e for e in captured_events if e.event_type == "CANARY_FILE_RESTORED"]
    assert len(rec_completed_events) == 1
    assert len(canary_restored_events) == 1
    assert canary_restored_events[0].data["relative_path"] == "canary_alpha.token"

    # Verify workspace files are 100% restored
    assert (ws_dir / "canary_alpha.token").read_bytes() == files["canary_alpha.token"]
    assert (ws_dir / "finance/ledger.dat").read_bytes() == files["finance/ledger.dat"]


# ============================================================================
# 7. Cancellation & Staging Cleanup on Failure
# ============================================================================

def test_staging_cleanup_on_cancellation_or_failure(recovery_env):
    """Verify in-flight staging sessions are completely purged on cancellation."""
    env = recovery_env
    files = {
        "file1.txt": b"Content 1\n",
        "file2.txt": b"Content 2\n",
    }
    snap_id = "SNAP-CANCEL-01"
    ws_id = "ws_cancel_01"

    manifest, ws_mgr = _create_mock_snapshot_and_workspace(env, snap_id, files, set(), ws_id)
    ws_dir = ws_mgr.get_workspace_path(ws_id)
    (ws_dir / "file1.txt").unlink()
    (ws_dir / "file2.txt").unlink()

    rest_mgr: RestorationManager = env["restoration_manager"]
    engine: RecoveryEngine = env["engine"]
    aes_key, manifest, _ = engine.unlock_snapshot(snap_id, passphrase=env["passphrase"])

    # Create pre-set cancellation event
    cancel_evt = threading.Event()
    cancel_evt.set()

    report = rest_mgr.execute_restoration(
        workspace_id=ws_id,
        snapshot_id=snap_id,
        manifest=manifest,
        aes_key=aes_key,
        dry_run=False,
        authorize=True,
        cancel_event=cancel_evt,
    )

    # Restoration aborted
    assert report.restored_count == 0

    # Ensure staging session directory is completely empty
    assert len(list(engine.staging_dir.iterdir())) == 0


# ============================================================================
# 8. Recovery Coordinator & CLI Integration Workflow
# ============================================================================

def test_recovery_coordinator_and_cli_workflow(recovery_env):
    """Verify end-to-end demo execution and CLI command dispatch."""
    env = recovery_env
    files = {
        f"dept_{i}/file_{i}.txt": f"Content for file {i}\n".encode("utf-8")
        for i in range(1, 15)
    }
    files["dept_1/canary.token"] = b"CANARY TOKEN WORKFLOW\n"
    canaries = {"dept_1/canary.token"}
    snap_id = "SNAP-WORKFLOW-01"

    _create_mock_snapshot_and_workspace(env, snap_id, files, canaries, "ws_baseline_seed")

    coordinator: RecoveryCoordinator = env["coordinator"]

    # 1. Run automated demo via Coordinator
    demo_res = coordinator.run_recovery_demo(
        file_count=10,
        snapshot_id=snap_id,
        passphrase=env["passphrase"],
        cleanup=True,
    )
    assert demo_res["success"] is True
    assert demo_res["restoration"]["restored_count"] > 0
    assert len(demo_res["damage_simulated"]["canaries_affected"]) >= 1
    assert demo_res["restoration"]["canaries_restored"] >= 1
    assert demo_res["restoration"]["audit_passed"] is True

    # 2. Test CLI Command Handlers via patched Coordinator
    import app.recovery
    orig_coord = app.recovery.RECOVERY_COORDINATOR
    app.recovery.RECOVERY_COORDINATOR = coordinator

    try:
        from app.main import cmd_recovery

        # Test status
        args_status = argparse.Namespace(recovery_command="status")
        assert cmd_recovery(args_status) == 0

        # Test workspace create
        args_ws_create = argparse.Namespace(
            recovery_command="workspace",
            workspace_command="create",
            id="ws_cli_test",
            seed=True,
            files=5,
            snapshot=snap_id,
        )
        assert cmd_recovery(args_ws_create) == 0

        # Test workspace list
        args_ws_list = argparse.Namespace(
            recovery_command="workspace",
            workspace_command="list",
        )
        assert cmd_recovery(args_ws_list) == 0

        # Test assess
        args_assess = argparse.Namespace(
            recovery_command="assess",
            workspace="ws_cli_test",
            snapshot=snap_id,
            passphrase=env["passphrase"],
            file=None,
            directory=None,
            overwrite_modified=True,
        )
        assert cmd_recovery(args_assess) == 0

        # Test preview
        args_preview = argparse.Namespace(
            recovery_command="preview",
            workspace="ws_cli_test",
            snapshot=snap_id,
            passphrase=env["passphrase"],
            file=None,
            directory=None,
            no_overwrite_modified=False,
        )
        assert cmd_recovery(args_preview) == 0

        # Test restore
        args_restore = argparse.Namespace(
            recovery_command="restore",
            workspace="ws_cli_test",
            snapshot=snap_id,
            passphrase=env["passphrase"],
            file=None,
            directory=None,
            authorize=True,
            no_overwrite_modified=False,
        )
        assert cmd_recovery(args_restore) == 0

        # Test verify
        args_verify = argparse.Namespace(
            recovery_command="verify",
            workspace="ws_cli_test",
            snapshot=snap_id,
            passphrase=env["passphrase"],
        )
        assert cmd_recovery(args_verify) == 0

        # Test workspace delete
        args_ws_del = argparse.Namespace(
            recovery_command="workspace",
            workspace_command="delete",
            workspace="ws_cli_test",
        )
        assert cmd_recovery(args_ws_del) == 0
    finally:
        app.recovery.RECOVERY_COORDINATOR = orig_coord
