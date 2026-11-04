"""
Unit tests for SnapshotManager in CryptoShield Vault (Phase 5).
"""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from app.containment.process_registry import ControlledProcessRegistry
from app.core.models import ProcessLifecycleStatus
from app.lab.dataset_generator import SyntheticDatasetGenerator
from app.lab.lab_manager import LabManager
from app.vault.key_manager import KeyManager
from app.vault.snapshot_manager import (
    ActiveSimulationError,
    BaselineIntegrityError,
    SnapshotManager,
)


@pytest.fixture
def snapshot_fixture():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        lab_dir = root / "lab"
        vault_dir = root / "vault"
        keys_dir = root / "keys"

        # Initialize lab and small dataset
        lab_mgr = LabManager(base_lab_dir=lab_dir)
        lab_mgr.initialize_lab()

        gen = SyntheticDatasetGenerator(base_lab_dir=lab_dir, seed=42)
        manifest = gen.generate_dataset(file_count=20, canary_count=2)

        # Initialize keys
        key_mgr = KeyManager(keys_dir=keys_dir)
        key_mgr.generate_key_pair(passphrase="SnapManagerTestPass123!", key_size=2048)

        # Initialize fresh registry
        registry = ControlledProcessRegistry()

        snap_mgr = SnapshotManager(
            vault_dir=vault_dir,
            base_lab_dir=lab_dir,
            key_manager=key_mgr,
            process_registry=registry,
        )

        yield snap_mgr, lab_dir, vault_dir, key_mgr, registry


def test_successful_snapshot_creation(snapshot_fixture):
    snap_mgr, lab_dir, vault_dir, _, _ = snapshot_fixture

    meta = snap_mgr.create_snapshot()

    assert meta.snapshot_id.startswith("SNAP-")
    assert meta.total_files == 20
    assert meta.total_encrypted_bytes > 0

    snapshot_dir = vault_dir / meta.snapshot_id
    assert snapshot_dir.exists()
    assert (snapshot_dir / "snapshot.json").exists()
    assert (snapshot_dir / "manifest.enc").exists()
    assert (snapshot_dir / "objects").exists()

    # Verify no staging directories remain
    staging_dirs = list(vault_dir.glob(".staging_*"))
    assert len(staging_dirs) == 0

    # Test listing snapshots
    snapshots = snap_mgr.list_snapshots()
    assert len(snapshots) == 1
    assert snapshots[0].snapshot_id == meta.snapshot_id

    # Test phase durations and storage accounting metadata
    assert "phase_durations" in meta.metadata
    durations = meta.metadata["phase_durations"]
    assert "audit_duration_seconds" in durations
    assert "encryption_duration_seconds" in durations
    assert "manifest_duration_seconds" in durations
    assert "key_wrapping_duration_seconds" in durations
    assert "publication_duration_seconds" in durations
    assert "total_creation_duration_seconds" in durations

    assert "storage_accounting" in meta.metadata
    acc = meta.metadata["storage_accounting"]
    assert acc["original_logical_bytes"] > 0
    assert acc["encrypted_objects_bytes"] > acc["original_logical_bytes"]
    # 20 files * 34 bytes container overhead = 680 bytes overhead
    assert acc["object_overhead_bytes"] == 20 * 34
    assert acc["manifest_encrypted_bytes"] > 0
    assert acc["total_vault_overhead_bytes"] > acc["object_overhead_bytes"]


def test_multiple_independent_snapshots(snapshot_fixture):
    snap_mgr, _, _, _, _ = snapshot_fixture

    snap1 = snap_mgr.create_snapshot()
    snap2 = snap_mgr.create_snapshot()

    assert snap1.snapshot_id != snap2.snapshot_id
    assert snap1.wrapped_aes_key_b64 != snap2.wrapped_aes_key_b64

    snapshots = snap_mgr.list_snapshots()
    assert len(snapshots) == 2


def test_refusal_when_baseline_file_modified(snapshot_fixture):
    snap_mgr, lab_dir, vault_dir, _, _ = snapshot_fixture

    # Tamper with a file in the lab
    sample_file = next(lab_dir.rglob("*.txt"))
    with open(sample_file, "a", encoding="utf-8") as f:
        f.write("\nUnauthorized malicious payload alteration!\n")

    with pytest.raises(BaselineIntegrityError):
        snap_mgr.create_snapshot()

    # Ensure no partial snapshot was created
    assert len(snap_mgr.list_snapshots()) == 0


def test_refusal_when_baseline_file_missing(snapshot_fixture):
    snap_mgr, lab_dir, vault_dir, _, _ = snapshot_fixture

    # Delete a file
    sample_file = next(lab_dir.rglob("*.txt"))
    sample_file.unlink()

    with pytest.raises(BaselineIntegrityError):
        snap_mgr.create_snapshot()

    assert len(snap_mgr.list_snapshots()) == 0


def test_refusal_when_active_simulation_running(snapshot_fixture):
    snap_mgr, _, _, _, registry = snapshot_fixture

    # Register an active simulation run
    from unittest.mock import MagicMock
    mock_handle = MagicMock()
    mock_handle.poll.return_value = None

    import os
    import psutil
    curr_pid = os.getpid()
    # Mock record directly to simulate running state
    from app.core.models import ControlledProcessRecord
    rec = ControlledProcessRecord(
        simulation_run_id="SIM-ACTIVE-RUN",
        pid=99999,
        process_creation_time="2026-11-04T12:00:00Z",
        executable_path="python.exe",
        expected_identity="test",
        parent_pid=curr_pid,
        registered_at="2026-11-04T12:00:00Z",
        lifecycle_status=ProcessLifecycleStatus.RUNNING.value,
    )
    registry._records["SIM-ACTIVE-RUN"] = rec

    with pytest.raises(ActiveSimulationError):
        snap_mgr.create_snapshot()

