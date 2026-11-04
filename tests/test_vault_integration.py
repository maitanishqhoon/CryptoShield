"""
Integration tests for VaultCoordinator in CryptoShield Vault (Phase 5).
"""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from app.lab.dataset_generator import SyntheticDatasetGenerator
from app.lab.lab_manager import LabManager
from app.vault.crypto_engine import CryptoEngine
from app.vault.key_manager import KeyManager
from app.vault.models import SnapshotVerificationOutcome
from app.vault.snapshot_manager import SnapshotManager
from app.vault.vault_coordinator import VaultCoordinator
from app.vault.vault_verifier import SnapshotVerifier


@pytest.fixture
def coordinator_fixture():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        lab_dir = root / "lab"
        vault_dir = root / "vault"
        keys_dir = root / "keys"
        passphrase = "CoordinatorPassphrase2026!"

        lab_mgr = LabManager(base_lab_dir=lab_dir)
        lab_mgr.initialize_lab()

        gen = SyntheticDatasetGenerator(base_lab_dir=lab_dir, seed=77)
        gen.generate_dataset(file_count=10, canary_count=1)

        key_mgr = KeyManager(keys_dir=keys_dir)
        crypto_engine = CryptoEngine()
        snap_mgr = SnapshotManager(
            vault_dir=vault_dir,
            base_lab_dir=lab_dir,
            key_manager=key_mgr,
            crypto_engine=crypto_engine,
        )
        verifier = SnapshotVerifier(
            vault_dir=vault_dir,
            key_manager=key_mgr,
            crypto_engine=crypto_engine,
        )

        coordinator = VaultCoordinator(
            vault_dir=vault_dir,
            key_manager=key_mgr,
            snapshot_manager=snap_mgr,
            verifier=verifier,
            crypto_engine=crypto_engine,
        )

        yield coordinator, passphrase, vault_dir, lab_dir


def test_vault_lifecycle_end_to_end(coordinator_fixture):
    coord, passphrase, vault_dir, _ = coordinator_fixture

    # 1. Initialize vault
    init_res = coord.initialize_vault(passphrase=passphrase, key_size=2048)
    assert init_res["status"] == "INITIALIZED"
    assert init_res["key_id"].startswith("KEY-")

    # 2. Status check before snapshot
    status_before = coord.get_vault_status()
    assert status_before["has_keys"] is True
    assert status_before["total_snapshots"] == 0

    # 3. Create snapshot
    meta = coord.create_snapshot()
    assert meta.total_files == 10
    assert meta.snapshot_id.startswith("SNAP-")

    # 4. Status check after snapshot
    status_after = coord.get_vault_status()
    assert status_after["total_snapshots"] == 1

    # 5. List snapshots
    snaps = coord.list_snapshots()
    assert len(snaps) == 1
    assert snaps[0].snapshot_id == meta.snapshot_id

    # 6. Inspect snapshot without passphrase
    info_public = coord.inspect_snapshot(meta.snapshot_id)
    assert info_public["snapshot_id"] == meta.snapshot_id
    assert "confidential_manifest" not in info_public

    # 7. Inspect snapshot with passphrase (decrypts manifest summary)
    info_private = coord.inspect_snapshot(meta.snapshot_id, passphrase=passphrase)
    assert "confidential_manifest" in info_private
    assert info_private["confidential_manifest"]["canary_count"] == 1

    # 8. Verify snapshot
    report = coord.verify_snapshot(meta.snapshot_id, passphrase=passphrase)
    assert report.outcome == SnapshotVerificationOutcome.FULLY_VERIFIED.value
    assert report.verified_objects == 10
    assert report.failed_objects == 0

