"""
Shared pytest isolation fixtures for CryptoShield integration and UI tests.

Ensures integration and UI tests run against ephemeral tmp_path runtime state
(marker, synthetic dataset, RSA keys, snapshot, and forensic dossier) without
reading from or mutating the host repository's runtime/ directory.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

import pytest

import app.config as app_config
from app.config import CryptoShieldConfig
from app.containment.containment_manager import ContainmentManager
from app.containment.lab_write_gate import LabWriteGate
from app.containment.process_registry import ControlledProcessRegistry
from app.core.event_bus import EventBus
from app.dlp.dlp_coordinator import DLPCoordinator
from app.exfiltration.exfiltration_coordinator import ExfiltrationCoordinator
from app.lab.dataset_generator import SyntheticDatasetGenerator
from app.lab.lab_manager import LabManager
from app.recovery.recovery_coordinator import RecoveryCoordinator
from app.recovery.recovery_engine import RecoveryEngine
from app.recovery.recovery_reporter import RecoveryReporter
from app.recovery.restoration_manager import RestorationManager
from app.recovery.workspace_manager import RecoveryWorkspaceManager
from app.reporting.forensic_coordinator import ForensicCoordinator
from app.simulation.forensic_demo import ControlledForensicDemo
from app.vault.key_manager import KeyManager
from app.vault.snapshot_manager import SnapshotManager
from app.vault.vault_coordinator import VaultCoordinator
from app.vault.vault_verifier import SnapshotVerifier


@pytest.fixture
def isolated_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
    """
    Redirect CONFIG and global subsystem singletons to an ephemeral tmp_path runtime.
    Pre-populates a small valid lab, RSA keypair, snapshot, and forensic report so
    tests pass on a completely clean repository clone without touching real runtime/.
    """
    passphrase = "TestIsolatedPassphrase2026!"
    runtime_dir = tmp_path / "runtime"
    iso_cfg = CryptoShieldConfig(RUNTIME_DIR=runtime_dir)
    iso_cfg.ensure_directories()

    orig_config = app_config.CONFIG
    monkeypatch.setenv("CRYPTOSHIELD_RUNTIME_DIR", str(runtime_dir))
    monkeypatch.setenv("CRYPTOSHIELD_VAULT_PASSPHRASE", passphrase)

    # Rebind CONFIG across app.config and every already-imported app.* module
    monkeypatch.setattr(app_config, "CONFIG", iso_cfg)
    for mod in list(sys.modules.values()):
        if mod and getattr(mod, "__name__", "").startswith("app."):
            if getattr(mod, "CONFIG", None) is orig_config:
                monkeypatch.setattr(mod, "CONFIG", iso_cfg)

    # Build isolated core managers/singletons bound to iso_cfg
    lab_mgr = LabManager(base_lab_dir=iso_cfg.LAB_DIR)
    lab_mgr.initialize_lab()

    gen = SyntheticDatasetGenerator(base_lab_dir=iso_cfg.LAB_DIR, seed=42)
    manifest = gen.generate_dataset(file_count=25, canary_count=3)

    key_mgr = KeyManager(keys_dir=iso_cfg.KEYS_DIR)
    _, _, key_id = key_mgr.generate_key_pair(passphrase=passphrase, key_size=2048)

    registry = ControlledProcessRegistry()
    write_gate = LabWriteGate(base_lab_dir=iso_cfg.LAB_DIR)
    containment_mgr = ContainmentManager(
        registry=registry,
        write_gate=write_gate,
        containment_dir=iso_cfg.CONTAINMENT_DIR,
    )

    snapshot_mgr = SnapshotManager(
        vault_dir=iso_cfg.VAULT_DIR,
        base_lab_dir=iso_cfg.LAB_DIR,
        key_manager=key_mgr,
        process_registry=registry,
    )
    verifier = SnapshotVerifier(
        vault_dir=iso_cfg.VAULT_DIR,
        key_manager=key_mgr,
    )
    vault_coord = VaultCoordinator(
        vault_dir=iso_cfg.VAULT_DIR,
        key_manager=key_mgr,
        snapshot_manager=snapshot_mgr,
        verifier=verifier,
    )
    snap_meta = snapshot_mgr.create_snapshot()

    ws_mgr = RecoveryWorkspaceManager(
        workspaces_root=iso_cfg.RECOVERY_WORKSPACES_DIR,
        lab_dir=iso_cfg.LAB_DIR,
    )
    rec_engine = RecoveryEngine(
        vault_dir=iso_cfg.VAULT_DIR,
        staging_dir=iso_cfg.RECOVERY_STAGING_DIR,
        key_manager=key_mgr,
    )
    rec_reporter = RecoveryReporter(reports_dir=iso_cfg.RECOVERY_REPORTS_DIR)
    rec_coord = RecoveryCoordinator(
        workspace_manager=ws_mgr,
        engine=rec_engine,
        restoration_manager=RestorationManager(
            workspace_manager=ws_mgr,
            recovery_engine=rec_engine,
        ),
        reporter=rec_reporter,
    )

    exfil_coord = ExfiltrationCoordinator(mock_host="127.0.0.1", mock_port=0)
    dlp_coord = DLPCoordinator(
        policies_path=iso_cfg.dlp_policies_path,
        audit_log_path=iso_cfg.dlp_audit_log_path,
    )
    # Attach DLP gate to the isolated ExfiltrationCoordinator transfer monitor
    exfil_coord.transfer_monitor.dlp_gate = dlp_coord.transfer_gate

    forensic_coord = ForensicCoordinator(
        event_bus=EventBus(),
        reports_dir=iso_cfg.REPORTS_DIR,
        incidents_dir=iso_cfg.INCIDENTS_DIR,
        containment_dir=iso_cfg.CONTAINMENT_DIR,
        recovery_reports_dir=iso_cfg.RECOVERY_REPORTS_DIR,
    )

    # Seed one forensic report inside isolated runtime for ForensicsTab tests
    demo_res = ControlledForensicDemo(
        event_bus=forensic_coord.bus,
        coordinator=forensic_coord,
    ).run_demo()

    import app.containment.containment_manager as cm_mod
    import app.containment.lab_write_gate as lwg_mod
    import app.containment.process_registry as pr_mod
    import app.dlp as dlp_pkg
    import app.dlp.dlp_coordinator as dlp_mod
    import app.exfiltration as exfil_pkg
    import app.exfiltration.exfiltration_coordinator as exfil_mod
    import app.recovery as rec_pkg
    import app.recovery.recovery_coordinator as rec_mod
    import app.reporting as rep_pkg
    import app.reporting.forensic_coordinator as rep_mod
    import app.vault.key_manager as km_mod
    import app.vault.snapshot_manager as sm_mod
    import app.vault.vault_coordinator as vc_mod
    import app.vault.vault_verifier as vv_mod

    # Capture original singleton references before swapping
    replacements = [
        (id(km_mod.KEY_MGR), key_mgr),
        (id(sm_mod.SNAPSHOT_MGR), snapshot_mgr),
        (id(vv_mod.VAULT_VERIFIER), verifier),
        (id(vc_mod.VAULT_COORDINATOR), vault_coord),
        (id(lwg_mod.WRITE_GATE), write_gate),
        (id(pr_mod.REGISTRY), registry),
        (id(cm_mod.CONTAINMENT_MGR), containment_mgr),
        (id(rec_mod.RECOVERY_COORDINATOR), rec_coord),
        (id(exfil_mod.EXFILTRATION_COORDINATOR), exfil_coord),
        (id(dlp_mod.DLP_COORDINATOR), dlp_coord),
        (id(rep_mod.FORENSIC_COORDINATOR), forensic_coord),
    ]
    replacement_by_id = dict(replacements)

    # Patch class singletons
    monkeypatch.setattr(KeyManager, "_instance", key_mgr)
    monkeypatch.setattr(SnapshotManager, "_instance", snapshot_mgr)
    monkeypatch.setattr(VaultCoordinator, "_instance", vault_coord)
    monkeypatch.setattr(LabWriteGate, "_instance", write_gate)
    monkeypatch.setattr(ContainmentManager, "_instance", containment_mgr)
    monkeypatch.setattr(ControlledProcessRegistry, "_instance", registry)
    monkeypatch.setattr(ForensicCoordinator, "_instance", forensic_coord)

    # Patch module-level singleton exports and any module-scope aliases across app.*
    for mod in list(sys.modules.values()):
        if not mod or not getattr(mod, "__name__", "").startswith("app."):
            continue
        for attr_name, attr_val in list(vars(mod).items()):
            new_val = replacement_by_id.get(id(attr_val))
            if new_val is not None:
                monkeypatch.setattr(mod, attr_name, new_val)

    # Ensure core packages also point to isolated singletons
    monkeypatch.setattr(rec_pkg, "RECOVERY_COORDINATOR", rec_coord)
    monkeypatch.setattr(exfil_pkg, "EXFILTRATION_COORDINATOR", exfil_coord)
    monkeypatch.setattr(dlp_pkg, "DLP_COORDINATOR", dlp_coord)
    monkeypatch.setattr(rep_pkg, "FORENSIC_COORDINATOR", forensic_coord)

    yield {
        "config": iso_cfg,
        "runtime_dir": runtime_dir,
        "passphrase": passphrase,
        "key_id": key_id,
        "snapshot_id": snap_meta.snapshot_id,
        "report_id": demo_res.report_id,
        "manifest": manifest,
        "recovery_coordinator": rec_coord,
        "forensic_coordinator": forensic_coord,
        "dlp_coordinator": dlp_coord,
        "exfiltration_coordinator": exfil_coord,
    }

    exfil_coord.stop()
