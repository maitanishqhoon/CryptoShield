"""
Unit tests for ContainmentVerifier (Phase 4).
"""

import subprocess
import sys
import pytest

from app.containment.containment_verifier import ContainmentVerifier
from app.containment.lab_write_gate import LabWriteGate
from app.containment.process_registry import ControlledProcessRegistry
from app.core.models import ProcessLifecycleStatus


@pytest.fixture
def verifier(tmp_path):
    registry = ControlledProcessRegistry()
    write_gate = LabWriteGate(base_lab_dir=tmp_path)
    ver = ContainmentVerifier(registry=registry, write_gate=write_gate)
    yield ver, registry, write_gate
    registry.clear()
    write_gate.clear()


def test_verification_succeeds_when_contained(verifier, tmp_path):
    ver, registry, write_gate = verifier

    proc = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(0)"])
    proc.wait()

    run_id = "SIM-VER-PASS"
    target_dir = tmp_path / "target_ver_pass"
    target_dir.mkdir()

    registry.register_process(
        simulation_run_id=run_id,
        process_handle=proc,
        pid=proc.pid,
        expected_identity="VerifierTestSimulator",
        associated_lab_target=str(target_dir),
    )
    registry.mark_status(run_id, ProcessLifecycleStatus.EXITED)
    write_gate.open_gate(run_id, target_dir)
    write_gate.close_gate(run_id)

    res = ver.verify_containment(run_id)
    assert res.is_verified
    assert res.checks["process_registered"]
    assert res.checks["write_gate_closed"]
    assert res.checks["process_exited"]
    assert res.checks["subsequent_writes_rejected"]


def test_verification_fails_if_process_still_running(verifier, tmp_path):
    ver, registry, write_gate = verifier

    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])

    try:
        run_id = "SIM-VER-RUNNING"
        target_dir = tmp_path / "target_ver_run"
        target_dir.mkdir()

        registry.register_process(
            simulation_run_id=run_id,
            process_handle=proc,
            pid=proc.pid,
            expected_identity="RunningSimulator",
            associated_lab_target=str(target_dir),
        )
        write_gate.open_gate(run_id, target_dir)
        write_gate.close_gate(run_id)

        res = ver.verify_containment(run_id)
        assert not res.is_verified
        assert not res.checks["process_exited"]
    finally:
        proc.kill()
        proc.wait()


def test_verification_fails_if_gate_still_open(verifier, tmp_path):
    ver, registry, write_gate = verifier

    proc = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(0)"])
    proc.wait()

    run_id = "SIM-VER-OPEN"
    target_dir = tmp_path / "target_ver_open"
    target_dir.mkdir()

    registry.register_process(
        simulation_run_id=run_id,
        process_handle=proc,
        pid=proc.pid,
        expected_identity="OpenGateSimulator",
        associated_lab_target=str(target_dir),
    )
    registry.mark_status(run_id, ProcessLifecycleStatus.EXITED)
    write_gate.open_gate(run_id, target_dir)
    # Do NOT close gate

    res = ver.verify_containment(run_id)
    assert not res.is_verified
    assert not res.checks["write_gate_closed"]


def test_verification_fails_if_unregistered(verifier):
    ver, _, _ = verifier
    res = ver.verify_containment("SIM-NONEXISTENT")
    assert not res.is_verified
    assert not res.checks["process_registered"]
    assert not res.checks["identity_matched"]

