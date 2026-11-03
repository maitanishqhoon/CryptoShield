"""
Unit tests for ControlledProcessRegistry (Phase 4).
"""

import os
import subprocess
import sys
import pytest

from app.containment.process_registry import ControlledProcessRegistry
from app.core.models import ProcessLifecycleStatus


@pytest.fixture
def registry():
    reg = ControlledProcessRegistry()
    yield reg
    reg.clear()


@pytest.fixture
def child_proc():
    # Spawn a harmless sleep child process to test real OS PID registration
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    yield proc
    if proc.poll() is None:
        proc.kill()
        proc.wait()


def test_valid_process_registration(registry, child_proc):
    record = registry.register_process(
        simulation_run_id="SIM-TEST-001",
        process_handle=child_proc,
        pid=child_proc.pid,
        expected_identity="TestSleepSimulator",
        associated_lab_target="runtime/lab/containment_demo_SIM-TEST-001",
    )
    assert record.simulation_run_id == "SIM-TEST-001"
    assert record.pid == child_proc.pid
    assert record.expected_identity == "TestSleepSimulator"
    assert record.lifecycle_status == ProcessLifecycleStatus.RUNNING.value
    assert registry.is_run_registered("SIM-TEST-001")
    assert registry.is_run_active("SIM-TEST-001")


def test_reject_unregistered_lookups(registry):
    assert not registry.is_run_registered("SIM-NONEXISTENT")
    assert not registry.is_run_active("SIM-NONEXISTENT")
    assert registry.get_record("SIM-NONEXISTENT") is None
    is_valid, msg = registry.verify_process_identity("SIM-NONEXISTENT")
    assert not is_valid
    assert "not registered" in msg


def test_reject_duplicate_registration(registry, child_proc):
    registry.register_process(
        simulation_run_id="SIM-TEST-DUP",
        process_handle=child_proc,
        pid=child_proc.pid,
        expected_identity="TestSimulator",
        associated_lab_target="runtime/lab/test",
    )
    with pytest.raises(ValueError, match="already registered"):
        registry.register_process(
            simulation_run_id="SIM-TEST-DUP",
            process_handle=child_proc,
            pid=child_proc.pid,
            expected_identity="TestSimulator",
            associated_lab_target="runtime/lab/test",
        )


def test_reject_system_pid_and_self_pid(registry, child_proc):
    with pytest.raises(ValueError, match="Safety violation: Cannot register system process"):
        registry.register_process(
            simulation_run_id="SIM-SYS",
            process_handle=child_proc,
            pid=4,
            expected_identity="System",
            associated_lab_target="runtime/lab/test",
        )

    with pytest.raises(ValueError, match="Safety violation: Cannot register CryptoShield's own"):
        registry.register_process(
            simulation_run_id="SIM-SELF",
            process_handle=child_proc,
            pid=os.getpid(),
            expected_identity="Self",
            associated_lab_target="runtime/lab/test",
        )


def test_reject_invalid_pid(registry, child_proc):
    with pytest.raises(RuntimeError, match="does not exist"):
        registry.register_process(
            simulation_run_id="SIM-INVALID-PID",
            process_handle=child_proc,
            pid=99999999,  # Non-existent PID
            expected_identity="GhostProcess",
            associated_lab_target="runtime/lab/test",
        )


def test_process_lifecycle_and_verification(registry, child_proc):
    registry.register_process(
        simulation_run_id="SIM-LIFE",
        process_handle=child_proc,
        pid=child_proc.pid,
        expected_identity="TestSleepSimulator",
        associated_lab_target="runtime/lab/test",
    )
    # Verification succeeds while running
    is_valid, msg = registry.verify_process_identity("SIM-LIFE")
    assert is_valid

    # Terminate the process
    child_proc.terminate()
    child_proc.wait(timeout=2.0)

    # Verification now notes it has exited
    is_valid2, msg2 = registry.verify_process_identity("SIM-LIFE")
    assert not is_valid2
    assert "already" in msg2.lower() or "no longer exists" in msg2.lower()

