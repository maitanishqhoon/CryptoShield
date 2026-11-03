"""
Unit tests for ControlledProcessController (Phase 4).
"""

import subprocess
import sys
import pytest

from app.containment.lab_write_gate import LabWriteGate
from app.containment.process_controller import ControlledProcessController
from app.containment.process_registry import ControlledProcessRegistry
from app.core.models import ProcessLifecycleStatus, WriteGateState


@pytest.fixture
def controller(tmp_path):
    registry = ControlledProcessRegistry()
    write_gate = LabWriteGate(base_lab_dir=tmp_path)
    ctrl = ControlledProcessController(
        registry=registry,
        write_gate=write_gate,
        graceful_timeout=1.5,
        forced_fallback_enabled=True,
    )
    yield ctrl, registry, write_gate
    registry.clear()
    write_gate.clear()


def test_graceful_cooperative_shutdown(controller, tmp_path):
    ctrl, registry, write_gate = controller

    # Python subprocess that loops until terminated
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])

    run_id = "SIM-CTRL-01"
    target_dir = tmp_path / "target_01"
    target_dir.mkdir()

    registry.register_process(
        simulation_run_id=run_id,
        process_handle=proc,
        pid=proc.pid,
        expected_identity="TestProcess",
        associated_lab_target=str(target_dir),
    )
    write_gate.open_gate(run_id, target_dir)

    # Set up cooperative channel that terminates child
    ctrl.register_control_channel(run_id, lambda: proc.terminate())

    outcome = ctrl.stop_controlled_process(run_id)

    assert outcome.success
    assert outcome.method == "COOPERATIVE"
    assert write_gate.get_state(run_id) == WriteGateState.CLOSED
    rec = registry.get_record(run_id)
    assert rec is not None
    assert rec.lifecycle_status == ProcessLifecycleStatus.EXITED.value


def test_already_exited_process_handled_safely(controller, tmp_path):
    ctrl, registry, write_gate = controller

    proc = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(0)"])
    proc.wait()

    run_id = "SIM-CTRL-EXITED"
    target_dir = tmp_path / "target_exited"
    target_dir.mkdir()

    registry.register_process(
        simulation_run_id=run_id,
        process_handle=proc,
        pid=proc.pid,
        expected_identity="ExitedProcess",
        associated_lab_target=str(target_dir),
    )

    outcome = ctrl.stop_controlled_process(run_id)
    assert outcome.success
    assert outcome.method == "ALREADY_EXITED"


def test_reject_unregistered_process(controller):
    ctrl, _, _ = controller
    outcome = ctrl.stop_controlled_process("SIM-NONEXISTENT")
    assert not outcome.success
    assert outcome.method == "REJECTED"


def test_forced_fallback_when_cooperative_signal_ignored(controller, tmp_path):
    ctrl, registry, write_gate = controller

    # Subprocess that ignores signals or simply sleeps
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])

    run_id = "SIM-CTRL-FALLBACK"
    target_dir = tmp_path / "target_fb"
    target_dir.mkdir()

    registry.register_process(
        simulation_run_id=run_id,
        process_handle=proc,
        pid=proc.pid,
        expected_identity="StubbornProcess",
        associated_lab_target=str(target_dir),
    )
    write_gate.open_gate(run_id, target_dir)

    # Do not register a cooperative stop channel so it times out and uses fallback
    outcome = ctrl.stop_controlled_process(run_id)

    assert outcome.success
    assert outcome.method == "FORCED_FALLBACK"
    rec = registry.get_record(run_id)
    assert rec is not None
    assert rec.lifecycle_status == ProcessLifecycleStatus.TERMINATED.value


def test_unrelated_process_remains_running(controller, tmp_path):
    ctrl, registry, write_gate = controller

    # Target process
    target_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    # Unrelated process
    unrelated_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])

    try:
        run_id = "SIM-CTRL-ISOLATION"
        target_dir = tmp_path / "target_iso"
        target_dir.mkdir()

        registry.register_process(
            simulation_run_id=run_id,
            process_handle=target_proc,
            pid=target_proc.pid,
            expected_identity="TargetProcess",
            associated_lab_target=str(target_dir),
        )

        ctrl.register_control_channel(run_id, lambda: target_proc.terminate())
        outcome = ctrl.stop_controlled_process(run_id)

        assert outcome.success
        assert target_proc.poll() is not None

        # Verify unrelated process is completely unaffected and still running!
        assert unrelated_proc.poll() is None
    finally:
        if unrelated_proc.poll() is None:
            unrelated_proc.kill()
            unrelated_proc.wait()

