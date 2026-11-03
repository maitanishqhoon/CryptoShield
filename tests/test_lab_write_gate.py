"""
Unit tests for LabWriteGate (Phase 4).
"""

import pytest

from app.containment.lab_write_gate import LabWriteGate
from app.core.models import WriteGateState


@pytest.fixture
def write_gate(tmp_path):
    gate = LabWriteGate(base_lab_dir=tmp_path)
    yield gate
    gate.clear()


def test_gate_opens_and_allows_writes(write_gate, tmp_path):
    run_id = "SIM-GATE-01"
    target_dir = tmp_path / "demo_target"
    target_dir.mkdir()

    write_gate.open_gate(run_id, target_dir)
    assert write_gate.get_state(run_id) == WriteGateState.OPEN

    allowed_file = target_dir / "test_doc.txt"
    allowed, msg = write_gate.is_write_allowed(run_id, allowed_file)
    assert allowed
    assert "permitted" in msg.lower()


def test_gate_closure_blocks_subsequent_writes(write_gate, tmp_path):
    run_id = "SIM-GATE-02"
    target_dir = tmp_path / "demo_target"
    target_dir.mkdir()

    write_gate.open_gate(run_id, target_dir)
    test_file = target_dir / "doc.txt"

    # Permitted while open
    allowed, _ = write_gate.is_write_allowed(run_id, test_file)
    assert allowed

    # Close gate
    write_gate.close_gate(run_id)
    assert write_gate.get_state(run_id) == WriteGateState.CLOSED

    # Blocked after close
    allowed2, msg2 = write_gate.is_write_allowed(run_id, test_file)
    assert not allowed2
    assert "closed" in msg2.lower()
    assert write_gate.get_rejected_count(run_id) == 1


def test_reject_operations_outside_laboratory_boundary(write_gate, tmp_path):
    run_id = "SIM-GATE-03"
    target_dir = tmp_path / "demo_target"
    target_dir.mkdir()

    write_gate.open_gate(run_id, target_dir)

    # Outside file (e.g. system root or tmp_path parent)
    outside_file = tmp_path.parent / "system_sensitive_file.txt"
    allowed, msg = write_gate.is_write_allowed(run_id, outside_file)
    assert not allowed
    assert "outside authorized laboratory" in msg.lower() or "breaches" in msg.lower()
    assert write_gate.get_rejected_count(run_id) == 1


def test_independent_gates_per_run(write_gate, tmp_path):
    run1 = "SIM-RUN-A"
    run2 = "SIM-RUN-B"

    dir1 = tmp_path / "dir_a"
    dir2 = tmp_path / "dir_b"
    dir1.mkdir()
    dir2.mkdir()

    write_gate.open_gate(run1, dir1)
    write_gate.open_gate(run2, dir2)

    # Close run1 only
    write_gate.close_gate(run1)

    assert write_gate.get_state(run1) == WriteGateState.CLOSED
    assert write_gate.get_state(run2) == WriteGateState.OPEN

    allowed1, _ = write_gate.is_write_allowed(run1, dir1 / "file.txt")
    allowed2, _ = write_gate.is_write_allowed(run2, dir2 / "file.txt")

    assert not allowed1
    assert allowed2

