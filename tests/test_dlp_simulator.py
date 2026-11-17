"""
Unit tests for Controlled DLP Simulator (Phase 8).
"""

from pathlib import Path
import pytest

from app.core.event_bus import EventBus
from app.dlp.dlp_coordinator import DLPCoordinator
from app.exfiltration.mock_receiver import MockReceiver
from app.exfiltration.models import TransferStatus
from app.exfiltration.transfer_monitor import TransferMonitor
from app.simulation.dlp_simulator import ControlledDLPSimulator


def test_dlp_simulator_prepare_and_cleanup(tmp_path: Path):
    # Set up simulator with custom temporary base lab
    marker = tmp_path / ".cryptoshield_lab_marker"
    marker.write_text("dummy", encoding="utf-8")

    bus = EventBus()
    sim = ControlledDLPSimulator(base_lab_dir=tmp_path, event_bus=bus)
    demo_dir = sim.prepare_fixtures()

    assert demo_dir.exists()
    assert (demo_dir / "Public Documents" / "press_release_2026.txt").exists()
    assert (demo_dir / "Finance" / "q4_executive_salaries.json").exists()
    assert (demo_dir / "IT" / "domain_controller_backup_keys.json").exists()

    sim.cleanup()
    assert not demo_dir.exists()


def test_dlp_simulator_end_to_end_demonstration(tmp_path: Path):
    marker = tmp_path / ".cryptoshield_lab_marker"
    marker.write_text("dummy", encoding="utf-8")

    bus = EventBus()
    receiver = MockReceiver(host="127.0.0.1", port=0)
    host, port = receiver.start()

    try:
        coord = DLPCoordinator(event_bus=bus)
        monitor = TransferMonitor(event_bus=bus, mock_receiver=receiver, dlp_gate=coord.transfer_gate)

        sim = ControlledDLPSimulator(
            base_lab_dir=tmp_path,
            event_bus=bus,
            dlp_coordinator=coord,
            transfer_monitor=monitor,
            mock_receiver=receiver,
        )
        sim.prepare_fixtures()

        result = sim.run_demonstration(mock_host=host, mock_port=port)

        assert result.total_scenarios_executed == 4
        assert result.transfers_allowed == 1
        assert result.transfers_alerted == 1
        assert result.transfers_quarantined_and_approved == 1
        assert result.transfers_blocked == 1
        assert result.zero_bytes_leakage_verified is True

        # Tier 4 check (Restricted / Canary)
        tier4 = result.steps[3]
        assert tier4.dlp_action == "BLOCK"
        assert tier4.bytes_transferred == 0
        assert tier4.transfer_status == TransferStatus.BLOCKED.value

        sim.cleanup()
    finally:
        receiver.stop()
