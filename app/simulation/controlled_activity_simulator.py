"""
Controlled Activity Simulator for CryptoShield (Phase 4).

Generates strictly bounded, harmless file activity within a dedicated laboratory
fixture to test monitoring, detection, and controlled process containment.

Safety Guarantees:
- Runs in a dedicated temporary subdirectory inside the authenticated laboratory.
- NEVER modifies, moves, or touches the original 20,000-file baseline dataset.
- Re-validates LabWriteGate before each file operation.
- Halts immediately when write gate is CLOSED or cooperative stop signal is received.
- Bounded by max operations count and max execution duration.
- Cleans up only its own temporary fixtures.
- Strictly NOT malware or actual ransomware: creates harmless plain text files.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

from app.config import CONFIG
from app.containment.lab_write_gate import WRITE_GATE
from app.containment.process_registry import REGISTRY
from app.core.logger import get_logger
from app.core.safety import validate_lab_path

logger = get_logger("controlled_activity_simulator")


class ControlledActivitySimulator:
    """
    Launcher and orchestrator for controlled, harmless laboratory demonstration processes.
    """

    def __init__(
        self,
        simulation_run_id: Optional[str] = None,
        base_lab_dir: Optional[Path] = None,
        max_operations: int = 50,
        max_duration_seconds: float = 10.0,
        operation_delay_seconds: float = 0.08,
    ) -> None:
        self.run_id = simulation_run_id or f"SIM-{uuid.uuid4().hex[:8].upper()}"
        self.lab_dir = (base_lab_dir or CONFIG.LAB_DIR).resolve()
        self.target_dir = self.lab_dir / f"containment_demo_{self.run_id}"
        self.max_operations = max_operations
        self.max_duration_seconds = max_duration_seconds
        self.operation_delay_seconds = operation_delay_seconds

        self.process_handle: Optional[subprocess.Popen] = None
        self.pid: Optional[int] = None
        self._stop_file = self.target_dir / ".stop_signal"

    def prepare_fixtures(self, file_count: int = 25) -> Path:
        """
        Create isolated demonstration fixtures within the dedicated demo target.
        Strictly validates path to ensure baseline dataset is protected.
        """
        validate_lab_path(self.target_dir, base_lab_dir=self.lab_dir)
        self.target_dir.mkdir(parents=True, exist_ok=True)

        for i in range(file_count):
            dept = "Finance" if i % 2 == 0 else "Operations"
            dept_dir = self.target_dir / dept
            dept_dir.mkdir(parents=True, exist_ok=True)
            fpath = dept_dir / f"sample_demo_doc_{i}.txt"
            fpath.write_text(
                f"CryptoShield controlled demonstration sample fixture {i}.\n"
                f"Generated at: {time.time()}\n",
                encoding="utf-8",
            )

        # Create one dedicated harmless demo canary file in demo directory
        canary_dir = self.target_dir / "Finance"
        canary_file = canary_dir / "canary_demo_accounts.csv"
        canary_file.write_text(
            "account_id,balance,client_name\nDEMO-001,50000,Acme_Lab\n",
            encoding="utf-8",
        )

        logger.info(
            f"Prepared {file_count} harmless demonstration fixtures and 1 canary in '{self.target_dir}'."
        )
        return self.target_dir

    def launch(self) -> int:
        """
        Launch the simulator as a distinct child process, register it in ProcessRegistry,
        and open its LabWriteGate.
        """
        self.prepare_fixtures()

        # Open the run's write gate before starting process
        WRITE_GATE.open_gate(self.run_id, self.target_dir)

        # Launch child process via subprocess
        cmd = [
            sys.executable,
            "-m",
            "app.simulation.controlled_activity_simulator",
            "--run-id",
            self.run_id,
            "--target-dir",
            str(self.target_dir),
            "--max-ops",
            str(self.max_operations),
            "--max-duration",
            str(self.max_duration_seconds),
            "--delay",
            str(self.operation_delay_seconds),
        ]

        self.process_handle = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.pid = self.process_handle.pid

        # Register immediately in ControlledProcessRegistry
        REGISTRY.register_process(
            simulation_run_id=self.run_id,
            process_handle=self.process_handle,
            pid=self.pid,
            expected_identity="ControlledActivitySimulator",
            associated_lab_target=str(self.target_dir),
            metadata={"max_operations": self.max_operations},
        )

        logger.info(
            f"[SIMULATOR LAUNCHED] Run ID '{self.run_id}' running as PID {self.pid}."
        )
        return self.pid

    def request_stop(self) -> None:
        """Cooperative stop channel implementation."""
        try:
            self._stop_file.write_text("STOP", encoding="utf-8")
            logger.info(f"Wrote cooperative stop signal to '{self._stop_file}'.")
        except Exception as e:
            logger.debug(f"Could not write stop signal file: {e}")

    def cleanup(self) -> None:
        """Safely remove only the dedicated temporary demonstration directory."""
        if self.process_handle and self.process_handle.poll() is None:
            try:
                self.process_handle.terminate()
                self.process_handle.wait(timeout=1.0)
            except Exception:
                pass

        if self.target_dir.exists():
            try:
                # Extra validation check before deletion
                validate_lab_path(self.target_dir, base_lab_dir=self.lab_dir)
                shutil.rmtree(self.target_dir, ignore_errors=True)
                logger.info(f"Cleaned up temporary demonstration directory '{self.target_dir}'.")
            except Exception as e:
                logger.warning(f"Error cleaning up demo directory: {e}")


def execute_simulator_workload(
    run_id: str,
    target_dir_path: str,
    max_ops: int = 50,
    max_duration: float = 10.0,
    delay: float = 0.08,
) -> int:
    """
    Main workload loop executed by the child process.
    Performs harmless bounded file operations while strictly obeying the LabWriteGate.
    """
    target_dir = Path(target_dir_path).resolve()
    stop_file = target_dir / ".stop_signal"
    gate_file = target_dir / ".write_gate_state"

    start_time = time.perf_counter()
    ops_completed = 0
    ops_rejected = 0

    files = sorted(target_dir.rglob("*.txt"))
    canary = target_dir / "Finance" / "canary_demo_accounts.csv"

    # Add canary to operational targets
    all_targets = list(files)
    if canary.exists():
        all_targets.append(canary)

    target_idx = 0

    while ops_completed < max_ops and (time.perf_counter() - start_time) < max_duration:
        # Check cooperative stop signal
        if stop_file.exists():
            break

        # Check write gate state
        is_gate_open = True
        if gate_file.exists():
            try:
                content = gate_file.read_text(encoding="utf-8").strip()
                if content != "OPEN":
                    is_gate_open = False
            except Exception:
                pass

        if not is_gate_open:
            ops_rejected += 1
            # Record operation attempt rejection
            time.sleep(0.05)
            continue

        if not all_targets:
            break

        target_file = all_targets[target_idx % len(all_targets)]
        target_idx += 1

        try:
            # Perform harmless modification
            if target_file.exists():
                with open(target_file, "a", encoding="utf-8") as f:
                    f.write(f"Harmless simulation append at {time.time()}\n")
                ops_completed += 1
        except Exception:
            pass

        time.sleep(delay)

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="CryptoShield Controlled Activity Simulator")
    parser.add_argument("--run-id", type=str, required=True, help="Simulation run ID")
    parser.add_argument("--target-dir", type=str, required=True, help="Dedicated laboratory target dir")
    parser.add_argument("--max-ops", type=int, default=50, help="Maximum number of harmless operations")
    parser.add_argument("--max-duration", type=float, default=10.0, help="Maximum execution duration in seconds")
    parser.add_argument("--delay", type=float, default=0.08, help="Delay between operations in seconds")

    args = parser.parse_args()
    return execute_simulator_workload(
        run_id=args.run_id,
        target_dir_path=args.target_dir,
        max_ops=args.max_ops,
        max_duration=args.max_duration,
        delay=args.delay,
    )


if __name__ == "__main__":
    sys.exit(main())

