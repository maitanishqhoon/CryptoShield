"""
Lab Write Gate for CryptoShield (Phase 4).

Provides application-level write-gate enforcement for controlled activity simulators.
Prevents controlled processes from performing further laboratory file operations
once containment has been initiated.

Key Properties:
- Per-simulation-run gate state (OPEN -> CLOSING -> CLOSED).
- Rejects operations outside approved laboratory boundaries.
- Tracks and logs all rejected operations for post-incident audit and verification.
- Application-level coordination mechanism; does NOT alter Windows system ACLs.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from app.config import CONFIG
from app.core.logger import get_logger
from app.core.models import WriteGateState
from app.core.safety import SafetyViolationError, validate_lab_path

logger = get_logger("lab_write_gate")


class LabWriteGate:
    """
    Application-level write gate managing simulated laboratory filesystem access.
    """

    _instance_lock = threading.Lock()
    _instance: Optional[LabWriteGate] = None

    def __init__(self, base_lab_dir: Optional[Path] = None) -> None:
        self.lab_dir = (base_lab_dir or CONFIG.LAB_DIR).resolve()
        self._gate_states: Dict[str, WriteGateState] = {}
        self._rejected_operations: Dict[str, List[Dict[str, Any]]] = {}
        self._allowed_targets: Dict[str, Path] = {}
        self._lock = threading.RLock()

    @classmethod
    def get_instance(cls) -> LabWriteGate:
        """Singleton accessor."""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = LabWriteGate()
            return cls._instance

    def open_gate(
        self,
        simulation_run_id: str,
        target_dir: Optional[Union[str, Path]] = None,
    ) -> None:
        """
        Initialize and open the write gate for a new controlled simulation run.
        """
        with self._lock:
            if not simulation_run_id:
                raise ValueError("simulation_run_id cannot be empty.")

            if target_dir is None:
                lab_target = (self.lab_dir / f"containment_demo_{simulation_run_id}").resolve()
            else:
                lab_target = Path(target_dir).resolve()

            # Verify target_dir is inside laboratory
            try:
                lab_target.relative_to(self.lab_dir)
            except ValueError:
                raise SafetyViolationError(
                    f"[CRITICAL SAFETY BREACH] Target directory '{lab_target}' is outside authorized laboratory directory '{self.lab_dir}'!"
                )

            self._gate_states[simulation_run_id] = WriteGateState.OPEN
            self._allowed_targets[simulation_run_id] = lab_target
            self._rejected_operations[simulation_run_id] = []

            # Persist file-backed gate indicator for child processes if target exists
            if lab_target.exists():
                try:
                    gate_file = lab_target / ".write_gate_state"
                    gate_file.write_text("OPEN", encoding="utf-8")
                except Exception as e:
                    logger.debug(f"Could not write gate file to {lab_target}: {e}")

            logger.info(
                f"[WRITE GATE OPENED] Run '{simulation_run_id}' for target '{lab_target}'"
            )

    def close_gate(self, simulation_run_id: str) -> None:
        """
        Close the write gate for a given simulation run, rejecting all subsequent writes.
        """
        with self._lock:
            self._gate_states[simulation_run_id] = WriteGateState.CLOSED

            # Synchronize file-backed gate indicator for child processes
            lab_target = self._allowed_targets.get(simulation_run_id)
            if lab_target and lab_target.exists():
                try:
                    gate_file = lab_target / ".write_gate_state"
                    gate_file.write_text("CLOSED", encoding="utf-8")
                except Exception as e:
                    logger.debug(f"Could not update gate file at {lab_target}: {e}")

            logger.warning(
                f"[WRITE GATE CLOSED] Run '{simulation_run_id}' is now CLOSED. File writes prohibited."
            )

    def set_state(self, simulation_run_id: str, state: WriteGateState) -> None:
        """Explicitly update gate state (e.g. CLOSING)."""
        with self._lock:
            self._gate_states[simulation_run_id] = state
            logger.debug(f"Write gate for run '{simulation_run_id}' transitioned to {state.value}")

    def get_state(self, simulation_run_id: str) -> WriteGateState:
        """Query current state of the write gate for a run."""
        with self._lock:
            return self._gate_states.get(simulation_run_id, WriteGateState.CLOSED)

    def is_write_allowed(
        self,
        simulation_run_id: str,
        target_path: Union[str, Path],
        operation_name: str = "WRITE",
    ) -> Tuple[bool, str]:
        """
        Validate whether a controlled write operation is permitted.

        Checks:
        1. Is the gate state OPEN?
        2. Is the path safely inside the laboratory directory?
        3. If closed or boundary breached, reject operation and log rejection.
        """
        with self._lock:
            state = self.get_state(simulation_run_id)
            target = Path(target_path).resolve()

            # Check file-backed state if in-memory gate indicates OPEN or unknown
            curr = target
            for _ in range(3):
                if curr == curr.parent:
                    break
                curr = curr.parent
                gf = curr / ".write_gate_state"
                if gf.exists():
                    try:
                        content = gf.read_text(encoding="utf-8").strip()
                        if content == "CLOSED":
                            state = WriteGateState.CLOSED
                            break
                    except Exception:
                        pass

            # 1. Gate state check
            if state != WriteGateState.OPEN:
                self._record_rejection(
                    simulation_run_id=simulation_run_id,
                    target_path=str(target),
                    operation_name=operation_name,
                    reason=f"Write gate is {state.value} (Containment in effect)",
                )
                return False, f"Operation rejected: Write gate is {state.value}."

            # 2. Safety boundary check
            try:
                validate_lab_path(target, base_lab_dir=self.lab_dir)
            except SafetyViolationError as e:
                self._record_rejection(
                    simulation_run_id=simulation_run_id,
                    target_path=str(target),
                    operation_name=operation_name,
                    reason=f"Safety violation: {e}",
                )
                return False, f"Operation rejected: Target path breaches laboratory boundaries: {e}"

            # 3. Dedicated target boundary check if set
            allowed_dir = self._allowed_targets.get(simulation_run_id)
            if allowed_dir:
                try:
                    target.relative_to(allowed_dir)
                except ValueError:
                    self._record_rejection(
                        simulation_run_id=simulation_run_id,
                        target_path=str(target),
                        operation_name=operation_name,
                        reason=f"Target path outside run designated area '{allowed_dir}'",
                    )
                    return False, f"Operation rejected: Outside designated target '{allowed_dir}'."

            return True, "Operation permitted by LabWriteGate."

    def _record_rejection(
        self,
        simulation_run_id: str,
        target_path: str,
        operation_name: str,
        reason: str,
    ) -> None:
        """Internal audit recording for rejected operations."""
        rejection_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "simulation_run_id": simulation_run_id,
            "operation": operation_name,
            "target_path": target_path,
            "reason": reason,
        }
        if simulation_run_id not in self._rejected_operations:
            self._rejected_operations[simulation_run_id] = []
        self._rejected_operations[simulation_run_id].append(rejection_entry)

        logger.warning(
            f"[LAB OPERATION PREVENTED] Run '{simulation_run_id}': {operation_name} on '{target_path}' "
            f"REJECTED ({reason})"
        )

    def get_rejected_count(self, simulation_run_id: str) -> int:
        """Return total count of operations rejected for a simulation run."""
        with self._lock:
            return len(self._rejected_operations.get(simulation_run_id, []))

    def get_rejected_operations(self, simulation_run_id: str) -> List[Dict[str, Any]]:
        """Return list of all recorded rejected operation events for a simulation run."""
        with self._lock:
            return list(self._rejected_operations.get(simulation_run_id, []))

    def clear(self) -> None:
        """Reset all write gates."""
        with self._lock:
            self._gate_states.clear()
            self._rejected_operations.clear()
            self._allowed_targets.clear()


# Global write gate singleton
WRITE_GATE = LabWriteGate.get_instance()
