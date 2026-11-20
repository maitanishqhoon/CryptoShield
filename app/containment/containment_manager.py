"""
Containment Manager for CryptoShield (Phase 4).

Coordinates the containment lifecycle:
- Manages lifecycle state transitions: REQUESTED -> VALIDATING -> IN_PROGRESS -> CONTAINED
- Enforces strict idempotency to prevent redundant terminations on already-contained runs
- Integrates ProcessRegistry, LabWriteGate, ProcessController, and ContainmentVerifier
- Maintains chronological audit timelines and persists dossiers to runtime/containment/
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import CONFIG
from app.containment.containment_verifier import ContainmentVerifier
from app.containment.lab_write_gate import WRITE_GATE, LabWriteGate
from app.containment.process_controller import ControlledProcessController
from app.containment.process_registry import REGISTRY, ControlledProcessRegistry
from app.core.event_bus import BUS, Event, EventBus
from app.core.logger import get_logger
from app.core.models import (
    ContainmentAction,
    ContainmentDecision,
    ContainmentRecord,
    ContainmentStatus,
    WriteGateState,
)

logger = get_logger("containment_manager")


class ContainmentManager:
    """
    Central manager for executing, verifying, and persisting controlled process containment.
    """

    _instance_lock = threading.Lock()
    _instance: Optional[ContainmentManager] = None

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        registry: Optional[ControlledProcessRegistry] = None,
        write_gate: Optional[LabWriteGate] = None,
        controller: Optional[ControlledProcessController] = None,
        verifier: Optional[ContainmentVerifier] = None,
        containment_dir: Optional[Path] = None,
    ) -> None:
        self.bus = event_bus or BUS
        self.registry = registry or REGISTRY
        self.write_gate = write_gate or WRITE_GATE
        self.controller = controller or ControlledProcessController(
            registry=self.registry, write_gate=self.write_gate
        )
        self.verifier = verifier or ContainmentVerifier(
            registry=self.registry, write_gate=self.write_gate
        )
        self.containment_dir = (containment_dir or CONFIG.containment_dir).resolve()

        self._records: Dict[str, ContainmentRecord] = {}
        self._contained_runs: Dict[str, str] = {}  # run_id -> containment_id
        self._lock = threading.RLock()

        # Operational metrics
        self.containments_requested: int = 0
        self.containments_completed: int = 0
        self.containments_failed: int = 0
        self.containments_skipped: int = 0

        # Ensure persistence directory exists
        try:
            self.containment_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.debug(f"Could not create containment directory: {e}")

    @classmethod
    def get_instance(cls) -> ContainmentManager:
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = ContainmentManager()
            return cls._instance

    def execute_containment(self, decision: ContainmentDecision) -> ContainmentRecord:
        """
        Execute containment based on a ContainmentDecision.

        Guarantees:
        - Strict idempotency: returns existing record if simulation run is already contained.
        - Enforces safety boundaries: refuses termination if not authorized.
        - Captures complete chronological audit timeline.
        """
        with self._lock:
            now_iso = datetime.now(CONFIG.TIMEZONE).isoformat()
            run_id = decision.simulation_run_id

            # 1. Idempotency check: Already contained?
            if run_id and run_id in self._contained_runs:
                prev_id = self._contained_runs[run_id]
                existing_record = self._records.get(prev_id)
                if existing_record and existing_record.final_status == ContainmentStatus.CONTAINED.value:
                    self.containments_skipped += 1
                    logger.info(
                        f"[CONTAINMENT IDEMPOTENT] Run '{run_id}' already contained by dossier {prev_id}. Skipping redundant action."
                    )
                    return existing_record

            containment_id = f"CONT-{uuid.uuid4().hex[:8].upper()}"
            self.containments_requested += 1

            record = ContainmentRecord(
                containment_id=containment_id,
                simulation_run_id=run_id,
                start_timestamp=now_iso,
                initial_threat_score=decision.threat_score,
                severity=decision.severity,
                actions_taken=["CONTAINMENT_REQUESTED"],
                final_status=ContainmentStatus.REQUESTED.value,
                incident_id=decision.related_incident_id,
                detection_id=decision.related_detection_id,
                metadata={"decision_id": decision.decision_id},
            )
            self._records[containment_id] = record

            self._add_timeline_entry(
                record,
                action="REQUEST_RECEIVED",
                desc=f"Containment requested: {decision.decision_reason}",
            )

            # Publish CONTAINMENT_REQUESTED
            self._publish_event("CONTAINMENT_REQUESTED", record.to_dict())

            # 2. Authorization check
            if not decision.auto_containment_authorized:
                record.final_status = ContainmentStatus.CONTAINMENT_RECOMMENDED.value
                record.completion_timestamp = datetime.now(CONFIG.TIMEZONE).isoformat()
                record.failure_explanation = "Automatic containment not authorized by policy."
                self._add_timeline_entry(
                    record,
                    action="CONTAINMENT_RECOMMENDED",
                    desc=decision.explanation,
                )
                self._save_record_to_disk(record)
                self._publish_event("CONTAINMENT_RECOMMENDED", record.to_dict())
                return record

            # 3. Registration check
            if not run_id or not self.registry.is_run_registered(run_id):
                record.final_status = ContainmentStatus.SKIPPED.value
                record.completion_timestamp = datetime.now(CONFIG.TIMEZONE).isoformat()
                record.failure_explanation = f"Simulation run '{run_id}' is not registered."
                self._add_timeline_entry(
                    record,
                    action="SKIPPED",
                    desc="Process control skipped: Missing or invalid simulation run registration.",
                )
                self._save_record_to_disk(record)
                self.containments_skipped += 1
                return record

            # 4. State -> VALIDATING
            record.final_status = ContainmentStatus.VALIDATING.value
            is_valid, id_msg = self.registry.verify_process_identity(run_id)
            record.process_identity_verification_outcome = id_msg
            self._add_timeline_entry(
                record,
                action="IDENTITY_VALIDATION",
                desc=f"Process identity verification: {id_msg}",
            )

            if not is_valid and "already" not in id_msg.lower():
                record.final_status = ContainmentStatus.FAILED.value
                record.completion_timestamp = datetime.now(CONFIG.TIMEZONE).isoformat()
                record.failure_explanation = id_msg
                self._add_timeline_entry(
                    record,
                    action="VALIDATION_FAILED",
                    desc=f"Containment aborted: {id_msg}",
                )
                self.containments_failed += 1
                self._save_record_to_disk(record)
                self._publish_event("CONTAINMENT_FAILED", record.to_dict())
                return record

            # 5. State -> IN_PROGRESS
            record.final_status = ContainmentStatus.IN_PROGRESS.value
            self._publish_event("CONTAINMENT_STARTED", record.to_dict())

            # 6. Close Lab Write Gate
            self.write_gate.close_gate(run_id)
            record.write_gate_status = WriteGateState.CLOSED.value
            record.actions_taken.append("LAB_WRITE_GATE_CLOSED")
            self._add_timeline_entry(
                record,
                action="WRITE_GATE_CLOSED",
                desc=f"Application-level write gate for run '{run_id}' transitioned to CLOSED.",
            )
            self._publish_event("LAB_WRITE_GATE_CLOSED", {"simulation_run_id": run_id})

            # 7. Request process shutdown via controller
            self._add_timeline_entry(
                record,
                action="SHUTDOWN_INITIATED",
                desc="Sending graceful stop request to registered simulator process.",
            )
            outcome = self.controller.stop_controlled_process(run_id)
            record.shutdown_method = outcome.method
            record.actions_taken.append(f"STOP_METHOD_{outcome.method}")

            self._add_timeline_entry(
                record,
                action="PROCESS_STOP_RESULT",
                desc=f"Outcome: {outcome.method} in {outcome.duration_seconds}s ({outcome.message})",
            )

            # 8. Verification checks
            verification = self.verifier.verify_containment(run_id)
            record.operations_prevented_count = self.write_gate.get_rejected_count(run_id)
            record.actions_taken.append("CONTAINMENT_VERIFIED" if verification.is_verified else "VERIFICATION_PARTIAL")

            self._add_timeline_entry(
                record,
                action="VERIFICATION_AUDIT",
                desc=(
                    f"7-point verification result: {'ALL PASSED' if verification.is_verified else 'FAILED'}. "
                    f"Operations prevented: {record.operations_prevented_count}."
                ),
            )

            # 9. Final status determination
            record.completion_timestamp = datetime.now(CONFIG.TIMEZONE).isoformat()
            if outcome.success and verification.is_verified:
                record.final_status = ContainmentStatus.CONTAINED.value
                self._contained_runs[run_id] = containment_id
                self.containments_completed += 1
                logger.info(
                    f"[CONTAINMENT SUCCESSFUL] Run '{run_id}' fully contained (Dossier: {containment_id})"
                )
                self._publish_event("CONTAINMENT_COMPLETED", record.to_dict())
            else:
                record.final_status = ContainmentStatus.FAILED.value
                record.failure_explanation = outcome.message
                self.containments_failed += 1
                logger.error(
                    f"[CONTAINMENT FAILED] Run '{run_id}' containment failed: {outcome.message}"
                )
                self._publish_event("CONTAINMENT_FAILED", record.to_dict())

            # 10. Persist to disk
            self._save_record_to_disk(record)
            return record

    def _add_timeline_entry(self, record: ContainmentRecord, action: str, desc: str) -> None:
        """Append chronological timeline entry to containment record."""
        entry = {
            "timestamp": datetime.now(CONFIG.TIMEZONE).isoformat(),
            "action": action,
            "description": desc,
        }
        record.timeline.append(entry)

    def _publish_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Publish event to EventBus."""
        try:
            self.bus.publish(
                Event(
                    event_type=event_type,
                    data=data,
                    source="CONTAINMENT_MANAGER",
                )
            )
        except Exception as e:
            logger.debug(f"Could not publish event {event_type}: {e}")

    def _save_record_to_disk(self, record: ContainmentRecord) -> Optional[Path]:
        """Persist containment record as structured JSON in runtime/containment/."""
        try:
            self.containment_dir.mkdir(parents=True, exist_ok=True)
            target = self.containment_dir / f"{record.containment_id}.json"
            with open(target, "w", encoding="utf-8") as f:
                json.dump(record.to_dict(), f, indent=2)
            return target
        except Exception as e:
            logger.debug(f"Could not persist containment dossier {record.containment_id}: {e}")
            return None

    def get_record(self, containment_id: str) -> Optional[ContainmentRecord]:
        """Retrieve record by containment ID."""
        with self._lock:
            if containment_id in self._records:
                return self._records[containment_id]

            # Try loading from disk
            target = self.containment_dir / f"{containment_id}.json"
            if target.exists():
                try:
                    with open(target, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    rec = ContainmentRecord.from_dict(data)
                    self._records[rec.containment_id] = rec
                    return rec
                except Exception:
                    pass
            return None

    def list_records(self) -> List[ContainmentRecord]:
        """Return all containment records, merging in-memory and disk."""
        with self._lock:
            # Sync from disk
            if self.containment_dir.exists():
                for f in self.containment_dir.glob("*.json"):
                    if f.stem not in self._records:
                        try:
                            with open(f, "r", encoding="utf-8") as fp:
                                data = json.load(fp)
                            rec = ContainmentRecord.from_dict(data)
                            self._records[rec.containment_id] = rec
                        except Exception:
                            pass
            return list(self._records.values())

    def clear(self) -> None:
        """Reset internal manager state."""
        with self._lock:
            self._records.clear()
            self._contained_runs.clear()
            self.containments_requested = 0
            self.containments_completed = 0
            self.containments_failed = 0
            self.containments_skipped = 0


# Global singleton instance
CONTAINMENT_MGR = ContainmentManager.get_instance()

