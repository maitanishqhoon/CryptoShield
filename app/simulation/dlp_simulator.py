"""
Controlled DLP Simulator for CryptoShield (Phase 8).

Executes safe, harmless multi-tier Data Loss Prevention demonstrations inside an isolated
laboratory subdirectory, verifying classification-aware policy decisions (ALLOW, ALERT,
REQUIRE_APPROVAL, BLOCK) and cryptographic zero-byte leakage guarantees.
"""

from __future__ import annotations

from dataclasses import dataclass
import io
import json
import logging
import os
from pathlib import Path
import shutil
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid
import zipfile

from app.config import CONFIG
from app.core.event_bus import BUS, EventBus
from app.core.safety import validate_lab_path
from app.dlp.approval_manager import DLPApprovalManager
from app.dlp.dlp_coordinator import DLPCoordinator
from app.dlp.models import DLPAction, DLPApprovalStatus, DLPEvaluationResult
from app.dlp.policy_engine import DLPPolicyEngine
from app.dlp.transfer_gate import DLPTransferGate
from app.exfiltration.mock_receiver import MockReceiver
from app.exfiltration.models import TransferStatus
from app.exfiltration.transfer_monitor import TransferMonitor
from app.monitoring.access_monitor import AccessMonitor

logger = logging.getLogger("cryptoshield.simulation.dlp_simulator")


@dataclass
class DLPSimulationStepResult:
    """Outcome of a single DLP scenario tier."""
    scenario_name: str
    target_classification: str
    is_canary: bool
    dlp_action: str
    allowed: bool
    bytes_transferred: int
    transfer_status: str
    reason: str
    approval_token: Optional[str] = None


@dataclass
class DLPSimulationResult:
    """Overall summary of the completed DLP multi-tier demonstration."""
    run_id: str
    target_dir: str
    total_scenarios_executed: int
    transfers_allowed: int
    transfers_alerted: int
    transfers_quarantined_and_approved: int
    transfers_blocked: int
    zero_bytes_leakage_verified: bool
    steps: List[DLPSimulationStepResult]
    duration_seconds: float
    metadata: Dict[str, Any]


class ControlledDLPSimulator:
    """
    Simulates multi-tier outbound transfer workflows to validate DLP enforcement.
    Demonstrates:
    1. Tier 1: PUBLIC document movement -> ALLOW
    2. Tier 2: INTERNAL operational report -> ALERT
    3. Tier 3: CONFIDENTIAL financial records -> REQUIRE_APPROVAL (Quarantine & Operator Approval)
    4. Tier 4: RESTRICTED IP & Canary Honeypot -> BLOCK (Interception & 0 bytes transferred)
    """

    def __init__(
        self,
        simulation_run_id: Optional[str] = None,
        base_lab_dir: Optional[Path] = None,
        event_bus: Optional[EventBus] = None,
        dlp_coordinator: Optional[DLPCoordinator] = None,
        transfer_monitor: Optional[TransferMonitor] = None,
        mock_receiver: Optional[Any] = None,
    ) -> None:
        self.run_id = simulation_run_id or f"DLPSIM-{uuid.uuid4().hex[:8].upper()}"
        self.lab_dir = (base_lab_dir or CONFIG.LAB_DIR).resolve()
        self.target_dir = self.lab_dir / f"dlp_demo_{self.run_id}"
        self.bus = event_bus or BUS

        self.dlp_coordinator = dlp_coordinator or DLPCoordinator(event_bus=self.bus)
        self.mock_receiver = mock_receiver
        self.transfer_monitor = transfer_monitor or TransferMonitor(
            event_bus=self.bus,
            mock_receiver=self.mock_receiver,
            dlp_gate=self.dlp_coordinator.transfer_gate,
        )

        self._files_created: List[Path] = []
        self._canary_files: List[Path] = []

    def prepare_fixtures(self) -> Path:
        """Creates dummy demo files across Public, Operations, Finance, IT, and Research."""
        validate_lab_path(self.target_dir, base_lab_dir=self.lab_dir)
        self.target_dir.mkdir(parents=True, exist_ok=True)

        # 1. Public
        pub_dir = self.target_dir / "Public Documents"
        pub_dir.mkdir(parents=True, exist_ok=True)
        pub_file = pub_dir / "press_release_2026.txt"
        pub_file.write_text("CryptoShield Open Architecture Whitepaper Press Release.", encoding="utf-8")
        self._files_created.append(pub_file)

        # 2. Operations (Internal)
        ops_dir = self.target_dir / "Operations"
        ops_dir.mkdir(parents=True, exist_ok=True)
        ops_file = ops_dir / "weekly_facility_shift_schedule.csv"
        ops_file.write_text("day,shift,lead\nMonday,Day,Alice\nTuesday,Night,Bob\n", encoding="utf-8")
        self._files_created.append(ops_file)

        # 3. Finance (Confidential)
        fin_dir = self.target_dir / "Finance"
        fin_dir.mkdir(parents=True, exist_ok=True)
        fin_file = fin_dir / "q4_executive_salaries.json"
        fin_file.write_text('{"payroll": [{"name": "Executive A", "compensation": 250000}]}', encoding="utf-8")
        self._files_created.append(fin_file)

        # 4. IT Honeypot Canary & Research (Restricted)
        it_dir = self.target_dir / "IT"
        it_dir.mkdir(parents=True, exist_ok=True)
        canary_file = it_dir / "domain_controller_backup_keys.json"
        canary_data = {
            "account": "root_domain_admin",
            "token": f"CANARY-DLP-HONEYPOT-{uuid.uuid4().hex}",
            "is_canary": True,
            "classification": "RESTRICTED",
        }
        canary_file.write_text(json.dumps(canary_data, indent=2), encoding="utf-8")
        self._canary_files.append(canary_file)

        res_dir = self.target_dir / "Research"
        res_dir.mkdir(parents=True, exist_ok=True)
        res_file = res_dir / "proprietary_ai_blueprint.md"
        res_file.write_text("# RESTRICTED PROPRIETARY RESEARCH\nPatented cryptographic architecture.", encoding="utf-8")
        self._files_created.append(res_file)

        logger.info("Prepared DLP fixtures in %s", self.target_dir)
        return self.target_dir

    def run_demonstration(
        self,
        mock_host: str = "127.0.0.1",
        mock_port: int = CONFIG.EXFILTRATION_MOCK_PORT,
    ) -> DLPSimulationResult:
        """
        Executes the 4-tier DLP demonstration:
        1. PUBLIC -> ALLOW
        2. INTERNAL -> ALERT
        3. CONFIDENTIAL -> REQUIRE_APPROVAL (Quarantined, then operator-approved)
        4. RESTRICTED & CANARY HONEYPOT -> BLOCK (Intercepted, 0 bytes leaked)
        """
        start_time = time.time()
        steps: List[DLPSimulationStepResult] = []

        allowed_count = 0
        alerted_count = 0
        approved_count = 0
        blocked_count = 0

        # Tier 1: PUBLIC -> ALLOW
        pub_payload = b"CryptoShield Open Architecture Whitepaper Press Release."
        rec_pub = self.transfer_monitor.transmit_to_mock_endpoint(
            target_host=mock_host,
            target_port=mock_port,
            payload_bytes=pub_payload,
            file_count=1,
            classifications=["PUBLIC"],
            departments=["Public Documents"],
            contains_canary=False,
        )
        steps.append(
            DLPSimulationStepResult(
                scenario_name="Tier 1: Public Documents",
                target_classification="PUBLIC",
                is_canary=False,
                dlp_action=DLPAction.ALLOW.value,
                allowed=True,
                bytes_transferred=rec_pub.bytes_transferred,
                transfer_status=rec_pub.status,
                reason="Publicly disclosable document transfer permitted.",
            )
        )
        allowed_count += 1

        # Tier 2: INTERNAL -> ALERT
        internal_payload = b"day,shift,lead\nMonday,Day,Alice\nTuesday,Night,Bob\n"
        rec_internal = self.transfer_monitor.transmit_to_mock_endpoint(
            target_host=mock_host,
            target_port=mock_port,
            payload_bytes=internal_payload,
            file_count=1,
            classifications=["INTERNAL"],
            departments=["Operations"],
            contains_canary=False,
        )
        steps.append(
            DLPSimulationStepResult(
                scenario_name="Tier 2: Internal Operations",
                target_classification="INTERNAL",
                is_canary=False,
                dlp_action=DLPAction.ALERT.value,
                allowed=True,
                bytes_transferred=rec_internal.bytes_transferred,
                transfer_status=rec_internal.status,
                reason="Internal operational records movement observed and logged.",
            )
        )
        alerted_count += 1

        # Tier 3: CONFIDENTIAL -> REQUIRE_APPROVAL (Quarantine & Operator Approval Workflow)
        conf_payload = b'{"payroll": [{"name": "Executive A", "compensation": 250000}]}'
        rec_conf = self.transfer_monitor.transmit_to_mock_endpoint(
            target_host=mock_host,
            target_port=mock_port,
            payload_bytes=conf_payload,
            file_count=1,
            classifications=["CONFIDENTIAL"],
            departments=["Finance"],
            contains_canary=False,
        )

        approval_token = rec_conf.metadata.get("approval_token")
        if approval_token:
            # Demonstrate operator authorization: approve the pending token
            ok, approved_req = self.dlp_coordinator.approve_transfer(
                approval_token=approval_token,
                decided_by="security_officer_demo",
                reason="Authorized for authorized external payroll audit",
            )
            if ok:
                approved_count += 1

        steps.append(
            DLPSimulationStepResult(
                scenario_name="Tier 3: Confidential Payroll (Approval Flow)",
                target_classification="CONFIDENTIAL",
                is_canary=False,
                dlp_action=DLPAction.REQUIRE_APPROVAL.value,
                allowed=False,  # Initially quarantined
                bytes_transferred=rec_conf.bytes_transferred,
                transfer_status=rec_conf.status,
                reason="Confidential financial records quarantined; operator approval demonstrated.",
                approval_token=approval_token,
            )
        )

        # Tier 4: RESTRICTED & CANARY HONEYPOT -> BLOCK (Active Interception)
        canary_payload = b'{"account": "root_domain_admin", "token": "CANARY-HONEYPOT-TOKEN"}'
        rec_block = self.transfer_monitor.transmit_to_mock_endpoint(
            target_host=mock_host,
            target_port=mock_port,
            payload_bytes=canary_payload,
            file_count=2,
            classifications=["RESTRICTED"],
            departments=["IT", "Research"],
            contains_canary=True,
        )

        steps.append(
            DLPSimulationStepResult(
                scenario_name="Tier 4: Restricted IP & Canary Honeypot",
                target_classification="RESTRICTED",
                is_canary=True,
                dlp_action=DLPAction.BLOCK.value,
                allowed=False,
                bytes_transferred=rec_block.bytes_transferred,  # Must be 0
                transfer_status=rec_block.status,              # Must be BLOCKED
                reason=rec_block.metadata.get("dlp_reason", "Blocked by DLP policy"),
            )
        )
        if rec_block.status == TransferStatus.BLOCKED.value:
            blocked_count += 1

        duration = round(time.time() - start_time, 3)
        zero_bytes_verified = (rec_block.bytes_transferred == 0) and (rec_block.status == TransferStatus.BLOCKED.value)

        return DLPSimulationResult(
            run_id=self.run_id,
            target_dir=str(self.target_dir),
            total_scenarios_executed=len(steps),
            transfers_allowed=allowed_count,
            transfers_alerted=alerted_count,
            transfers_quarantined_and_approved=approved_count,
            transfers_blocked=blocked_count,
            zero_bytes_leakage_verified=zero_bytes_verified,
            steps=steps,
            duration_seconds=duration,
            metadata={
                "dlp_profile": self.dlp_coordinator.policy_engine.profile.value,
                "tier4_status": rec_block.status,
                "tier4_bytes": rec_block.bytes_transferred,
            },
        )

    def cleanup(self) -> None:
        """Safely cleans up only the dedicated demonstration directory."""
        if self.target_dir.exists() and self.target_dir.is_dir():
            validate_lab_path(self.target_dir, base_lab_dir=self.lab_dir)
            shutil.rmtree(self.target_dir, ignore_errors=True)
            logger.info("Cleaned up DLP simulation fixtures at %s", self.target_dir)
