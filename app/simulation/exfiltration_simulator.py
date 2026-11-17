"""
Controlled Exfiltration Simulator for CryptoShield (Phase 7).

Generates strictly bounded, harmless simulated data exfiltration activity within
a dedicated laboratory fixture to evaluate read-burst detection, canary honeypot
triggering, staging archive detection, and mock socket transfer telemetry.

Safety Guarantees:
- Runs within an isolated demonstration subdirectory in the authenticated laboratory.
- NEVER modifies, damages, or deletes the original 20,000-file baseline dataset.
- Transmits simulated payload strictly to local loopback (127.0.0.1).
- Bounded file count, byte limits, and execution duration.
- Cleans up only its own temporary fixtures.
- Strictly NOT malware: reads harmless synthetic text and sends synthetic bytes.
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
from typing import Any, Dict, List, Optional
import uuid
import zipfile

from app.config import CONFIG
from app.core.event_bus import BUS, EventBus
from app.core.safety import validate_lab_path
from app.exfiltration.mock_receiver import MockReceiver
from app.exfiltration.models import (
    OutboundTransferRecord,
    StagingType,
    TransferProtocol,
    TransferStatus,
)
from app.exfiltration.transfer_monitor import TransferMonitor
from app.monitoring.access_monitor import AccessMonitor

logger = logging.getLogger("cryptoshield.simulation.exfiltration_simulator")


@dataclass
class ExfiltrationSimulationResult:
    """Summary record of a completed controlled exfiltration simulation run."""
    run_id: str
    target_dir: str
    files_created: int
    files_read: int
    canaries_read: int
    bytes_staged: int
    bytes_transferred: int
    staging_archive_path: Optional[str]
    transfer_status: str
    duration_seconds: float
    metadata: Dict[str, Any]


class ControlledExfiltrationSimulator:
    """
    Harmless test simulator executing the 4 stages of simulated data exfiltration:
    1. Read harvesting (burst reads across departments)
    2. Honeypot canary reading
    3. Archive staging (.zip creation)
    4. Mock loopback socket transfer (127.0.0.1)
    """

    def __init__(
        self,
        simulation_run_id: Optional[str] = None,
        base_lab_dir: Optional[Path] = None,
        event_bus: Optional[EventBus] = None,
        access_monitor: Optional[AccessMonitor] = None,
        transfer_monitor: Optional[TransferMonitor] = None,
        mock_receiver: Optional[Any] = None,
    ) -> None:
        self.run_id = simulation_run_id or f"EXFILSIM-{uuid.uuid4().hex[:8].upper()}"
        self.lab_dir = (base_lab_dir or CONFIG.LAB_DIR).resolve()
        self.target_dir = self.lab_dir / f"exfiltration_demo_{self.run_id}"
        self.bus = event_bus or BUS
        self.access_monitor = access_monitor or AccessMonitor(base_lab_dir=self.lab_dir, event_bus=self.bus)
        self.mock_receiver = mock_receiver
        self.transfer_monitor = transfer_monitor or TransferMonitor(
            event_bus=self.bus, mock_receiver=self.mock_receiver
        )

        self._files_created: List[Path] = []
        self._canary_files: List[Path] = []
        self._staging_archive: Optional[Path] = None

    def prepare_fixtures(
        self,
        file_count: int = 15,
        canary_count: int = 2,
    ) -> Path:
        """
        Creates isolated demonstration fixtures in the dedicated demo target directory.
        Includes files across Finance, Legal, and HR, plus deceptive canaries.
        """
        validate_lab_path(self.target_dir, base_lab_dir=self.lab_dir)
        self.target_dir.mkdir(parents=True, exist_ok=True)

        departments = ["Finance", "Legal", "Human Resources"]

        for i in range(file_count):
            dept = departments[i % len(departments)]
            dept_dir = self.target_dir / dept
            dept_dir.mkdir(parents=True, exist_ok=True)
            fpath = dept_dir / f"sim_sensitive_doc_{i}.txt"
            content = (
                f"CryptoShield Confidential Demonstration Document #{i}\n"
                f"Department: {dept}\n"
                f"Classification: CONFIDENTIAL\n"
                f"Timestamp: {time.time()}\n"
            )
            fpath.write_text(content, encoding="utf-8")
            self._files_created.append(fpath)

        # Create deceptive honeypot canaries
        for c in range(canary_count):
            canary_dir = self.target_dir / "IT"
            canary_dir.mkdir(parents=True, exist_ok=True)
            cpath = canary_dir / f"executive_credentials_canary_{c}.json"
            canary_data = {
                "account": f"root_admin_{c}",
                "token": f"CANARY-SECRET-TOKEN-{uuid.uuid4().hex}",
                "is_canary": True,
                "canary_id": f"CANARY-EXFIL-{c}",
            }
            cpath.write_text(json.dumps(canary_data, indent=2), encoding="utf-8")
            self._canary_files.append(cpath)

        logger.info(
            "Prepared %d demo files and %d canaries in %s",
            len(self._files_created),
            len(self._canary_files),
            self.target_dir,
        )
        return self.target_dir

    def run_simulation(
        self,
        mock_host: str = "127.0.0.1",
        mock_port: int = CONFIG.EXFILTRATION_MOCK_PORT,
    ) -> ExfiltrationSimulationResult:
        """
        Executes the end-to-end exfiltration workflow:
        1. Harvest files via AccessMonitor (records FILE_READ telemetry).
        2. Read canary honeypot files (records CANARY_ACCESS telemetry).
        3. Compress harvested files into a staging archive.
        4. Transmit mock archive bytes to the local MockReceiver on 127.0.0.1.
        """
        start_time = time.time()
        files_read_count = 0
        canaries_read_count = 0
        harvested_contents: List[Tuple[str, bytes]] = []

        # Step 1: Read harvesting
        for fpath in self._files_created:
            try:
                rel_path = str(fpath.relative_to(self.lab_dir)).replace("\\", "/")
                dept = fpath.parent.name
                content = self.access_monitor.read_file(
                    file_path=fpath,
                    pid=os.getpid(),
                    process_name="controlled_exfiltration_simulator",
                )
                harvested_contents.append((rel_path, content.encode("utf-8")))
                files_read_count += 1
            except Exception as e:
                logger.error("Failed to read fixture %s: %s", fpath, e)

        # Step 2: Honeypot canary reading
        for cpath in self._canary_files:
            try:
                rel_path = str(cpath.relative_to(self.lab_dir)).replace("\\", "/")
                # Record access explicitly as a canary access event
                self.access_monitor.record_access(
                    file_path=cpath,
                    operation="READ",
                    pid=os.getpid(),
                    process_name="controlled_exfiltration_simulator",
                    custom_metadata={"is_canary": True, "classification": "RESTRICTED", "department": "IT"},
                )
                content = cpath.read_bytes()
                harvested_contents.append((rel_path, content))
                canaries_read_count += 1
            except Exception as e:
                logger.error("Failed to read canary %s: %s", cpath, e)

        # Step 3: Local staging archive creation
        staging_dir = self.target_dir / ".staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        self._staging_archive = staging_dir / "exfiltration_payload.zip"

        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for rel_name, data in harvested_contents:
                zf.writestr(rel_name, data)

        staged_bytes = archive_buffer.getvalue()
        self._staging_archive.write_bytes(staged_bytes)

        # Step 4: Simulated outbound transfer to local mock receiver
        transfer_record = self.transfer_monitor.transmit_to_mock_endpoint(
            target_host=mock_host,
            target_port=mock_port,
            payload_bytes=staged_bytes,
            file_count=len(harvested_contents),
            process_id=os.getpid(),
            process_name="controlled_exfiltration_simulator",
            classifications=["CONFIDENTIAL", "RESTRICTED"],
            departments=["Finance", "Legal", "Human Resources", "IT"],
            contains_canary=canaries_read_count > 0,
        )

        duration = round(time.time() - start_time, 3)

        return ExfiltrationSimulationResult(
            run_id=self.run_id,
            target_dir=str(self.target_dir),
            files_created=len(self._files_created) + len(self._canary_files),
            files_read=files_read_count,
            canaries_read=canaries_read_count,
            bytes_staged=len(staged_bytes),
            bytes_transferred=transfer_record.bytes_transferred,
            staging_archive_path=str(self._staging_archive),
            transfer_status=transfer_record.status,
            duration_seconds=duration,
            metadata={
                "transfer_id": transfer_record.transfer_id,
                "destination_endpoint": transfer_record.destination_endpoint,
            },
        )

    def cleanup(self) -> None:
        """Safely removes only the dedicated demonstration directory."""
        if self.target_dir.exists() and self.target_dir.is_dir():
            # Validate safety before removing
            validate_lab_path(self.target_dir, base_lab_dir=self.lab_dir)
            shutil.rmtree(self.target_dir, ignore_errors=True)
            logger.info("Cleaned up simulation target: %s", self.target_dir)
