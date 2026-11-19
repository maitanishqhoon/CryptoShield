"""
Forensic Reporting Coordinator for CryptoShield (Phase 9).

Orchestrates multi-subsystem forensic dossier aggregation, multi-format export,
report indexing, integrity auditing, and EventBus listener hooks.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from app.config import CONFIG
from app.core.event_bus import BUS, Event, EventBus
from app.core.logger import get_logger
from app.core.models import SecurityIncident
from app.detection.incident_manager import IncidentManager
from app.reporting.aggregator import ForensicAggregator
from app.reporting.exporter import ReportExporter
from app.reporting.models import (
    ForensicDossier,
    ReportFormat,
    ReportMetadata,
)

logger = get_logger("forensic_coordinator")


class ForensicCoordinator:
    """
    Central lifecycle coordinator for the Phase 9 Forensic Incident Reporting Subsystem.
    """

    _instance: Optional[ForensicCoordinator] = None
    _instance_lock = threading.Lock()

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        reports_dir: Optional[Path] = None,
        incidents_dir: Optional[Path] = None,
        containment_dir: Optional[Path] = None,
        recovery_reports_dir: Optional[Path] = None,
        auto_generate_on_resolve: bool = True,
    ) -> None:
        self.bus = event_bus or BUS
        self.reports_dir = (reports_dir or CONFIG.reports_dir).resolve()
        self.incidents_dir = (incidents_dir or CONFIG.incidents_dir).resolve()
        self.containment_dir = (containment_dir or CONFIG.CONTAINMENT_DIR).resolve()
        self.recovery_reports_dir = (recovery_reports_dir or CONFIG.recovery_reports_dir).resolve()
        self.auto_generate_on_resolve = auto_generate_on_resolve

        self.aggregator = ForensicAggregator(
            incidents_dir=self.incidents_dir,
            containment_dir=self.containment_dir,
            recovery_reports_dir=self.recovery_reports_dir,
        )
        self.exporter = ReportExporter(reports_dir=self.reports_dir)

        self._reports_cache: Dict[str, ForensicDossier] = {}
        self._lock = threading.RLock()

        # Operational metrics
        self.reports_generated_count: int = 0
        self.reports_verified_count: int = 0

        # Ensure directory
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # EventBus subscription
        self._subscribe_events()

    @classmethod
    def get_instance(cls) -> ForensicCoordinator:
        """Singleton accessor."""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def _subscribe_events(self) -> None:
        """Register listeners on EventBus."""
        try:
            self.bus.subscribe("SECURITY_INCIDENT_RESOLVED", self._handle_incident_resolved)
        except Exception as e:
            logger.debug(f"Could not subscribe to EventBus: {e}")

    def _handle_incident_resolved(self, event: Event) -> None:
        """Automated trigger when a SecurityIncident transitions to RESOLVED."""
        if not self.auto_generate_on_resolve:
            return

        try:
            incident_data = event.data
            inc_id = incident_data.get("incident_id")
            if not inc_id:
                return

            incident = SecurityIncident.from_dict(incident_data)
            logger.info(f"Auto-generating forensic incident report for resolved incident {inc_id}...")
            self.generate_report(incident)
        except Exception as e:
            logger.debug(f"Failed to auto-generate report on incident resolved: {e}")

    # =========================================================================
    # Report Lifecycle & Generation
    # =========================================================================

    def generate_report(
        self,
        incident_or_id: Union[SecurityIncident, str],
        formats: Optional[List[Union[ReportFormat, str]]] = None,
        containment_id: Optional[str] = None,
        recovery_id: Optional[str] = None,
    ) -> ForensicDossier:
        """
        Generate and export a comprehensive ForensicDossier for an incident.

        Args:
            incident_or_id: SecurityIncident instance or string incident ID.
            formats: List of formats to export (defaults to JSON, MD, CSV, HTML).
            containment_id: Optional explicit containment record ID.
            recovery_id: Optional explicit recovery record ID.

        Returns:
            The generated and cryptographically sealed ForensicDossier.
        """
        with self._lock:
            incident = self._resolve_incident(incident_or_id)
            if not incident:
                raise ValueError(f"Could not locate or resolve incident: {incident_or_id}")

            # Aggregate multi-subsystem telemetry
            dossier = self.aggregator.aggregate(
                incident=incident,
                containment_id=containment_id,
                recovery_id=recovery_id,
            )

            # Export across requested formats
            exported_files = self.exporter.export_all(dossier, formats=formats)

            # Store in cache
            self._reports_cache[dossier.report_id] = dossier
            self.reports_generated_count += 1

            # Publish notification to EventBus
            try:
                self.bus.publish(
                    Event(
                        event_type="FORENSIC_REPORT_GENERATED",
                        data={
                            "report_id": dossier.report_id,
                            "incident_id": dossier.incident_id,
                            "threat_score": dossier.threat_score,
                            "severity": dossier.severity,
                            "dossier_sha256": dossier.chain_of_custody.dossier_sha256 if dossier.chain_of_custody else "",
                            "exported_files": {k: str(v) for k, v in exported_files.items()},
                        },
                        source="forensic_coordinator",
                    )
                )
            except Exception as e:
                logger.debug(f"Failed to publish report generation event: {e}")

            logger.info(
                f"Generated forensic report {dossier.report_id} for incident {dossier.incident_id} "
                f"(Score: {dossier.threat_score}, Sealed: {dossier.chain_of_custody.dossier_sha256[:12] if dossier.chain_of_custody else 'N/A'})"
            )
            return dossier

    def get_report(self, report_id: str) -> Optional[ForensicDossier]:
        """Retrieve a ForensicDossier by report ID (cache or disk)."""
        with self._lock:
            if report_id in self._reports_cache:
                return self._reports_cache[report_id]

            # Look up on disk
            matches = list(self.reports_dir.glob(f"{report_id}_*.json"))
            if not matches:
                matches = list(self.reports_dir.glob(f"{report_id}.json"))

            if matches:
                try:
                    with open(matches[0], "r", encoding="utf-8") as f:
                        data = json.load(f)
                    dossier = ForensicDossier.from_dict(data)
                    self._reports_cache[report_id] = dossier
                    return dossier
                except Exception as e:
                    logger.debug(f"Failed to load report {matches[0]}: {e}")

            return None

    def list_reports(self) -> List[ReportMetadata]:
        """Scan `runtime/reports/` and return list of available report metadata descriptors."""
        with self._lock:
            results: List[ReportMetadata] = []
            if not self.reports_dir.exists():
                return results

            json_files = list(self.reports_dir.glob("REP-*_INC-*.json"))
            for jf in json_files:
                try:
                    with open(jf, "r", encoding="utf-8") as f:
                        data = json.load(f)

                    rep_id = data.get("report_id", jf.stem.split("_")[0])
                    inc_id = data.get("incident_id", "")
                    metrics = data.get("metrics", {})
                    coc = data.get("chain_of_custody", {})

                    # Find companion format files
                    companion_files: Dict[str, str] = {"json": str(jf)}
                    md_path = jf.with_suffix(".md")
                    if md_path.exists():
                        companion_files["markdown"] = str(md_path)
                    csv_path = self.reports_dir / f"{rep_id}_{inc_id}_timeline.csv"
                    if csv_path.exists():
                        companion_files["csv"] = str(csv_path)
                    html_path = jf.with_suffix(".html")
                    if html_path.exists():
                        companion_files["html"] = str(html_path)

                    results.append(
                        ReportMetadata(
                            report_id=rep_id,
                            incident_id=inc_id,
                            generated_at=data.get("generated_at", ""),
                            status=data.get("incident_status", "UNKNOWN"),
                            threat_score=int(data.get("threat_score", 0)),
                            severity=data.get("severity", "LOW"),
                            files_affected=int(metrics.get("files_affected_count", 0)),
                            restored_count=int(metrics.get("files_preserved_or_restored_count", 0)),
                            dossier_sha256=coc.get("dossier_sha256", ""),
                            export_files=companion_files,
                        )
                    )
                except Exception as e:
                    logger.debug(f"Failed to parse report metadata for {jf}: {e}")

            results.sort(key=lambda r: r.generated_at, reverse=True)
            return results

    def verify_report(self, target: Union[str, Path]) -> Tuple[bool, str]:
        """
        Verify the cryptographic chain-of-custody seal on a report file or report ID.

        Returns:
            Tuple of (is_valid: bool, reason: str).
        """
        with self._lock:
            if isinstance(target, str) and not target.endswith(".json"):
                # Interpret as report ID
                dossier = self.get_report(target)
                if not dossier:
                    return False, f"Report ID '{target}' not found."
                valid = self.exporter.verify_dossier_seal(dossier)
                if valid:
                    self.reports_verified_count += 1
                    return True, f"Report '{target}' cryptographic SHA-256 seal verified successfully."
                else:
                    return False, f"Report '{target}' SHA-256 seal mismatch!"

            path = Path(target)
            valid, msg = self.exporter.verify_report_file(path)
            if valid:
                self.reports_verified_count += 1
            return valid, msg

    def clear(self) -> None:
        """Clear in-memory cache and reset counters."""
        with self._lock:
            self._reports_cache.clear()
            self.reports_generated_count = 0
            self.reports_verified_count = 0

    # =========================================================================
    # Helpers
    # =========================================================================

    def _resolve_incident(self, incident_or_id: Union[SecurityIncident, str]) -> Optional[SecurityIncident]:
        """Resolves SecurityIncident from instance, memory, or disk."""
        if isinstance(incident_or_id, SecurityIncident):
            return incident_or_id

        if isinstance(incident_or_id, str):
            # Check disk
            target = self.incidents_dir / f"{incident_or_id}.json"
            if target.exists():
                try:
                    with open(target, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    return SecurityIncident.from_dict(data)
                except Exception as e:
                    logger.debug(f"Failed to load incident from {target}: {e}")

        return None


# Global singleton instance
FORENSIC_COORDINATOR = ForensicCoordinator()
