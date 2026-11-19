"""
Forensic Incident Reporting Models for CryptoShield (Phase 9).

Defines strongly typed schemas and data structures for forensic dossiers,
chronological timeline records, cross-subsystem summaries (detection, containment,
exfiltration, DLP, recovery), academic evaluation metrics, and cryptographic
chain-of-custody verification.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


# ============================================================================
# 1. Enums
# ============================================================================

class ReportFormat(str, Enum):
    """Supported export formats for forensic incident reports."""
    JSON = "JSON"
    MARKDOWN = "MARKDOWN"
    CSV = "CSV"
    HTML = "HTML"


class ForensicSubsystem(str, Enum):
    """Subsystems originating forensic telemetry entries."""
    MONITORING = "MONITORING"
    DETECTION = "DETECTION"
    CONTAINMENT = "CONTAINMENT"
    VAULT = "VAULT"
    RECOVERY = "RECOVERY"
    EXFILTRATION = "EXFILTRATION"
    DLP = "DLP"
    INCIDENT = "INCIDENT"


# ============================================================================
# 2. Forensic Timeline & Canary Records
# ============================================================================

@dataclass
class ForensicTimelineEntry:
    """
    Standardized chronological entry in the unified forensic attack-and-defense timeline.
    Normalizes timestamps and actions across all CryptoShield subsystems.
    """
    timestamp: str                                    # ISO 8601 UTC
    subsystem: str                                    # ForensicSubsystem string
    action: str                                       # Normalized action token
    description: str                                  # Human-readable contextual description
    severity: str = "INFO"                            # INFO, LOW, MEDIUM, HIGH, CRITICAL
    threat_score: Optional[int] = None
    event_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ForensicTimelineEntry:
        return cls(
            timestamp=data["timestamp"],
            subsystem=data["subsystem"],
            action=data["action"],
            description=data["description"],
            severity=data.get("severity", "INFO"),
            threat_score=data.get("threat_score"),
            event_id=data.get("event_id"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class ForensicCanaryRecord:
    """Canary decoy interaction record captured during forensic analysis."""
    path: str
    timestamp: str
    event_type: str
    operation: str
    department: str
    classification: str
    process_attribution: str = "UNKNOWN"
    process_id: Optional[int] = None
    tampered: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ForensicCanaryRecord:
        return cls(
            path=data["path"],
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            operation=data["operation"],
            department=data["department"],
            classification=data["classification"],
            process_attribution=data.get("process_attribution", "UNKNOWN"),
            process_id=data.get("process_id"),
            tampered=bool(data.get("tampered", False)),
        )


# ============================================================================
# 3. Subsystem Forensic Summaries
# ============================================================================

@dataclass
class DetectionForensicSummary:
    """Aggregated detection and behavioral telemetry for an incident."""
    first_detected_at: str
    last_detected_at: str
    detection_latency_seconds: float
    initial_threat_score: int
    peak_threat_score: int
    peak_severity: str
    detection_reasons: List[str] = field(default_factory=list)
    total_contributing_events: int = 0
    affected_paths_count: int = 0
    departments_targeted: List[str] = field(default_factory=list)
    canaries_compromised_count: int = 0
    canary_records: List[ForensicCanaryRecord] = field(default_factory=list)
    process_attribution: str = "UNKNOWN"
    process_id: Optional[int] = None
    process_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["canary_records"] = [c.to_dict() for c in self.canary_records]
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DetectionForensicSummary:
        canaries = [
            ForensicCanaryRecord.from_dict(c) if isinstance(c, dict) else c
            for c in data.get("canary_records", [])
        ]
        return cls(
            first_detected_at=data["first_detected_at"],
            last_detected_at=data["last_detected_at"],
            detection_latency_seconds=float(data.get("detection_latency_seconds", 0.0)),
            initial_threat_score=int(data.get("initial_threat_score", 0)),
            peak_threat_score=int(data.get("peak_threat_score", 0)),
            peak_severity=data.get("peak_severity", "LOW"),
            detection_reasons=list(data.get("detection_reasons", [])),
            total_contributing_events=int(data.get("total_contributing_events", 0)),
            affected_paths_count=int(data.get("affected_paths_count", 0)),
            departments_targeted=list(data.get("departments_targeted", [])),
            canaries_compromised_count=int(data.get("canaries_compromised_count", 0)),
            canary_records=canaries,
            process_attribution=data.get("process_attribution", "UNKNOWN"),
            process_id=data.get("process_id"),
            process_name=data.get("process_name"),
        )


@dataclass
class ContainmentForensicSummary:
    """Containment intervention record and execution audit."""
    containment_id: Optional[str] = None
    status: str = "NOT_CONTAINED"                     # CONTAINED, SKIPPED, NOT_CONTAINED, FAILED
    initiated_at: Optional[str] = None
    completed_at: Optional[str] = None
    containment_duration_seconds: float = 0.0
    shutdown_method: str = "NONE"                     # COOPERATIVE, OWNED_HANDLE, NONE
    write_gate_status: str = "OPEN"                   # CLOSED, OPEN
    operations_prevented_count: int = 0
    actions_taken: List[str] = field(default_factory=list)
    failure_explanation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ContainmentForensicSummary:
        return cls(
            containment_id=data.get("containment_id"),
            status=data.get("status", "NOT_CONTAINED"),
            initiated_at=data.get("initiated_at"),
            completed_at=data.get("completed_at"),
            containment_duration_seconds=float(data.get("containment_duration_seconds", 0.0)),
            shutdown_method=data.get("shutdown_method", "NONE"),
            write_gate_status=data.get("write_gate_status", "OPEN"),
            operations_prevented_count=int(data.get("operations_prevented_count", 0)),
            actions_taken=list(data.get("actions_taken", [])),
            failure_explanation=data.get("failure_explanation"),
        )


@dataclass
class ExfiltrationForensicSummary:
    """Data exfiltration telemetry and threat evaluation summary."""
    assessment_id: Optional[str] = None
    risk_tier: str = "LOW"                            # LOW, MEDIUM, HIGH, CRITICAL, NONE
    threat_score: int = 0
    read_bursts_observed: int = 0
    sensitive_reads_count: int = 0
    staging_events_count: int = 0
    staging_volume_bytes: int = 0
    transfers_attempted_count: int = 0
    outbound_bytes_transmitted: int = 0
    indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExfiltrationForensicSummary:
        return cls(
            assessment_id=data.get("assessment_id"),
            risk_tier=data.get("risk_tier", "LOW"),
            threat_score=int(data.get("threat_score", 0)),
            read_bursts_observed=int(data.get("read_bursts_observed", 0)),
            sensitive_reads_count=int(data.get("sensitive_reads_count", 0)),
            staging_events_count=int(data.get("staging_events_count", 0)),
            staging_volume_bytes=int(data.get("staging_volume_bytes", 0)),
            transfers_attempted_count=int(data.get("transfers_attempted_count", 0)),
            outbound_bytes_transmitted=int(data.get("outbound_bytes_transmitted", 0)),
            indicators=list(data.get("indicators", [])),
        )


@dataclass
class DLPForensicSummary:
    """Data Loss Prevention rule evaluations and transfer interception audit."""
    profile: str = "DEFAULT"
    total_evaluations: int = 0
    transfers_allowed: int = 0
    transfers_alerted: int = 0
    transfers_quarantined: int = 0
    transfers_blocked: int = 0
    bytes_blocked_at_gate: int = 0
    zero_byte_leakage_enforced: bool = True
    rules_triggered: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DLPForensicSummary:
        return cls(
            profile=data.get("profile", "DEFAULT"),
            total_evaluations=int(data.get("total_evaluations", 0)),
            transfers_allowed=int(data.get("transfers_allowed", 0)),
            transfers_alerted=int(data.get("transfers_alerted", 0)),
            transfers_quarantined=int(data.get("transfers_quarantined", 0)),
            transfers_blocked=int(data.get("transfers_blocked", 0)),
            bytes_blocked_at_gate=int(data.get("bytes_blocked_at_gate", 0)),
            zero_byte_leakage_enforced=bool(data.get("zero_byte_leakage_enforced", True)),
            rules_triggered=list(data.get("rules_triggered", [])),
        )


@dataclass
class RecoveryForensicSummary:
    """Cryptographic recovery, evidence quarantine, and restoration hash audit."""
    recovery_id: Optional[str] = None
    workspace_id: Optional[str] = None
    snapshot_id: Optional[str] = None
    mode: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    total_evaluated: int = 0
    restored_count: int = 0
    skipped_intact_count: int = 0
    evidence_quarantined_count: int = 0
    untracked_preserved_count: int = 0
    canaries_restored_count: int = 0
    failed_count: int = 0
    sha256_verification_pass_rate: float = 100.0
    audit_passed: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RecoveryForensicSummary:
        return cls(
            recovery_id=data.get("recovery_id"),
            workspace_id=data.get("workspace_id"),
            snapshot_id=data.get("snapshot_id"),
            mode=data.get("mode"),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            total_evaluated=int(data.get("total_evaluated", 0)),
            restored_count=int(data.get("restored_count", 0)),
            skipped_intact_count=int(data.get("skipped_intact_count", 0)),
            evidence_quarantined_count=int(data.get("evidence_quarantined_count", 0)),
            untracked_preserved_count=int(data.get("untracked_preserved_count", 0)),
            canaries_restored_count=int(data.get("canaries_restored_count", 0)),
            failed_count=int(data.get("failed_count", 0)),
            sha256_verification_pass_rate=float(data.get("sha256_verification_pass_rate", 100.0)),
            audit_passed=bool(data.get("audit_passed", True)),
        )


# ============================================================================
# 4. Evaluation Metrics & Chain of Custody
# ============================================================================

@dataclass
class ForensicEvaluationMetrics:
    """Academic evaluation metrics measuring defensive efficacy across double-extortion facets."""
    detection_latency_seconds: float                  # First telemetry to incident alert
    containment_duration_seconds: float               # Incident alert to process/write-gate containment
    recovery_duration_seconds: float                  # Snapshot unwrap to verified disk restore
    files_affected_count: int                         # Files modified or encrypted before containment
    files_preserved_or_restored_count: int            # Files successfully shielded or restored
    total_enterprise_files: int                       # Total files in target laboratory baseline
    protection_success_rate: float                    # % of files preserved/restored
    exfiltration_bytes_blocked: int                   # Unauthorized bytes stopped at DLP gate
    exfiltration_leakage_bytes: int                   # Unauthorized bytes leaked (must be 0)
    zero_leakage_verified: bool                       # True if leakage is 0 bytes
    sha256_hash_match_rate: float                     # % restored files matching manifest hash (100.0%)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ForensicEvaluationMetrics:
        return cls(
            detection_latency_seconds=float(data.get("detection_latency_seconds", 0.0)),
            containment_duration_seconds=float(data.get("containment_duration_seconds", 0.0)),
            recovery_duration_seconds=float(data.get("recovery_duration_seconds", 0.0)),
            files_affected_count=int(data.get("files_affected_count", 0)),
            files_preserved_or_restored_count=int(data.get("files_preserved_or_restored_count", 0)),
            total_enterprise_files=int(data.get("total_enterprise_files", 0)),
            protection_success_rate=float(data.get("protection_success_rate", 100.0)),
            exfiltration_bytes_blocked=int(data.get("exfiltration_bytes_blocked", 0)),
            exfiltration_leakage_bytes=int(data.get("exfiltration_leakage_bytes", 0)),
            zero_leakage_verified=bool(data.get("zero_leakage_verified", True)),
            sha256_hash_match_rate=float(data.get("sha256_hash_match_rate", 100.0)),
        )


@dataclass
class ChainOfCustodyRecord:
    """Cryptographic chain-of-custody seal certifying forensic integrity of evidence and dossiers."""
    record_id: str
    incident_id: str
    sealed_at: str
    manifest_sha256: str
    quarantined_evidence_hashes: Dict[str, str] = field(default_factory=dict)
    dossier_sha256: str = ""
    certifying_system: str = "CryptoShield Forensic Engine v1.0"
    certifier: str = "CryptoShield Autonomous Agent"
    notes: str = "Chain of custody sealed with SHA-256 integrity digest."

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ChainOfCustodyRecord:
        return cls(
            record_id=data["record_id"],
            incident_id=data["incident_id"],
            sealed_at=data["sealed_at"],
            manifest_sha256=data.get("manifest_sha256", ""),
            quarantined_evidence_hashes=dict(data.get("quarantined_evidence_hashes", {})),
            dossier_sha256=data.get("dossier_sha256", ""),
            certifying_system=data.get("certifying_system", "CryptoShield Forensic Engine v1.0"),
            certifier=data.get("certifier", "CryptoShield Autonomous Agent"),
            notes=data.get("notes", ""),
        )


# ============================================================================
# 5. Consolidated Forensic Dossier
# ============================================================================

@dataclass
class ForensicDossier:
    """
    Consolidated forensic dossier aggregating all dimensions of a security incident:
    detection heuristics, canary triggers, containment actions, exfiltration telemetry,
    DLP policy enforcement, cryptographic restoration, and chronological timeline.
    """
    report_id: str                                    # REP-<8-hex>
    incident_id: str                                  # INC-<8-hex>
    generated_at: str                                 # ISO 8601 UTC
    incident_status: str                              # OPEN, INVESTIGATING, RESOLVED
    threat_score: int                                 # 0 to 100
    severity: str                                     # LOW, MEDIUM, HIGH, CRITICAL
    assessment_title: str
    executive_summary: str
    detection: DetectionForensicSummary
    containment: ContainmentForensicSummary
    exfiltration: ExfiltrationForensicSummary
    dlp: DLPForensicSummary
    recovery: RecoveryForensicSummary
    metrics: ForensicEvaluationMetrics
    timeline: List[ForensicTimelineEntry] = field(default_factory=list)
    chain_of_custody: Optional[ChainOfCustodyRecord] = None
    affected_files_sample: List[str] = field(default_factory=list)
    mitre_attack_techniques: List[Dict[str, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "report_id": self.report_id,
            "incident_id": self.incident_id,
            "generated_at": self.generated_at,
            "incident_status": self.incident_status,
            "threat_score": self.threat_score,
            "severity": self.severity,
            "assessment_title": self.assessment_title,
            "executive_summary": self.executive_summary,
            "detection": self.detection.to_dict(),
            "containment": self.containment.to_dict(),
            "exfiltration": self.exfiltration.to_dict(),
            "dlp": self.dlp.to_dict(),
            "recovery": self.recovery.to_dict(),
            "metrics": self.metrics.to_dict(),
            "timeline": [t.to_dict() for t in self.timeline],
            "chain_of_custody": self.chain_of_custody.to_dict() if self.chain_of_custody else None,
            "affected_files_sample": self.affected_files_sample,
            "mitre_attack_techniques": self.mitre_attack_techniques,
            "metadata": self.metadata,
        }
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ForensicDossier:
        coc = None
        if data.get("chain_of_custody"):
            coc = ChainOfCustodyRecord.from_dict(data["chain_of_custody"])
        timeline = [
            ForensicTimelineEntry.from_dict(t) if isinstance(t, dict) else t
            for t in data.get("timeline", [])
        ]
        return cls(
            report_id=data["report_id"],
            incident_id=data["incident_id"],
            generated_at=data["generated_at"],
            incident_status=data.get("incident_status", "OPEN"),
            threat_score=int(data.get("threat_score", 0)),
            severity=data.get("severity", "LOW"),
            assessment_title=data.get("assessment_title", ""),
            executive_summary=data.get("executive_summary", ""),
            detection=DetectionForensicSummary.from_dict(data["detection"]),
            containment=ContainmentForensicSummary.from_dict(data["containment"]),
            exfiltration=ExfiltrationForensicSummary.from_dict(data["exfiltration"]),
            dlp=DLPForensicSummary.from_dict(data["dlp"]),
            recovery=RecoveryForensicSummary.from_dict(data["recovery"]),
            metrics=ForensicEvaluationMetrics.from_dict(data["metrics"]),
            timeline=timeline,
            chain_of_custody=coc,
            affected_files_sample=list(data.get("affected_files_sample", [])),
            mitre_attack_techniques=list(data.get("mitre_attack_techniques", [])),
            metadata=dict(data.get("metadata", {})),
        )

    def compute_dossier_hash(self) -> str:
        """
        Calculates a deterministic SHA-256 digest over the dossier content
        (excluding any prior dossier_sha256 inside chain_of_custody to avoid circularity).
        """
        data = self.to_dict()
        if data.get("chain_of_custody"):
            data["chain_of_custody"]["dossier_sha256"] = ""
        canonical_json = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return hashlib.sha256(canonical_json).hexdigest()


# ============================================================================
# 6. Report Index Metadata
# ============================================================================

@dataclass
class ReportMetadata:
    """Compact summary of a generated forensic report for directory listings and CLI queries."""
    report_id: str
    incident_id: str
    generated_at: str
    status: str
    threat_score: int
    severity: str
    files_affected: int
    restored_count: int
    dossier_sha256: str
    export_files: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ReportMetadata:
        return cls(
            report_id=data["report_id"],
            incident_id=data["incident_id"],
            generated_at=data["generated_at"],
            status=data["status"],
            threat_score=int(data["threat_score"]),
            severity=data["severity"],
            files_affected=int(data.get("files_affected", 0)),
            restored_count=int(data.get("restored_count", 0)),
            dossier_sha256=data.get("dossier_sha256", ""),
            export_files=dict(data.get("export_files", {})),
        )
