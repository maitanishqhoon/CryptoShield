"""
Data models, enumerations, and structures for CryptoShield.

Provides strongly typed schemas for data classification, threat levels,
lab markers, manifests, and integrity verification.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DataClassification(str, Enum):
    """Data sensitivity classification levels for enterprise files and DLP."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"

    @classmethod
    def from_string(cls, value: str) -> DataClassification:
        try:
            return cls[value.upper()]
        except KeyError:
            return cls.INTERNAL


class ThreatLevel(str, Enum):
    """Threat severity levels emitted by the detection engine."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FileAction(str, Enum):
    """Filesystem events monitored and evaluated."""
    CREATE = "CREATE"
    MODIFY = "MODIFY"
    DELETE = "DELETE"
    RENAME = "RENAME"
    ACCESS = "ACCESS"


class DatasetPreset(int, Enum):
    """Standard benchmark file count presets for testing."""
    QUICK = 1000
    DEFAULT = 10000
    STRESS = 20000
    CUSTOM = -1


@dataclass
class LabMarker:
    """
    Cryptographic safety marker placed inside the lab root.
    Ensures that CryptoShield will ONLY touch its designated laboratory directory.
    """
    lab_id: str
    created_at: str
    version: str
    authorized_root: str
    system_hostname: str
    platform: str
    marker_signature: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> LabMarker:
        return cls(
            lab_id=data["lab_id"],
            created_at=data["created_at"],
            version=data["version"],
            authorized_root=data["authorized_root"],
            system_hostname=data["system_hostname"],
            platform=data["platform"],
            marker_signature=data.get("marker_signature", ""),
        )


@dataclass
class ManifestEntry:
    """Record representing a single baseline file in the laboratory."""
    relative_path: str  # POSIX relative path from lab root
    file_type: str      # e.g., 'txt', 'csv', 'json', etc.
    file_size_bytes: int
    data_classification: str
    sha256: str
    is_canary: bool
    department: str
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ManifestEntry:
        return cls(
            relative_path=data["relative_path"],
            file_type=data["file_type"],
            file_size_bytes=data["file_size_bytes"],
            data_classification=data["data_classification"],
            sha256=data["sha256"],
            is_canary=bool(data["is_canary"]),
            department=data["department"],
            created_at=data["created_at"],
        )


@dataclass
class Manifest:
    """
    Baseline manifest containing all registered laboratory files,
    their SHA-256 hashes, classifications, and canary flags.
    """
    manifest_version: str
    lab_id: str
    generated_at: str
    total_files: int
    total_size_bytes: int
    canary_count: int
    seed: Optional[int]
    department_counts: Dict[str, int] = field(default_factory=dict)
    type_counts: Dict[str, int] = field(default_factory=dict)
    classification_counts: Dict[str, int] = field(default_factory=dict)
    entries: Dict[str, ManifestEntry] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "lab_id": self.lab_id,
            "generated_at": self.generated_at,
            "total_files": self.total_files,
            "total_size_bytes": self.total_size_bytes,
            "canary_count": self.canary_count,
            "seed": self.seed,
            "department_counts": self.department_counts,
            "type_counts": self.type_counts,
            "classification_counts": self.classification_counts,
            "entries": {k: v.to_dict() for k, v in self.entries.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Manifest:
        entries = {
            k: ManifestEntry.from_dict(v)
            for k, v in data.get("entries", {}).items()
        }
        return cls(
            manifest_version=data.get("manifest_version", "1.0.0"),
            lab_id=data.get("lab_id", ""),
            generated_at=data.get("generated_at", ""),
            total_files=data.get("total_files", len(entries)),
            total_size_bytes=data.get("total_size_bytes", 0),
            canary_count=data.get("canary_count", 0),
            seed=data.get("seed"),
            department_counts=data.get("department_counts", {}),
            type_counts=data.get("type_counts", {}),
            classification_counts=data.get("classification_counts", {}),
            entries=entries,
        )


@dataclass
class IntegrityVerificationResult:
    """Results from auditing the laboratory directory against baseline manifest."""
    is_valid: bool
    total_manifest_files: int
    total_disk_files: int
    matched_files: int
    modified_files: List[str] = field(default_factory=list)
    missing_files: List[str] = field(default_factory=list)
    untracked_files: List[str] = field(default_factory=list)
    canary_tampered_files: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EventPriority(str, Enum):
    """Telemetry event priority levels."""
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ProcessAttribution(str, Enum):
    """Confidence level of process attribution for an observed event."""
    CONFIRMED = "CONFIRMED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


@dataclass
class MonitoringEvent:
    """
    Standardized telemetry event model for filesystem, process, and file access observations.
    Consistently consumable by Phase 3 detection and threat-scoring engine.
    """
    event_id: str
    timestamp: str
    event_type: str
    source: str
    relative_path: Optional[str] = None
    is_canary: bool = False
    canary_id: Optional[str] = None
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    process_attribution: str = ProcessAttribution.UNKNOWN.value
    operation: str = FileAction.ACCESS.value
    priority: str = EventPriority.NORMAL.value
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_bus_event(self) -> Any:
        from app.core.event_bus import Event
        return Event(
            event_type=self.event_type,
            data=self.to_dict(),
            source=self.source,
            timestamp=self.timestamp,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MonitoringEvent:
        return cls(
            event_id=data["event_id"],
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            source=data["source"],
            relative_path=data.get("relative_path"),
            is_canary=bool(data.get("is_canary", False)),
            canary_id=data.get("canary_id"),
            process_id=data.get("process_id"),
            process_name=data.get("process_name"),
            process_attribution=data.get("process_attribution", ProcessAttribution.UNKNOWN.value),
            operation=data.get("operation", FileAction.ACCESS.value),
            priority=data.get("priority", EventPriority.NORMAL.value),
            metadata=data.get("metadata", {}),
        )

