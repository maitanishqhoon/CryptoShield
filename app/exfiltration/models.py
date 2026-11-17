"""
Data models and schemas for the Data Exfiltration Monitoring Subsystem (Phase 7).

Defines strongly-typed representations for read bursts, staging detections,
mock outbound transfers, and consolidated exfiltration assessments.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class ExfiltrationRiskTier(str, Enum):
    """Risk severity classifications for data exfiltration activity."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TransferProtocol(str, Enum):
    """Simulated transport protocols used in mock exfiltration transfers."""
    MOCK_SOCKET = "MOCK_SOCKET"
    MOCK_HTTP = "MOCK_HTTP"
    LOCAL_PIPE = "LOCAL_PIPE"


class StagingType(str, Enum):
    """Method utilized to aggregate and stage sensitive files prior to outbound transfer."""
    DIRECTORY_AGGREGATION = "DIRECTORY_AGGREGATION"
    ARCHIVE_ZIP = "ARCHIVE_ZIP"
    TEMP_BUFFER = "TEMP_BUFFER"


class TransferStatus(str, Enum):
    """Status lifecycle of a monitored transfer operation."""
    ATTEMPTED = "ATTEMPTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


@dataclass
class ReadBurstEvent:
    """Record representing a detected burst of rapid file read operations."""
    burst_id: str
    timestamp: str
    read_count: int
    duration_seconds: float
    department_counts: Dict[str, int]
    classification_counts: Dict[str, int]
    canary_reads_count: int
    canary_paths: List[str]
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    process_attribution: str = "UNKNOWN"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ReadBurstEvent:
        return cls(**data)


@dataclass
class StagingEvent:
    """Record representing detection of localized data aggregation or archive staging."""
    staging_id: str
    timestamp: str
    staging_path: str
    staging_type: str
    staged_files_count: int
    total_staged_bytes: int
    source_paths: List[str]
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> StagingEvent:
        return cls(**data)


@dataclass
class OutboundTransferRecord:
    """Record representing a simulated outbound data transmission to a mock endpoint."""
    transfer_id: str
    timestamp: str
    destination_endpoint: str
    protocol: str
    bytes_transferred: int
    file_count: int
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    classifications_included: List[str] = field(default_factory=list)
    departments_included: List[str] = field(default_factory=list)
    contains_canary: bool = False
    status: str = TransferStatus.COMPLETED.value
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> OutboundTransferRecord:
        return cls(**data)


@dataclass
class ExfiltrationAssessment:
    """
    Consolidated exfiltration threat assessment fusing read bursts, staging actions,
    honeypot canary read breaches, and outbound transfer telemetry.
    """
    assessment_id: str
    timestamp: str
    threat_score: int
    risk_tier: str
    indicators: List[str]
    read_burst_count: int
    total_reads_observed: int
    canary_reads_count: int
    canaries_compromised: List[str]
    staging_events_count: int
    total_staged_bytes: int
    transfers_attempted: int
    transfers_completed: int
    total_bytes_exfiltrated: int
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    correlated_incident_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExfiltrationAssessment:
        return cls(**data)

    def summary(self) -> str:
        return (
            f"[{self.risk_tier}] Score={self.threat_score}/100 | "
            f"Reads={self.total_reads_observed} (Canaries={self.canary_reads_count}) | "
            f"Staged={self.total_staged_bytes:,}B | "
            f"Exfiltrated={self.total_bytes_exfiltrated:,}B | "
            f"Indicators={len(self.indicators)}"
        )
