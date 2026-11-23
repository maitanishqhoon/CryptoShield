"""
Data models, schemas, enums, and exceptions for CryptoShield Recovery (Phase 6).

Defines strongly typed structures for recovery workspaces, damage assessment,
object staging, file restoration, and recovery reporting.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


# ============================================================================
# 1. Recovery Exceptions
# ============================================================================

class RecoveryError(Exception):
    """Base exception for all Phase 6 cryptographic recovery operations."""
    pass


class WorkspaceSafetyError(RecoveryError):
    """
    Raised on path traversal, symlink escape, invalid/missing recovery marker,
    or any attempt to target runtime/lab or arbitrary host paths as a workspace.
    """
    pass


class WorkspaceNotFoundError(RecoveryError):
    """Raised when a requested recovery workspace ID does not exist."""
    pass


class RecoveryAuthenticationError(RecoveryError):
    """
    Raised when private key passphrase, RSA key unwrap, manifest AES-GCM tag,
    or .cso object AES-GCM tag verification fails.
    """
    pass


class RecoveryIntegrityError(RecoveryError):
    """Raised when decrypted plaintext SHA-256 does not match authenticated manifest SHA-256."""
    pass


class RestorationPolicyError(RecoveryError):
    """
    Raised when attempting to commit without explicit authorization or
    attempting to overwrite modified files without explicit permission.
    """
    pass


# ============================================================================
# 2. Enumerations
# ============================================================================

class FileAssessmentStatus(str, Enum):
    """Assessment status of a file within a recovery workspace."""
    INTACT = "INTACT"
    MODIFIED = "MODIFIED"
    MISSING = "MISSING"
    UNREADABLE = "UNREADABLE"
    UNTRACKED = "UNTRACKED"


class PlannedRecoveryAction(str, Enum):
    """Action scheduled to be performed on a target workspace file."""
    SKIP_INTACT = "SKIP_INTACT"
    RESTORE_MISSING = "RESTORE_MISSING"
    RESTORE_MODIFIED_PRESERVE_EVIDENCE = "RESTORE_MODIFIED_PRESERVE_EVIDENCE"
    SKIP_MODIFIED_NO_OVERWRITE_AUTH = "SKIP_MODIFIED_NO_OVERWRITE_AUTH"
    MANUAL_REVIEW_UNREADABLE = "MANUAL_REVIEW_UNREADABLE"
    PRESERVE_UNTRACKED = "PRESERVE_UNTRACKED"


class RecoveryMode(str, Enum):
    """Operational mode for cryptographic recovery execution."""
    SELECTIVE_FILE = "SELECTIVE_FILE"
    DIRECTORY = "DIRECTORY"
    FULL_WORKSPACE = "FULL_WORKSPACE"
    ASSESS_ONLY = "ASSESS_ONLY"


class FileRestorationOutcome(str, Enum):
    """Final outcome of an attempted file restoration."""
    RESTORED = "RESTORED"
    SKIPPED = "SKIPPED"
    PRESERVED_UNTRACKED = "PRESERVED_UNTRACKED"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    FAILED_AUTH = "FAILED_AUTH"
    FAILED_INTEGRITY = "FAILED_INTEGRITY"
    FAILED_IO = "FAILED_IO"


# ============================================================================
# 3. Signature & Cryptographic Helpers
# ============================================================================

WORKSPACE_SIGNATURE_KEY = b"CRYPTOSHIELD_RECOVERY_WORKSPACE_KEY_2026"


def compute_workspace_marker_signature(
    workspace_id: str,
    workspace_uuid: str,
    authorized_root: str,
    source_snapshot_id: Optional[str],
    seeded_file_count: int,
    created_at: str,
    host_platform: str,
    secret_key: bytes = WORKSPACE_SIGNATURE_KEY,
) -> str:
    """
    Compute deterministic HMAC-SHA256 signature binding all marker fields
    in canonical sorted JSON order.
    """
    payload = {
        "authorized_root": authorized_root,
        "created_at": created_at,
        "host_platform": host_platform,
        "seeded_file_count": seeded_file_count,
        "source_snapshot_id": source_snapshot_id,
        "workspace_id": workspace_id,
        "workspace_uuid": workspace_uuid,
    }
    canonical_json = json.dumps(payload, sort_keys=True)
    return hmac.new(secret_key, canonical_json.encode("utf-8"), hashlib.sha256).hexdigest()


# ============================================================================
# 4. Strongly-Typed Dataclasses
# ============================================================================

@dataclass
class RecoveryWorkspaceMarker:
    """Cryptographically authenticated safety marker for recovery workspaces."""
    workspace_id: str
    workspace_uuid: str
    authorized_root: str
    source_snapshot_id: Optional[str]
    seeded_file_count: int
    created_at: str
    host_platform: str
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "workspace_uuid": self.workspace_uuid,
            "authorized_root": self.authorized_root,
            "source_snapshot_id": self.source_snapshot_id,
            "seeded_file_count": self.seeded_file_count,
            "created_at": self.created_at,
            "host_platform": self.host_platform,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RecoveryWorkspaceMarker:
        return cls(
            workspace_id=str(data["workspace_id"]),
            workspace_uuid=str(data["workspace_uuid"]),
            authorized_root=str(data["authorized_root"]),
            source_snapshot_id=data.get("source_snapshot_id"),
            seeded_file_count=int(data["seeded_file_count"]),
            created_at=str(data["created_at"]),
            host_platform=str(data["host_platform"]),
            signature=str(data.get("signature", "")),
        )


@dataclass
class WorkspaceMetadata:
    """Metadata summary for a recovery workspace."""
    workspace_id: str
    workspace_path: Path
    created_at: str
    seeded_file_count: int
    source_snapshot_id: Optional[str]
    marker_valid: bool

    @property
    def is_marker_valid(self) -> bool:
        return self.marker_valid

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workspace_id": self.workspace_id,
            "workspace_path": str(self.workspace_path),
            "created_at": self.created_at,
            "seeded_file_count": self.seeded_file_count,
            "source_snapshot_id": self.source_snapshot_id,
            "marker_valid": self.marker_valid,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkspaceMetadata:
        return cls(
            workspace_id=str(data["workspace_id"]),
            workspace_path=Path(data["workspace_path"]),
            created_at=str(data["created_at"]),
            seeded_file_count=int(data["seeded_file_count"]),
            source_snapshot_id=data.get("source_snapshot_id"),
            marker_valid=bool(data["marker_valid"]),
        )


@dataclass
class FileAssessmentRecord:
    """Assessment record for an individual workspace file against snapshot baseline."""
    relative_path: str
    status: FileAssessmentStatus
    planned_action: PlannedRecoveryAction
    expected_sha256: Optional[str] = None
    current_sha256: Optional[str] = None
    expected_size_bytes: Optional[int] = None
    current_size_bytes: Optional[int] = None
    opaque_id: Optional[str] = None
    department: Optional[str] = None
    data_classification: Optional[str] = None
    is_canary: bool = False
    error_detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "status": self.status.value if isinstance(self.status, Enum) else str(self.status),
            "planned_action": self.planned_action.value if isinstance(self.planned_action, Enum) else str(self.planned_action),
            "expected_sha256": self.expected_sha256,
            "current_sha256": self.current_sha256,
            "expected_size_bytes": self.expected_size_bytes,
            "current_size_bytes": self.current_size_bytes,
            "opaque_id": self.opaque_id,
            "department": self.department,
            "data_classification": self.data_classification,
            "is_canary": self.is_canary,
            "error_detail": self.error_detail,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FileAssessmentRecord:
        return cls(
            relative_path=str(data["relative_path"]),
            status=FileAssessmentStatus(data["status"]),
            planned_action=PlannedRecoveryAction(data["planned_action"]),
            expected_sha256=data.get("expected_sha256"),
            current_sha256=data.get("current_sha256"),
            expected_size_bytes=int(data["expected_size_bytes"]) if data.get("expected_size_bytes") is not None else None,
            current_size_bytes=int(data["current_size_bytes"]) if data.get("current_size_bytes") is not None else None,
            opaque_id=data.get("opaque_id"),
            department=data.get("department"),
            data_classification=data.get("data_classification"),
            is_canary=bool(data.get("is_canary", False)),
            error_detail=data.get("error_detail"),
        )


@dataclass
class WorkspaceAssessmentSummary:
    """Comprehensive damage assessment summary for an entire workspace."""
    assessment_id: str
    workspace_id: str
    snapshot_id: str
    assessed_at: str
    total_manifest_files: int
    total_workspace_files_scanned: int
    intact_count: int
    modified_count: int
    missing_count: int
    unreadable_count: int
    untracked_count: int
    canary_affected_count: int
    duration_seconds: float
    records: Dict[str, FileAssessmentRecord] = field(default_factory=dict)

    @property
    def total_files(self) -> int:
        return self.total_workspace_files_scanned or self.total_manifest_files

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "workspace_id": self.workspace_id,
            "snapshot_id": self.snapshot_id,
            "assessed_at": self.assessed_at,
            "total_manifest_files": self.total_manifest_files,
            "total_workspace_files_scanned": self.total_workspace_files_scanned,
            "intact_count": self.intact_count,
            "modified_count": self.modified_count,
            "missing_count": self.missing_count,
            "unreadable_count": self.unreadable_count,
            "untracked_count": self.untracked_count,
            "canary_affected_count": self.canary_affected_count,
            "duration_seconds": self.duration_seconds,
            "records": {k: v.to_dict() for k, v in self.records.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkspaceAssessmentSummary:
        records_raw = data.get("records", {})
        records = {k: FileAssessmentRecord.from_dict(v) for k, v in records_raw.items()}
        return cls(
            assessment_id=str(data["assessment_id"]),
            workspace_id=str(data["workspace_id"]),
            snapshot_id=str(data["snapshot_id"]),
            assessed_at=str(data["assessed_at"]),
            total_manifest_files=int(data["total_manifest_files"]),
            total_workspace_files_scanned=int(data["total_workspace_files_scanned"]),
            intact_count=int(data["intact_count"]),
            modified_count=int(data["modified_count"]),
            missing_count=int(data["missing_count"]),
            unreadable_count=int(data["unreadable_count"]),
            untracked_count=int(data["untracked_count"]),
            canary_affected_count=int(data["canary_affected_count"]),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            records=records,
        )


@dataclass
class StagedObjectResult:
    """Result of staging and decrypting an individual vault object."""
    relative_path: str
    opaque_id: str
    staged_path: Optional[Path]
    gcm_authenticated: bool
    sha256_verified: bool
    computed_sha256: Optional[str]
    expected_sha256: str
    decrypted_size_bytes: int
    is_canary: bool
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "opaque_id": self.opaque_id,
            "staged_path": str(self.staged_path) if self.staged_path is not None else None,
            "gcm_authenticated": self.gcm_authenticated,
            "sha256_verified": self.sha256_verified,
            "computed_sha256": self.computed_sha256,
            "expected_sha256": self.expected_sha256,
            "decrypted_size_bytes": self.decrypted_size_bytes,
            "is_canary": self.is_canary,
            "error_message": self.error_message,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> StagedObjectResult:
        staged_path_raw = data.get("staged_path")
        return cls(
            relative_path=str(data["relative_path"]),
            opaque_id=str(data["opaque_id"]),
            staged_path=Path(staged_path_raw) if staged_path_raw is not None else None,
            gcm_authenticated=bool(data["gcm_authenticated"]),
            sha256_verified=bool(data["sha256_verified"]),
            computed_sha256=data.get("computed_sha256"),
            expected_sha256=str(data["expected_sha256"]),
            decrypted_size_bytes=int(data["decrypted_size_bytes"]),
            is_canary=bool(data["is_canary"]),
            error_message=data.get("error_message"),
        )


@dataclass
class FileRestorationRecord:
    """Record of an individual file restoration attempt and evidence preservation."""
    relative_path: str
    status_before: FileAssessmentStatus
    outcome: FileRestorationOutcome
    opaque_id: Optional[str] = None
    restored_sha256: Optional[str] = None
    evidence_backup_path: Optional[str] = None
    is_canary: bool = False
    error_detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "status_before": self.status_before.value if isinstance(self.status_before, Enum) else str(self.status_before),
            "outcome": self.outcome.value if isinstance(self.outcome, Enum) else str(self.outcome),
            "opaque_id": self.opaque_id,
            "restored_sha256": self.restored_sha256,
            "evidence_backup_path": self.evidence_backup_path,
            "is_canary": self.is_canary,
            "error_detail": self.error_detail,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FileRestorationRecord:
        return cls(
            relative_path=str(data["relative_path"]),
            status_before=FileAssessmentStatus(data["status_before"]),
            outcome=FileRestorationOutcome(data["outcome"]),
            opaque_id=data.get("opaque_id"),
            restored_sha256=data.get("restored_sha256"),
            evidence_backup_path=data.get("evidence_backup_path"),
            is_canary=bool(data.get("is_canary", False)),
            error_detail=data.get("error_detail"),
        )


@dataclass
class RecoveryOperationReport:
    """Comprehensive post-recovery forensic and auditing report."""
    recovery_id: str
    workspace_id: str
    snapshot_id: str
    mode: RecoveryMode
    dry_run: bool
    authorized: bool
    overwrite_modified: bool
    started_at: str
    completed_at: str
    duration_seconds: float
    target_filter: Optional[str]
    total_evaluated: int
    restored_count: int
    skipped_intact_count: int
    evidence_preserved_count: int
    untracked_preserved_count: int
    manual_review_count: int
    failed_count: int
    canary_restored_count: int
    post_recovery_audit_passed: Optional[bool] = None
    file_records: List[FileRestorationRecord] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recovery_id": self.recovery_id,
            "workspace_id": self.workspace_id,
            "snapshot_id": self.snapshot_id,
            "mode": self.mode.value if isinstance(self.mode, Enum) else str(self.mode),
            "dry_run": self.dry_run,
            "authorized": self.authorized,
            "overwrite_modified": self.overwrite_modified,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "target_filter": self.target_filter,
            "total_evaluated": self.total_evaluated,
            "restored_count": self.restored_count,
            "skipped_intact_count": self.skipped_intact_count,
            "evidence_preserved_count": self.evidence_preserved_count,
            "untracked_preserved_count": self.untracked_preserved_count,
            "manual_review_count": self.manual_review_count,
            "failed_count": self.failed_count,
            "canary_restored_count": self.canary_restored_count,
            "post_recovery_audit_passed": self.post_recovery_audit_passed,
            "file_records": [r.to_dict() for r in self.file_records],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RecoveryOperationReport:
        records_raw = data.get("file_records", [])
        file_records = [FileRestorationRecord.from_dict(r) for r in records_raw]
        return cls(
            recovery_id=str(data["recovery_id"]),
            workspace_id=str(data["workspace_id"]),
            snapshot_id=str(data["snapshot_id"]),
            mode=RecoveryMode(data["mode"]),
            dry_run=bool(data["dry_run"]),
            authorized=bool(data["authorized"]),
            overwrite_modified=bool(data["overwrite_modified"]),
            started_at=str(data["started_at"]),
            completed_at=str(data["completed_at"]),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            target_filter=data.get("target_filter"),
            total_evaluated=int(data["total_evaluated"]),
            restored_count=int(data["restored_count"]),
            skipped_intact_count=int(data["skipped_intact_count"]),
            evidence_preserved_count=int(data["evidence_preserved_count"]),
            untracked_preserved_count=int(data["untracked_preserved_count"]),
            manual_review_count=int(data["manual_review_count"]),
            failed_count=int(data["failed_count"]),
            canary_restored_count=int(data["canary_restored_count"]),
            post_recovery_audit_passed=data.get("post_recovery_audit_passed"),
            file_records=file_records,
        )
