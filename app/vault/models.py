"""
Data models, schemas, and verification structures for CryptoShield Vault (Phase 5).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SnapshotStatus(str, Enum):
    """Lifecycle status of a cryptographic snapshot."""
    STAGING = "STAGING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class VerificationStatus(str, Enum):
    """Integrity and cryptographic verification status for an individual object."""
    VERIFIED = "VERIFIED"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    HASH_MISMATCH = "HASH_MISMATCH"
    MISSING_OBJECT = "MISSING_OBJECT"
    INVALID_FORMAT = "INVALID_FORMAT"
    DECRYPTION_FAILED = "DECRYPTION_FAILED"


class SnapshotVerificationOutcome(str, Enum):
    """Overall verification outcome for an entire snapshot."""
    FULLY_VERIFIED = "FULLY_VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"


@dataclass
class EncryptedObjectRecord:
    """Record describing an individual encrypted file inside a snapshot."""
    opaque_id: str
    relative_path: str
    original_size_bytes: int
    original_sha256: str
    department: str
    data_classification: str
    is_canary: bool
    encrypted_size_bytes: int
    nonce_hex: str
    tag_hex: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EncryptedObjectRecord:
        return cls(
            opaque_id=data["opaque_id"],
            relative_path=data["relative_path"],
            original_size_bytes=int(data["original_size_bytes"]),
            original_sha256=str(data["original_sha256"]).lower(),
            department=data["department"],
            data_classification=data["data_classification"],
            is_canary=bool(data["is_canary"]),
            encrypted_size_bytes=int(data["encrypted_size_bytes"]),
            nonce_hex=data["nonce_hex"],
            tag_hex=data["tag_hex"],
        )


@dataclass
class SnapshotManifest:
    """
    Confidential snapshot manifest containing the inventory of encrypted files.
    This manifest itself is encrypted with AES-256-GCM under the snapshot key.
    """
    snapshot_id: str
    format_version: str
    created_at: str
    lab_id: str
    total_files: int
    total_original_bytes: int
    canary_count: int
    department_counts: Dict[str, int] = field(default_factory=dict)
    classification_counts: Dict[str, int] = field(default_factory=dict)
    entries: Dict[str, EncryptedObjectRecord] = field(default_factory=dict)
    opaque_id_map: Dict[str, str] = field(default_factory=dict)  # opaque_id -> relative_path

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "format_version": self.format_version,
            "created_at": self.created_at,
            "lab_id": self.lab_id,
            "total_files": self.total_files,
            "total_original_bytes": self.total_original_bytes,
            "canary_count": self.canary_count,
            "department_counts": self.department_counts,
            "classification_counts": self.classification_counts,
            "entries": {k: v.to_dict() for k, v in self.entries.items()},
            "opaque_id_map": self.opaque_id_map,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SnapshotManifest:
        entries = {
            k: EncryptedObjectRecord.from_dict(v)
            for k, v in data.get("entries", {}).items()
        }
        return cls(
            snapshot_id=data["snapshot_id"],
            format_version=data.get("format_version", "1.0.0"),
            created_at=data["created_at"],
            lab_id=data.get("lab_id", ""),
            total_files=int(data.get("total_files", len(entries))),
            total_original_bytes=int(data.get("total_original_bytes", 0)),
            canary_count=int(data.get("canary_count", 0)),
            department_counts=dict(data.get("department_counts", {})),
            classification_counts=dict(data.get("classification_counts", {})),
            entries=entries,
            opaque_id_map=dict(data.get("opaque_id_map", {})),
        )


@dataclass
class PublicSnapshotMetadata:
    """
    Publicly accessible metadata file ('snapshot.json') stored in the snapshot directory.
    Contains NO plaintext file paths, NO department names, and NO sensitive file lists.
    """
    snapshot_id: str
    format_version: str
    created_at: str
    completed_status: str
    total_files: int
    total_original_bytes: int
    total_encrypted_bytes: int
    key_id: str
    wrapped_aes_key_b64: str
    manifest_nonce_b64: str
    manifest_tag_b64: str
    manifest_encrypted_size: int
    source_lab_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PublicSnapshotMetadata:
        return cls(
            snapshot_id=data["snapshot_id"],
            format_version=data.get("format_version", "1.0.0"),
            created_at=data["created_at"],
            completed_status=data.get("completed_status", SnapshotStatus.COMPLETED.value),
            total_files=int(data.get("total_files", 0)),
            total_original_bytes=int(data.get("total_original_bytes", 0)),
            total_encrypted_bytes=int(data.get("total_encrypted_bytes", 0)),
            key_id=data.get("key_id", ""),
            wrapped_aes_key_b64=data.get("wrapped_aes_key_b64", ""),
            manifest_nonce_b64=data.get("manifest_nonce_b64", ""),
            manifest_tag_b64=data.get("manifest_tag_b64", ""),
            manifest_encrypted_size=int(data.get("manifest_encrypted_size", 0)),
            source_lab_id=data.get("source_lab_id", ""),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class ObjectVerificationResult:
    """Individual object verification check details."""
    opaque_id: str
    relative_path: str
    status: str
    calculated_sha256: Optional[str] = None
    expected_sha256: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ObjectVerificationResult:
        return cls(
            opaque_id=data["opaque_id"],
            relative_path=data["relative_path"],
            status=data["status"],
            calculated_sha256=data.get("calculated_sha256"),
            expected_sha256=data.get("expected_sha256"),
            error_message=data.get("error_message"),
        )


@dataclass
class SnapshotVerificationReport:
    """Comprehensive cryptographic and integrity verification report for a snapshot."""
    snapshot_id: str
    verified_at: str
    duration_seconds: float
    outcome: str
    total_manifest_objects: int
    verified_objects: int
    failed_objects: int
    missing_objects: List[str] = field(default_factory=list)
    unexpected_objects: List[str] = field(default_factory=list)
    tampered_objects: List[str] = field(default_factory=list)
    details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    summary: str = ""

    @property
    def is_valid(self) -> bool:
        return self.outcome == SnapshotVerificationOutcome.FULLY_VERIFIED.value

    @property
    def total_objects(self) -> int:
        return self.total_manifest_objects

    @property
    def valid_objects(self) -> int:
        return self.verified_objects

    @property
    def corrupted_objects(self) -> List[str]:
        return self.tampered_objects

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SnapshotVerificationReport:
        return cls(
            snapshot_id=data["snapshot_id"],
            verified_at=data["verified_at"],
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            outcome=data.get("outcome", SnapshotVerificationOutcome.VERIFICATION_FAILED.value),
            total_manifest_objects=int(data.get("total_manifest_objects", 0)),
            verified_objects=int(data.get("verified_objects", 0)),
            failed_objects=int(data.get("failed_objects", 0)),
            missing_objects=list(data.get("missing_objects", [])),
            unexpected_objects=list(data.get("unexpected_objects", [])),
            tampered_objects=list(data.get("tampered_objects", [])),
            details=dict(data.get("details", {})),
            summary=data.get("summary", ""),
        )

