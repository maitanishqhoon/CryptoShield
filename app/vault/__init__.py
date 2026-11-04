"""
CryptoShield Vault Package (Phase 5).

Provides cryptographic snapshot protection, AES-256-GCM file encryption,
RSA-OAEP session-key wrapping, tamper detection, and cryptographic verification.
"""

from app.vault.models import (
    EncryptedObjectRecord,
    ObjectVerificationResult,
    PublicSnapshotMetadata,
    SnapshotManifest,
    SnapshotStatus,
    SnapshotVerificationOutcome,
    SnapshotVerificationReport,
    VerificationStatus,
)

__all__ = [
    "EncryptedObjectRecord",
    "ObjectVerificationResult",
    "PublicSnapshotMetadata",
    "SnapshotManifest",
    "SnapshotStatus",
    "SnapshotVerificationOutcome",
    "SnapshotVerificationReport",
    "VerificationStatus",
]
