"""
Cryptographic Recovery Engine for CryptoShield (Phase 6).
Snapshot decryption, file restoration, and SHA-256 verification against baseline manifest.
"""

from app.recovery.models import (
    FileAssessmentRecord,
    FileAssessmentStatus,
    FileRestorationOutcome,
    FileRestorationRecord,
    PlannedRecoveryAction,
    RecoveryAuthenticationError,
    RecoveryError,
    RecoveryIntegrityError,
    RecoveryMode,
    RecoveryOperationReport,
    RecoveryWorkspaceMarker,
    RestorationPolicyError,
    StagedObjectResult,
    WorkspaceAssessmentSummary,
    WorkspaceMetadata,
    WorkspaceNotFoundError,
    WorkspaceSafetyError,
)
from app.recovery.recovery_assessor import RecoveryAssessor
from app.recovery.recovery_coordinator import RECOVERY_COORDINATOR, RecoveryCoordinator
from app.recovery.recovery_engine import RecoveryEngine
from app.recovery.recovery_reporter import RecoveryReporter
from app.recovery.restoration_manager import RestorationManager
from app.recovery.workspace_manager import RecoveryWorkspaceManager

__all__ = [
    "RecoveryError",
    "WorkspaceSafetyError",
    "WorkspaceNotFoundError",
    "RecoveryAuthenticationError",
    "RecoveryIntegrityError",
    "RestorationPolicyError",
    "FileAssessmentStatus",
    "PlannedRecoveryAction",
    "RecoveryMode",
    "FileRestorationOutcome",
    "RecoveryWorkspaceMarker",
    "WorkspaceMetadata",
    "FileAssessmentRecord",
    "WorkspaceAssessmentSummary",
    "StagedObjectResult",
    "FileRestorationRecord",
    "RecoveryOperationReport",
    "RecoveryWorkspaceManager",
    "RecoveryAssessor",
    "RecoveryEngine",
    "RestorationManager",
    "RecoveryReporter",
    "RecoveryCoordinator",
    "RECOVERY_COORDINATOR",
]
