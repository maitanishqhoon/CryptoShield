"""
Central Configuration for CryptoShield.

Defines all filesystem paths, laboratory safety parameters, dataset generation
rules, limits, and departmental taxonomy.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from app.core.models import DataClassification, DatasetPreset
from app.core.time import IST, DEFAULT_TIMEZONE_NAME


@dataclass(frozen=True)
class CryptoShieldConfig:
    """Immutable configuration holding all paths and operational constraints."""

    # Timezone & Temporal Configuration (Indian Standard Time - IST)
    TIMEZONE: Any = IST
    TIMEZONE_NAME: str = DEFAULT_TIMEZONE_NAME

    # Base project paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent
    RUNTIME_DIR: Path = field(
        default_factory=lambda: (
            Path(os.environ["CRYPTOSHIELD_RUNTIME_DIR"]).resolve()
            if os.environ.get("CRYPTOSHIELD_RUNTIME_DIR")
            else Path(__file__).resolve().parent.parent / "runtime"
        )
    )

    # Laboratory and subsystem directories (derived from RUNTIME_DIR in __post_init__)
    LAB_DIR: Path = field(init=False)
    VAULT_DIR: Path = field(init=False)
    KEYS_DIR: Path = field(init=False)
    SNAPSHOTS_DIR: Path = field(init=False)
    LOGS_DIR: Path = field(init=False)
    REPORTS_DIR: Path = field(init=False)
    INCIDENTS_DIR: Path = field(init=False)

    # Cryptographic Vault Parameters (Phase 5)
    PRIVATE_KEY_FILENAME: str = "cryptoshield_private.pem"
    PUBLIC_KEY_FILENAME: str = "cryptoshield_public.pem"
    KEY_METADATA_FILENAME: str = "key_metadata.json"
    VAULT_OBJECT_EXT: str = ".cso"
    VAULT_MAGIC: bytes = b"CSO1"
    VAULT_FORMAT_VERSION: str = "1.0.0"
    VAULT_BINARY_VERSION: int = 1
    AES_KEY_SIZE_BYTES: int = 32          # 256 bits
    AES_GCM_NONCE_SIZE_BYTES: int = 12    # 96 bits
    AES_GCM_TAG_SIZE_BYTES: int = 16      # 128 bits
    RSA_KEY_SIZE_BITS: int = 3072         # 3072 bits
    RSA_PUBLIC_EXPONENT: int = 65537
    STREAMING_CHUNK_SIZE_BYTES: int = 1024 * 1024  # 1 MiB chunk size

    # Private-Key Protection Envelope & Argon2id Hardening (Phase 5)
    KEY_ENVELOPE_VERSION: int = 2
    ARGON2_SALT_BYTES: int = 32           # >= 16 bytes
    ARGON2_ITERATIONS: int = 3            # OWASP recommended time cost
    ARGON2_MEMORY_COST_KIB: int = 65536   # 64 MiB (OWASP High Security)
    ARGON2_LANES: int = 4                 # Parallelism threads
    ARGON2_KEY_LENGTH_BYTES: int = 64     # 32B AES key + 32B HMAC verifier key
    ARGON2_CIPHER: str = "AES-256-GCM"

    # Identification & Safety
    LAB_MARKER_FILENAME: str = ".cryptoshield_lab_marker"
    MANIFEST_FILENAME: str = "baseline_manifest.json"
    LOG_FILENAME: str = "cryptoshield.log"
    JSON_LOG_FILENAME: str = "cryptoshield.json.log"

    # Supported enterprise departments
    DEPARTMENTS: List[str] = field(
        default_factory=lambda: [
            "Finance",
            "Human Resources",
            "Legal",
            "Sales",
            "Customers",
            "Operations",
            "Research",
            "IT",
            "Public Documents",
        ]
    )

    # Supported file extensions
    FILE_FORMATS: List[str] = field(
        default_factory=lambda: [
            "txt",
            "csv",
            "json",
            "xml",
            "md",
            "html",
            "log",
        ]
    )

    # Department classification guidelines
    DEPARTMENT_CLASSIFICATIONS: Dict[str, List[DataClassification]] = field(
        default_factory=lambda: {
            "Finance": [DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED],
            "Human Resources": [DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED],
            "Legal": [DataClassification.RESTRICTED, DataClassification.CONFIDENTIAL],
            "Sales": [DataClassification.INTERNAL, DataClassification.CONFIDENTIAL],
            "Customers": [DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED],
            "Operations": [DataClassification.INTERNAL, DataClassification.PUBLIC],
            "Research": [DataClassification.CONFIDENTIAL, DataClassification.INTERNAL],
            "IT": [DataClassification.RESTRICTED, DataClassification.INTERNAL],
            "Public Documents": [DataClassification.PUBLIC],
        }
    )

    # Safety and dataset limits
    MAX_FILE_SIZE_BYTES: int = 128 * 1024        # 128 KB max single synthetic file
    MAX_DATASET_TOTAL_BYTES: int = 500 * 1024 * 1024  # 500 MB safety cap
    CANARY_RATIO: float = 0.02                   # 2% of files as canaries
    MIN_CANARY_COUNT: int = 5                    # Minimum canaries generated
    MAX_CANARY_COUNT: int = 250                  # Cap to avoid excessive canaries
    IO_BUFFER_SIZE_BYTES: int = 64 * 1024        # 64 KB buffer for streaming SHA256

    # Presets
    PRESET_COUNTS: Dict[str, int] = field(
        default_factory=lambda: {
            "quick": DatasetPreset.QUICK.value,
            "default": DatasetPreset.DEFAULT.value,
            "stress": DatasetPreset.STRESS.value,
        }
    )

    # Telemetry and Monitoring Parameters (Phase 2)
    MONITORING_ENABLED: bool = True
    MONITOR_EVENT_QUEUE_CAPACITY: int = 10000
    MONITOR_DEBOUNCE_SECONDS: float = 0.05
    MONITOR_OBSERVER_TIMEOUT_SECONDS: float = 0.05
    PROCESS_POLL_INTERVAL_SECONDS: float = 1.0
    CANARY_EVENT_PRIORITY: str = "HIGH"
    MONITOR_IGNORED_DIRS: List[str] = field(
        default_factory=lambda: [".git", "__pycache__", ".pytest_cache", ".demo_tmp"]
    )
    MONITOR_IGNORED_FILENAMES: List[str] = field(
        default_factory=lambda: [".cryptoshield_lab_marker", "baseline_manifest.json"]
    )

    # Detection & Threat Scoring Engine Parameters (Phase 3)
    DETECTION_ENABLED: bool = True
    DETECTION_SLIDING_WINDOWS: List[float] = field(
        default_factory=lambda: [1.0, 5.0, 10.0, 30.0]
    )
    DETECTION_PRIMARY_WINDOW: float = 5.0

    # Behavioral Thresholds
    BURST_MODERATE_MODIFICATION_THRESHOLD: int = 15
    BURST_LARGE_MODIFICATION_THRESHOLD: int = 40
    BURST_RAPID_RENAME_THRESHOLD: int = 10
    BURST_DELETION_THRESHOLD: int = 15
    MULTI_DEPARTMENT_THRESHOLD: int = 3
    MULTI_EXTENSION_THRESHOLD: int = 3

    # Threat Scoring Weights (Total capped at 100)
    WEIGHT_MODERATE_MODIFICATIONS: int = 20
    WEIGHT_LARGE_MODIFICATIONS: int = 40
    WEIGHT_RAPID_RENAMING: int = 20
    WEIGHT_LARGE_DELETIONS: int = 20
    WEIGHT_MULTI_DEPARTMENT: int = 10
    WEIGHT_MULTI_EXTENSION: int = 10
    WEIGHT_MULTIPLE_PATTERNS: int = 10
    WEIGHT_FIRST_CANARY: int = 50
    WEIGHT_ADDITIONAL_CANARY: int = 15
    WEIGHT_CANARY_TAMPERING: int = 60

    # Severity Score Thresholds
    SEVERITY_THRESHOLDS: Dict[str, int] = field(
        default_factory=lambda: {
            "NORMAL": 0,
            "LOW": 20,
            "MEDIUM": 40,
            "HIGH": 60,
            "CRITICAL": 80,
        }
    )

    # Incident Management & False-Positive Cooldown
    INCIDENT_AUTO_CREATE_THRESHOLD: int = 40
    INCIDENT_MERGE_WINDOW_SECONDS: float = 60.0
    DETECTION_COOLDOWN_SECONDS: float = 1.0
    DEDUPLICATION_CACHE_MAX_SIZE: int = 20000
    DEDUPLICATION_CACHE_TTL_SECONDS: float = 120.0

    # Explicitly configured classifications permitted for verified legitimate bulk workloads
    VERIFIED_LEGITIMATE_SOURCES: List[str] = field(
        default_factory=lambda: [
            "CRYPTO_SHIELD_TEST_HARNESS_LEGITIMATE",
            "CONFIGURED_BACKUP_SERVICE",
            "CONFIGURED_DATASET_GENERATOR",
        ]
    )

    # Threat Containment & Controlled Process Isolation Parameters (Phase 4)
    CONTAINMENT_DIR: Path = field(init=False)
    CONTAINMENT_DEMO_DIR: Path = field(init=False)
    AUTO_CONTAINMENT_ENABLED: bool = True
    AUTO_CONTAINMENT_THRESHOLD: int = 80
    CONTAINMENT_HIGH_THRESHOLD: int = 60
    GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS: float = 3.0
    FORCED_TERMINATION_FALLBACK_ENABLED: bool = True
    CONTAINMENT_VERIFICATION_INTERVAL_SECONDS: float = 0.1
    SIMULATOR_MAX_DURATION_SECONDS: float = 10.0
    SIMULATOR_MAX_OPERATIONS: int = 100

    # Recovery and Restoration Parameters (Phase 6)
    RECOVERY_DIR: Path = field(init=False)
    RECOVERY_WORKSPACES_DIR: Path = field(init=False)
    RECOVERY_STAGING_DIR: Path = field(init=False)
    RECOVERY_REPORTS_DIR: Path = field(init=False)
    RECOVERY_MARKER_FILENAME: str = ".cryptoshield_recovery_marker"
    RECOVERY_EVIDENCE_DIRNAME: str = ".evidence_quarantine"

    # Data Exfiltration Monitoring Parameters (Phase 7)
    EXFILTRATION_DIR: Path = field(init=False)
    EXFILTRATION_STAGING_DIR: Path = field(init=False)
    EXFILTRATION_MOCK_HOST: str = "127.0.0.1"
    EXFILTRATION_MOCK_PORT: int = 8999
    EXFILTRATION_READ_BURST_THRESHOLD: int = 10       # 10+ reads in window
    EXFILTRATION_READ_WINDOW_SECONDS: float = 5.0
    EXFILTRATION_CANARY_READ_WEIGHT: int = 40         # Weight for tripping canary read
    EXFILTRATION_MASS_READ_WEIGHT: int = 25           # Weight for mass sensitive reads
    EXFILTRATION_STAGING_WEIGHT: int = 20             # Weight for local archive staging
    EXFILTRATION_TRANSFER_WEIGHT: int = 30            # Weight for outbound mock transfer
    EXFILTRATION_HIGH_THRESHOLD: int = 60
    EXFILTRATION_CRITICAL_THRESHOLD: int = 80

    # Data Loss Prevention (DLP) Parameters (Phase 8)
    DLP_DIR: Path = field(init=False)
    DLP_POLICIES_FILENAME: str = "policies.json"
    DLP_AUDIT_LOG_FILENAME: str = "audit.log"
    DLP_ENABLED: bool = True
    DLP_STRICT_MODE: bool = False
    DLP_MAX_BURST_FILES: int = 20
    DLP_MAX_PAYLOAD_BYTES: int = 5 * 1024 * 1024  # 5 MB
    DLP_APPROVAL_TIMEOUT_SECONDS: float = 300.0   # 5 minutes

    def __post_init__(self) -> None:
        """Derive all subsystem directories from RUNTIME_DIR."""
        rt = self.RUNTIME_DIR.resolve()
        lab = rt / "lab"
        rec = rt / "recovery"
        object.__setattr__(self, "RUNTIME_DIR", rt)
        object.__setattr__(self, "LAB_DIR", lab)
        object.__setattr__(self, "VAULT_DIR", rt / "vault")
        object.__setattr__(self, "KEYS_DIR", rt / "keys")
        object.__setattr__(self, "SNAPSHOTS_DIR", rt / "snapshots")
        object.__setattr__(self, "LOGS_DIR", rt / "logs")
        object.__setattr__(self, "REPORTS_DIR", rt / "reports")
        object.__setattr__(self, "INCIDENTS_DIR", rt / "incidents")
        object.__setattr__(self, "CONTAINMENT_DIR", rt / "containment")
        object.__setattr__(self, "CONTAINMENT_DEMO_DIR", lab / "containment_demo")
        object.__setattr__(self, "RECOVERY_DIR", rec)
        object.__setattr__(self, "RECOVERY_WORKSPACES_DIR", rec / "workspaces")
        object.__setattr__(self, "RECOVERY_STAGING_DIR", rec / "staging")
        object.__setattr__(self, "RECOVERY_REPORTS_DIR", rec / "reports")
        object.__setattr__(self, "EXFILTRATION_DIR", rt / "exfiltration")
        object.__setattr__(self, "EXFILTRATION_STAGING_DIR", lab / ".exfiltration_staging")
        object.__setattr__(self, "DLP_DIR", rt / "dlp")

    @property
    def containment_dir(self) -> Path:
        return self.CONTAINMENT_DIR

    @property
    def vault_dir(self) -> Path:
        return self.VAULT_DIR

    @property
    def keys_dir(self) -> Path:
        return self.KEYS_DIR

    @property
    def private_key_path(self) -> Path:
        return self.KEYS_DIR / self.PRIVATE_KEY_FILENAME

    @property
    def public_key_path(self) -> Path:
        return self.KEYS_DIR / self.PUBLIC_KEY_FILENAME

    @property
    def key_metadata_path(self) -> Path:
        return self.KEYS_DIR / self.KEY_METADATA_FILENAME

    @property
    def containment_demo_dir(self) -> Path:
        return self.CONTAINMENT_DEMO_DIR

    @property
    def incidents_dir(self) -> Path:
        return self.INCIDENTS_DIR

    @property
    def reports_dir(self) -> Path:
        return self.REPORTS_DIR

    @property
    def lab_marker_path(self) -> Path:
        return self.LAB_DIR / self.LAB_MARKER_FILENAME

    @property
    def manifest_path(self) -> Path:
        return self.LAB_DIR / self.MANIFEST_FILENAME

    @property
    def log_path(self) -> Path:
        return self.LOGS_DIR / self.LOG_FILENAME

    @property
    def json_log_path(self) -> Path:
        return self.LOGS_DIR / self.JSON_LOG_FILENAME

    @property
    def recovery_dir(self) -> Path:
        return self.RECOVERY_DIR

    @property
    def recovery_workspaces_dir(self) -> Path:
        return self.RECOVERY_WORKSPACES_DIR

    @property
    def recovery_staging_dir(self) -> Path:
        return self.RECOVERY_STAGING_DIR

    @property
    def recovery_reports_dir(self) -> Path:
        return self.RECOVERY_REPORTS_DIR

    @property
    def exfiltration_dir(self) -> Path:
        return self.EXFILTRATION_DIR

    @property
    def exfiltration_staging_dir(self) -> Path:
        return self.EXFILTRATION_STAGING_DIR

    @property
    def dlp_dir(self) -> Path:
        return self.DLP_DIR

    @property
    def dlp_policies_path(self) -> Path:
        return self.DLP_DIR / self.DLP_POLICIES_FILENAME

    @property
    def dlp_audit_log_path(self) -> Path:
        return self.DLP_DIR / self.DLP_AUDIT_LOG_FILENAME

    def ensure_directories(self) -> None:
        """Create necessary runtime directories for CryptoShield including recovery, exfiltration, and dlp."""
        for path in [
            self.RUNTIME_DIR,
            self.LAB_DIR,
            self.VAULT_DIR,
            self.KEYS_DIR,
            self.SNAPSHOTS_DIR,
            self.LOGS_DIR,
            self.REPORTS_DIR,
            self.INCIDENTS_DIR,
            self.CONTAINMENT_DIR,
            self.RECOVERY_DIR,
            self.RECOVERY_WORKSPACES_DIR,
            self.RECOVERY_STAGING_DIR,
            self.RECOVERY_REPORTS_DIR,
            self.EXFILTRATION_DIR,
            self.DLP_DIR,
        ]:
            path.mkdir(parents=True, exist_ok=True)


# Global singleton instance
CONFIG = CryptoShieldConfig()
Config = CryptoShieldConfig


def ensure_directories() -> None:
    """Convenience helper to create all runtime directories."""
    CONFIG.ensure_directories()

