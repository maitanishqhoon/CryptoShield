"""
Data Loss Prevention (DLP) Models and Schemas for CryptoShield (Phase 8).

Defines strongly-typed representations for DLP policy rules, evaluation decisions,
operator approval requests, profiles, and audit records.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Tuple
import uuid


class DLPAction(str, Enum):
    """Actions resulting from DLP policy evaluation on outbound transfers."""
    ALLOW = "ALLOW"                      # Transfer permitted without friction
    ALERT = "ALERT"                      # Transfer permitted; security alert published
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL" # Transfer suspended; requires operator approval
    BLOCK = "BLOCK"                      # Transfer strictly forbidden and intercepted (0 bytes sent)


class DLPProfile(str, Enum):
    """Operational security policy profiles governing default rule sets."""
    DEFAULT = "DEFAULT"                  # Standard enterprise posture (RESTRICTED blocked, CONFIDENTIAL approvals)
    STRICT = "STRICT"                    # Zero-trust posture (RESTRICTED/CONFIDENTIAL blocked, INTERNAL approval)
    AUDIT_ONLY = "AUDIT_ONLY"            # Non-blocking dry-run posture (all rules convert to ALERT)
    PERMISSIVE = "PERMISSIVE"            # Relaxed lab posture (RESTRICTED requires approval, rest allowed)


class DLPApprovalStatus(str, Enum):
    """Lifecycle status of an operator approval request."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


@dataclass
class DLPPolicyRule:
    """
    Individual rule within the Data Loss Prevention policy matrix.
    Rules are evaluated in descending priority order (100 down to 0).
    """
    rule_id: str
    name: str
    description: str
    priority: int                                 # 0 to 100 (higher evaluated first)
    enabled: bool = True
    action: DLPAction = DLPAction.BLOCK
    severity: str = "MEDIUM"                      # "NORMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    target_classifications: List[str] = field(default_factory=list) # e.g. ["RESTRICTED", "CONFIDENTIAL"]
    target_departments: List[str] = field(default_factory=list)     # e.g. ["Finance", "Legal"]
    block_canaries: bool = False                  # If True, matches any transfer with canary honeypot files
    max_file_count: Optional[int] = None          # Throttles bulk transfers exceeding file count
    max_bytes: Optional[int] = None               # Throttles bulk transfers exceeding byte volume
    destination_pattern: Optional[str] = None     # Optional regex for destination endpoints
    allowed_processes: List[str] = field(default_factory=list)
    blocked_processes: List[str] = field(default_factory=list)
    reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def matches(self, transfer_context: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Evaluates whether this rule applies to a given outbound transfer attempt.
        Returns a tuple (matches: bool, match_reason: str).
        """
        if not self.enabled:
            return False, "Rule disabled"

        process_name = transfer_context.get("process_name")
        if process_name and self.allowed_processes and process_name in self.allowed_processes:
            return False, f"Process '{process_name}' is explicitly whitelisted"

        if process_name and self.blocked_processes and process_name in self.blocked_processes:
            return True, f"Process '{process_name}' is explicitly blacklisted by DLP rule '{self.name}'"

        # 1. Canary honeypot check
        if self.block_canaries and transfer_context.get("contains_canary", False):
            return True, self.reason or f"Transfer includes registered canary honeypots (Rule: {self.name})"

        # 2. Classification match check
        context_classifications = [c.upper() for c in transfer_context.get("classifications", [])]
        rule_classifications = [c.upper() for c in self.target_classifications]
        matched_classifications = set(context_classifications).intersection(rule_classifications)
        if rule_classifications and matched_classifications:
            # If departments filter is also specified, both must match
            if self.target_departments:
                context_departments = transfer_context.get("departments", [])
                matched_depts = set(context_departments).intersection(set(self.target_departments))
                if not matched_depts:
                    return False, "Department did not match rule target"
            return True, self.reason or (
                f"Transfer contains sensitive classification(s) {sorted(list(matched_classifications))} "
                f"governed by rule '{self.name}'"
            )

        # 3. Department match check (if rule has departments but no classifications)
        if self.target_departments and not rule_classifications:
            context_departments = transfer_context.get("departments", [])
            matched_depts = set(context_departments).intersection(set(self.target_departments))
            if matched_depts:
                return True, self.reason or f"Transfer targets department(s) {sorted(list(matched_depts))}"

        # 4. Bulk volume / file count check
        file_count = transfer_context.get("file_count", 0)
        if self.max_file_count is not None and file_count > self.max_file_count:
            return True, self.reason or (
                f"Bulk transfer exceeded file count threshold ({file_count} > {self.max_file_count})"
            )

        byte_count = transfer_context.get("bytes", 0) or transfer_context.get("bytes_transferred", 0)
        if self.max_bytes is not None and byte_count > self.max_bytes:
            return True, self.reason or (
                f"Bulk transfer exceeded byte volume threshold ({byte_count}B > {self.max_bytes}B)"
            )

        # 5. Destination pattern check
        endpoint = transfer_context.get("destination_endpoint", "")
        if self.destination_pattern and endpoint:
            try:
                if re.search(self.destination_pattern, endpoint):
                    return True, self.reason or f"Destination '{endpoint}' matched pattern '{self.destination_pattern}'"
            except re.error:
                pass

        return False, "No condition matched"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["action"] = self.action.value if isinstance(self.action, DLPAction) else str(self.action)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DLPPolicyRule:
        data_copy = dict(data)
        if "action" in data_copy and isinstance(data_copy["action"], str):
            data_copy["action"] = DLPAction(data_copy["action"])
        return cls(**data_copy)


@dataclass
class DLPEvaluationResult:
    """Outcome of evaluating an outbound data transfer against DLP policies."""
    evaluation_id: str
    timestamp: str
    action: DLPAction
    allowed: bool                                 # True for ALLOW/ALERT; False for REQUIRE_APPROVAL/BLOCK
    triggered_rule_id: Optional[str] = None
    triggered_rule_name: Optional[str] = None
    severity: str = "NORMAL"
    reason: str = ""
    classifications_evaluated: List[str] = field(default_factory=list)
    departments_evaluated: List[str] = field(default_factory=list)
    contains_canary: bool = False
    file_count: int = 0
    bytes_requested: int = 0
    destination_endpoint: str = ""
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    approval_token: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["action"] = self.action.value if isinstance(self.action, DLPAction) else str(self.action)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DLPEvaluationResult:
        data_copy = dict(data)
        if "action" in data_copy and isinstance(data_copy["action"], str):
            data_copy["action"] = DLPAction(data_copy["action"])
        return cls(**data_copy)


@dataclass
class DLPApprovalRequest:
    """Record representing a transfer quarantined pending operator authorization."""
    approval_token: str
    evaluation_id: str
    requested_at: str
    status: str = DLPApprovalStatus.PENDING.value
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    decision_reason: Optional[str] = None
    transfer_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DLPApprovalRequest:
        return cls(**data)


@dataclass
class DLPAuditRecord:
    """Tamper-evident audit trail record for DLP decisions and policy enforcement."""
    record_id: str
    timestamp: str
    event_type: str                               # e.g. "DLP_TRANSFER_BLOCKED", "DLP_APPROVAL_GRANTED"
    action: str
    rule_id: Optional[str]
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DLPAuditRecord:
        return cls(**data)
