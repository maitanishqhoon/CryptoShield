"""
Data Loss Prevention (DLP) Policy Engine for CryptoShield (Phase 8).

Evaluates outbound transfer contexts against priority-ordered policy rules,
enforces classification-aware access decisions (ALLOW, ALERT, REQUIRE_APPROVAL, BLOCK),
and supports configurable security profiles (DEFAULT, STRICT, AUDIT_ONLY, PERMISSIVE).
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Tuple
import uuid

from app.config import CONFIG
from app.dlp.models import (
    DLPAction,
    DLPEvaluationResult,
    DLPPolicyRule,
    DLPProfile,
)

logger = logging.getLogger("cryptoshield.dlp.policy_engine")


def get_default_enterprise_rules() -> List[DLPPolicyRule]:
    """Builds the default institutional DLP policy rule set."""
    return [
        DLPPolicyRule(
            rule_id="DLP-RULE-001-CANARY",
            name="Honeypot Canary Exfiltration Prevention",
            description="Unconditionally intercepts any outbound transfer containing deceptive canary honeypots.",
            priority=100,
            enabled=True,
            action=DLPAction.BLOCK,
            severity="CRITICAL",
            block_canaries=True,
            reason="Exfiltration of registered honeypot canary detected. Transfer strictly blocked.",
        ),
        DLPPolicyRule(
            rule_id="DLP-RULE-002-RESTRICTED",
            name="Restricted Intellectual Property & Credentials Guard",
            description="Blocks outbound transmission of RESTRICTED classified assets without exception.",
            priority=90,
            enabled=True,
            action=DLPAction.BLOCK,
            severity="CRITICAL",
            target_classifications=["RESTRICTED"],
            reason="Transmission of RESTRICTED intellectual property or credentials is strictly blocked.",
        ),
        DLPPolicyRule(
            rule_id="DLP-RULE-003-CONFIDENTIAL",
            name="Confidential Business & Financial Data Gate",
            description="Protects CONFIDENTIAL customer and financial data. Requires operator authorization.",
            priority=80,
            enabled=True,
            action=DLPAction.REQUIRE_APPROVAL,
            severity="HIGH",
            target_classifications=["CONFIDENTIAL"],
            reason="Outbound transmission of CONFIDENTIAL records requires explicit operator approval.",
        ),
        DLPPolicyRule(
            rule_id="DLP-RULE-004-BULK-BURST",
            name="Bulk Data Exfiltration Throttling",
            description="Catches abnormal bulk transfer bursts exceeding 20 files or 5 MB.",
            priority=70,
            enabled=True,
            action=DLPAction.REQUIRE_APPROVAL,
            severity="MEDIUM",
            max_file_count=CONFIG.DLP_MAX_BURST_FILES,
            max_bytes=CONFIG.DLP_MAX_PAYLOAD_BYTES,
            reason="Bulk transfer volume exceeds standard thresholds. Quarantined for review.",
        ),
        DLPPolicyRule(
            rule_id="DLP-RULE-005-INTERNAL",
            name="Internal Operational Records Movement Audit",
            description="Permits transmission of INTERNAL records but logs an audit alert.",
            priority=60,
            enabled=True,
            action=DLPAction.ALERT,
            severity="MEDIUM",
            target_classifications=["INTERNAL"],
            reason="Internal company document transmission observed and logged to audit trail.",
        ),
        DLPPolicyRule(
            rule_id="DLP-RULE-006-PUBLIC",
            name="Public Information Permissive Allow",
            description="Permits outbound movement of PUBLIC documents with standard logging.",
            priority=10,
            enabled=True,
            action=DLPAction.ALLOW,
            severity="NORMAL",
            target_classifications=["PUBLIC"],
            reason="Publicly disclosable document transfer permitted.",
        ),
        DLPPolicyRule(
            rule_id="DLP-RULE-000-FALLBACK",
            name="Default Unclassified Fallback",
            description="Fallback rule applied when no specific classification or pattern matches.",
            priority=0,
            enabled=True,
            action=DLPAction.ALLOW,
            severity="NORMAL",
            reason="Transfer permitted under default baseline policy.",
        ),
    ]


class DLPPolicyEngine:
    """
    Evaluates outbound data transfers against prioritized policy rules.
    Maintains rule ordering, dynamic modifications, and profile postures.
    """

    def __init__(
        self,
        rules: Optional[List[DLPPolicyRule]] = None,
        profile: Optional[DLPProfile] = None,
        policies_path: Optional[Path] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._policies_path = policies_path or CONFIG.dlp_policies_path
        self._rules: Dict[str, DLPPolicyRule] = {}
        self._profile = DLPProfile.DEFAULT

        if rules is not None:
            for r in rules:
                self._rules[r.rule_id] = r
            if profile is not None:
                self._profile = profile
        else:
            self._load_or_initialize_defaults()
            if profile is not None:
                self._profile = profile

        # Apply profile configuration
        self._apply_profile(self._profile)

    @property
    def profile(self) -> DLPProfile:
        with self._lock:
            return self._profile

    def set_profile(self, profile: DLPProfile) -> None:
        """Switches the active security posture profile."""
        with self._lock:
            self._profile = profile
            self._apply_profile(profile)
            logger.info("DLP policy engine switched to profile: %s", profile.value)

    def _load_or_initialize_defaults(self) -> None:
        """Loads rules from persistent JSON file if present, else loads defaults."""
        if self._policies_path and self._policies_path.exists():
            try:
                self.load_from_file(self._policies_path)
                return
            except Exception as e:
                logger.warning("Failed to load policies from %s (%s); reverting to defaults.", self._policies_path, e)

        self._rules.clear()
        for r in get_default_enterprise_rules():
            self._rules[r.rule_id] = r

    def _apply_profile(self, profile: DLPProfile) -> None:
        """Adjusts rule actions according to the target profile."""
        if profile == DLPProfile.STRICT:
            if "DLP-RULE-003-CONFIDENTIAL" in self._rules:
                self._rules["DLP-RULE-003-CONFIDENTIAL"].action = DLPAction.BLOCK
                self._rules["DLP-RULE-003-CONFIDENTIAL"].severity = "CRITICAL"
            if "DLP-RULE-004-BULK-BURST" in self._rules:
                self._rules["DLP-RULE-004-BULK-BURST"].action = DLPAction.BLOCK
            if "DLP-RULE-005-INTERNAL" in self._rules:
                self._rules["DLP-RULE-005-INTERNAL"].action = DLPAction.REQUIRE_APPROVAL
            if "DLP-RULE-006-PUBLIC" in self._rules:
                self._rules["DLP-RULE-006-PUBLIC"].action = DLPAction.ALERT

        elif profile == DLPProfile.PERMISSIVE:
            if "DLP-RULE-002-RESTRICTED" in self._rules:
                self._rules["DLP-RULE-002-RESTRICTED"].action = DLPAction.REQUIRE_APPROVAL
            if "DLP-RULE-003-CONFIDENTIAL" in self._rules:
                self._rules["DLP-RULE-003-CONFIDENTIAL"].action = DLPAction.ALERT
            if "DLP-RULE-005-INTERNAL" in self._rules:
                self._rules["DLP-RULE-005-INTERNAL"].action = DLPAction.ALLOW

        elif profile == DLPProfile.DEFAULT:
            # Re-apply defaults
            defaults = {r.rule_id: r for r in get_default_enterprise_rules()}
            for rid, default_rule in defaults.items():
                if rid in self._rules:
                    self._rules[rid].action = default_rule.action
                    self._rules[rid].severity = default_rule.severity

    def evaluate(self, transfer_context: Dict[str, Any]) -> DLPEvaluationResult:
        """
        Evaluates a candidate transfer context against all active rules in priority order.
        Returns the resulting DLPEvaluationResult.
        """
        with self._lock:
            eval_id = f"DLP-EVAL-{uuid.uuid4().hex[:8].upper()}"
            now_iso = datetime.now(CONFIG.TIMEZONE).isoformat()

            sorted_rules = sorted(
                [r for r in self._rules.values() if r.enabled],
                key=lambda r: r.priority,
                reverse=True,
            )

            triggered_rule: Optional[DLPPolicyRule] = None
            match_reason: str = ""

            for rule in sorted_rules:
                matches, reason = rule.matches(transfer_context)
                if matches:
                    triggered_rule = rule
                    match_reason = reason
                    break

            if not triggered_rule:
                # Default safety fallback
                action = DLPAction.ALLOW
                severity = "NORMAL"
                reason = "No DLP rules triggered; default permissive allow."
                rule_id = None
                rule_name = None
            else:
                action = triggered_rule.action
                severity = triggered_rule.severity
                reason = match_reason
                rule_id = triggered_rule.rule_id
                rule_name = triggered_rule.name

            # In AUDIT_ONLY mode, convert BLOCK and REQUIRE_APPROVAL to ALERT
            if self._profile == DLPProfile.AUDIT_ONLY and action in (DLPAction.BLOCK, DLPAction.REQUIRE_APPROVAL):
                logger.info("AUDIT_ONLY mode: converting action %s to ALERT for audit tracking", action.value)
                reason = f"[AUDIT_ONLY MODE: Originally {action.value}] {reason}"
                action = DLPAction.ALERT

            allowed = action in (DLPAction.ALLOW, DLPAction.ALERT)

            return DLPEvaluationResult(
                evaluation_id=eval_id,
                timestamp=now_iso,
                action=action,
                allowed=allowed,
                triggered_rule_id=rule_id,
                triggered_rule_name=rule_name,
                severity=severity,
                reason=reason,
                classifications_evaluated=list(transfer_context.get("classifications", [])),
                departments_evaluated=list(transfer_context.get("departments", [])),
                contains_canary=bool(transfer_context.get("contains_canary", False)),
                file_count=int(transfer_context.get("file_count", 0)),
                bytes_requested=int(transfer_context.get("bytes", 0) or transfer_context.get("bytes_transferred", 0)),
                destination_endpoint=str(transfer_context.get("destination_endpoint", "")),
                process_id=transfer_context.get("process_id"),
                process_name=transfer_context.get("process_name"),
                metadata={
                    "profile": self._profile.value,
                },
            )

    def add_rule(self, rule: DLPPolicyRule) -> None:
        """Adds or updates a policy rule."""
        with self._lock:
            self._rules[rule.rule_id] = rule
            logger.info("Added/Updated DLP rule %s (%s)", rule.rule_id, rule.name)

    def remove_rule(self, rule_id: str) -> bool:
        """Removes a policy rule by ID."""
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                logger.info("Removed DLP rule %s", rule_id)
                return True
            return False

    def get_rule(self, rule_id: str) -> Optional[DLPPolicyRule]:
        with self._lock:
            return self._rules.get(rule_id)

    def enable_rule(self, rule_id: str) -> bool:
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule:
                rule.enabled = True
                return True
            return False

    def disable_rule(self, rule_id: str) -> bool:
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule:
                rule.enabled = False
                return True
            return False

    def get_rules(self, enabled_only: bool = False) -> List[DLPPolicyRule]:
        """Returns policy rules sorted by descending priority."""
        with self._lock:
            rules = list(self._rules.values())
            if enabled_only:
                rules = [r for r in rules if r.enabled]
            return sorted(rules, key=lambda r: r.priority, reverse=True)

    def reset_to_defaults(self) -> None:
        """Resets all policies to the baseline enterprise rules."""
        with self._lock:
            self._rules.clear()
            for r in get_default_enterprise_rules():
                self._rules[r.rule_id] = r
            self._apply_profile(self._profile)
            logger.info("Reset DLP policies to institutional defaults.")

    def save_to_file(self, target_path: Optional[Path] = None) -> Path:
        """Persists the current rules and profile to a JSON file."""
        with self._lock:
            path = target_path or self._policies_path
            path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "profile": self._profile.value,
                "saved_at": datetime.now(CONFIG.TIMEZONE).isoformat(),
                "rules": [r.to_dict() for r in self.get_rules()],
            }
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            logger.info("Saved %d DLP rules to %s", len(data["rules"]), path)
            return path

    def load_from_file(self, target_path: Optional[Path] = None) -> None:
        """Loads rules and profile from a JSON file."""
        with self._lock:
            path = target_path or self._policies_path
            if not path.exists():
                raise FileNotFoundError(f"DLP policy file not found: {path}")

            data = json.loads(path.read_text(encoding="utf-8"))
            if "profile" in data:
                self._profile = DLPProfile(data["profile"])

            self._rules.clear()
            for rule_dict in data.get("rules", []):
                rule = DLPPolicyRule.from_dict(rule_dict)
                self._rules[rule.rule_id] = rule

            logger.info("Loaded %d DLP rules from %s (profile: %s)", len(self._rules), path, self._profile.value)
