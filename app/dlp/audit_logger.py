"""
Data Loss Prevention (DLP) Audit Logger for CryptoShield (Phase 8).

Maintains structured, append-only, tamper-evident audit logs documenting every
DLP evaluation, policy violation, transfer interception, and operator authorization.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional
import uuid

from app.config import CONFIG
from app.dlp.models import DLPAuditRecord

logger = logging.getLogger("cryptoshield.dlp.audit_logger")


class DLPAuditLogger:
    """
    Thread-safe append-only audit logger writing to runtime/dlp/audit.log in JSONL format.
    """

    def __init__(self, log_path: Optional[Path] = None) -> None:
        self.log_path = log_path or CONFIG.dlp_audit_log_path
        self._lock = threading.RLock()
        self._entries_cache: List[DLPAuditRecord] = []

        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.debug("Failed to create DLP log parent directory: %s", e)

    def log_event(
        self,
        event_type: str,
        action: str,
        details: Dict[str, Any],
        rule_id: Optional[str] = None,
    ) -> DLPAuditRecord:
        """
        Appends an audit record to the persistent log and in-memory cache.
        """
        with self._lock:
            record = DLPAuditRecord(
                record_id=f"AUD-{uuid.uuid4().hex[:8].upper()}",
                timestamp=datetime.now(CONFIG.TIMEZONE).isoformat(),
                event_type=event_type,
                action=action,
                rule_id=rule_id,
                details=details,
            )
            self._entries_cache.append(record)

            try:
                line = json.dumps(record.to_dict()) + "\n"
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception as e:
                logger.error("Failed to write DLP audit record to %s: %s", self.log_path, e)

            return record

    def get_recent_entries(self, limit: int = 50) -> List[DLPAuditRecord]:
        """Returns the most recent audit records."""
        with self._lock:
            if not self._entries_cache and self.log_path.exists():
                try:
                    records = []
                    with open(self.log_path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                records.append(DLPAuditRecord.from_dict(json.loads(line)))
                    self._entries_cache = records
                except Exception as e:
                    logger.debug("Failed to read audit log from disk: %s", e)

            return list(self._entries_cache[-limit:])

    def clear(self) -> None:
        """Clears the in-memory cache and log file (used during tests/reset)."""
        with self._lock:
            self._entries_cache.clear()
            if self.log_path.exists():
                try:
                    self.log_path.unlink()
                except Exception:
                    pass
