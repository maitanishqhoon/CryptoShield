"""
Canary Decoy Analyzer for CryptoShield.

Detects, verifies, and analyzes telemetry events affecting registered cryptographic
canary decoy files. Raises immediate high-priority security alerts, escalates threat
evaluations, and prevents duplicate alerts without mutating files or processes.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from app.config import CONFIG
from app.core.event_bus import BUS, Event, EventBus
from app.core.logger import get_logger
from app.core.models import (
    ContributingIndicator,
    DetectionReason,
    EventPriority,
    Manifest,
    MonitoringEvent,
    ProcessAttribution,
    SecurityAlert,
)
from app.lab.manifest import ManifestManager

logger = get_logger("canary_analyzer")


@dataclass
class CanaryEvaluation:
    """Evaluation result produced by CanaryAnalyzer for a given set of telemetry events."""
    canary_events_count: int = 0
    unique_canaries_accessed: Set[str] = field(default_factory=set)
    unique_canaries_tampered: Set[str] = field(default_factory=set)
    indicators: List[ContributingIndicator] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    alerts_generated: List[SecurityAlert] = field(default_factory=list)
    is_canary_tripped: bool = False
    process_attribution: str = ProcessAttribution.UNKNOWN.value
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    explanations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canary_events_count": self.canary_events_count,
            "unique_canaries_accessed": sorted(self.unique_canaries_accessed),
            "unique_canaries_tampered": sorted(self.unique_canaries_tampered),
            "indicators": [i.to_dict() for i in self.indicators],
            "reasons": self.reasons,
            "alerts_generated": [a.to_dict() for a in self.alerts_generated],
            "is_canary_tripped": self.is_canary_tripped,
            "process_attribution": self.process_attribution,
            "process_id": self.process_id,
            "process_name": self.process_name,
            "explanations": self.explanations,
        }


class CanaryAnalyzer:
    """
    Specialized analyzer for cryptographic canary decoy telemetry.
    
    Identifies breaches of canary decoys, cross-references with registered
    baseline manifests, and generates immediate high-priority alerts.
    """

    def __init__(
        self,
        manifest: Optional[Manifest] = None,
        event_bus: Optional[EventBus] = None,
        base_lab_dir: Optional[Path] = None,
    ) -> None:
        self.bus = event_bus or BUS
        self.lab_dir = (base_lab_dir or CONFIG.LAB_DIR).resolve()
        self.manifest: Optional[Manifest] = manifest

        self._registered_canaries: Set[str] = set()
        if not self.manifest:
            self._try_load_manifest()
        else:
            self._sync_registered_canaries()

        self._seen_alert_event_ids: Set[str] = set()
        self._history_accessed_canaries: Set[str] = set()
        self._history_tampered_canaries: Set[str] = set()
        self._lock = threading.RLock()

        # Operational metrics
        self.total_canary_events_analyzed: int = 0
        self.alerts_emitted: int = 0

    def _try_load_manifest(self) -> None:
        """Attempt to load manifest from laboratory root."""
        manifest_path = self.lab_dir / CONFIG.MANIFEST_FILENAME
        if manifest_path.exists():
            try:
                self.manifest = ManifestManager.load_manifest(manifest_path, base_lab_dir=self.lab_dir)
                self._sync_registered_canaries()
            except Exception as e:
                logger.debug(f"CanaryAnalyzer could not load baseline manifest: {e}")

    def _sync_registered_canaries(self) -> None:
        """Extract all canary file paths from loaded manifest."""
        if self.manifest:
            self._registered_canaries = {
                entry.relative_path
                for entry in self.manifest.entries.values()
                if entry.is_canary
            }
            logger.debug(
                f"CanaryAnalyzer registered {len(self._registered_canaries)} canary decoy files."
            )

    def set_manifest(self, manifest: Manifest) -> None:
        """Update active manifest reference."""
        with self._lock:
            self.manifest = manifest
            self._sync_registered_canaries()

    def is_registered_canary(self, relative_path: Optional[str]) -> bool:
        """Verify whether relative path is a registered canary decoy."""
        if not relative_path:
            return False
        with self._lock:
            if self._registered_canaries:
                return relative_path in self._registered_canaries
            # Fallback if no manifest loaded: check filename convention
            return "canary" in relative_path.lower()

    def evaluate_events(self, events: List[MonitoringEvent]) -> CanaryEvaluation:
        """
        Evaluate a list of telemetry events for canary file interactions.
        
        Generates immediate SecurityAlert objects for un-alerted canary events,
        determines distinct canary counts, and returns a structured CanaryEvaluation.
        """
        eval_result = CanaryEvaluation()

        with self._lock:
            for ev in events:
                is_canary_event = ev.is_canary or ev.event_type == "CANARY_ACCESS" or self.is_registered_canary(ev.relative_path)
                if not is_canary_event:
                    continue

                self.total_canary_events_analyzed += 1
                eval_result.canary_events_count += 1
                eval_result.is_canary_tripped = True

                canary_path = ev.relative_path or ev.canary_id or "UNKNOWN_CANARY"
                is_registered = self.is_registered_canary(canary_path)

                # Process attribution
                if ev.process_attribution == ProcessAttribution.CONFIRMED.value:
                    eval_result.process_attribution = ProcessAttribution.CONFIRMED.value
                    eval_result.process_id = ev.process_id
                    eval_result.process_name = ev.process_name
                elif eval_result.process_attribution == ProcessAttribution.UNKNOWN.value and ev.process_attribution == ProcessAttribution.INFERRED.value:
                    eval_result.process_attribution = ProcessAttribution.INFERRED.value
                    eval_result.process_id = ev.process_id
                    eval_result.process_name = ev.process_name

                # Check if this is a tampering event (delete, move, modify) vs read/access
                is_tampering = ev.event_type in {"FILE_DELETED", "FILE_MOVED", "FILE_MODIFIED"}

                if is_tampering:
                    eval_result.unique_canaries_tampered.add(canary_path)
                    self._history_tampered_canaries.add(canary_path)
                else:
                    eval_result.unique_canaries_accessed.add(canary_path)
                    self._history_accessed_canaries.add(canary_path)

                # Check if security alert should be emitted for this event ID
                if ev.event_id not in self._seen_alert_event_ids:
                    self._seen_alert_event_ids.add(ev.event_id)

                    alert_priority = (
                        EventPriority.CRITICAL.value
                        if is_tampering
                        else EventPriority.HIGH.value
                    )
                    alert_type = (
                        "CANARY_TAMPERING_BREACH"
                        if is_tampering
                        else "CANARY_ACCESS_BREACH"
                    )
                    alert_msg = (
                        f"CRITICAL: Canary decoy file '{canary_path}' was tampered ({ev.event_type}) "
                        f"by source '{ev.source}'."
                        if is_tampering
                        else f"HIGH: Cryptographic canary decoy file '{canary_path}' accessed by '{ev.source}'."
                    )

                    alert = SecurityAlert(
                        alert_id=str(uuid.uuid4()),
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        priority=alert_priority,
                        alert_type=alert_type,
                        message=alert_msg,
                        source_event_id=ev.event_id,
                        target_path=canary_path,
                        process_attribution=ev.process_attribution,
                        process_id=ev.process_id,
                        process_name=ev.process_name,
                        metadata={
                            "is_registered_manifest_canary": is_registered,
                            "operation": ev.operation,
                            "original_event_type": ev.event_type,
                        },
                    )
                    eval_result.alerts_generated.append(alert)
                    self.alerts_emitted += 1

                    # Publish security alert to EventBus
                    try:
                        self.bus.publish(
                            Event(
                                event_type="CANARY_SECURITY_ALERT",
                                data=alert.to_dict(),
                                source="CANARY_ANALYZER",
                            )
                        )
                    except Exception as e:
                        logger.exception(f"Failed to publish canary security alert: {e}")

            # Now compile contributing indicators for the evaluation
            if eval_result.unique_canaries_tampered:
                tampered_list = sorted(eval_result.unique_canaries_tampered)
                eval_result.reasons.append(DetectionReason.CANARY_FILE_TAMPERED.value)
                eval_result.explanations.append(
                    f"Canary file tampering detected on {len(tampered_list)} decoy file(s): "
                    f"{', '.join(tampered_list)}."
                )
                eval_result.indicators.append(
                    ContributingIndicator(
                        indicator_name="CANARY_FILE_TAMPERED",
                        score_contribution=CONFIG.WEIGHT_CANARY_TAMPERING,
                        description="Direct modification, deletion, or renaming of registered canary decoy files.",
                        observed_value=len(tampered_list),
                        threshold=1,
                    )
                )

            if eval_result.unique_canaries_accessed:
                accessed_list = sorted(eval_result.unique_canaries_accessed)
                eval_result.reasons.append(DetectionReason.CANARY_FILE_ACCESS.value)
                eval_result.explanations.append(
                    f"Canary file access detected on {len(accessed_list)} decoy file(s): "
                    f"{', '.join(accessed_list)}."
                )
                # First canary access indicator
                eval_result.indicators.append(
                    ContributingIndicator(
                        indicator_name="FIRST_CANARY_ACCESS",
                        score_contribution=CONFIG.WEIGHT_FIRST_CANARY,
                        description="Initial access to a registered cryptographic canary file.",
                        observed_value=1,
                        threshold=1,
                    )
                )

                # Additional canaries accessed
                extra_canaries = len(accessed_list) - 1
                if extra_canaries > 0:
                    eval_result.reasons.append(DetectionReason.MULTIPLE_CANARIES_ACCESSED.value)
                    extra_score = extra_canaries * CONFIG.WEIGHT_ADDITIONAL_CANARY
                    eval_result.explanations.append(
                        f"Repeated access across {len(accessed_list)} distinct canary files."
                    )
                    eval_result.indicators.append(
                        ContributingIndicator(
                            indicator_name="ADDITIONAL_CANARY_ACCESS",
                            score_contribution=extra_score,
                            description="Subsequent access to multiple distinct canary decoys.",
                            observed_value=extra_canaries,
                            threshold=1,
                        )
                    )

        return eval_result

    def clear(self) -> None:
        """Reset internal history and deduplication caches."""
        with self._lock:
            self._seen_alert_event_ids.clear()
            self._history_accessed_canaries.clear()
            self._history_tampered_canaries.clear()
            self.total_canary_events_analyzed = 0
            self.alerts_emitted = 0

