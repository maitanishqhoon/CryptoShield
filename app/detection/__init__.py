"""
Detection Engine for CryptoShield (Phase 3).

Rule-based behavioral threat scoring, sliding windows, canary alerts,
and security incident lifecycle management.
"""

from app.detection.behavior_analyzer import BehaviorAnalyzer, BehaviorEvaluation
from app.detection.canary_analyzer import CanaryAnalyzer, CanaryEvaluation
from app.detection.detection_coordinator import DetectionCoordinator
from app.detection.event_correlator import EventCorrelator, WindowActivitySummary
from app.detection.incident_manager import IncidentManager
from app.detection.threat_scorer import ThreatScorer

__all__ = [
    "BehaviorAnalyzer",
    "BehaviorEvaluation",
    "CanaryAnalyzer",
    "CanaryEvaluation",
    "DetectionCoordinator",
    "EventCorrelator",
    "WindowActivitySummary",
    "IncidentManager",
    "ThreatScorer",
]
