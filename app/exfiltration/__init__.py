"""
Data Exfiltration Monitoring Subsystem for CryptoShield (Phase 7).

Outbound staging detection, mass file read bursts, honeypot canary breaches,
local loopback mock socket transfer monitoring, and incident correlation.
"""

from app.exfiltration.exfiltration_coordinator import (
    EXFILTRATION_COORDINATOR,
    ExfiltrationCoordinator,
)
from app.exfiltration.exfiltration_correlator import ExfiltrationCorrelator
from app.exfiltration.mock_receiver import MockReceiver
from app.exfiltration.models import (
    ExfiltrationAssessment,
    ExfiltrationRiskTier,
    OutboundTransferRecord,
    ReadBurstEvent,
    StagingEvent,
    StagingType,
    TransferProtocol,
    TransferStatus,
)
from app.exfiltration.read_burst_detector import ReadBurstDetector
from app.exfiltration.staging_detector import StagingDetector
from app.exfiltration.transfer_monitor import TransferMonitor

__all__ = [
    "EXFILTRATION_COORDINATOR",
    "ExfiltrationCoordinator",
    "ExfiltrationCorrelator",
    "MockReceiver",
    "ReadBurstDetector",
    "StagingDetector",
    "TransferMonitor",
    "ExfiltrationAssessment",
    "ExfiltrationRiskTier",
    "OutboundTransferRecord",
    "ReadBurstEvent",
    "StagingEvent",
    "StagingType",
    "TransferProtocol",
    "TransferStatus",
]
