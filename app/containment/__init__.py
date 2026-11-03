"""
Containment Engine for CryptoShield (Phase 4).

Threat Containment and Controlled Process Isolation Framework.
Safely isolates and terminates explicitly registered controlled simulation processes,
enforces application-level write-gate blocking, and maintains complete audit dossiers.
"""

from app.containment.containment_coordinator import ContainmentCoordinator
from app.containment.containment_manager import ContainmentManager
from app.containment.containment_policy import ContainmentPolicy
from app.containment.containment_verifier import ContainmentVerificationResult, ContainmentVerifier
from app.containment.lab_write_gate import LabWriteGate
from app.containment.process_controller import ControlledProcessController, ShutdownOutcome
from app.containment.process_registry import ControlledProcessRegistry

__all__ = [
    "ContainmentCoordinator",
    "ContainmentManager",
    "ContainmentPolicy",
    "ContainmentVerifier",
    "ContainmentVerificationResult",
    "ControlledProcessController",
    "ControlledProcessRegistry",
    "LabWriteGate",
    "ShutdownOutcome",
]
