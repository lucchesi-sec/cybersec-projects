"""
Incident Response Automation Suite

Comprehensive incident response automation platform for threat detection,
analysis, and automated response capabilities.
"""

__version__ = "1.0.0"
__author__ = "Cybersecurity Portfolio"
__description__ = "Incident Response Automation Suite"

from .core.orchestrator import IncidentOrchestrator
from .core.detector import ThreatDetector
from .core.analyzer import IncidentAnalyzer
from .core.responder import AutomatedResponder

__all__ = [
    "IncidentOrchestrator",
    "ThreatDetector", 
    "IncidentAnalyzer",
    "AutomatedResponder"
]