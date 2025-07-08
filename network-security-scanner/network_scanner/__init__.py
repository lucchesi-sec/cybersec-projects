"""
Network Security Scanner

A comprehensive network security scanning tool for vulnerability assessment,
port scanning, and security configuration analysis.
"""

__version__ = "1.0.0"
__author__ = "Cybersecurity Portfolio"
__description__ = "Network Security Scanner for vulnerability assessment"

from .core.scanner import NetworkScanner
from .core.config import ScannerConfig

__all__ = ["NetworkScanner", "ScannerConfig"]