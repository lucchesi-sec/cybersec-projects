"""
RDS Security Scanner Plugin for AWS Security Suite.
Comprehensive security analysis for Amazon RDS instances and related resources.
"""

from .scanner import register

__all__ = ['register']