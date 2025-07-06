"""
Lambda Security Scanner Plugin
Comprehensive security analysis for AWS Lambda functions and related resources.
"""

from .scanner import register

__all__ = ['register']