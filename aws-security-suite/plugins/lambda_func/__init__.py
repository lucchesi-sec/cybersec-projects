"""
Lambda Security Scanner Plugin Package
Provides comprehensive security analysis for AWS Lambda functions.
Supports both original monolithic and new modular architecture.
"""

# Import the scanner module (for backward compatibility)
try:
    # Try to import refactored version first if USE_REFACTORED_SCANNER is set
    import os
    if os.environ.get('USE_REFACTORED_SCANNER', '').lower() == 'true':
        from .scanner_refactored import scan_lambda, register
        __scanner_type__ = 'refactored'
    else:
        from .scanner import scan_lambda, register
        __scanner_type__ = 'original'
except ImportError as e:
    # Fall back to original
    from .scanner import scan_lambda, register
    __scanner_type__ = 'original'

# Export main functions
__all__ = ['scan_lambda', 'register']

# Package metadata
__version__ = '2.0.0'
__author__ = 'AWS Security Suite Team'
__description__ = f'Lambda Security Scanner - Using {__scanner_type__} implementation'