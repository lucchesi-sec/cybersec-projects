#!/usr/bin/env python3
"""
Password Strength Analyzer - Main entry point script

This script provides a simple entry point to the password analyzer.
Run with '--cli' for the interactive interface, or without for a simple analysis.
"""

import sys
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Password Strength Analyzer")
    parser.add_argument("--cli", action="store_true", help="Launch interactive CLI mode")
    args = parser.parse_args()
    
    if args.cli:
        # Import and run the CLI interface
        from src.cli import main
        main()
    else:
        # Import and run the simple analyzer
        from src.password_analyzer import main
        main()