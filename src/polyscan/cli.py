#!/usr/bin/env python3
"""
PolyScan CLI Entry Point
-----------------------
Command-line interface for PolyScan image polyglot scanner.
"""

from .core import main

def cli_main():
    """Entry point for the CLI application"""
    return main()

# For backwards compatibility and direct script execution
if __name__ == "__main__":
    cli_main()