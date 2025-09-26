"""
Terminal User Interface (TUI) for Cerberus Password Manager.

This module provides a rich, interactive terminal interface for managing passwords.
"""

__all__ = ["main"]

def main():
    """Launch the Cerberus TUI."""
    from .app import CerberusTUI
    app = CerberusTUI()
    app.run()

if __name__ == "__main__":
    main()
