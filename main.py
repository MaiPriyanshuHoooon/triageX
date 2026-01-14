"""
Main Entry Point for Windows Forensic Triage Tool
PyQt6 version with modern UI
"""

import sys
from PyQt6.QtWidgets import QApplication
from ui import ForensicToolGUI


def main():
    """Main entry point"""
    app = QApplication(sys.argv)

    # Set application style
    app.setStyle("Fusion")

    # Create and show main window
    window = ForensicToolGUI()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
