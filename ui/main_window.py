"""
Main Window for triageX — Multi-Platform Forensic Triage
Loads UI from main_window.ui and handles forensic operations
"""

import os
import sys
import webbrowser
from datetime import datetime

from PyQt6.QtWidgets import QMainWindow, QFileDialog, QMessageBox, QApplication
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QRect
from PyQt6.QtGui import QFont, QTextCursor
from PyQt6 import uic

from license_manager import LicenseManager
from .forensic_worker import ForensicWorker
from .license_dialog import LicenseActivationDialog
from core.os_detector import detect_os, is_admin, get_os_info


class ForensicToolGUI(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.license_manager = LicenseManager()
        self.worker = None
        self.report_path = None
        self.license_info = None
        self.current_os = detect_os()
        self.os_info = get_os_info()

        # Check license first
        if not self.check_license():
            self.show_activation_dialog()
        else:
            self.init_ui()

    def check_license(self) -> bool:
        """Check if valid license exists"""
        is_valid, message, license_data = self.license_manager.validate_license()

        if is_valid:
            self.license_info = license_data
            return True
        return False

    def show_activation_dialog(self):
        """Show license activation dialog"""
        dialog = LicenseActivationDialog()
        dialog.show()
        dialog.exec()

        # Re-check license after activation
        if self.check_license():
            self.init_ui()
            self.show()
        else:
            QMessageBox.critical(
                self,
                "License Required",
                "❌ A valid license is required to use this software.\n\nExiting..."
            )
            sys.exit(0)

    def init_ui(self):
        """Initialize main UI"""
        # Load UI from .ui file
        ui_path = os.path.join(os.path.dirname(__file__), 'main_window.ui')
        uic.loadUi(ui_path, self)

        # Load and apply stylesheet
        self.load_stylesheet()

        # Set window properties
        self.setGeometry(100, 100, 900, 700)

        # Set default output directory
        self.outputDirField.setText(os.path.join(os.getcwd(), "forensic_output"))

        # Connect signals
        self.connect_signals()

        # Update license info
        self.update_license_display()

        # Initialize log with welcome message
        self.initialize_log()

    def load_stylesheet(self):
        """Load and apply QSS stylesheet"""
        style_path = os.path.join(os.path.dirname(__file__), '..', 'styles', 'style.qss')
        if os.path.exists(style_path):
            with open(style_path, 'r', encoding='utf-8') as f:
                self.setStyleSheet(f.read())

    def connect_signals(self):
        """Connect all signal handlers"""
        self.browseButton.clicked.connect(self.browse_output_dir)
        self.startButton.clicked.connect(self.start_collection)
        self.reportButton.clicked.connect(self.open_report)
        self.clearLogButton.clicked.connect(self.logViewer.clear)
        self.upgradeButton.clicked.connect(self.show_activation_dialog)

    def update_license_display(self):
        """Update license information in UI"""
        if self.license_info:
            self.licenseTypeLabel.setText(f"Type: {self.license_info['license_type'].upper()}")
            self.deviceIdLabel.setText(f"Device ID: {self.license_info['device_id']}")
            self.deviceIdLabel.setStyleSheet("font-family: 'Consolas', monospace; font-size: 8pt;")

            if self.license_info.get('expiration_date'):
                self.expirationLabel.setText(f"Expires: {self.license_info['expiration_date']}")
                self.expirationLabel.setStyleSheet("color: #FFA726; font-weight: bold;")
            else:
                self.expirationLabel.setText("Expires: Never (Perpetual License)")
                self.expirationLabel.setStyleSheet("color: #66BB6A; font-weight: bold;")

    def initialize_log(self):
        """Initialize activity log with welcome message"""
        self.log_message("=" * 50)
        self.log_message(f"triageX  |  {self.current_os}  |  {self.license_info['license_type'].upper()}")
        self.log_message("=" * 50)

        if is_admin():
            self.log_message("Elevated privileges: YES — full forensic access")
        else:
            self.log_message("Elevated privileges: NO — some features limited")
            if self.current_os == "Windows":
                self.log_message("  Tip: Right-click EXE → Run as Administrator")
            else:
                self.log_message(f"  Tip: sudo python3 {sys.argv[0]}")

        self.log_message("")

    def browse_output_dir(self):
        """Browse for output directory"""
        directory = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if directory:
            self.outputDirField.setText(directory)

    def log_message(self, message: str):
        """Add message to log viewer"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.logViewer.append(f"[{timestamp}] {message}")
        self.logViewer.moveCursor(QTextCursor.MoveOperation.End)

    def start_collection(self):
        """Start forensic collection in background"""
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Already Running", "Forensic collection is already running!")
            return

        # Check admin/root privileges and warn if not elevated
        if not is_admin():
            if self.current_os == "Windows":
                warn_text = (
                    "⚠️  Not running as Administrator!\n\n"
                    "Some features will be limited:\n"
                    "  • MFT (Master File Table) analysis\n"
                    "  • Pagefile.sys analysis\n"
                    "  • Some registry keys\n"
                    "  • Low-level disk access\n\n"
                    "For complete forensic data collection:\n"
                    "  → Close this application\n"
                    "  → Right-click the EXE\n"
                    "  → Select 'Run as Administrator'\n\n"
                    "Continue with limited access?"
                )
            else:
                warn_text = (
                    f"⚠️  Not running as root ({self.current_os})!\n\n"
                    "Some features will be limited:\n"
                    "  • System log access\n"
                    "  • Full process listing\n"
                    "  • Network connection details\n"
                    "  • USB device history\n\n"
                    f"For complete forensic data:\n"
                    f"  → Re-run with: sudo python3 {sys.argv[0]}\n\n"
                    "Continue with limited access?"
                )

            result = QMessageBox.warning(
                self,
                "Elevated Privileges Required",
                warn_text,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )

            if result == QMessageBox.StandardButton.No:
                return

        output_dir = self.outputDirField.text()

        # Disable start button with animation
        self.animate_button_disable(self.startButton)
        self.reportButton.setEnabled(False)
        self.progressBar.setValue(0)

        # Create worker thread
        self.worker = ForensicWorker(output_dir)
        self.worker.progress.connect(self.update_progress)
        self.worker.log_message.connect(self.log_message)
        self.worker.finished.connect(self.collection_finished)
        self.worker.error.connect(self.collection_error)

        # Start collection
        self.worker.start()

    def animate_button_disable(self, button):
        """Animate button when disabling"""
        button.setEnabled(False)

    def update_progress(self, value: int):
        """Update progress bar with smooth animation"""
        self.progressBar.setValue(value)

    def collection_finished(self, report_path: str):
        """Handle collection completion"""
        self.report_path = report_path
        self.progressLabel.setText("✅ Forensic collection complete!")
        self.progressLabel.setStyleSheet("color: #66BB6A; font-weight: bold; font-size: 11pt;")

        self.startButton.setEnabled(True)
        self.reportButton.setEnabled(True)

        QMessageBox.information(
            self,
            "Collection Complete",
            f"✅ Forensic collection completed successfully!\n\n"
            f"Report saved to:\n{report_path}\n\n"
            f"Click 'Open Forensic Report' to view results."
        )

    def collection_error(self, error_msg: str):
        """Handle collection error"""
        self.log_message(error_msg)
        self.progressLabel.setText("❌ Collection failed!")
        self.progressLabel.setStyleSheet("color: #ef5350; font-weight: bold; font-size: 11pt;")

        self.startButton.setEnabled(True)

        QMessageBox.critical(self, "Error", f"Forensic collection failed:\n\n{error_msg}")

    def open_report(self):
        """Open forensic report in browser"""
        if self.report_path and os.path.exists(self.report_path):
            webbrowser.open(f"file://{os.path.abspath(self.report_path)}")
            self.log_message(f"📄 Opened report: {self.report_path}")
        else:
            QMessageBox.warning(self, "No Report", "No report found. Run forensic collection first!")
