"""
Forensic Tool GUI Launcher
===========================
Professional GUI interface for Windows Forensics Tool

Features:
- License activation
- Progress tracking
- Log viewer
- Report launcher
- Device ID display

Author: Forensics Tool Team
"""

import sys
import os
import threading
import webbrowser
import ctypes
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QLineEdit, QFileDialog,
    QProgressBar, QMessageBox, QTabWidget, QGroupBox, QFrame, QDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon, QTextCursor

from license_manager import LicenseManager
from forensics_tool import ForensicCollector


def is_admin():
    """Check if the application is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


class ForensicWorker(QThread):
    """Background thread for running forensic collection"""

    progress = pyqtSignal(int)
    log_message = pyqtSignal(str)
    finished = pyqtSignal(str)  # Report path
    error = pyqtSignal(str)

    def __init__(self, output_dir):
        super().__init__()
        self.output_dir = output_dir

    def run(self):
        """Run forensic collection in background"""
        try:
            self.log_message.emit("🔍 Starting forensic triage collection...")
            self.progress.emit(10)

            # Initialize collector
            collector = ForensicCollector(output_dir=self.output_dir)
            self.log_message.emit("✅ Forensic collector initialized")
            self.progress.emit(20)

            # Execute commands
            self.log_message.emit("📋 Executing Windows forensic commands...")
            self.progress.emit(30)
            self.log_message.emit("   → Collecting system information...")
            self.progress.emit(35)
            self.log_message.emit("   → Gathering network configuration...")
            self.progress.emit(40)
            self.log_message.emit("   → Enumerating running processes...")
            self.progress.emit(45)

            results = collector.execute_all_commands()
            self.log_message.emit(f"✅ Collected {len(results)} command results")
            self.progress.emit(50)

            # Analyze IOCs
            self.log_message.emit("🔎 Scanning for Indicators of Compromise (IOCs)...")
            self.progress.emit(55)
            self.log_message.emit("   → Checking for known malware signatures...")
            self.progress.emit(58)

            ioc_results = collector.scan_iocs()
            self.log_message.emit(f"✅ IOC scan complete: {len(ioc_results)} items analyzed")
            self.progress.emit(60)

            # Analyze browser history
            self.log_message.emit("🌐 Analyzing browser history...")
            self.progress.emit(65)
            self.log_message.emit("   → Scanning Chrome, Firefox, Edge databases...")
            self.progress.emit(68)

            browser_results = collector.analyze_browser_history()
            self.log_message.emit(f"✅ Browser analysis complete: {len(browser_results)} entries found")
            self.progress.emit(70)

            # Hash analysis
            self.log_message.emit("🔐 Performing hash analysis on suspicious files...")
            self.progress.emit(72)
            self.log_message.emit("   → Computing file hashes (MD5, SHA1, SHA256)...")
            self.progress.emit(75)

            # Scan event logs
            self.log_message.emit("📊 Scanning Windows Event Logs...")
            self.progress.emit(78)

            eventlog_results = collector.analyze_event_logs()
            self.log_message.emit(f"✅ Event log analysis complete: {len(eventlog_results)} events analyzed")
            self.progress.emit(82)

            # Scan for PII (Personally Identifiable Information)
            self.log_message.emit("🔍 Scanning for PII in user directories...")
            self.progress.emit(84)
            self.log_message.emit("   → Scanning Downloads, Desktop, Documents folders...")
            self.progress.emit(85)

            # Scan for encrypted files
            self.log_message.emit("🔐 Detecting encrypted files across drives...")
            self.progress.emit(86)
            self.log_message.emit("   → Scanning user directories for encrypted content...")
            self.progress.emit(87)

            # Registry analysis
            self.log_message.emit("📝 Analyzing Windows Registry...")
            self.progress.emit(88)
            self.log_message.emit("   → Extracting startup programs, installed software, USB history...")
            self.progress.emit(89)

            # MFT analysis
            self.log_message.emit("💾 Analyzing Master File Table (MFT)...")
            self.progress.emit(90)
            self.log_message.emit("   → Scanning all volumes for file system metadata...")
            self.progress.emit(91)

            # Pagefile analysis
            self.log_message.emit("📄 Analyzing pagefile and memory artifacts...")
            self.progress.emit(92)
            self.log_message.emit("   → Extracting data from pagefile.sys...")
            self.progress.emit(93)

            # Generate report
            self.log_message.emit("📊 Preparing HTML forensic report...")
            self.progress.emit(95)
            self.log_message.emit("   → Compiling all collected data...")
            self.progress.emit(96)

            report_path = collector.generate_html_report(
                results, ioc_results, browser_results, eventlog_results
            )

            self.log_message.emit("   → Generating HTML tables and charts...")
            self.progress.emit(97)
            self.log_message.emit("   → Finalizing report structure...")
            self.progress.emit(98)
            self.log_message.emit(f"✅ Report generated: {report_path}")
            self.progress.emit(100)

            self.finished.emit(report_path)

        except Exception as e:
            self.error.emit(f"❌ Error: {str(e)}")


class LicenseActivationDialog(QDialog):
    """License activation window"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.license_manager = LicenseManager()
        self.init_ui()

    def init_ui(self):
        """Initialize license activation UI"""
        self.setWindowTitle("Activate License - Forensic Tool")
        self.setFixedSize(600, 400)

        layout = QVBoxLayout()

        # Title
        title = QLabel("🔐 License Activation")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Device ID section
        device_group = QGroupBox("Your Device ID")
        device_layout = QVBoxLayout()

        info_label = QLabel("📧 Send this Device ID to get your license key:")
        device_layout.addWidget(info_label)

        self.device_id_field = QLineEdit()
        device_id = self.license_manager.get_device_id()
        self.device_id_field.setText(device_id)
        self.device_id_field.setReadOnly(True)
        self.device_id_field.setStyleSheet("background-color: #f0f0f0; font-family: monospace;")
        device_layout.addWidget(self.device_id_field)

        copy_btn = QPushButton("📋 Copy to Clipboard")
        copy_btn.clicked.connect(self.copy_device_id)
        device_layout.addWidget(copy_btn)

        device_group.setLayout(device_layout)
        layout.addWidget(device_group)

        # License key section
        license_group = QGroupBox("Enter License Key")
        license_layout = QVBoxLayout()

        key_label = QLabel("🔑 Paste your license key below:")
        license_layout.addWidget(key_label)

        self.license_key_field = QTextEdit()
        self.license_key_field.setMaximumHeight(80)
        self.license_key_field.setPlaceholderText("Paste license key here...")
        license_layout.addWidget(self.license_key_field)

        activate_btn = QPushButton("✅ Activate License")
        activate_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; padding: 8px;")
        activate_btn.clicked.connect(self.activate_license)
        license_layout.addWidget(activate_btn)

        license_group.setLayout(license_layout)
        layout.addWidget(license_group)

        # Status
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        # Trial button
        trial_btn = QPushButton("🕐 Start 7-Day Trial")
        trial_btn.clicked.connect(self.start_trial)
        layout.addWidget(trial_btn)

        self.setLayout(layout)

    def copy_device_id(self):
        """Copy device ID to clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.device_id_field.text())
        self.status_label.setText("✅ Device ID copied to clipboard!")
        self.status_label.setStyleSheet("color: green;")

    def activate_license(self):
        """Activate license with provided key"""
        license_key = self.license_key_field.toPlainText().strip()

        if not license_key:
            QMessageBox.warning(self, "Invalid Input", "Please enter a license key!")
            return

        # Save license key to file
        try:
            with open(self.license_manager.license_file, 'w') as f:
                f.write(license_key)

            # Validate license
            is_valid, message, license_data = self.license_manager.validate_license()

            if is_valid:
                QMessageBox.information(
                    self,
                    "License Activated",
                    f"✅ License activated successfully!\n\n"
                    f"Type: {license_data['license_type'].upper()}\n"
                    f"Device: {license_data['device_id'][:20]}...\n"
                    f"Expires: {license_data.get('expiry_date', 'Never')}"
                )
                self.accept()  # Close dialog with success
            else:
                QMessageBox.critical(
                    self,
                    "Activation Failed",
                    f"❌ License activation failed!\n\n{message}"
                )

        except Exception as e:
            QMessageBox.critical(self, "Error", f"❌ Error: {str(e)}")

    def start_trial(self):
        """Start 7-day trial"""
        try:
            # Generate trial license for current device
            encrypted_license = self.license_manager.generate_trial_license(days=7)

            # Save to file
            with open(self.license_manager.license_file, 'w') as f:
                f.write(encrypted_license)

            QMessageBox.information(
                self,
                "Trial Started",
                "✅ 7-day trial activated!\n\nYou can now use all features for 7 days."
            )
            self.accept()  # Close dialog with success

        except Exception as e:
            QMessageBox.critical(self, "Error", f"❌ Error starting trial: {str(e)}")


class ForensicToolGUI(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.license_manager = LicenseManager()
        self.worker = None
        self.report_path = None

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
        dialog.exec_()

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
        self.setWindowTitle("Windows Forensic Triage Tool - Professional Edition")
        self.setGeometry(100, 100, 900, 700)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()

        # Header
        header = self.create_header()
        layout.addWidget(header)

        # Tabs
        tabs = QTabWidget()

        # Main tab
        main_tab = self.create_main_tab()
        tabs.addTab(main_tab, "🔍 Forensic Scan")

        # Log tab
        log_tab = self.create_log_tab()
        tabs.addTab(log_tab, "📋 Activity Log")

        # License tab
        license_tab = self.create_license_tab()
        tabs.addTab(license_tab, "🔐 License Info")

        layout.addWidget(tabs)

        central_widget.setLayout(layout)

    def create_header(self) -> QWidget:
        """Create header section"""
        header = QFrame()
        header.setFrameShape(QFrame.StyledPanel)
        header.setStyleSheet("background-color: #2196F3; color: white; padding: 10px;")

        layout = QVBoxLayout()

        title = QLabel("🛡️ Windows Forensic Triage Tool")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        layout.addWidget(title)

        subtitle = QLabel("Professional Edition - Automated Incident Response")
        subtitle.setFont(QFont("Arial", 10))
        layout.addWidget(subtitle)

        header.setLayout(layout)
        return header

    def create_main_tab(self) -> QWidget:
        """Create main forensic scan tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Output directory
        dir_group = QGroupBox("Output Directory")
        dir_layout = QHBoxLayout()

        self.output_dir_field = QLineEdit()
        self.output_dir_field.setText(os.path.join(os.getcwd(), "forensic_output"))
        dir_layout.addWidget(self.output_dir_field)

        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(self.browse_output_dir)
        dir_layout.addWidget(browse_btn)

        dir_group.setLayout(dir_layout)
        layout.addWidget(dir_group)

        # Start button
        self.start_btn = QPushButton("🚀 Start Forensic Collection")
        self.start_btn.setStyleSheet(
            "background-color: #4CAF50; color: white; font-size: 14px; "
            "font-weight: bold; padding: 12px;"
        )
        self.start_btn.clicked.connect(self.start_collection)
        layout.addWidget(self.start_btn)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        self.progress_label = QLabel("Ready to start forensic collection")
        self.progress_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.progress_label)

        # Open report button
        self.report_btn = QPushButton("📄 Open Forensic Report")
        self.report_btn.setEnabled(False)
        self.report_btn.clicked.connect(self.open_report)
        layout.addWidget(self.report_btn)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def create_log_tab(self) -> QWidget:
        """Create activity log tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        self.log_viewer = QTextEdit()
        self.log_viewer.setReadOnly(True)
        self.log_viewer.setStyleSheet("background-color: #1E1E1E; color: #00FF00; font-family: monospace;")

        # Add welcome message
        self.log_message("=" * 60)
        self.log_message("🛡️  Windows Forensic Triage Tool - Professional Edition")
        self.log_message("=" * 60)
        self.log_message(f"License Type: {self.license_info['license_type'].upper()}")
        self.log_message(f"Device ID: {self.license_info['device_id'][:30]}...")
        if self.license_info.get('expiration_date'):
            self.log_message(f"Expires: {self.license_info['expiration_date']}")
        self.log_message("=" * 60)
        
        # Check admin privileges
        if is_admin():
            self.log_message("✅ Running with Administrator privileges")
            self.log_message("   → Full forensic access enabled (MFT, Pagefile, Registry)")
        else:
            self.log_message("⚠️  NOT running as Administrator")
            self.log_message("   → Some features may be limited (MFT, Pagefile analysis)")
            self.log_message("   → Right-click and 'Run as Administrator' for full access")
        
        self.log_message("")

        layout.addWidget(self.log_viewer)

        clear_btn = QPushButton("🗑️ Clear Log")
        clear_btn.clicked.connect(self.log_viewer.clear)
        layout.addWidget(clear_btn)

        widget.setLayout(layout)
        return widget

    def create_license_tab(self) -> QWidget:
        """Create license info tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        info_group = QGroupBox("License Information")
        info_layout = QVBoxLayout()

        # License details
        license_type = QLabel(f"Type: {self.license_info['license_type'].upper()}")
        license_type.setFont(QFont("Arial", 12))
        info_layout.addWidget(license_type)

        device_id = QLabel(f"Device ID: {self.license_info['device_id']}")
        device_id.setStyleSheet("font-family: monospace;")
        info_layout.addWidget(device_id)

        if self.license_info.get('expiration_date'):
            expiration = QLabel(f"Expires: {self.license_info['expiration_date']}")
            expiration.setStyleSheet("color: orange;")
            info_layout.addWidget(expiration)
        else:
            perpetual = QLabel("Expires: Never (Perpetual License)")
            perpetual.setStyleSheet("color: green;")
            info_layout.addWidget(perpetual)

        info_group.setLayout(info_layout)
        layout.addWidget(info_group)

        # Upgrade button
        upgrade_btn = QPushButton("⬆️ Upgrade License")
        upgrade_btn.clicked.connect(self.show_activation_dialog)
        layout.addWidget(upgrade_btn)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def browse_output_dir(self):
        """Browse for output directory"""
        directory = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if directory:
            self.output_dir_field.setText(directory)

    def log_message(self, message: str):
        """Add message to log viewer"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_viewer.append(f"[{timestamp}] {message}")
        self.log_viewer.moveCursor(QTextCursor.End)

    def start_collection(self):
        """Start forensic collection in background"""
        if self.worker and self.worker.isRunning():
            QMessageBox.warning(self, "Already Running", "Forensic collection is already running!")
            return

        # Check admin privileges and warn if not admin
        if not is_admin():
            result = QMessageBox.warning(
                self,
                "Administrator Privileges Required",
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
                "Continue with limited access?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if result == QMessageBox.No:
                return

        output_dir = self.output_dir_field.text()

        # Disable start button
        self.start_btn.setEnabled(False)
        self.report_btn.setEnabled(False)
        self.progress_bar.setValue(0)

        # Create worker thread
        self.worker = ForensicWorker(output_dir)
        self.worker.progress.connect(self.update_progress)
        self.worker.log_message.connect(self.log_message)
        self.worker.finished.connect(self.collection_finished)
        self.worker.error.connect(self.collection_error)

        # Start collection
        self.worker.start()

    def update_progress(self, value: int):
        """Update progress bar"""
        self.progress_bar.setValue(value)

    def collection_finished(self, report_path: str):
        """Handle collection completion"""
        self.report_path = report_path
        self.progress_label.setText("✅ Forensic collection complete!")
        self.progress_label.setStyleSheet("color: green; font-weight: bold;")

        self.start_btn.setEnabled(True)
        self.report_btn.setEnabled(True)

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
        self.progress_label.setText("❌ Collection failed!")
        self.progress_label.setStyleSheet("color: red; font-weight: bold;")

        self.start_btn.setEnabled(True)

        QMessageBox.critical(self, "Error", f"Forensic collection failed:\n\n{error_msg}")

    def open_report(self):
        """Open forensic report in browser"""
        if self.report_path and os.path.exists(self.report_path):
            webbrowser.open(f"file://{os.path.abspath(self.report_path)}")
            self.log_message(f"📄 Opened report: {self.report_path}")
        else:
            QMessageBox.warning(self, "No Report", "No report found. Run forensic collection first!")


def main():
    """Main entry point"""
    app = QApplication(sys.argv)

    # Set application style
    app.setStyle("Fusion")

    # Create and show main window
    window = ForensicToolGUI()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
