"""
Main Window for triageX — Multi-Platform Forensic Triage
Loads UI from main_window.ui and handles forensic operations
"""

import os
import sys
import webbrowser
from datetime import datetime

from PyQt6.QtWidgets import QMainWindow, QFileDialog, QMessageBox, QApplication, QTableWidgetItem
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QRect
from PyQt6.QtGui import QFont, QTextCursor
from PyQt6 import uic

from license_manager import LicenseManager
from .forensic_worker import ForensicWorker
from .license_dialog import LicenseActivationDialog
from core.os_detector import detect_os, is_admin, get_os_info
from core import write_blocker


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
        self.device_monitor = None

        # Check license first
        if not self.check_license():
            self.show_activation_dialog()
        else:
            self.init_ui()

        # Device monitoring for macOS (auto-refresh disks on attach)
        if self.current_os == "Darwin":
            try:
                from core.device_monitor import DeviceMonitor
                self.device_monitor = DeviceMonitor(self.on_device_attached)
                self.device_monitor.start()
            except Exception as e:
                print(f"Device monitoring not available: {e}")

    def on_device_attached(self, info):
        # Called when a device is attached (macOS only for now)
        self.log_message("[Device Monitor] Device attached: {}".format(info))
        self.wb_refresh_disks()

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

        # Write Blocker signals (Windows only)
        if self.current_os == "Windows":
            self.wbEnableButton.clicked.connect(self.wb_enable)
            self.wbDisableButton.clicked.connect(self.wb_disable)
            self.wbRefreshStatusButton.clicked.connect(self.wb_refresh_status)
            self.wbBlockDiskButton.clicked.connect(self.wb_block_disk)
            self.wbUnblockDiskButton.clicked.connect(self.wb_unblock_disk)
            self.wbRefreshDisksButton.clicked.connect(self.wb_refresh_disks)
            self.wb_refresh_status()
            self.wb_refresh_disks()
        else:
            self._wb_set_windows_only_mode()

    def update_license_display(self):
        """Update license information in UI"""
        if self.license_info:
            self.licenseTypeLabel.setText(f"Type: {self.license_info['license_type'].upper()}")
            self.deviceIdLabel.setText(f"Device ID: {self.license_info['device_id']}")
            self.deviceIdLabel.setStyleSheet("font-family: 'Consolas', monospace; font-size: 8pt;")

            if self.license_info.get('expiry_date'):
                self.expirationLabel.setText(f"Expires: {self.license_info['expiry_date']}")
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
                    "Not running as Administrator!\n\n"
                    "Some features will be limited:\n"
                    "  - MFT (Master File Table) analysis\n"
                    "  - Pagefile.sys analysis\n"
                    "  - Some registry keys\n"
                    "  - Low-level disk access\n\n"
                    "For complete forensic data collection:\n"
                    "  Close this application, right-click the EXE,\n"
                    "  and select 'Run as Administrator'.\n\n"
                    "Continue with limited access?"
                )
            else:
                warn_text = (
                    f"Not running as root ({self.current_os})!\n\n"
                    "Some features will be limited:\n"
                    "  - System log access\n"
                    "  - Full process listing\n"
                    "  - Network connection details\n"
                    "  - USB device history\n\n"
                    f"For complete forensic data, re-run with:\n"
                    f"  sudo python3 {sys.argv[0]}\n\n"
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
        """Update progress bar with smooth animation and label update"""
        self.progressBar.setValue(value)
        self.progressLabel.setText(f"Progress: {value}%")
        QApplication.processEvents()

    def collection_finished(self, report_path: str):
        """Handle collection completion"""
        self.report_path = report_path
        self.progressLabel.setText("Forensic collection complete!")
        self.progressLabel.setStyleSheet("color: #66BB6A; font-weight: bold; font-size: 11pt;")

        self.startButton.setEnabled(True)
        self.reportButton.setEnabled(True)

        QMessageBox.information(
            self,
            "Collection Complete",
            f"Forensic collection completed successfully!\n\n"
            f"Report saved to:\n{report_path}\n\n"
            f"Click 'Open Forensic Report' to view results."
        )

    def collection_error(self, error_msg: str):
        """Handle collection error"""
        self.log_message(error_msg)
        self.progressLabel.setText("Collection failed!")
        self.progressLabel.setStyleSheet("color: #ef5350; font-weight: bold; font-size: 11pt;")

        self.startButton.setEnabled(True)

        QMessageBox.critical(self, "Error", f"Forensic collection failed:\n\n{error_msg}")

    def open_report(self):
        """Open forensic report in browser"""
        if self.report_path and os.path.exists(self.report_path):
            webbrowser.open(f"file://{os.path.abspath(self.report_path)}")
            self.log_message(f"[Report] Opened: {self.report_path}")
        else:
            QMessageBox.warning(self, "No Report", "No report found. Run forensic collection first!")

    # ── Write Blocker ─────────────────────────────────────────────────────────

    def _wb_set_windows_only_mode(self):
        """Disable all write blocker controls when not on Windows."""
        for btn in (self.wbEnableButton, self.wbDisableButton, self.wbRefreshStatusButton,
                    self.wbBlockDiskButton, self.wbUnblockDiskButton, self.wbRefreshDisksButton):
            btn.setEnabled(False)
        self.wbStatusLabel.setText("Write Blocker is only available on Windows")
        self.wbStatusLabel.setStyleSheet("color: #FFA726; font-weight: bold;")
        self.wbLogLabel.setText(
            "Write Blocker requires a Windows system. "
            "This tab is shown for reference only on non-Windows platforms."
        )

    def wb_refresh_status(self):
        """Refresh the global write-protect registry status."""
        status = write_blocker.get_write_protect_status()
        if status["error"]:
            self.wbStatusLabel.setText(f"Warning: {status['error']}")
            self.wbStatusLabel.setStyleSheet("color: #FFA726; font-weight: bold; font-size: 11pt;")
        elif status["enabled"]:
            self.wbStatusLabel.setText("Write Protection: ENABLED  —  all USB storage is blocked from writing")
            self.wbStatusLabel.setStyleSheet("color: #ef5350; font-weight: bold; font-size: 11pt;")
        else:
            self.wbStatusLabel.setText("Write Protection: DISABLED  —  USB storage is writable")
            self.wbStatusLabel.setStyleSheet("color: #66BB6A; font-weight: bold; font-size: 11pt;")
        self.log_message(f"[Write Blocker] Registry status refreshed — enabled={status['enabled']}")

    def wb_enable(self):
        """Enable global USB write protection via registry."""
        result = write_blocker.set_write_protect(True)
        if result["success"]:
            QMessageBox.information(self, "Write Blocker", result['message'])
            self.log_message("[Write Blocker] Global write protection ENABLED via registry")
        else:
            QMessageBox.critical(self, "Write Blocker Error", result['message'])
            self.log_message(f"[Write Blocker] Error enabling: {result['message']}")
        self.wb_refresh_status()

    def wb_disable(self):
        """Disable global USB write protection via registry."""
        confirm = QMessageBox.question(
            self, "Confirm",
            "Are you sure you want to DISABLE USB Write Protection?\n\n"
            "This will allow connected USB devices to be written to.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        result = write_blocker.set_write_protect(False)
        if result["success"]:
            QMessageBox.information(self, "Write Blocker", result['message'])
            self.log_message("[Write Blocker] Global write protection DISABLED via registry")
        else:
            QMessageBox.critical(self, "Write Blocker Error", result['message'])
            self.log_message(f"[Write Blocker] Error disabling: {result['message']}")
        self.wb_refresh_status()

    def wb_refresh_disks(self):
        """Refresh both USB disk table and PnP device table."""
        # ── Disk table ──────────────────────────────────────────────────
        disks = write_blocker.get_usb_disks()
        self.wbDiskTable.setRowCount(len(disks))
        for row, disk in enumerate(disks):
            self.wbDiskTable.setItem(row, 0, QTableWidgetItem(str(disk["number"])))
            self.wbDiskTable.setItem(row, 1, QTableWidgetItem(disk["name"]))
            self.wbDiskTable.setItem(row, 2, QTableWidgetItem(disk["bus"]))
            self.wbDiskTable.setItem(row, 3, QTableWidgetItem(str(disk["size_gb"])))
            blocked_text = "YES" if disk["is_readonly"] else "NO"
            item = QTableWidgetItem(blocked_text)
            item.setForeground(
                __import__("PyQt6.QtGui", fromlist=["QColor"]).QColor(
                    "#ef5350" if disk["is_readonly"] else "#66BB6A"
                )
            )
            self.wbDiskTable.setItem(row, 4, item)
        self.wbDiskTable.resizeColumnsToContents()
        self.log_message(f"[Write Blocker] Found {len(disks)} USB disk(s)")

        # ── PnP device table ────────────────────────────────────────────
        devices = write_blocker.get_usb_pnp_devices()
        self.wbPnpTable.setRowCount(len(devices))
        for row, dev in enumerate(devices):
            self.wbPnpTable.setItem(row, 0, QTableWidgetItem(dev["name"]))
            self.wbPnpTable.setItem(row, 1, QTableWidgetItem(dev["instance_id"]))
            self.wbPnpTable.setItem(row, 2, QTableWidgetItem(dev["status"]))
        self.wbPnpTable.resizeColumnsToContents()
        self.log_message(f"[Write Blocker] Found {len(devices)} USB PnP mass storage device(s)")

    def _wb_selected_disk_number(self) -> int | None:
        """Return disk number of the selected row in the disk table, or None."""
        selected = self.wbDiskTable.selectedItems()
        if not selected:
            QMessageBox.warning(self, "No Selection", "Please select a disk from the table first.")
            return None
        row = self.wbDiskTable.currentRow()
        try:
            return int(self.wbDiskTable.item(row, 0).text())
        except (ValueError, AttributeError):
            return None

    def wb_block_disk(self):
        """Write-block the selected USB disk (Set-Disk -IsReadOnly $true)."""
        disk_num = self._wb_selected_disk_number()
        if disk_num is None:
            return
        result = write_blocker.set_disk_readonly(disk_num, True)
        if result["success"]:
            QMessageBox.information(self, "Write Blocker", result['message'])
            self.log_message(f"[Write Blocker] Disk {disk_num} BLOCKED (read-only)")
        else:
            QMessageBox.critical(self, "Write Blocker Error", result['message'])
            self.log_message(f"[Write Blocker] Error blocking disk {disk_num}: {result['message']}")
        self.wb_refresh_disks()

    def wb_unblock_disk(self):
        """Remove write-block from the selected USB disk (Set-Disk -IsReadOnly $false)."""
        disk_num = self._wb_selected_disk_number()
        if disk_num is None:
            return
        confirm = QMessageBox.question(
            self, "Confirm Unblock",
            f"Remove write block from Disk {disk_num}?\n\nThis will allow writes to the device.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        result = write_blocker.set_disk_readonly(disk_num, False)
        if result["success"]:
            QMessageBox.information(self, "Write Blocker", result['message'])
            self.log_message(f"[Write Blocker] Disk {disk_num} UNBLOCKED (read-write)")
        else:
            QMessageBox.critical(self, "Write Blocker Error", result['message'])
            self.log_message(f"[Write Blocker] Error unblocking disk {disk_num}: {result['message']}")
        self.wb_refresh_disks()
