"""
License Activation Dialog
Loads UI from license_dialog.ui and handles license activation logic
"""

import os
from PyQt6.QtWidgets import QDialog, QApplication, QMessageBox
from PyQt6.QtCore import Qt
from PyQt6 import uic

from license_manager import LicenseManager


class LicenseActivationDialog(QDialog):
    """License activation window"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.license_manager = LicenseManager()
        self.init_ui()

    def init_ui(self):
        """Initialize license activation UI"""
        # Load UI from .ui file
        ui_path = os.path.join(os.path.dirname(__file__), 'license_dialog.ui')
        uic.loadUi(ui_path, self)

        # Set fixed size
        self.setFixedSize(600, 450)

        # Populate device ID
        device_id = self.license_manager.get_device_id()
        self.deviceIdField.setText(device_id)

        # Connect signals
        self.copyButton.clicked.connect(self.copy_device_id)
        self.activateButton.clicked.connect(self.activate_license)
        self.trialButton.clicked.connect(self.start_trial)

    def copy_device_id(self):
        """Copy device ID to clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.deviceIdField.text())
        self.statusLabel.setText("Device ID copied to clipboard!")
        self.statusLabel.setStyleSheet("color: #66BB6A; font-weight: bold;")

    def activate_license(self):
        """Activate license with provided key"""
        license_key = self.licenseKeyField.toPlainText().strip()

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
                    f"License activated successfully!\n\n"
                    f"Type: {license_data['license_type'].upper()}\n"
                    f"Device: {license_data['device_id'][:20]}...\n"
                    f"Expires: {license_data.get('expiry_date', 'Never')}"
                )
                self.accept()  # Close dialog with success
            else:
                QMessageBox.critical(
                    self,
                    "Activation Failed",
                    f"License activation failed!\n\n{message}"
                )

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error: {str(e)}")

    def start_trial(self):
        """Start 1-day trial"""
        try:
            # Generate trial license for current device
            encrypted_license = self.license_manager.generate_trial_license(days=1)

            # Save to file
            with open(self.license_manager.license_file, 'w') as f:
                f.write(encrypted_license)

            QMessageBox.information(
                self,
                "Trial Started",
                "1-day trial activated!\n\nYou have full access to all features for 1 day."
            )
            self.accept()  # Close dialog with success

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error starting trial: {str(e)}")
