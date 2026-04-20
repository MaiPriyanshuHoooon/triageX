"""
triageX License Key Generator
================================
Standalone admin/vendor tool with a GUI for generating license keys.

Usage:
    python license_generator.py

This tool is NOT shipped with the customer build.
Keep it on the vendor/admin machine only.
"""

import sys
import os

# Add parent directory to path so we can import license_manager
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGroupBox, QLabel, QLineEdit, QTextEdit, QPushButton,
    QComboBox, QSpinBox, QMessageBox, QCheckBox, QFrame
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from license_manager import LicenseManager


ALL_FEATURES = [
    "pagefile_analysis",
    "mft_analysis",
    "registry_analysis",
    "browser_history",
    "event_logs",
    "ioc_detection",
    "virustotal_integration",
    "encrypted_files",
    "pii_detection",
]

TRIAL_FEATURES = [
    "pagefile_analysis",
    "mft_analysis",
    "registry_analysis",
]


class LicenseGeneratorWindow(QMainWindow):
    """Admin tool for generating triageX license keys."""

    def __init__(self):
        super().__init__()
        self.lm = LicenseManager()
        self.setWindowTitle("triageX — License Key Generator (Admin)")
        self.setMinimumSize(700, 620)
        self._build_ui()

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setSpacing(12)

        # Title
        title = QLabel("triageX License Key Generator")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root_layout.addWidget(title)

        subtitle = QLabel("Generate device-locked license keys for customers")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #888;")
        root_layout.addWidget(subtitle)

        # ── Device ID Input ───────────────────────────────────────────────
        device_group = QGroupBox("Customer Device ID")
        device_layout = QVBoxLayout(device_group)

        device_hint = QLabel(
            "Enter the Device ID provided by the customer. "
            "The customer can find it in the License Activation dialog of triageX."
        )
        device_hint.setWordWrap(True)
        device_hint.setStyleSheet("color: #aaa; font-size: 9pt;")
        device_layout.addWidget(device_hint)

        self.device_id_field = QLineEdit()
        self.device_id_field.setPlaceholderText("e.g. A1B2C3D4E5F67890")
        self.device_id_field.setFont(QFont("Consolas", 11))
        device_layout.addWidget(self.device_id_field)

        root_layout.addWidget(device_group)

        # ── Customer Info ─────────────────────────────────────────────────
        info_group = QGroupBox("Customer Information")
        info_layout = QVBoxLayout(info_group)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Name:"))
        self.name_field = QLineEdit()
        self.name_field.setPlaceholderText("Customer Name")
        row1.addWidget(self.name_field)
        info_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Email:"))
        self.email_field = QLineEdit()
        self.email_field.setPlaceholderText("customer@example.com")
        row2.addWidget(self.email_field)
        info_layout.addLayout(row2)

        root_layout.addWidget(info_group)

        # ── License Options ───────────────────────────────────────────────
        opts_group = QGroupBox("License Options")
        opts_layout = QVBoxLayout(opts_group)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("License Type:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["FULL", "TRIAL"])
        self.type_combo.currentTextChanged.connect(self._on_type_changed)
        row3.addWidget(self.type_combo)

        row3.addWidget(QLabel("  Validity (days):"))
        self.days_spin = QSpinBox()
        self.days_spin.setMinimum(1)
        self.days_spin.setMaximum(3650)
        self.days_spin.setValue(365)
        row3.addWidget(self.days_spin)
        opts_layout.addLayout(row3)

        # Feature checkboxes
        feat_label = QLabel("Enabled Features:")
        feat_label.setStyleSheet("font-weight: bold; margin-top: 6px;")
        opts_layout.addWidget(feat_label)

        self.feature_checks: dict[str, QCheckBox] = {}
        feat_grid = QHBoxLayout()
        col1 = QVBoxLayout()
        col2 = QVBoxLayout()
        for i, feat in enumerate(ALL_FEATURES):
            cb = QCheckBox(feat)
            cb.setChecked(True)
            self.feature_checks[feat] = cb
            (col1 if i < 5 else col2).addWidget(cb)
        feat_grid.addLayout(col1)
        feat_grid.addLayout(col2)
        opts_layout.addLayout(feat_grid)

        root_layout.addWidget(opts_group)

        # ── Generate Button ───────────────────────────────────────────────
        self.gen_button = QPushButton("Generate License Key")
        self.gen_button.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self.gen_button.setMinimumHeight(40)
        self.gen_button.clicked.connect(self._generate)
        root_layout.addWidget(self.gen_button)

        # ── Output ────────────────────────────────────────────────────────
        output_group = QGroupBox("Generated License Key (send this to customer)")
        output_layout = QVBoxLayout(output_group)
        self.output_field = QTextEdit()
        self.output_field.setReadOnly(True)
        self.output_field.setFont(QFont("Consolas", 9))
        self.output_field.setMinimumHeight(80)
        output_layout.addWidget(self.output_field)

        btn_row = QHBoxLayout()
        self.copy_btn = QPushButton("Copy to Clipboard")
        self.copy_btn.clicked.connect(self._copy_output)
        self.copy_btn.setEnabled(False)
        btn_row.addWidget(self.copy_btn)

        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        btn_row.addWidget(self.status_label)
        output_layout.addLayout(btn_row)

        root_layout.addWidget(output_group)

    # ── Slots ─────────────────────────────────────────────────────────────────

    def _on_type_changed(self, text: str):
        """Auto-adjust defaults when license type changes."""
        if text == "TRIAL":
            self.days_spin.setValue(1)
            # All features enabled for trial too — only duration differs
            for cb in self.feature_checks.values():
                cb.setChecked(True)
        else:
            self.days_spin.setValue(365)
            for cb in self.feature_checks.values():
                cb.setChecked(True)

    def _generate(self):
        """Generate and display the encrypted license key."""
        device_id = self.device_id_field.text().strip().upper()
        if not device_id:
            QMessageBox.warning(self, "Missing Device ID",
                                "Please enter the customer's Device ID.")
            return

        customer_name = self.name_field.text().strip() or "Customer"
        customer_email = self.email_field.text().strip()
        license_type = self.type_combo.currentText()
        days_valid = self.days_spin.value()
        features = [f for f, cb in self.feature_checks.items() if cb.isChecked()]

        if not features:
            QMessageBox.warning(self, "No Features",
                                "Select at least one feature to enable.")
            return

        try:
            # Create license data
            license_data = self.lm.create_license(
                license_type=license_type,
                device_id=device_id,
                days_valid=days_valid,
                customer_name=customer_name,
                customer_email=customer_email,
                features=features,
            )

            # For FULL licenses, override the trial feature cap
            if license_type == "FULL":
                license_data["enabled_features"] = features
                license_data["days_valid"] = days_valid
                from datetime import datetime, timedelta
                license_data["expiry_date"] = (
                    datetime.fromisoformat(license_data["issue_date"]) + timedelta(days=days_valid)
                ).isoformat()

            # Encrypt with the target device's key
            from cryptography.fernet import Fernet
            import json

            encryption_key = self.lm.generate_encryption_key(device_id)
            fernet = Fernet(encryption_key)
            encrypted = fernet.encrypt(json.dumps(license_data, indent=2).encode())

            encrypted_text = encrypted.decode()

            self.output_field.setPlainText(encrypted_text)
            self.copy_btn.setEnabled(True)
            self.status_label.setText(
                f"License generated  |  Type: {license_type}  |  "
                f"Valid: {days_valid} days  |  Device: {device_id}"
            )
            self.status_label.setStyleSheet("color: #66BB6A; font-weight: bold;")

            # Also save as .lic file for convenience
            lic_filename = f"forensics_tool_{license_type.lower()}_{device_id}.lic"
            with open(lic_filename, 'wb') as f:
                f.write(encrypted)

            QMessageBox.information(
                self,
                "License Generated",
                f"License key generated successfully!\n\n"
                f"Type: {license_type}\n"
                f"Device: {device_id}\n"
                f"Valid: {days_valid} days\n"
                f"Expires: {license_data['expiry_date'][:10]}\n"
                f"Features: {len(features)} enabled\n\n"
                f"File also saved as: {lic_filename}\n\n"
                f"The customer can either:\n"
                f"  1. Paste the key from clipboard into the Activate dialog, or\n"
                f"  2. Copy the .lic file and rename to forensics_tool.lic"
            )

        except Exception as e:
            QMessageBox.critical(self, "Generation Failed", f"Error: {e}")
            self.status_label.setText(f"Error: {e}")
            self.status_label.setStyleSheet("color: #ef5350;")

    def _copy_output(self):
        """Copy the generated key to clipboard."""
        text = self.output_field.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            self.status_label.setText("Copied to clipboard!")
            self.status_label.setStyleSheet("color: #66BB6A; font-weight: bold;")


def main():
    app = QApplication(sys.argv)

    # Dark theme matching triageX
    app.setStyleSheet("""
        QMainWindow, QWidget { background-color: #1e1e2e; color: #cdd6f4; }
        QGroupBox { border: 1px solid #45475a; border-radius: 6px; margin-top: 8px; padding-top: 14px; font-weight: bold; }
        QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; }
        QLineEdit, QTextEdit, QSpinBox, QComboBox { background-color: #313244; border: 1px solid #45475a; border-radius: 4px; padding: 4px 8px; color: #cdd6f4; }
        QPushButton { background-color: #45475a; border: 1px solid #585b70; border-radius: 4px; padding: 6px 16px; color: #cdd6f4; }
        QPushButton:hover { background-color: #585b70; }
        QPushButton:pressed { background-color: #6c7086; }
        QCheckBox { spacing: 6px; }
        QCheckBox::indicator { width: 14px; height: 14px; }
    """)

    win = LicenseGeneratorWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
