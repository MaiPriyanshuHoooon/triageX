"""
Forensic Tool License Manager
==============================
Professional license management system for forensic triage tool

Features:
- Device-locked licenses (hardware ID binding)
- Trial and full licenses
- Expiration dates
- Online/offline validation
- Encrypted license keys
- Anti-tampering protection

Author: Forensics Tool Team
Date: December 2025
"""

import os
import sys
import json
import hashlib
import uuid
import platform
import subprocess
import logging
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# Configure logging for professional debugging (silent in GUI mode)
logging.basicConfig(
    level=logging.WARNING,  # Only show warnings and errors
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('forensic_tool_license.log'),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)


class LicenseManager:
    """
    Professional license management system
    Handles device binding, expiration, and validation
    """

    def __init__(self):
        self.license_file = "forensics_tool.lic"
        self.config_file = ".license_config"

        # Master encryption key (KEEP THIS SECRET!)
        # In production, store this in secure hardware/cloud
        self.master_secret = b"YOUR_SECRET_MASTER_KEY_CHANGE_THIS_IN_PRODUCTION_32BYTES!!"

    def get_device_id(self) -> str:
        """
        Get unique device identifier (hardware-based)

        This combines multiple hardware identifiers to create
        a unique fingerprint for the device.

        Returns:
            Unique device ID string
        """
        identifiers = []

        try:
            # Windows-specific: CREATE_NO_WINDOW flag to prevent console popup
            creation_flags = 0
            if sys.platform == 'win32':
                creation_flags = subprocess.CREATE_NO_WINDOW

            # 1. CPU ID (processor serial number)
            if sys.platform == 'win32':
                # Windows: WMIC CPU ID
                result = subprocess.run(
                    ['wmic', 'cpu', 'get', 'ProcessorId'],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=creation_flags
                )
                cpu_id = result.stdout.strip().split('\n')[-1].strip()
                identifiers.append(cpu_id)

            # 2. Motherboard serial
            if sys.platform == 'win32':
                result = subprocess.run(
                    ['wmic', 'baseboard', 'get', 'serialnumber'],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=creation_flags
                )
                mb_serial = result.stdout.strip().split('\n')[-1].strip()
                identifiers.append(mb_serial)

            # 3. MAC Address (first network adapter)
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                          for elements in range(0, 2*6, 2)][::-1])
            identifiers.append(mac)

            # 4. System UUID
            if sys.platform == 'win32':
                result = subprocess.run(
                    ['wmic', 'csproduct', 'get', 'uuid'],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=creation_flags
                )
                system_uuid = result.stdout.strip().split('\n')[-1].strip()
                identifiers.append(system_uuid)

            # 5. Computer name
            identifiers.append(platform.node())

        except Exception as e:
            logger.warning(f"Warning: Could not collect all hardware IDs: {e}")

        # Combine all identifiers and hash
        combined = "|".join(identifiers)
        device_hash = hashlib.sha256(combined.encode()).hexdigest()

        # Return first 16 characters (enough uniqueness)
        return device_hash[:16].upper()

    def generate_encryption_key(self, device_id: str) -> bytes:
        """
        Generate encryption key from device ID
        This ensures license files are device-specific
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.master_secret[:16],
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(device_id.encode()))
        return key

    def create_license(
        self,
        license_type: str = "TRIAL",
        device_id: str = None,
        days_valid: int = 30,
        customer_name: str = "Trial User",
        customer_email: str = "",
        features: list = None
    ) -> dict:
        """
        Create a new license

        Args:
            license_type: "TRIAL" or "FULL"
            device_id: Target device ID (if None, will be set during activation)
            days_valid: Number of days license is valid
            customer_name: Customer name
            customer_email: Customer email
            features: List of enabled features

        Returns:
            License dictionary
        """
        if features is None:
            features = [
                "pagefile_analysis",
                "mft_analysis",
                "registry_analysis",
                "browser_history",
                "event_logs",
                "ioc_detection",
                "virustotal_integration"
            ]

        # Trial licenses have all features but limited duration
        if license_type == "TRIAL":
            days_valid = min(days_valid, 1)  # Max 1 day for trial

        issue_date = datetime.now()
        expiry_date = issue_date + timedelta(days=days_valid)

        license_data = {
            "license_type": license_type,
            "device_id": device_id,
            "customer_name": customer_name,
            "customer_email": customer_email,
            "issue_date": issue_date.isoformat(),
            "expiry_date": expiry_date.isoformat(),
            "days_valid": days_valid,
            "enabled_features": features,
            "version": "2.0.1",
            "license_id": self._generate_license_id()
        }

        return license_data

    def _generate_license_id(self) -> str:
        """Generate unique license ID"""
        random_uuid = uuid.uuid4().hex[:12].upper()
        timestamp = datetime.now().strftime("%Y%m%d")
        return f"FT-{timestamp}-{random_uuid}"

    def save_license(self, license_data: dict, output_file: str = None) -> str:
        """
        Save license to encrypted file

        Args:
            license_data: License dictionary
            output_file: Output filename (default: forensics_tool.lic)

        Returns:
            License key string (to send to customer)
        """
        if output_file is None:
            output_file = self.license_file

        # Encrypt license data
        device_id = license_data.get('device_id', 'UNBOUND')
        encryption_key = self.generate_encryption_key(device_id)
        fernet = Fernet(encryption_key)

        # Serialize to JSON
        license_json = json.dumps(license_data, indent=2)

        # Encrypt
        encrypted_data = fernet.encrypt(license_json.encode())

        # Save to file
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)

        # Generate activation key (base64 encoded filename + device_id)
        activation_key = base64.b64encode(
            f"{license_data['license_id']}|{device_id}".encode()
        ).decode()

        print(f"License saved: {output_file}")
        print(f"Send this to customer:\n")
        print(f"   License File: {output_file}")
        print(f"   Activation Key: {activation_key}")
        print(f"   Device ID Required: {device_id or 'Will be bound on first run'}")

        return activation_key

    def load_license(self, license_file: str = None) -> dict:
        """
        Load and decrypt license file

        Args:
            license_file: Path to license file

        Returns:
            License data dictionary

        Raises:
            Exception if license invalid or tampered
        """
        if license_file is None:
            license_file = self.license_file

        if not os.path.exists(license_file):
            raise FileNotFoundError(f"License file not found: {license_file}")

        # Get current device ID
        current_device_id = self.get_device_id()

        # Try to decrypt with current device ID
        try:
            encryption_key = self.generate_encryption_key(current_device_id)
            fernet = Fernet(encryption_key)

            with open(license_file, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = fernet.decrypt(encrypted_data)
            license_data = json.loads(decrypted_data.decode())

            return license_data

        except Exception as e:
            raise Exception(f"Invalid or tampered license file: {e}")

    def validate_license(self, license_data: dict = None) -> tuple:
        """
        Validate license

        Args:
            license_data: License dictionary (if None, will load from file)

        Returns:
            (is_valid: bool, message: str, license_data: dict)
        """
        try:
            if license_data is None:
                license_data = self.load_license()

            # Check device ID
            current_device_id = self.get_device_id()
            license_device_id = license_data.get('device_id')

            if license_device_id and license_device_id != current_device_id:
                return False, f"License is bound to different device (ID: {license_device_id})", None

            # Check expiration
            expiry_date = datetime.fromisoformat(license_data['expiry_date'])
            if datetime.now() > expiry_date:
                return False, f"License expired on {expiry_date.strftime('%Y-%m-%d')}", license_data

            # Check license type
            license_type = license_data.get('license_type', 'TRIAL')
            days_remaining = (expiry_date - datetime.now()).days

            if license_type == "TRIAL":
                message = f"TRIAL LICENSE valid for {days_remaining} more days"
            else:
                message = f"FULL LICENSE valid until {expiry_date.strftime('%Y-%m-%d')}"

            return True, message, license_data

        except FileNotFoundError:
            return False, "No license file found. Please contact vendor for license.", None
        except Exception as e:
            return False, f"License validation failed: {e}", None

    def is_feature_enabled(self, feature_name: str, license_data: dict = None) -> bool:
        """
        Check if a feature is enabled in the license

        Args:
            feature_name: Feature name to check
            license_data: License data (if None, will load)

        Returns:
            True if feature is enabled
        """
        try:
            if license_data is None:
                is_valid, message, license_data = self.validate_license()
                if not is_valid:
                    return False

            enabled_features = license_data.get('enabled_features', [])
            return feature_name in enabled_features

        except:
            return False

    def get_license_info(self) -> dict:
        """
        Get current license information

        Returns:
            Dictionary with license details
        """
        try:
            is_valid, message, license_data = self.validate_license()

            if not is_valid:
                return {
                    'valid': False,
                    'message': message,
                    'license_type': 'NONE'
                }

            expiry_date = datetime.fromisoformat(license_data['expiry_date'])
            days_remaining = (expiry_date - datetime.now()).days

            return {
                'valid': True,
                'message': message,
                'license_type': license_data.get('license_type'),
                'customer_name': license_data.get('customer_name'),
                'license_id': license_data.get('license_id'),
                'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                'days_remaining': days_remaining,
                'enabled_features': license_data.get('enabled_features', []),
                'device_id': license_data.get('device_id')
            }

        except Exception as e:
            return {
                'valid': False,
                'message': f"License error: {e}",
                'license_type': 'NONE'
            }

    def generate_trial_license(self, days: int = 7) -> str:
        """
        Generate a trial license for current device

        Args:
            days: Number of days for trial (default: 7)

        Returns:
            Encrypted license data string
        """
        # Get current device ID
        device_id = self.get_device_id()

        # Create trial license
        license_data = self.create_license(
            license_type="TRIAL",
            device_id=device_id,
            days_valid=days,
            customer_name="Trial User",
            customer_email="trial@forensic-tool.com"
        )

        # Encrypt and return license data
        encryption_key = self.generate_encryption_key(device_id)
        fernet = Fernet(encryption_key)
        license_json = json.dumps(license_data, indent=2)
        encrypted_data = fernet.encrypt(license_json.encode())

        return encrypted_data.decode()


# ==============================================================================
# LICENSE GENERATION TOOL (For vendor/admin use only)
# ==============================================================================

def generate_trial_license():
    """Generate a trial license"""
    logger.info("="*70)
    logger.info(" GENERATE TRIAL LICENSE")
    logger.info("="*70)

    lm = LicenseManager()

    # Get customer info
    customer_name = input("Customer Name: ").strip()
    customer_email = input("Customer Email: ").strip()

    # Get device ID from customer
    logger.info("\nDevice ID:")
    logger.info("   Ask customer to run the tool and copy Device ID from License Activation dialog")
    device_id = input("   Enter Device ID: ").strip().upper()

    if not device_id:
        logger.error("Device ID required!")
        return

    # Create license
    license_data = lm.create_license(
        license_type="TRIAL",
        device_id=device_id,
        days_valid=1,
        customer_name=customer_name,
        customer_email=customer_email
    )

    # Save license
    output_file = f"forensics_tool_trial_{device_id}.lic"
    activation_key = lm.save_license(license_data, output_file)

    logger.info(f"\nSEND TO CUSTOMER:")
    logger.info(f"   1. License file: {output_file}")
    logger.info(f"   2. Activation instructions:")
    logger.info(f"      - Copy {output_file} to tool directory")
    logger.info(f"      - Rename to: forensics_tool.lic")
    logger.info(f"      - Run tool normally")
    logger.info(f"\nLicense expires: {license_data['expiry_date']}")
    logger.info(f"Enabled features: {', '.join(license_data['enabled_features'])}")


def generate_full_license():
    """Generate a full license"""
    logger.info("="*70)
    logger.info(" GENERATE FULL LICENSE")
    logger.info("="*70)

    lm = LicenseManager()

    # Get customer info
    customer_name = input("Customer Name: ").strip()
    customer_email = input("Customer Email: ").strip()
    days_valid = int(input("Days Valid (365 for 1 year): ").strip() or "365")

    # Get device ID
    logger.info("\nDevice ID:")
    logger.info("   Ask customer to run the tool and copy Device ID from License Activation dialog")
    device_id = input("   Enter Device ID: ").strip().upper()

    if not device_id:
        logger.error("Device ID required!")
        return

    # All features enabled for full license
    features = [
        "pagefile_analysis",
        "mft_analysis",
        "registry_analysis",
        "browser_history",
        "event_logs",
        "ioc_detection",
        "virustotal_integration",
        "encrypted_files",
        "pii_detection"
    ]

    # Create license
    license_data = lm.create_license(
        license_type="FULL",
        device_id=device_id,
        days_valid=days_valid,
        customer_name=customer_name,
        customer_email=customer_email,
        features=features
    )

    # Save license
    output_file = f"forensics_tool_full_{device_id}.lic"
    activation_key = lm.save_license(license_data, output_file)

    logger.info(f"\nSEND TO CUSTOMER:")
    logger.info(f"   1. License file: {output_file}")
    logger.info(f"   2. Activation instructions:")
    logger.info(f"      - Copy {output_file} to tool directory")
    logger.info(f"      - Rename to: forensics_tool.lic")
    logger.info(f"      - Run tool normally")
    logger.info(f"\nLicense expires: {license_data['expiry_date']}")
    logger.info(f"All features enabled")


def check_license():
    """Check current license status"""
    logger.info("="*70)
    logger.info(" LICENSE STATUS")
    logger.info("="*70)

    lm = LicenseManager()

    # Show device ID
    device_id = lm.get_device_id()
    logger.info(f"\nThis Device ID: {device_id}")
    logger.info(f"   (Share this with vendor to get license)")

    # Check license
    info = lm.get_license_info()

    print(f"\nLicense Status:")
    if info['valid']:
        logger.info(f"   Status: VALID")
        logger.info(f"   Type: {info['license_type']}")
        logger.info(f"   Customer: {info['customer_name']}")
        logger.info(f"   License ID: {info['license_id']}")
        logger.info(f"   Expires: {info['expiry_date']} ({info['days_remaining']} days remaining)")
        logger.info(f"\n   Enabled Features:")
        for feature in info['enabled_features']:
            print(f"      - {feature}")
    else:
        logger.info(f"   Status: {info['message']}")
        logger.info(f"\n   To activate:")
        logger.info(f"      1. Contact vendor with Device ID: {device_id}")
        logger.info(f"      2. Receive license file: forensics_tool.lic")
        logger.info(f"      3. Place in tool directory")


if __name__ == '__main__':
    """
    License management CLI
    """
    import sys

    if len(sys.argv) < 2:
        logger.info("Usage:")
        logger.info("  python license_manager.py check          - Check license status")
        logger.info("  python license_manager.py device_id      - Show device ID")
        logger.info("  python license_manager.py trial          - Generate trial license (vendor only)")
        logger.info("  python license_manager.py full           - Generate full license (vendor only)")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == 'check':
        check_license()
    elif command == 'device_id':
        lm = LicenseManager()
        device_id = lm.get_device_id()
        print(f"Device ID: {device_id}")
    elif command == 'trial':
        generate_trial_license()
    elif command == 'full':
        generate_full_license()
    else:
        logger.error(f"Unknown command: {command}")
