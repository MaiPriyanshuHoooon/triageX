"""
Quick License Generator
======================
Generate trial or full licenses for the Forensic Tool

Usage:
    python quick_license_gen.py
"""

from license_manager import LicenseManager
from datetime import datetime

def main():
    print("=" * 70)
    print("  FORENSIC TOOL - LICENSE GENERATOR")
    print("=" * 70)
    print()

    lm = LicenseManager()

    # Menu
    print("Select license type:")
    print("1. Trial License (7 days)")
    print("2. Trial License (30 days)")
    print("3. Full License (1 year)")
    print("4. Full License (Perpetual)")
    print()

    choice = input("Enter choice (1-4): ").strip()

    # Get device ID
    print("\n" + "=" * 70)
    print("DEVICE ID")
    print("=" * 70)
    print("\nTo get customer's Device ID, ask them to run:")
    print('  python -c "from license_manager import LicenseManager; print(LicenseManager().get_device_id())"')
    print("\nOr they can see it in the License Activation dialog.\n")

    device_id = input("Enter customer's Device ID: ").strip().upper()

    if not device_id:
        print("❌ Device ID is required!")
        return

    # Get customer info
    customer_name = input("\nCustomer Name (optional): ").strip() or "Licensed User"
    customer_email = input("Customer Email (optional): ").strip() or "customer@example.com"

    # Generate license based on choice
    if choice == "1":
        license_data = lm.create_license(
            license_type="TRIAL",
            device_id=device_id,
            days_valid=7,
            customer_name=customer_name,
            customer_email=customer_email
        )
        output_file = f"forensics_tool_trial_7d_{device_id[:8]}.lic"

    elif choice == "2":
        license_data = lm.create_license(
            license_type="TRIAL",
            device_id=device_id,
            days_valid=30,
            customer_name=customer_name,
            customer_email=customer_email
        )
        output_file = f"forensics_tool_trial_30d_{device_id[:8]}.lic"

    elif choice == "3":
        license_data = lm.create_license(
            license_type="FULL",
            device_id=device_id,
            days_valid=365,
            customer_name=customer_name,
            customer_email=customer_email
        )
        output_file = f"forensics_tool_full_1y_{device_id[:8]}.lic"

    elif choice == "4":
        license_data = lm.create_license(
            license_type="PERPETUAL",
            device_id=device_id,
            days_valid=36500,  # 100 years
            customer_name=customer_name,
            customer_email=customer_email
        )
        output_file = f"forensics_tool_perpetual_{device_id[:8]}.lic"

    else:
        print("❌ Invalid choice!")
        return

    # Encrypt and save license
    from cryptography.fernet import Fernet
    import json

    encryption_key = lm.generate_encryption_key(device_id)
    fernet = Fernet(encryption_key)
    license_json = json.dumps(license_data, indent=2)
    encrypted_data = fernet.encrypt(license_json.encode())

    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

    # Display results
    print("\n" + "=" * 70)
    print("  LICENSE GENERATED SUCCESSFULLY!")
    print("=" * 70)
    print(f"\n📄 License File: {output_file}")
    print(f"🆔 License ID: {license_data['license_id']}")
    print(f"👤 Customer: {customer_name}")
    print(f"📧 Email: {customer_email}")
    print(f"📱 Device ID: {device_id}")
    print(f"📅 Created: {license_data['issue_date']}")
    print(f"⏰ Expires: {license_data['expiry_date']}")
    print(f"✨ Features: {', '.join(license_data['enabled_features'])}")

    print("\n" + "=" * 70)
    print("  INSTRUCTIONS FOR CUSTOMER")
    print("=" * 70)
    print(f"\n1. Send the file '{output_file}' to the customer")
    print("2. Customer should:")
    print("   a. Open the License Activation dialog")
    print("   b. Open the license file in a text editor")
    print("   c. Copy the entire encrypted content")
    print("   d. Paste it in the 'Enter License Key' box")
    print("   e. Click 'Activate License'")
    print("\nAlternatively:")
    print(f"   - Rename '{output_file}' to 'forensics_tool.lic'")
    print("   - Place it in the tool directory")
    print("   - Run the tool normally")
    print("\n" + "=" * 70)

if __name__ == "__main__":
    main()
