"""
Test Script - Verify Forensic Tool Setup
=========================================
Run this to test all components before building EXE
"""

import sys
import os

print("=" * 70)
print("  FORENSIC TOOL - PRE-BUILD TEST")
print("=" * 70)
print()

# Test 1: Python Version
print("✓ Testing Python version...")
if sys.version_info < (3, 8):
    print("  ❌ FAILED: Python 3.8+ required. You have:", sys.version)
    sys.exit(1)
else:
    print(f"  ✅ PASSED: Python {sys.version_info.major}.{sys.version_info.minor}")

# Test 2: Required Modules
print("\n✓ Testing required modules...")
required_modules = [
    'PyQt5',
    'cryptography',
    'requests',
    'psutil',
    'win32evtlog',
    'wmi'
]

missing_modules = []
for module in required_modules:
    try:
        if module == 'win32evtlog':
            __import__('win32evtlogutil')
        else:
            __import__(module)
        print(f"  ✅ {module}")
    except ImportError:
        print(f"  ❌ {module} - MISSING!")
        missing_modules.append(module)

if missing_modules:
    print(f"\n  ❌ FAILED: Install missing modules:")
    print(f"     pip install {' '.join(missing_modules)}")
    sys.exit(1)

# Test 3: Project Files
print("\n✓ Testing project files...")
required_files = [
    'gui_launcher.py',
    'forensics_tool.py',
    'license_manager.py',
    'requirements.txt',
    'config/commands.py',
    'core/executor.py',
    'templates/html_generator.py'
]

missing_files = []
for file in required_files:
    if os.path.exists(file):
        print(f"  ✅ {file}")
    else:
        print(f"  ❌ {file} - MISSING!")
        missing_files.append(file)

if missing_files:
    print("\n  ❌ FAILED: Missing project files!")
    sys.exit(1)

# Test 4: License Manager
print("\n✓ Testing License Manager...")
try:
    from license_manager import LicenseManager
    lm = LicenseManager()
    device_id = lm.get_device_id()
    print(f"  ✅ License Manager loaded")
    print(f"  📱 Your Device ID: {device_id}")
except Exception as e:
    print(f"  ❌ FAILED: {e}")
    sys.exit(1)

# Test 5: Trial License Generation
print("\n✓ Testing trial license generation...")
try:
    test_license = lm.generate_trial_license(days=7)
    print(f"  ✅ Trial license generation works")
    print(f"  🔑 License length: {len(test_license)} bytes")
except Exception as e:
    print(f"  ❌ FAILED: {e}")
    sys.exit(1)

# Test 6: GUI Components
print("\n✓ Testing GUI components...")
try:
    from PyQt5.QtWidgets import QApplication
    app = QApplication(sys.argv)
    print(f"  ✅ PyQt5 GUI system works")
except Exception as e:
    print(f"  ❌ FAILED: {e}")
    sys.exit(1)

# Test 7: Forensic Collector
print("\n✓ Testing Forensic Collector...")
try:
    from forensics_tool import ForensicCollector
    collector = ForensicCollector(output_dir="test_output_temp")
    print(f"  ✅ Forensic Collector initializes")
except Exception as e:
    print(f"  ❌ FAILED: {e}")
    sys.exit(1)

# Test 8: Check for EXE build files
print("\n✓ Checking build configuration...")
if os.path.exists('forensic_tool_onedir.spec'):
    print(f"  ✅ PyInstaller spec file found")
else:
    print(f"  ⚠️  No spec file (will use default)")

# Summary
print("\n" + "=" * 70)
print("  ALL TESTS PASSED! ✅")
print("=" * 70)
print("\n📋 Next Steps:")
print("  1. Run the GUI: python gui_launcher.py")
print("  2. Test with trial license: Click 'Start 7-Day Trial'")
print("  3. Test forensic collection: Click 'Start Forensic Collection'")
print("  4. If everything works, build EXE: pyinstaller forensic_tool_onedir.spec")
print("\n📚 Documentation:")
print("  • Admin Guide: ADMIN_GUIDE.md")
print("  • User Guide: HOW_TO_USE.md")
print("  • License Generator: python quick_license_gen.py")
print("\n" + "=" * 70)
print(f"📱 YOUR DEVICE ID: {device_id}")
print("=" * 70)
print("\n💡 TIP: Save this Device ID if you want to generate a license for yourself!")
print()
