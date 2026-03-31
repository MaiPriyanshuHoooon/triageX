"""
OS Detection Module
====================
Central OS detection utility for cross-platform forensic triage.
Single source of truth — all other modules import from here.
"""

import sys
import os
import platform


# OS type constants
OS_WINDOWS = "Windows"
OS_LINUX = "Linux"
OS_MACOS = "macOS"
OS_UNKNOWN = "Unknown"


def detect_os():
    """
    Detect the current operating system at runtime.

    Returns:
        str: One of OS_WINDOWS, OS_LINUX, OS_MACOS, OS_UNKNOWN
    """
    if sys.platform == 'win32':
        return OS_WINDOWS
    elif sys.platform == 'darwin':
        return OS_MACOS
    elif sys.platform.startswith('linux'):
        return OS_LINUX
    else:
        return OS_UNKNOWN


def is_windows():
    """Check if running on Windows"""
    return sys.platform == 'win32'


def is_linux():
    """Check if running on Linux"""
    return sys.platform.startswith('linux')


def is_macos():
    """Check if running on macOS"""
    return sys.platform == 'darwin'


def is_admin():
    """
    Check if script is running with elevated/root/admin privileges.
    Cross-platform: works on Windows, Linux, and macOS.

    Returns:
        bool: True if running with elevated privileges
    """
    if is_windows():
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:
        # Linux / macOS: check if running as root (UID 0)
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False


def run_as_admin():
    """
    Attempt to restart with elevated privileges.
    - Windows: UAC elevation via ShellExecuteW
    - Linux/macOS: Print sudo instruction (cannot auto-elevate)
    """
    if is_windows():
        try:
            import ctypes
            script = os.path.abspath(sys.argv[0])
            params = f'"{script}"'
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
            if ret > 32:
                sys.exit(0)
            else:
                print(f"[ERROR] Failed to elevate privileges (Error Code: {ret})")
                print("Please run this script as Administrator manually.")
                input("\nPress ENTER to continue without admin privileges...")
        except Exception as e:
            print(f"[ERROR] Failed to elevate privileges: {e}")
            input("Press ENTER to continue without admin privileges...")
    else:
        # Linux / macOS
        print("=" * 60)
        print("ROOT/SUDO PRIVILEGES RECOMMENDED")
        print("=" * 60)
        print("\nSome forensic features require elevated privileges:")
        print("  • USB device history")
        print("  • System log access")
        print("  • Process inspection")
        print("  • Network connection details")
        print(f"\nRe-run with: sudo python3 {sys.argv[0]}")
        print("=" * 60)


def get_os_info():
    """
    Get detailed OS information for the report header.

    Returns:
        dict: OS details (name, version, architecture, hostname)
    """
    return {
        'os_type': detect_os(),
        'platform': platform.platform(),
        'version': platform.version(),
        'architecture': platform.machine(),
        'hostname': platform.node(),
        'python_version': platform.python_version(),
        'is_admin': is_admin()
    }


def get_shell_type():
    """
    Detect the default shell type for the current OS.

    Returns:
        str: Shell type label (e.g., 'PS', 'CMD', 'BASH', 'ZSH')
    """
    current_os = detect_os()
    if current_os == OS_WINDOWS:
        return "PS"  # PowerShell is default for forensic commands
    elif current_os == OS_LINUX:
        return "BASH"
    elif current_os == OS_MACOS:
        return "ZSH"
    else:
        return "SH"
