"""
Command Executor Module
=======================
Handles execution of CMD and PowerShell commands
"""

import subprocess
import re
import sys
import ctypes
import os
from config.commands import POWERSHELL_INDICATORS


def detect_command_type(cmd):
    """
    Automatically detect if a command is PowerShell, CMD, or Analysis

    Args:
        cmd: Command string

    Returns:
        "powershell", "cmd", "regex_analysis", or "hash_analysis"
    """
    # Check for analysis commands (not shell commands)
    if cmd.startswith("ANALYZE_") or cmd.startswith("HASH_"):
        if "ANALYZE" in cmd:
            return "regex_analysis"
        elif "HASH" in cmd:
            return "hash_analysis"

    cmd_lower = cmd.lower()

    # Check for PowerShell indicators
    for indicator in POWERSHELL_INDICATORS:
        if indicator.lower() in cmd_lower:
            return "powershell"

    # Check for PowerShell variable syntax ($variable)
    if re.search(r'\$\w+', cmd):
        return "powershell"

    # Check for PowerShell pipeline with cmdlets
    if '|' in cmd and any(x in cmd for x in ['Get-', 'Set-', 'Where-', 'Select-']):
        return "powershell"

    # Default to CMD
    return "cmd"


def is_admin():
    """Check if script is running with administrator privileges (Windows only)"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    """Restart the script with administrator privileges (Windows only)"""
    try:
        if sys.platform == 'win32':
            # Get the path to the Python executable and script
            script = os.path.abspath(sys.argv[0])

            # Build parameters: pass the script as the first argument
            params = f'"{script}"'

            # Request UAC elevation - Run Python with the script as parameter
            ret = ctypes.windll.shell32.ShellExecuteW(
                None,           # hwnd (parent window)
                "runas",        # Operation (run as admin)
                sys.executable, # Python executable path
                params,         # Parameters (script path)
                None,           # Working directory (use current)
                1               # SW_SHOWNORMAL (show window)
            )

            # ShellExecuteW returns > 32 if successful
            if ret > 32:
                sys.exit(0)  # Exit current process
            else:
                print(f"❌ Failed to elevate privileges (Error Code: {ret})")
                print("Please run this script as Administrator manually:")
                print(f"  1. Right-click on this file: {script}")
                print("  2. Select 'Run as Administrator'")
                input("\nPress ENTER to continue without admin privileges...")
    except Exception as e:
        print(f"❌ Failed to elevate privileges: {e}")
        print("Please run this script as Administrator manually.")
        input("Press ENTER to continue without admin privileges...")


def execute_cmd(cmd):
    """Execute Command Prompt (cmd.exe) commands"""
    try:
        # Windows-specific: CREATE_NO_WINDOW flag to prevent console popup
        creation_flags = 0
        if sys.platform == 'win32':
            creation_flags = subprocess.CREATE_NO_WINDOW
        
        return subprocess.check_output(
            cmd, 
            shell=True, 
            text=True, 
            stderr=subprocess.STDOUT,
            creationflags=creation_flags  # No timeout - runs until complete
        )
    except subprocess.CalledProcessError as e:
        # More detailed error message
        error_msg = f"❌ Command failed (Error Code: {e.returncode})"
        if e.output:
            # Include the actual error output
            error_msg += f"\n\nError Details:\n{e.output[:500]}"  # First 500 chars
        return error_msg
    except Exception as e:
        return f"❌ Error: {str(e)}"


def execute_powershell(cmd):
    """Execute PowerShell commands"""
    try:
        # Windows-specific: CREATE_NO_WINDOW flag to prevent console popup
        creation_flags = 0
        if sys.platform == 'win32':
            creation_flags = subprocess.CREATE_NO_WINDOW

        powershell_cmd = [
            'powershell.exe',
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy', 'Bypass',
            '-Command', cmd
        ]

        result = subprocess.check_output(
            powershell_cmd,
            text=True,
            stderr=subprocess.STDOUT,
            creationflags=creation_flags    # No timeout - runs until complete
        )
        return result
    except subprocess.CalledProcessError as e:
        # More detailed error message
        error_msg = f"❌ PowerShell command failed (Error Code: {e.returncode})"
        if e.output:
            # Include the actual error output from PowerShell
            error_msg += f"\n\nError Details:\n{e.output[:500]}"  # First 500 chars
        return error_msg
    except FileNotFoundError:
        return "❌ PowerShell not found on this system (Windows only)"
    except Exception as e:
        return f"❌ Error: {str(e)}"


def execute(cmd):
    """
    Automatically detect command type and execute

    Args:
        cmd: Command string

    Returns:
        Tuple of (output, command_type)
    """
    # Auto-detect command type
    cmd_type = detect_command_type(cmd)

    # Execute based on detected type
    if cmd_type == 'powershell':
        output = execute_powershell(cmd)
    elif cmd_type == 'regex_analysis':
        output = f"REGEX_ANALYSIS:{cmd}"  # Placeholder - handled by main tool
    elif cmd_type == 'hash_analysis':
        output = f"HASH_ANALYSIS:{cmd}"  # Placeholder - handled by main tool
    else:
        output = execute_cmd(cmd)

    return output, cmd_type
