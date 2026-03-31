"""
Command Executor Module
=======================
Cross-platform command execution for Windows, Linux, and macOS.
Auto-detects OS and routes commands to the correct shell.
"""

import subprocess
import re
import sys
import os
from config.commands import POWERSHELL_INDICATORS
from core.os_detector import detect_os, is_windows, is_linux, is_macos, is_admin, run_as_admin, OS_WINDOWS, OS_LINUX, OS_MACOS


def detect_command_type(cmd):
    """
    Automatically detect if a command is PowerShell, CMD, Bash, Zsh, or Analysis.

    Args:
        cmd: Command string

    Returns:
        "powershell", "cmd", "bash", "zsh", "regex_analysis", or "hash_analysis"
    """
    # Check for analysis commands (not shell commands)
    if cmd.startswith("ANALYZE_") or cmd.startswith("HASH_"):
        if "ANALYZE" in cmd:
            return "regex_analysis"
        elif "HASH" in cmd:
            return "hash_analysis"

    current_os = detect_os()

    # On Linux → always bash
    if current_os == OS_LINUX:
        return "bash"

    # On macOS → always zsh
    if current_os == OS_MACOS:
        return "zsh"

    # On Windows → detect PowerShell vs CMD
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

    # Default to CMD on Windows
    return "cmd"


def execute_cmd(cmd):
    """Execute Command Prompt (cmd.exe) commands — Windows only"""
    try:
        creation_flags = 0
        if sys.platform == 'win32':
            creation_flags = subprocess.CREATE_NO_WINDOW

        kwargs = dict(
            shell=True,
            text=True,
            stderr=subprocess.STDOUT,
        )
        # creationflags is Windows-only
        if sys.platform == 'win32':
            kwargs['creationflags'] = creation_flags

        return subprocess.check_output(cmd, **kwargs)
    except subprocess.CalledProcessError as e:
        error_msg = f"[ERROR] Command failed (Error Code: {e.returncode})"
        if e.output:
            error_msg += f"\n\nError Details:\n{e.output[:500]}"
        return error_msg
    except Exception as e:
        return f"[ERROR] Error: {str(e)}"


def execute_powershell(cmd):
    """Execute PowerShell commands — Windows only"""
    try:
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

        kwargs = dict(
            text=True,
            stderr=subprocess.STDOUT,
        )
        if sys.platform == 'win32':
            kwargs['creationflags'] = creation_flags

        result = subprocess.check_output(powershell_cmd, **kwargs)
        return result
    except subprocess.CalledProcessError as e:
        error_msg = f"[ERROR] PowerShell command failed (Error Code: {e.returncode})"
        if e.output:
            error_msg += f"\n\nError Details:\n{e.output[:500]}"
        return error_msg
    except FileNotFoundError:
        return "[ERROR] PowerShell not found on this system (Windows only)"
    except Exception as e:
        return f"[ERROR] Error: {str(e)}"


def execute_bash(cmd):
    """Execute Bash shell commands — Linux"""
    try:
        result = subprocess.check_output(
            ['bash', '-c', cmd],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=120  # 2 minute timeout per command
        )
        return result
    except subprocess.CalledProcessError as e:
        error_msg = f"[ERROR] Bash command failed (Error Code: {e.returncode})"
        if e.output:
            error_msg += f"\n\nError Details:\n{e.output[:500]}"
        return error_msg
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out (120s limit)"
    except FileNotFoundError:
        # Fallback to sh if bash not available
        try:
            result = subprocess.check_output(
                ['sh', '-c', cmd],
                text=True,
                stderr=subprocess.STDOUT,
                timeout=120
            )
            return result
        except Exception as e:
            return f"[ERROR] Shell not found: {str(e)}"
    except Exception as e:
        return f"[ERROR] Error: {str(e)}"


def execute_zsh(cmd):
    """Execute Zsh shell commands — macOS"""
    try:
        result = subprocess.check_output(
            ['zsh', '-c', cmd],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=120  # 2 minute timeout per command
        )
        return result
    except subprocess.CalledProcessError as e:
        error_msg = f"[ERROR] Zsh command failed (Error Code: {e.returncode})"
        if e.output:
            error_msg += f"\n\nError Details:\n{e.output[:500]}"
        return error_msg
    except subprocess.TimeoutExpired:
        return "[ERROR] Command timed out (120s limit)"
    except FileNotFoundError:
        # Fallback to bash if zsh not available
        try:
            result = subprocess.check_output(
                ['bash', '-c', cmd],
                text=True,
                stderr=subprocess.STDOUT,
                timeout=120
            )
            return result
        except Exception as e:
            return f"[ERROR] Shell not found: {str(e)}"
    except Exception as e:
        return f"[ERROR] Error: {str(e)}"


def execute(cmd):
    """
    Automatically detect command type and execute on the correct shell.
    Cross-platform: routes to PowerShell/CMD on Windows, Bash on Linux, Zsh on macOS.

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
    elif cmd_type == 'bash':
        output = execute_bash(cmd)
    elif cmd_type == 'zsh':
        output = execute_zsh(cmd)
    elif cmd_type == 'regex_analysis':
        output = f"REGEX_ANALYSIS:{cmd}"  # Placeholder - handled by main tool
    elif cmd_type == 'hash_analysis':
        output = f"HASH_ANALYSIS:{cmd}"  # Placeholder - handled by main tool
    else:
        output = execute_cmd(cmd)

    return output, cmd_type
