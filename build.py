#!/usr/bin/env python3
"""
triageX — Cross-Platform Build System
=======================================

Unified build script that auto-detects the current OS and produces
the correct native package:

    Windows  →  ForensicTool.exe           (PyInstaller one-dir)
    macOS    →  ForensicTool.app / .dmg    (PyInstaller .app bundle)
    Linux    →  ForensicTool.AppImage      (PyInstaller + AppImage)

Usage
-----
    python build.py                  # auto-detect OS, build release
    python build.py --target windows # explicit target
    python build.py --mode onefile   # single-file mode
    python build.py --clean          # remove all build artifacts
    python build.py --check          # verify prerequisites only

Requirements
------------
    pip install pyinstaller          # all platforms
    brew install create-dmg          # macOS only (optional, for .dmg)

Author: triageX Team
"""

import os
import sys
import shutil
import platform
import subprocess
import argparse
import json
from datetime import datetime
from pathlib import Path

# ── Constants ──────────────────────────────────────────────────────
APP_NAME = "ForensicTool"
APP_VERSION = "2.0.0"
APP_ID = "com.triagex.forensictool"
ENTRY_POINT = "main.py"                        # PyQt6 entry point
PROJECT_ROOT = Path(__file__).resolve().parent

# Directories / data to bundle
DATA_DIRS = ["templates", "assets", "config", "core", "ui", "styles"]
# Hidden imports common to all platforms
COMMON_HIDDEN_IMPORTS = [
    "PyQt6", "PyQt6.QtCore", "PyQt6.QtGui", "PyQt6.QtWidgets",
    "PyQt6.uic",
    "cryptography", "cryptography.fernet",
    "cryptography.hazmat", "cryptography.hazmat.primitives",
    "cryptography.hazmat.primitives.kdf.pbkdf2",
    "cryptography.hazmat.backends",
    "requests", "psutil",
]
# Windows-only hidden imports
WIN_HIDDEN_IMPORTS = [
    "win32com", "win32com.client",
    "win32api", "win32con", "pywintypes", "pythoncom",
    "win32file", "win32security", "ntsecuritycon",
    "win32evtlog", "win32evtlogutil",
    "wmi",
]
# Modules to exclude everywhere
EXCLUDES = [
    "_tkinter", "tkinter", "unittest", "pydoc",
    "doctest", "test", "lib2to3",
]

# Terminal colours (ANSI)
C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_CYAN   = "\033[96m"


# ── Helpers ────────────────────────────────────────────────────────
def banner():
    """Print build banner."""
    print(f"""
{C_CYAN}{'='*62}
   triageX Build System  v{APP_VERSION}
   {platform.system()} {platform.machine()} - Python {platform.python_version()}
{'='*62}{C_RESET}
""")


def step(num, total, msg):
    """Print a build-step marker."""
    print(f"  {C_BOLD}[{num}/{total}]{C_RESET} {msg}")


def ok(msg):
    print(f"  {C_GREEN}✓{C_RESET} {msg}")


def warn(msg):
    print(f"  {C_YELLOW}⚠{C_RESET} {msg}")


def fail(msg):
    print(f"  {C_RED}✗{C_RESET} {msg}")
    sys.exit(1)


def run(cmd, **kwargs):
    """Run a shell command, streaming output."""
    kwargs.setdefault("cwd", str(PROJECT_ROOT))
    kwargs.setdefault("check", True)
    if isinstance(cmd, str):
        kwargs["shell"] = True
    return subprocess.run(cmd, **kwargs)


def detect_host_os():
    """Return normalised OS name."""
    s = platform.system()
    if s == "Darwin":
        return "macOS"
    return s          # "Windows" or "Linux"


def ensure_pyinstaller():
    """Verify PyInstaller is installed."""
    try:
        import PyInstaller
        ok(f"PyInstaller {PyInstaller.__version__} found")
    except ImportError:
        warn("PyInstaller not found — installing...")
        run([sys.executable, "-m", "pip", "install", "pyinstaller"])
        ok("PyInstaller installed")


def clean_build():
    """Remove all build / dist artifacts."""
    for d in ["build", "dist", "__pycache__"]:
        p = PROJECT_ROOT / d
        if p.exists():
            shutil.rmtree(p)
            ok(f"Removed {d}/")
    for f in PROJECT_ROOT.glob("*.spec"):
        if f.name.startswith("_build_"):
            f.unlink()
            ok(f"Removed {f.name}")
    ok("Clean complete")


# ── Spec-file generators ──────────────────────────────────────────
def _data_pairs():
    """Return list of (src, dest) data directory tuples."""
    pairs = []
    for d in DATA_DIRS:
        src = PROJECT_ROOT / d
        if src.is_dir():
            pairs.append((str(src), d))
    # Include .ui files explicitly
    for ui_file in PROJECT_ROOT.glob("ui/*.ui"):
        pairs.append((str(ui_file), "ui"))
    # Include .qss files
    for qss_file in PROJECT_ROOT.glob("styles/*.qss"):
        pairs.append((str(qss_file), "styles"))
    return pairs


def _hidden_imports(target_os):
    """Return full list of hidden imports for target OS."""
    imports = list(COMMON_HIDDEN_IMPORTS)
    if target_os == "Windows":
        imports.extend(WIN_HIDDEN_IMPORTS)
    return imports


# ── Windows Build ─────────────────────────────────────────────────
def build_windows(mode="onedir"):
    """Build Windows .exe using PyInstaller."""
    total = 5
    step(1, total, "Preparing Windows build...")

    hidden = _hidden_imports("Windows")
    data = _data_pairs()

    # Build PyInstaller command
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--name", APP_NAME,
        "--windowed",           # No console window
    ]

    # Icon
    ico = PROJECT_ROOT / "assets" / "icon.ico"
    if ico.exists():
        cmd.extend(["--icon", str(ico)])

    # Manifest for UAC elevation
    manifest = PROJECT_ROOT / "ForensicTool.manifest"
    if manifest.exists():
        cmd.extend(["--manifest", str(manifest)])

    # UAC admin
    cmd.append("--uac-admin")

    # Mode
    if mode == "onefile":
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")

    # Data dirs
    for src, dest in data:
        cmd.extend(["--add-data", f"{src}{os.pathsep}{dest}"])

    # Hidden imports
    for imp in hidden:
        cmd.extend(["--hidden-import", imp])

    # Excludes
    for exc in EXCLUDES:
        cmd.extend(["--exclude-module", exc])

    # Entry point
    cmd.append(str(PROJECT_ROOT / ENTRY_POINT))

    step(2, total, "Running PyInstaller (this takes a few minutes)...")
    run(cmd)

    step(3, total, "Verifying output...")
    if mode == "onefile":
        exe = PROJECT_ROOT / "dist" / f"{APP_NAME}.exe"
    else:
        exe = PROJECT_ROOT / "dist" / APP_NAME / f"{APP_NAME}.exe"

    if not exe.exists():
        fail(f"Expected output not found: {exe}")

    size_mb = exe.stat().st_size / (1024 * 1024)
    ok(f"Built: {exe}  ({size_mb:.1f} MB)")

    step(4, total, "Writing distribution README...")
    write_readme("Windows", PROJECT_ROOT / "dist")

    step(5, total, "Build complete!")
    print(f"\n  {C_GREEN}{'='*50}")
    print(f"   Output: {exe}")
    print(f"   Run:    Right-click → Run as Administrator")
    print(f"  {'='*50}{C_RESET}\n")
    return exe


# ── macOS Build ───────────────────────────────────────────────────
def build_macos(mode="onedir"):
    """Build macOS .app bundle, optionally wrap in .dmg."""
    total = 6
    step(1, total, "Preparing macOS build...")

    hidden = _hidden_imports("macOS")
    data = _data_pairs()

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--name", APP_NAME,
        "--windowed",           # Creates .app bundle on macOS
        "--osx-bundle-identifier", APP_ID,
    ]

    # Icon (.icns for macOS)
    icns = PROJECT_ROOT / "assets" / "icon.icns"
    ico = PROJECT_ROOT / "assets" / "icon.ico"
    if icns.exists():
        cmd.extend(["--icon", str(icns)])
    elif ico.exists():
        warn("No .icns icon found — using .ico (may look blurry)")
        cmd.extend(["--icon", str(ico)])

    if mode == "onefile":
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")

    # Entitlements for macOS (memory access, etc.)
    entitlements = PROJECT_ROOT / "build_resources" / "entitlements.plist"
    if entitlements.exists():
        cmd.extend(["--osx-entitlements-file", str(entitlements)])

    for src, dest in data:
        cmd.extend(["--add-data", f"{src}:{dest}"])

    for imp in hidden:
        cmd.extend(["--hidden-import", imp])

    for exc in EXCLUDES:
        cmd.extend(["--exclude-module", exc])

    cmd.append(str(PROJECT_ROOT / ENTRY_POINT))

    step(2, total, "Running PyInstaller...")
    run(cmd)

    step(3, total, "Verifying .app bundle...")
    app_bundle = PROJECT_ROOT / "dist" / f"{APP_NAME}.app"
    app_dir = PROJECT_ROOT / "dist" / APP_NAME

    if app_bundle.exists():
        ok(f"App bundle: {app_bundle}")
    elif app_dir.exists():
        ok(f"App directory: {app_dir}")
    else:
        fail("Build output not found")

    # Attempt to create .dmg
    step(4, total, "Creating .dmg installer (if create-dmg available)...")
    dmg_path = None
    try:
        run(["which", "create-dmg"], capture_output=True, check=True)
        dmg_path = PROJECT_ROOT / "dist" / f"{APP_NAME}-{APP_VERSION}-macOS.dmg"

        dmg_cmd = [
            "create-dmg",
            "--volname", f"{APP_NAME} Installer",
            "--volicon", str(icns) if icns.exists() else "",
            "--window-pos", "200", "120",
            "--window-size", "600", "400",
            "--icon-size", "100",
            "--icon", f"{APP_NAME}.app", "175", "180",
            "--app-drop-link", "425", "180",
            "--hide-extension", f"{APP_NAME}.app",
            str(dmg_path),
            str(PROJECT_ROOT / "dist"),
        ]
        # Filter empty strings
        dmg_cmd = [x for x in dmg_cmd if x]
        run(dmg_cmd)
        ok(f"DMG created: {dmg_path}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        warn("create-dmg not found — skipping .dmg creation")
        warn("Install with: brew install create-dmg")

    step(5, total, "Writing distribution README...")
    write_readme("macOS", PROJECT_ROOT / "dist")

    step(6, total, "Build complete!")
    output = dmg_path or app_bundle or app_dir
    print(f"\n  {C_GREEN}{'='*50}")
    print(f"   Output: {output}")
    print(f"   Run:    sudo open {APP_NAME}.app")
    print(f"  {'='*50}{C_RESET}\n")
    return output


# ── Linux Build ───────────────────────────────────────────────────
def build_linux(mode="onefile"):
    """Build Linux binary. Default to onefile for easy distribution."""
    total = 6
    step(1, total, "Preparing Linux build...")

    hidden = _hidden_imports("Linux")
    data = _data_pairs()

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--name", APP_NAME,
        "--windowed",
    ]

    # Icon
    png = PROJECT_ROOT / "assets" / "icon.png"
    ico = PROJECT_ROOT / "assets" / "icon.ico"
    if png.exists():
        cmd.extend(["--icon", str(png)])
    elif ico.exists():
        cmd.extend(["--icon", str(ico)])

    if mode == "onefile":
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")

    for src, dest in data:
        cmd.extend(["--add-data", f"{src}:{dest}"])

    for imp in hidden:
        cmd.extend(["--hidden-import", imp])

    for exc in EXCLUDES:
        cmd.extend(["--exclude-module", exc])

    cmd.append(str(PROJECT_ROOT / ENTRY_POINT))

    step(2, total, "Running PyInstaller...")
    run(cmd)

    step(3, total, "Verifying output...")
    if mode == "onefile":
        binary = PROJECT_ROOT / "dist" / APP_NAME
    else:
        binary = PROJECT_ROOT / "dist" / APP_NAME / APP_NAME

    if not binary.exists():
        fail(f"Expected output not found: {binary}")

    # Make executable
    binary.chmod(0o755)
    size_mb = binary.stat().st_size / (1024 * 1024)
    ok(f"Built: {binary}  ({size_mb:.1f} MB)")

    # Create .desktop launcher
    step(4, total, "Creating .desktop launcher & AppDir...")
    create_linux_desktop(binary)

    step(5, total, "Writing distribution README...")
    write_readme("Linux", PROJECT_ROOT / "dist")

    step(6, total, "Build complete!")
    print(f"\n  {C_GREEN}{'='*50}")
    print(f"   Output: {binary}")
    print(f"   Run:    sudo ./{APP_NAME}")
    print(f"  {'='*50}{C_RESET}\n")
    return binary


def create_linux_desktop(binary_path):
    """Create a .desktop launcher for Linux."""
    desktop = f"""[Desktop Entry]
Name=triageX Forensic Tool
Comment=Cross-Platform Forensic Triage Tool
Exec=sudo {binary_path}
Icon={PROJECT_ROOT / 'assets' / 'icon.png'}
Terminal=true
Type=Application
Categories=System;Security;Utility;
Keywords=forensic;triage;security;incident;response;
"""
    desktop_file = PROJECT_ROOT / "dist" / f"{APP_NAME}.desktop"
    desktop_file.write_text(desktop)
    desktop_file.chmod(0o755)
    ok(f"Created {desktop_file.name}")


# ── README generator ──────────────────────────────────────────────
def write_readme(target_os, dist_dir):
    """Write a platform-specific README in dist/."""
    run_instructions = {
        "Windows": (
            "  1. Right-click ForensicTool.exe\n"
            "  2. Select 'Run as Administrator'\n"
            "  3. Activate license or start trial\n"
            "  4. Click 'Start Collection'\n"
        ),
        "macOS": (
            "  1. Open Terminal\n"
            "  2. Run: sudo open ForensicTool.app\n"
            "     (or drag to Applications, right-click → Open)\n"
            "  3. Grant Full Disk Access in System Settings → Privacy\n"
            "  4. Activate license or start trial\n"
        ),
        "Linux": (
            "  1. Open Terminal\n"
            "  2. chmod +x ForensicTool\n"
            "  3. sudo ./ForensicTool\n"
            "  4. Activate license or start trial\n"
        ),
    }

    readme = f"""{'='*62}
  triageX Forensic Tool v{APP_VERSION} — {target_os} Edition
  Built: {datetime.now().strftime('%Y-%m-%d %H:%M')}
{'='*62}

HOW TO RUN:
{run_instructions.get(target_os, '')}

FEATURES:
  • Cross-platform forensic triage (Windows / macOS / Linux)
  • OS command collection with auto-detection
  • Browser history analysis (Chrome, Firefox, Edge, Safari)
  • Hash analysis with VirusTotal integration
  • IOC scanning & regex pattern matching
  • PII detection across user directories
  • Encrypted file detection
  • Memory analysis (RAM info, process memory, dumps)
  • Professional HTML report generation
  {"• Windows Registry, Event Logs, MFT, Pagefile analysis" if target_os == "Windows" else ""}

SYSTEM REQUIREMENTS:
  • {"Windows 10/11" if target_os == "Windows" else "macOS 12+" if target_os == "macOS" else "Ubuntu 20.04+ / Fedora 36+ / Debian 11+"}
  • {"Administrator" if target_os == "Windows" else "root/sudo"} privileges (for full forensic access)
  • 4 GB RAM minimum
  • 500 MB free disk space
  • Display resolution: 1280×720 or higher

{'='*62}
"""
    readme_path = dist_dir / "README.txt"
    readme_path.write_text(readme)
    ok("README.txt written")


# ── Pre-flight checks ─────────────────────────────────────────────
def preflight(target_os):
    """Verify all prerequisites before building."""
    print(f"\n  {C_CYAN}Pre-flight checks for {target_os}...{C_RESET}\n")

    # Python version
    if sys.version_info < (3, 9):
        fail(f"Python 3.9+ required, found {platform.python_version()}")
    ok(f"Python {platform.python_version()}")

    # PyInstaller
    ensure_pyinstaller()

    # PyQt6
    try:
        from PyQt6.QtWidgets import QApplication
        ok("PyQt6 available")
    except ImportError:
        fail("PyQt6 not installed. Run: pip install PyQt6")

    # Entry point exists
    entry = PROJECT_ROOT / ENTRY_POINT
    if not entry.exists():
        fail(f"Entry point not found: {entry}")
    ok(f"Entry point: {ENTRY_POINT}")

    # Data directories
    for d in DATA_DIRS:
        p = PROJECT_ROOT / d
        if p.is_dir():
            ok(f"Data dir: {d}/  ({sum(1 for _ in p.rglob('*') if _.is_file())} files)")
        else:
            warn(f"Data dir missing: {d}/  (may cause runtime issues)")

    # Platform-specific checks
    if target_os == "Windows":
        try:
            import win32api
            ok("pywin32 available")
        except ImportError:
            warn("pywin32 not installed — Windows-specific features may fail at runtime")

    if target_os == "macOS":
        # Check for Xcode command line tools
        try:
            run(["xcode-select", "-p"], capture_output=True, check=True)
            ok("Xcode CLI tools found")
        except (subprocess.CalledProcessError, FileNotFoundError):
            warn("Xcode CLI tools not found — install with: xcode-select --install")

    print()


# ── Main entry point ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="triageX Cross-Platform Build System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python build.py                     # auto-detect OS, build
    python build.py --target macos      # build macOS .app
    python build.py --mode onefile      # single executable
    python build.py --clean             # remove build artifacts
    python build.py --check             # verify prerequisites only
        """
    )
    parser.add_argument(
        "--target", "-t",
        choices=["windows", "macos", "linux", "auto"],
        default="auto",
        help="Target OS (default: auto-detect)"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["onefile", "onedir"],
        default=None,
        help="Packaging mode (default: onedir for Windows/macOS, onefile for Linux)"
    )
    parser.add_argument(
        "--clean", action="store_true",
        help="Remove all build artifacts and exit"
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Run pre-flight checks only"
    )

    args = parser.parse_args()

    banner()

    # Clean
    if args.clean:
        print(f"  {C_CYAN}Cleaning build artifacts...{C_RESET}\n")
        clean_build()
        return

    # Determine target
    if args.target == "auto":
        target_os = detect_host_os()
    else:
        target_os = {"windows": "Windows", "macos": "macOS", "linux": "Linux"}[args.target]

    print(f"  Target OS: {C_BOLD}{target_os}{C_RESET}")
    print(f"  Host:      {platform.system()} {platform.machine()}")
    print(f"  Python:    {platform.python_version()}")

    # Pre-flight
    preflight(target_os)

    if args.check:
        print(f"  {C_GREEN}All checks passed!{C_RESET}\n")
        return

    # Determine default mode per platform
    if args.mode:
        mode = args.mode
    else:
        mode = "onefile" if target_os == "Linux" else "onedir"

    print(f"  Build mode: {C_BOLD}{mode}{C_RESET}\n")

    # Build
    if target_os == "Windows":
        build_windows(mode)
    elif target_os == "macOS":
        build_macos(mode)
    elif target_os == "Linux":
        build_linux(mode)
    else:
        fail(f"Unsupported target: {target_os}")


if __name__ == "__main__":
    main()
