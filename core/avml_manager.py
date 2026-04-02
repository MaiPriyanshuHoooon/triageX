"""
AVML Binary Manager
====================
Downloads, caches, and manages the Microsoft AVML binary for Linux
memory acquisition.

AVML (Acquire Volatile Memory for Linux) is a portable memory acquisition
tool written in Rust by Microsoft. It produces LiME-format memory images
compatible with Volatility, Rekall, and other forensic analysis tools.

This module:
  - Auto-detects CPU architecture (x86_64 / aarch64)
  - Downloads the correct pre-built static binary from GitHub Releases
  - Caches it locally so re-downloads are not needed
  - Verifies integrity (size check)
  - Provides a single entry point: get_avml_binary() -> Path

Source: https://github.com/microsoft/avml
License: MIT (Microsoft)
"""

import os
import sys
import stat
import shutil
import logging
import platform
import subprocess
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────
AVML_VERSION = "0.17.0"
AVML_REPO = "microsoft/avml"
AVML_BASE_URL = f"https://github.com/{AVML_REPO}/releases/download/v{AVML_VERSION}"

# Binary names per architecture
AVML_BINARIES = {
    "x86_64":  "avml",
    "aarch64": "avml-aarch64",
    "arm64":   "avml-aarch64",   # alias
}

# Minimum expected sizes (bytes) to verify download is not corrupt
AVML_MIN_SIZES = {
    "avml":          500_000,   # ~1.75 MB actual
    "avml-aarch64":  400_000,   # ~1.53 MB actual
}

# Cache directory name (inside the output/tools folder)
CACHE_DIR_NAME = "avml_tools"


# ── Public API ─────────────────────────────────────────────────

def get_avml_binary(output_dir=None, force_download=False):
    """
    Get a ready-to-use AVML binary path.

    1. If already cached locally, return that path.
    2. Otherwise download from GitHub Releases.
    3. Make it executable.

    Args:
        output_dir: Directory where tools/ cache is stored.
                    Defaults to ~/.triagex/tools/
        force_download: Re-download even if cached.

    Returns:
        Path to the avml binary (ready to execute with sudo)

    Raises:
        RuntimeError: If not on Linux, or download fails.
    """
    if platform.system() != "Linux":
        raise RuntimeError(
            f"AVML only runs on Linux. Current OS: {platform.system()}. "
            "Memory acquisition via AVML is not available on this platform."
        )

    arch = platform.machine()
    binary_name = AVML_BINARIES.get(arch)
    if not binary_name:
        raise RuntimeError(
            f"Unsupported architecture: {arch}. "
            f"AVML supports: {', '.join(AVML_BINARIES.keys())}"
        )

    # ── Check for bundled binary (PyInstaller dist) first ──
    if not force_download:
        bundled = _get_bundled_avml()
        if bundled:
            logger.info(f"Using bundled AVML binary: {bundled}")
            _ensure_executable(bundled)
            return bundled

    # Determine cache directory
    cache_dir = _get_cache_dir(output_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    cached_path = cache_dir / "avml"

    # Check if we already have a valid cached binary
    if not force_download and cached_path.exists():
        min_size = AVML_MIN_SIZES.get(binary_name, 400_000)
        if cached_path.stat().st_size >= min_size:
            logger.info(f"Using cached AVML binary: {cached_path}")
            _ensure_executable(cached_path)
            return cached_path
        else:
            logger.warning("Cached AVML binary appears corrupt, re-downloading...")
            cached_path.unlink()

    # Download
    download_url = f"{AVML_BASE_URL}/{binary_name}"
    logger.info(f"Downloading AVML v{AVML_VERSION} ({binary_name}) from {download_url}")
    print(f"    [*] Downloading AVML v{AVML_VERSION} for {arch}...")

    try:
        _download_file(download_url, cached_path)
    except Exception as e:
        raise RuntimeError(
            f"Failed to download AVML: {e}\n"
            f"URL: {download_url}\n"
            "You can manually download from: "
            f"https://github.com/{AVML_REPO}/releases/tag/v{AVML_VERSION}"
        ) from e

    # Verify
    min_size = AVML_MIN_SIZES.get(binary_name, 400_000)
    actual_size = cached_path.stat().st_size
    if actual_size < min_size:
        cached_path.unlink()
        raise RuntimeError(
            f"Downloaded AVML binary is too small ({actual_size} bytes). "
            "Download may have failed. Please check your internet connection."
        )

    _ensure_executable(cached_path)
    print(f"    [+] AVML v{AVML_VERSION} ready ({_human_size(actual_size)})")
    logger.info(f"AVML binary downloaded: {cached_path} ({actual_size} bytes)")

    # Write a version marker
    version_file = cache_dir / "VERSION"
    version_file.write_text(f"avml {AVML_VERSION}\n{binary_name}\n{arch}\n")

    return cached_path


def is_avml_available(output_dir=None):
    """
    Check if AVML can be used on this system (Linux only).

    Returns:
        dict with keys: available (bool), reason (str), arch (str)
    """
    if platform.system() != "Linux":
        return {
            "available": False,
            "reason": f"AVML only runs on Linux (current OS: {platform.system()})",
            "arch": platform.machine(),
        }

    arch = platform.machine()
    if arch not in AVML_BINARIES:
        return {
            "available": False,
            "reason": f"Unsupported architecture: {arch}",
            "arch": arch,
        }

    # Check if bundled (PyInstaller dist) or already cached
    bundled = _get_bundled_avml()
    cache_dir = _get_cache_dir(output_dir)
    cached = cache_dir / "avml"
    is_cached = cached.exists() and cached.stat().st_size > 400_000
    is_bundled = bundled is not None

    return {
        "available": True,
        "reason": "AVML can acquire full physical memory on this Linux system",
        "arch": arch,
        "binary_name": AVML_BINARIES[arch],
        "version": AVML_VERSION,
        "cached": is_cached or is_bundled,
        "bundled": is_bundled,
        "cache_path": str(bundled) if is_bundled else (str(cached) if is_cached else None),
    }


# ── Internal helpers ───────────────────────────────────────────

def _get_bundled_avml():
    """Check if AVML is bundled inside a PyInstaller distribution.

    When build.py bundles the AVML binary during a Linux build, it gets
    placed in `avml_tools/avml` inside the PyInstaller `_MEIPASS` directory.
    This function checks for that bundled copy first, avoiding a download.

    Returns:
        Path to bundled binary if found and valid, else None.
    """
    # PyInstaller sets sys._MEIPASS to the temp extraction dir
    meipass = getattr(sys, "_MEIPASS", None)
    if not meipass:
        return None

    bundled = Path(meipass) / "avml_tools" / "avml"
    if bundled.exists() and bundled.stat().st_size > 400_000:
        return bundled

    return None


def _get_cache_dir(output_dir=None):
    """Return the cache directory for AVML tools."""
    if output_dir:
        return Path(output_dir) / CACHE_DIR_NAME
    # Default: ~/.triagex/tools/
    return Path.home() / ".triagex" / "tools"


def _ensure_executable(path):
    """Ensure the binary has execute permission."""
    current = path.stat().st_mode
    path.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _download_file(url, dest):
    """Download a file from a URL with redirect support."""
    request = Request(url, headers={"User-Agent": "triageX-forensic-tool/2.0"})

    try:
        with urlopen(request, timeout=120) as response:
            total = int(response.headers.get("Content-Length", 0))
            downloaded = 0
            chunk_size = 65536

            with open(dest, "wb") as f:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)

                    if total > 0:
                        pct = (downloaded / total) * 100
                        bar = "#" * int(pct // 5) + "-" * (20 - int(pct // 5))
                        print(f"\r    [{bar}] {pct:.0f}%  {_human_size(downloaded)}", end="", flush=True)

            print()  # newline after progress bar

    except HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.reason}") from e
    except URLError as e:
        raise RuntimeError(f"Network error: {e.reason}") from e


def _human_size(size_bytes):
    """Convert bytes to human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"
