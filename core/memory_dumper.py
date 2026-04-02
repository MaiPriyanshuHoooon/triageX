"""
Memory Dump Module
==================
Cross-platform volatile memory acquisition for forensic triage.

Linux:   Uses AVML (auto-downloaded) for full physical RAM dump in LiME format,
         with fallback to /proc/kcore, /dev/crash, or /dev/mem for samples
macOS:   Collects VM stats, process memory maps, and system memory info
Windows: Collects existing crash dumps, hibernation file info, and process memory details

AVML source: https://github.com/microsoft/avml (MIT License, Microsoft)
"""

import os
import sys
import json
import time
import hashlib
import platform
import subprocess
import struct
import logging
from datetime import datetime
from pathlib import Path

from core.os_detector import detect_os, is_admin, OS_WINDOWS, OS_LINUX, OS_MACOS

logger = logging.getLogger(__name__)


# ============================================================
# COMMON UTILITIES
# ============================================================

def get_human_readable_size(size_bytes):
    """Convert bytes to human-readable format."""
    if size_bytes == 0:
        return "0 B"
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    size = float(size_bytes)
    while size >= 1024 and i < len(units) - 1:
        size /= 1024
        i += 1
    return f"{size:.2f} {units[i]}"


def compute_file_hash(filepath, algorithm='sha256'):
    """Compute hash of a file in chunks (handles large files)."""
    h = hashlib.new(algorithm)
    try:
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"Error: {e}"


# ============================================================
# LINUX MEMORY DUMPER  (inspired by AVML)
# ============================================================

class LinuxMemoryDumper:
    """
    Acquire volatile memory on Linux systems.

    Memory sources (in priority order):
      1. /proc/kcore  — virtual ELF coredump of kernel memory
      2. /dev/crash   — read-only physical memory (RHEL/CentOS)
      3. /dev/mem     — physical memory device (may be restricted)

    System RAM ranges are parsed from /proc/iomem.
    """

    SOURCES = [
        ("/proc/kcore", "Virtual ELF coredump of kernel memory"),
        ("/dev/crash", "Read-only physical memory device (RHEL/CentOS)"),
        ("/dev/mem", "Physical memory device"),
    ]

    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.results = {
            "os": "Linux",
            "status": "not_started",
            "is_admin": is_admin(),
            "system_memory": {},
            "memory_sources": [],
            "iomem_ranges": [],
            "dump_info": None,
            "process_memory": [],
            "errors": [],
            "warnings": [],
        }

    # ---------- System RAM info ----------

    def get_system_memory_info(self):
        """Parse /proc/meminfo for total/available/used RAM."""
        info = {}
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        key = parts[0].rstrip(":")
                        val_kb = int(parts[1])
                        info[key] = val_kb * 1024  # store in bytes
            self.results["system_memory"] = {
                "total": info.get("MemTotal", 0),
                "total_human": get_human_readable_size(info.get("MemTotal", 0)),
                "available": info.get("MemAvailable", info.get("MemFree", 0)),
                "available_human": get_human_readable_size(info.get("MemAvailable", info.get("MemFree", 0))),
                "used": info.get("MemTotal", 0) - info.get("MemAvailable", info.get("MemFree", 0)),
                "used_human": get_human_readable_size(
                    info.get("MemTotal", 0) - info.get("MemAvailable", info.get("MemFree", 0))
                ),
                "swap_total": info.get("SwapTotal", 0),
                "swap_total_human": get_human_readable_size(info.get("SwapTotal", 0)),
                "swap_free": info.get("SwapFree", 0),
                "swap_free_human": get_human_readable_size(info.get("SwapFree", 0)),
                "buffers": info.get("Buffers", 0),
                "cached": info.get("Cached", 0),
            }
        except Exception as e:
            self.results["errors"].append(f"Failed to read /proc/meminfo: {e}")
            self.results["system_memory"] = {"error": str(e)}
        return self.results["system_memory"]

    # ---------- /proc/iomem parsing (AVML-style) ----------

    def parse_iomem(self):
        """
        Parse /proc/iomem to find System RAM address ranges.
        This mirrors AVML's iomem.rs::parse() logic.
        Requires CAP_SYS_ADMIN / root for full addresses.
        """
        ranges = []
        try:
            with open("/proc/iomem", "r") as f:
                for line in f:
                    # Only top-level lines (no leading spaces) that are "System RAM"
                    if line.startswith(" "):
                        continue
                    if "System RAM" not in line:
                        continue
                    # Format: "00001000-0009ffff : System RAM"
                    addr_part = line.split(":")[0].strip()
                    if "-" not in addr_part:
                        continue
                    start_hex, end_hex = addr_part.split("-")
                    start = int(start_hex, 16)
                    end = int(end_hex, 16)
                    if start == 0 and end == 0:
                        continue
                    ranges.append({
                        "start": start,
                        "end": end,
                        "start_hex": f"0x{start_hex}",
                        "end_hex": f"0x{end_hex}",
                        "size": end - start + 1,
                        "size_human": get_human_readable_size(end - start + 1),
                    })
        except PermissionError:
            self.results["warnings"].append(
                "/proc/iomem requires root for full addresses. "
                "Non-root reads show zeroed addresses."
            )
        except Exception as e:
            self.results["errors"].append(f"Failed to parse /proc/iomem: {e}")

        self.results["iomem_ranges"] = ranges
        total_ram = sum(r["size"] for r in ranges)
        self.results["iomem_total"] = total_ram
        self.results["iomem_total_human"] = get_human_readable_size(total_ram)
        return ranges

    # ---------- Check available memory sources ----------

    def check_memory_sources(self):
        """Check which memory acquisition sources are available."""
        sources = []
        for path, description in self.SOURCES:
            entry = {
                "path": path,
                "description": description,
                "exists": os.path.exists(path),
                "readable": False,
                "size": None,
                "usable": False,
            }
            if entry["exists"]:
                try:
                    with open(path, "rb") as f:
                        f.read(1)
                    entry["readable"] = True
                except PermissionError:
                    entry["readable"] = False
                    self.results["warnings"].append(
                        f"{path} exists but is not readable (need root/CAP_SYS_ADMIN)"
                    )
                except Exception:
                    entry["readable"] = False

                # Special size check for /proc/kcore
                if path == "/proc/kcore" and entry["readable"]:
                    try:
                        size = os.path.getsize(path)
                        entry["size"] = size
                        entry["size_human"] = get_human_readable_size(size)
                        # kcore must be > 0x2000 (8KB) to be usable (AVML check)
                        entry["usable"] = size > 0x2000
                        if not entry["usable"]:
                            self.results["warnings"].append(
                                "/proc/kcore exists but appears locked down (size too small)"
                            )
                    except Exception:
                        pass
                elif entry["readable"]:
                    entry["usable"] = True

            sources.append(entry)

        self.results["memory_sources"] = sources
        return sources

    # ---------- Memory dump (lightweight/safe approach) ----------

    def acquire_memory_sample(self, max_mb=64):
        """
        Acquire a sample of physical memory (first N MB).
        This is a SAFE, lightweight approach — not a full RAM dump.

        For a full forensic RAM dump, use AVML directly:
            sudo ./avml --compress output.lime

        Args:
            max_mb: Maximum MB to dump (default 64 MB for safety)

        Returns:
            dict with dump metadata or error info
        """
        if not is_admin():
            self.results["dump_info"] = {
                "status": "skipped",
                "reason": "Root/sudo privileges required for memory acquisition",
                "recommendation": "Run with sudo, or use AVML: sudo ./avml --compress output.lime",
            }
            return self.results["dump_info"]

        # Find best available source
        source_path = None
        source_name = None
        for src in self.results.get("memory_sources", []):
            if src["usable"]:
                source_path = src["path"]
                source_name = src["path"]
                break

        if not source_path:
            self.results["dump_info"] = {
                "status": "failed",
                "reason": "No usable memory source found",
                "checked": [s["path"] for s in self.results.get("memory_sources", [])],
                "recommendation": "Kernel lockdown may be active. Use AVML with appropriate kernel module.",
            }
            return self.results["dump_info"]

        # Perform the dump
        dump_filename = f"memory_sample_{self.timestamp}.raw"
        dump_path = os.path.join(self.output_dir, dump_filename)
        max_bytes = max_mb * 1024 * 1024

        start_time = time.time()
        bytes_read = 0

        try:
            with open(source_path, "rb") as src, open(dump_path, "wb") as dst:
                while bytes_read < max_bytes:
                    chunk_size = min(4096, max_bytes - bytes_read)
                    data = src.read(chunk_size)
                    if not data:
                        break
                    dst.write(data)
                    bytes_read += len(data)

            elapsed = time.time() - start_time

            # Compute hash of the dump
            dump_hash = compute_file_hash(dump_path, "sha256")

            self.results["dump_info"] = {
                "status": "success",
                "source": source_name,
                "output_file": dump_path,
                "output_filename": dump_filename,
                "bytes_dumped": bytes_read,
                "size_human": get_human_readable_size(bytes_read),
                "max_requested": get_human_readable_size(max_bytes),
                "duration_seconds": round(elapsed, 2),
                "sha256": dump_hash,
                "format": "raw",
                "timestamp": self.timestamp,
            }

        except Exception as e:
            self.results["dump_info"] = {
                "status": "failed",
                "source": source_name,
                "reason": str(e),
                "bytes_before_failure": bytes_read,
            }
            self.results["errors"].append(f"Memory dump failed: {e}")

        return self.results["dump_info"]

    # ---------- Full AVML memory dump ----------

    def acquire_full_dump(self, compress=True, max_wait=600):
        """
        Acquire a FULL physical memory dump using Microsoft AVML.

        Downloads the AVML binary (if not cached), then runs it with sudo
        to capture the entire physical RAM in LiME format. The output file
        is placed in the output directory and linked in the HTML report
        as a downloadable artifact.

        Args:
            compress: Use Snappy compression (--compress). Saves ~40-60% space.
            max_wait: Maximum seconds to wait for the dump to complete.

        Returns:
            dict with dump metadata (status, output_file, sha256, size, etc.)
        """
        from core.avml_manager import get_avml_binary, is_avml_available, AVML_VERSION

        # Pre-flight checks
        avml_check = is_avml_available(self.output_dir)
        if not avml_check["available"]:
            self.results["dump_info"] = {
                "status": "failed",
                "reason": avml_check["reason"],
                "recommendation": "AVML requires Linux x86_64 or aarch64.",
            }
            return self.results["dump_info"]

        if not is_admin():
            self.results["dump_info"] = {
                "status": "failed",
                "reason": "Root/sudo privileges required for full memory acquisition",
                "recommendation": "Run triageX with sudo for full memory dump.",
            }
            return self.results["dump_info"]

        # Get AVML binary (downloads if needed)
        try:
            avml_path = get_avml_binary(self.output_dir)
        except RuntimeError as e:
            self.results["dump_info"] = {
                "status": "failed",
                "reason": f"Could not obtain AVML binary: {e}",
                "recommendation": "Check internet connection, or manually place avml in output/avml_tools/",
            }
            self.results["errors"].append(f"AVML download failed: {e}")
            return self.results["dump_info"]

        # Build output filename
        ext = ".lime.compressed" if compress else ".lime"
        dump_filename = f"memory_dump_{self.timestamp}{ext}"
        dump_path = os.path.join(self.output_dir, dump_filename)

        # Build AVML command
        cmd = [str(avml_path)]
        if compress:
            cmd.append("--compress")
        cmd.append(dump_path)

        logger.info(f"Starting AVML memory acquisition: {' '.join(cmd)}")
        print(f"    [*] Acquiring full memory dump with AVML v{AVML_VERSION}...")
        print(f"    [*] Output: {dump_filename}")
        if compress:
            print(f"    [*] Compression: Snappy (enabled)")

        start_time = time.time()

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Monitor progress by watching file size growth
            last_size = 0
            total_ram = self.results.get("system_memory", {}).get("total", 0)

            while proc.poll() is None:
                time.sleep(2)
                elapsed = time.time() - start_time

                if elapsed > max_wait:
                    proc.kill()
                    self.results["dump_info"] = {
                        "status": "failed",
                        "reason": f"AVML timed out after {max_wait}s",
                        "recommendation": "System may have too much RAM for the timeout. Increase max_wait.",
                    }
                    return self.results["dump_info"]

                # Show progress
                if os.path.exists(dump_path):
                    current_size = os.path.getsize(dump_path)
                    if current_size != last_size:
                        speed = current_size / elapsed if elapsed > 0 else 0
                        size_str = self._human_size(current_size)
                        speed_str = self._human_size(speed) + "/s"
                        if total_ram > 0:
                            # Rough estimate (compressed output is smaller than RAM)
                            ratio = 0.6 if compress else 1.0
                            pct = min((current_size / (total_ram * ratio)) * 100, 99)
                            print(f"\r    [*] Dumping... {size_str} ({pct:.0f}%) @ {speed_str}   ", end="", flush=True)
                        else:
                            print(f"\r    [*] Dumping... {size_str} @ {speed_str}   ", end="", flush=True)
                        last_size = current_size

            # Process finished
            print()  # newline after progress
            returncode = proc.returncode
            stdout = proc.stdout.read().decode(errors="replace").strip()
            stderr = proc.stderr.read().decode(errors="replace").strip()

            elapsed = time.time() - start_time

            if returncode != 0:
                error_msg = stderr or stdout or f"AVML exited with code {returncode}"
                self.results["dump_info"] = {
                    "status": "failed",
                    "reason": error_msg,
                    "returncode": returncode,
                    "duration_seconds": round(elapsed, 2),
                    "recommendation": (
                        "Kernel lockdown may be active. Check: "
                        "cat /sys/kernel/security/lockdown"
                    ),
                }
                self.results["errors"].append(f"AVML failed: {error_msg}")
                return self.results["dump_info"]

            # Success — gather metadata
            if not os.path.exists(dump_path):
                self.results["dump_info"] = {
                    "status": "failed",
                    "reason": "AVML returned success but output file not found",
                }
                return self.results["dump_info"]

            file_size = os.path.getsize(dump_path)
            dump_hash = compute_file_hash(dump_path, "sha256")

            print(f"    [+] Memory dump complete!")
            print(f"    [+] File: {dump_filename}")
            print(f"    [+] Size: {self._human_size(file_size)}")
            print(f"    [+] Duration: {elapsed:.1f}s")
            print(f"    [+] SHA-256: {dump_hash[:32]}...")

            self.results["dump_info"] = {
                "status": "success",
                "method": "avml",
                "avml_version": AVML_VERSION,
                "source": "auto (AVML selects best: /proc/kcore > /dev/crash > /dev/mem)",
                "output_file": dump_path,
                "output_filename": dump_filename,
                "bytes_dumped": file_size,
                "size_human": self._human_size(file_size),
                "compressed": compress,
                "format": "lime_compressed" if compress else "lime",
                "format_description": "LiME format (Linux Memory Extractor) — compatible with Volatility, Rekall",
                "sha256": dump_hash,
                "duration_seconds": round(elapsed, 2),
                "timestamp": self.timestamp,
                "downloadable": True,
            }

        except FileNotFoundError:
            self.results["dump_info"] = {
                "status": "failed",
                "reason": "AVML binary not found or not executable",
                "recommendation": "Ensure the AVML binary was downloaded correctly.",
            }
            self.results["errors"].append("AVML binary not found")
        except PermissionError:
            self.results["dump_info"] = {
                "status": "failed",
                "reason": "Permission denied — AVML requires root privileges",
                "recommendation": "Run triageX with: sudo python3 forensics_tool.py",
            }
        except Exception as e:
            self.results["dump_info"] = {
                "status": "failed",
                "reason": str(e),
                "recommendation": "Check system logs for details.",
            }
            self.results["errors"].append(f"AVML error: {e}")

        return self.results["dump_info"]

    @staticmethod
    def _human_size(size_bytes):
        """Convert bytes to human-readable format."""
        return get_human_readable_size(size_bytes)

    # ---------- Process memory info ----------

    def get_process_memory_info(self, top_n=20):
        """Get memory usage of top N processes."""
        procs = []
        try:
            result = subprocess.run(
                ["ps", "aux", "--sort=-rss"],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.strip().split("\n")
            if len(lines) > 1:
                header = lines[0]
                for line in lines[1:top_n + 1]:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        procs.append({
                            "user": parts[0],
                            "pid": parts[1],
                            "cpu_pct": parts[2],
                            "mem_pct": parts[3],
                            "vsz_kb": int(parts[4]) if parts[4].isdigit() else 0,
                            "rss_kb": int(parts[5]) if parts[5].isdigit() else 0,
                            "rss_human": get_human_readable_size(int(parts[5]) * 1024) if parts[5].isdigit() else "N/A",
                            "command": parts[10] if len(parts) > 10 else "?",
                        })
        except Exception as e:
            self.results["errors"].append(f"Failed to get process memory info: {e}")

        self.results["process_memory"] = procs
        return procs

    # ---------- Kernel info ----------

    def get_kernel_memory_info(self):
        """Collect kernel-related memory information."""
        info = {}

        # Kernel version
        try:
            info["kernel_version"] = platform.release()
        except Exception:
            info["kernel_version"] = "Unknown"

        # Check kernel lockdown status
        lockdown_path = "/sys/kernel/security/lockdown"
        try:
            if os.path.exists(lockdown_path):
                with open(lockdown_path, "r") as f:
                    content = f.read().strip()
                    info["kernel_lockdown"] = content
                    # Parse: [none] integrity confidentiality
                    if "[confidentiality]" in content:
                        info["lockdown_level"] = "confidentiality"
                        self.results["warnings"].append(
                            "Kernel lockdown is set to 'confidentiality' — memory acquisition may fail"
                        )
                    elif "[integrity]" in content:
                        info["lockdown_level"] = "integrity"
                        self.results["warnings"].append(
                            "Kernel lockdown is set to 'integrity' — some memory sources may be restricted"
                        )
                    elif "[none]" in content:
                        info["lockdown_level"] = "none"
                    else:
                        info["lockdown_level"] = content
            else:
                info["kernel_lockdown"] = "Not available"
                info["lockdown_level"] = "unknown"
        except Exception as e:
            info["kernel_lockdown"] = f"Error: {e}"

        # Kernel command line
        try:
            with open("/proc/cmdline", "r") as f:
                info["kernel_cmdline"] = f.read().strip()
        except Exception:
            info["kernel_cmdline"] = "N/A"

        # KASLR status (from /proc/kallsyms)
        try:
            with open("/proc/kallsyms", "r") as f:
                first_line = f.readline()
                # If all addresses are 0, KASLR is hiding them (non-root)
                if first_line.startswith("0000000000000000"):
                    info["kaslr_note"] = "Symbols hidden (non-root or KASLR active)"
                else:
                    info["kaslr_note"] = "Kernel symbols visible"
        except Exception:
            info["kaslr_note"] = "Cannot read /proc/kallsyms"

        self.results["kernel_info"] = info
        return info

    # ---------- Full collection ----------

    def collect_all(self, acquire_sample=False, acquire_full=False, sample_max_mb=64):
        """
        Run all Linux memory analysis steps.

        Args:
            acquire_sample: Whether to attempt a small memory sample dump (requires root)
            acquire_full: Whether to attempt a FULL memory dump via AVML (requires root)
            sample_max_mb: Max size of sample dump in MB
        """
        self.results["status"] = "collecting"
        self.results["collection_start"] = datetime.now().isoformat()

        # 1. System memory info
        self.get_system_memory_info()

        # 2. Parse /proc/iomem
        self.parse_iomem()

        # 3. Check memory sources
        self.check_memory_sources()

        # 4. Kernel memory info
        self.get_kernel_memory_info()

        # 5. Process memory
        self.get_process_memory_info(top_n=20)

        # 6. Memory acquisition
        if acquire_full:
            # Full physical RAM dump via AVML
            self.acquire_full_dump(compress=True)
        elif acquire_sample:
            self.acquire_memory_sample(max_mb=sample_max_mb)
        else:
            self.results["dump_info"] = {
                "status": "skipped",
                "reason": "Memory acquisition not requested",
                "recommendation": "Enable full memory dump for complete forensic capture.",
            }

        self.results["status"] = "completed"
        self.results["collection_end"] = datetime.now().isoformat()
        return self.results


# ============================================================
# macOS MEMORY ANALYZER
# ============================================================

class MacOSMemoryDumper:
    """
    Memory analysis for macOS systems.

    Full physical RAM dump is not possible on modern macOS with SIP enabled.
    Instead, we collect:
      - System memory statistics (vm_stat)
      - Memory pressure info
      - Process memory maps (vmmap for key processes)
      - Swap/compressed memory info
      - Hardware memory details
    """

    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.results = {
            "os": "macOS",
            "status": "not_started",
            "is_admin": is_admin(),
            "system_memory": {},
            "vm_statistics": {},
            "memory_pressure": {},
            "process_memory": [],
            "swap_info": {},
            "hardware_memory": {},
            "dump_info": None,
            "errors": [],
            "warnings": [],
        }

    def get_system_memory_info(self):
        """Get system memory via sysctl."""
        info = {}
        try:
            # Total physical memory
            result = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                capture_output=True, text=True, timeout=5
            )
            total_bytes = int(result.stdout.strip())
            info["total"] = total_bytes
            info["total_human"] = get_human_readable_size(total_bytes)

            # Memory page size
            result = subprocess.run(
                ["sysctl", "-n", "hw.pagesize"],
                capture_output=True, text=True, timeout=5
            )
            info["page_size"] = int(result.stdout.strip())

        except Exception as e:
            self.results["errors"].append(f"Failed to get system memory: {e}")

        self.results["system_memory"] = info
        return info

    def get_vm_statistics(self):
        """Parse vm_stat output for virtual memory statistics."""
        stats = {}
        try:
            result = subprocess.run(
                ["vm_stat"],
                capture_output=True, text=True, timeout=5
            )
            page_size = self.results.get("system_memory", {}).get("page_size", 4096)

            for line in result.stdout.strip().split("\n"):
                if ":" not in line:
                    continue
                key, _, val = line.partition(":")
                val = val.strip().rstrip(".")
                key = key.strip()
                if val.isdigit():
                    pages = int(val)
                    stats[key] = {
                        "pages": pages,
                        "bytes": pages * page_size,
                        "human": get_human_readable_size(pages * page_size),
                    }

        except Exception as e:
            self.results["errors"].append(f"Failed to get vm_stat: {e}")

        self.results["vm_statistics"] = stats
        return stats

    def get_memory_pressure(self):
        """Get memory pressure information."""
        info = {}
        try:
            result = subprocess.run(
                ["sysctl", "-n", "kern.memorystatus_level"],
                capture_output=True, text=True, timeout=5
            )
            level = result.stdout.strip()
            if level.isdigit():
                info["pressure_level"] = int(level)
                info["pressure_description"] = (
                    "Normal" if int(level) > 50
                    else "Warning" if int(level) > 20
                    else "Critical"
                )
        except Exception:
            pass

        # Memory pressure via memory_pressure command
        try:
            result = subprocess.run(
                ["memory_pressure", "-S"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                info["pressure_report"] = result.stdout.strip()
        except Exception:
            pass

        self.results["memory_pressure"] = info
        return info

    def get_process_memory_info(self, top_n=20):
        """Get top processes by memory usage."""
        procs = []
        try:
            result = subprocess.run(
                ["ps", "aux", "-m"],  # -m sorts by memory
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.strip().split("\n")
            if len(lines) > 1:
                for line in lines[1:top_n + 1]:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        rss_kb = int(parts[5]) if parts[5].isdigit() else 0
                        procs.append({
                            "user": parts[0],
                            "pid": parts[1],
                            "cpu_pct": parts[2],
                            "mem_pct": parts[3],
                            "vsz_kb": int(parts[4]) if parts[4].isdigit() else 0,
                            "rss_kb": rss_kb,
                            "rss_human": get_human_readable_size(rss_kb * 1024),
                            "command": parts[10] if len(parts) > 10 else "?",
                        })
        except Exception as e:
            self.results["errors"].append(f"Failed to get process memory: {e}")

        self.results["process_memory"] = procs
        return procs

    def get_swap_info(self):
        """Get swap/compressed memory information."""
        info = {}
        try:
            result = subprocess.run(
                ["sysctl", "vm.swapusage"],
                capture_output=True, text=True, timeout=5
            )
            info["swap_usage"] = result.stdout.strip()
        except Exception:
            pass

        try:
            result = subprocess.run(
                ["sysctl", "-n", "vm.compressor_mode"],
                capture_output=True, text=True, timeout=5
            )
            mode = result.stdout.strip()
            modes = {
                "1": "Compress only",
                "2": "Swap only",
                "4": "Compress + swap",
            }
            info["compressor_mode"] = modes.get(mode, f"Mode {mode}")
        except Exception:
            pass

        # Compressed memory stats from vm_stat
        vm_stats = self.results.get("vm_statistics", {})
        if "Pages stored in compressor" in vm_stats:
            info["compressed_pages"] = vm_stats["Pages stored in compressor"]
        if "Pages occupied by compressor" in vm_stats:
            info["compressor_size"] = vm_stats["Pages occupied by compressor"]

        self.results["swap_info"] = info
        return info

    def get_hardware_memory_details(self):
        """Get hardware memory details via system_profiler."""
        info = {}
        try:
            result = subprocess.run(
                ["system_profiler", "SPMemoryDataType", "-json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                info["hardware_detail"] = data
        except Exception as e:
            # Fallback to non-JSON
            try:
                result = subprocess.run(
                    ["system_profiler", "SPMemoryDataType"],
                    capture_output=True, text=True, timeout=15
                )
                info["hardware_detail_text"] = result.stdout.strip()
            except Exception:
                pass

        self.results["hardware_memory"] = info
        return info

    def collect_all(self, acquire_sample=False, sample_max_mb=64):
        """Run all macOS memory analysis steps."""
        self.results["status"] = "collecting"
        self.results["collection_start"] = datetime.now().isoformat()

        self.results["warnings"].append(
            "Full physical RAM dump is not available on macOS with SIP enabled. "
            "Collecting system memory statistics, VM info, and process memory instead."
        )

        # 1. System memory info
        self.get_system_memory_info()

        # 2. VM statistics
        self.get_vm_statistics()

        # 3. Memory pressure
        self.get_memory_pressure()

        # 4. Process memory
        self.get_process_memory_info(top_n=20)

        # 5. Swap info
        self.get_swap_info()

        # 6. Hardware details
        self.get_hardware_memory_details()

        self.results["dump_info"] = {
            "status": "not_applicable",
            "reason": "macOS SIP prevents direct physical memory access",
            "recommendation": "Use osxpmem or disable SIP for full memory acquisition (not forensically sound)",
        }

        self.results["status"] = "completed"
        self.results["collection_end"] = datetime.now().isoformat()
        return self.results


# ============================================================
# WINDOWS MEMORY ANALYZER
# ============================================================

class WindowsMemoryDumper:
    """
    Memory analysis for Windows systems.

    Collects:
      - System memory information (wmic, systeminfo)
      - Existing crash dumps (MEMORY.DMP, minidumps)
      - Hibernation file info (hiberfil.sys)
      - Page file info (pagefile.sys)
      - Process memory usage
      - Crash dump analysis metadata
    """

    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.results = {
            "os": "Windows",
            "status": "not_started",
            "is_admin": is_admin(),
            "system_memory": {},
            "crash_dumps": [],
            "hibernation_file": {},
            "pagefile_info": {},
            "process_memory": [],
            "memory_dump_config": {},
            "dump_info": None,
            "errors": [],
            "warnings": [],
        }

    def get_system_memory_info(self):
        """Get system memory using wmic/PowerShell."""
        info = {}
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-CimInstance Win32_OperatingSystem | "
                 "Select-Object TotalVisibleMemorySize,FreePhysicalMemory,"
                 "TotalVirtualMemorySize,FreeVirtualMemory | "
                 "ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                total_kb = data.get("TotalVisibleMemorySize", 0)
                free_kb = data.get("FreePhysicalMemory", 0)
                info["total"] = total_kb * 1024
                info["total_human"] = get_human_readable_size(total_kb * 1024)
                info["free"] = free_kb * 1024
                info["free_human"] = get_human_readable_size(free_kb * 1024)
                info["used"] = (total_kb - free_kb) * 1024
                info["used_human"] = get_human_readable_size((total_kb - free_kb) * 1024)
                info["total_virtual"] = data.get("TotalVirtualMemorySize", 0) * 1024
                info["total_virtual_human"] = get_human_readable_size(data.get("TotalVirtualMemorySize", 0) * 1024)
        except Exception as e:
            self.results["errors"].append(f"Failed to get system memory info: {e}")

        self.results["system_memory"] = info
        return info

    def find_crash_dumps(self):
        """Find existing Windows crash dump files."""
        dumps = []
        systemroot = os.environ.get("SystemRoot", r"C:\Windows")

        # Full memory dump
        memory_dmp = os.path.join(systemroot, "MEMORY.DMP")
        if os.path.exists(memory_dmp):
            try:
                stat = os.stat(memory_dmp)
                dumps.append({
                    "path": memory_dmp,
                    "type": "Full Memory Dump",
                    "size": stat.st_size,
                    "size_human": get_human_readable_size(stat.st_size),
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "description": "Complete physical memory dump from a BSOD crash",
                })
            except Exception as e:
                self.results["warnings"].append(f"Cannot access MEMORY.DMP: {e}")

        # Minidump directory
        minidump_dir = os.path.join(systemroot, "Minidump")
        if os.path.isdir(minidump_dir):
            try:
                for fname in os.listdir(minidump_dir):
                    if fname.lower().endswith(".dmp"):
                        fpath = os.path.join(minidump_dir, fname)
                        stat = os.stat(fpath)
                        dumps.append({
                            "path": fpath,
                            "type": "Minidump",
                            "size": stat.st_size,
                            "size_human": get_human_readable_size(stat.st_size),
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "description": f"Kernel minidump from crash event",
                        })
            except Exception as e:
                self.results["warnings"].append(f"Cannot access Minidump dir: {e}")

        self.results["crash_dumps"] = dumps
        return dumps

    def check_hibernation_file(self):
        """Check for hibernation file (hiberfil.sys)."""
        info = {}
        hiberfil = r"C:\hiberfil.sys"
        try:
            if os.path.exists(hiberfil):
                stat = os.stat(hiberfil)
                info["exists"] = True
                info["path"] = hiberfil
                info["size"] = stat.st_size
                info["size_human"] = get_human_readable_size(stat.st_size)
                info["modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
                info["description"] = (
                    "Hibernation file contains a snapshot of RAM at hibernation time. "
                    "Can be analyzed with Volatility or other memory forensics tools."
                )
            else:
                info["exists"] = False
                info["note"] = "Hibernation may be disabled"
        except PermissionError:
            info["exists"] = True
            info["accessible"] = False
            info["note"] = "File exists but requires admin access"
        except Exception as e:
            info["error"] = str(e)

        self.results["hibernation_file"] = info
        return info

    def check_pagefile_info(self):
        """Get pagefile configuration."""
        info = {}
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-CimInstance Win32_PageFileSetting | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                info["settings"] = json.loads(result.stdout)
        except Exception:
            pass

        # Check actual pagefile
        pagefile = r"C:\pagefile.sys"
        try:
            if os.path.exists(pagefile):
                stat = os.stat(pagefile)
                info["exists"] = True
                info["size"] = stat.st_size
                info["size_human"] = get_human_readable_size(stat.st_size)
        except Exception:
            pass

        self.results["pagefile_info"] = info
        return info

    def get_process_memory_info(self, top_n=20):
        """Get top processes by memory usage."""
        procs = []
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-Process | Sort-Object WorkingSet64 -Descending | "
                 f"Select-Object -First {top_n} Name,Id,WorkingSet64,VirtualMemorySize64,"
                 "CPU,PagedMemorySize64 | ConvertTo-Json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for p in data:
                    ws = p.get("WorkingSet64", 0) or 0
                    procs.append({
                        "name": p.get("Name", "?"),
                        "pid": p.get("Id", "?"),
                        "working_set": ws,
                        "working_set_human": get_human_readable_size(ws),
                        "virtual_memory": p.get("VirtualMemorySize64", 0),
                        "virtual_memory_human": get_human_readable_size(p.get("VirtualMemorySize64", 0) or 0),
                        "cpu": p.get("CPU", 0),
                        "paged_memory": p.get("PagedMemorySize64", 0),
                    })
        except Exception as e:
            self.results["errors"].append(f"Failed to get process memory: {e}")

        self.results["process_memory"] = procs
        return procs

    def get_memory_dump_config(self):
        """Check Windows memory dump configuration (registry)."""
        config = {}
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' | "
                 "Select-Object CrashDumpEnabled,DumpFile,MinidumpDir,LogEvent,"
                 "AutoReboot,Overwrite | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                dump_types = {0: "None", 1: "Complete", 2: "Kernel", 3: "Small (Minidump)", 7: "Automatic"}
                config["crash_dump_type"] = dump_types.get(data.get("CrashDumpEnabled", -1), "Unknown")
                config["dump_file_path"] = data.get("DumpFile", "N/A")
                config["minidump_dir"] = data.get("MinidumpDir", "N/A")
                config["auto_reboot"] = bool(data.get("AutoReboot", 0))
                config["overwrite"] = bool(data.get("Overwrite", 0))
                config["log_event"] = bool(data.get("LogEvent", 0))
        except Exception as e:
            self.results["errors"].append(f"Failed to read crash control config: {e}")

        self.results["memory_dump_config"] = config
        return config

    def collect_all(self, acquire_sample=False, sample_max_mb=64):
        """Run all Windows memory analysis steps."""
        self.results["status"] = "collecting"
        self.results["collection_start"] = datetime.now().isoformat()

        # 1. System memory info
        self.get_system_memory_info()

        # 2. Find crash dumps
        self.find_crash_dumps()

        # 3. Check hibernation file
        self.check_hibernation_file()

        # 4. Pagefile info
        self.check_pagefile_info()

        # 5. Process memory
        self.get_process_memory_info(top_n=20)

        # 6. Dump configuration
        self.get_memory_dump_config()

        self.results["dump_info"] = {
            "status": "info_collected",
            "reason": "Windows memory artifacts collected (crash dumps, hiberfil.sys, pagefile)",
            "recommendation": "For live memory acquisition, use winpmem or DumpIt",
        }

        self.results["status"] = "completed"
        self.results["collection_end"] = datetime.now().isoformat()
        return self.results


# ============================================================
# FACTORY FUNCTION
# ============================================================

def get_memory_dumper(output_dir, os_type=None):
    """
    Factory: return the correct memory dumper for the detected OS.

    Args:
        output_dir: Directory to store memory dump output
        os_type: Override OS detection (Windows/Linux/macOS)

    Returns:
        OS-specific memory dumper instance
    """
    if os_type is None:
        os_type = detect_os()

    if os_type == OS_LINUX:
        return LinuxMemoryDumper(output_dir)
    elif os_type == OS_MACOS:
        return MacOSMemoryDumper(output_dir)
    elif os_type == OS_WINDOWS:
        return WindowsMemoryDumper(output_dir)
    else:
        # Fallback: return Linux dumper with a warning
        logger.warning(f"Unknown OS '{os_type}', defaulting to Linux memory dumper")
        return LinuxMemoryDumper(output_dir)
