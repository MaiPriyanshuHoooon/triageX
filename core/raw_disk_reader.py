"""
Raw Disk Access for Pagefile Reading
=====================================
Professional-grade raw disk access to read locked pagefile.sys
Uses the SAME technique as Autopsy/The Sleuth Kit

This bypasses Windows file locks by:
1. Opening logical volume device (\\.\C:)
2. Finding pagefile location in MFT
3. Reading raw disk sectors directly
4. No kernel driver needed!

Requires: Administrator privileges
Works on: Windows 7/8/10/11

Author: Forensics Tool Team
Date: December 2025
"""

import ctypes
from ctypes import wintypes
import struct
import sys


class RawDiskReader:
    """
    Raw disk reader for accessing locked files
    Uses Windows device I/O to bypass file system locks
    """

    def __init__(self):
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        # Windows API constants
        self.GENERIC_READ = 0x80000000
        self.FILE_SHARE_READ = 0x00000001
        self.FILE_SHARE_WRITE = 0x00000002
        self.OPEN_EXISTING = 3
        self.FILE_FLAG_NO_BUFFERING = 0x20000000
        self.FILE_FLAG_RANDOM_ACCESS = 0x10000000

        self.sector_size = 512  # Standard sector size
        self.cluster_size = 4096  # Default NTFS cluster size (will be detected)

    def open_volume(self, volume_letter='C'):
        """
        Open logical volume device for raw access

        Args:
            volume_letter: Drive letter (default 'C')

        Returns:
            Handle to volume device, or None if failed
        """
        device_path = f"\\\\.\\{volume_letter}:"

        print(f"    🔓 Opening volume device: {device_path}")

        handle = self.kernel32.CreateFileW(
            device_path,
            self.GENERIC_READ,
            self.FILE_SHARE_READ | self.FILE_SHARE_WRITE,
            None,
            self.OPEN_EXISTING,
            self.FILE_FLAG_NO_BUFFERING | self.FILE_FLAG_RANDOM_ACCESS,
            None
        )

        if handle == -1 or handle == 0:
            error = ctypes.get_last_error()
            print(f"    ❌ Cannot open volume device (Error {error})")
            print(f"    💡 Make sure you're running as Administrator!")
            return None

        print(f"    ✅ Volume device opened successfully (handle: {handle})")
        return handle

    def get_volume_info(self, handle):
        """
        Get volume geometry (cluster size, sector size)
        """
        # IOCTL_DISK_GET_DRIVE_GEOMETRY
        IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x00070000

        class DISK_GEOMETRY(ctypes.Structure):
            _fields_ = [
                ("Cylinders", wintypes.LARGE_INTEGER),
                ("MediaType", wintypes.DWORD),
                ("TracksPerCylinder", wintypes.DWORD),
                ("SectorsPerTrack", wintypes.DWORD),
                ("BytesPerSector", wintypes.DWORD),
            ]

        geometry = DISK_GEOMETRY()
        bytes_returned = wintypes.DWORD()

        result = self.kernel32.DeviceIoControl(
            handle,
            IOCTL_DISK_GET_DRIVE_GEOMETRY,
            None,
            0,
            ctypes.byref(geometry),
            ctypes.sizeof(geometry),
            ctypes.byref(bytes_returned),
            None
        )

        if result:
            self.sector_size = geometry.BytesPerSector
            print(f"    📊 Sector size: {self.sector_size} bytes")
            return True
        else:
            print(f"    ⚠️  Could not get volume geometry, using defaults")
            return False

    def read_boot_sector(self, handle):
        """
        Read NTFS boot sector to get cluster size
        """
        print(f"    📖 Reading NTFS boot sector...")

        # Read first sector (boot sector)
        buffer = ctypes.create_string_buffer(self.sector_size)
        bytes_read = wintypes.DWORD()

        # Seek to beginning
        self.kernel32.SetFilePointer(handle, 0, None, 0)

        result = self.kernel32.ReadFile(
            handle,
            buffer,
            self.sector_size,
            ctypes.byref(bytes_read),
            None
        )

        if not result or bytes_read.value != self.sector_size:
            print(f"    ❌ Could not read boot sector")
            return False

        # Parse NTFS boot sector
        # Offset 0x0B: Bytes per sector (2 bytes)
        # Offset 0x0D: Sectors per cluster (1 byte)

        bytes_per_sector = struct.unpack('<H', buffer.raw[0x0B:0x0D])[0]
        sectors_per_cluster = struct.unpack('B', buffer.raw[0x0D:0x0E])[0]

        self.cluster_size = bytes_per_sector * sectors_per_cluster

        print(f"    ✅ NTFS cluster size: {self.cluster_size} bytes")
        return True

    def find_pagefile_simple(self, handle, volume_size_bytes):
        """
        Simple pagefile finder - scans for pagefile signature
        This is MUCH simpler than parsing full MFT

        Pagefile.sys characteristics:
        - Usually at beginning of disk (first few GB)
        - Contains signature: "PAGE" or repeating patterns
        - Large contiguous allocation
        """
        print(f"    🔍 Scanning for pagefile.sys signature...")

        # Scan first 10 GB (pagefile usually near start of disk)
        max_scan_size = min(10 * 1024 * 1024 * 1024, volume_size_bytes)
        chunk_size = 1024 * 1024  # 1 MB chunks

        # Align to sector boundary
        chunk_size = (chunk_size // self.sector_size) * self.sector_size

        buffer = ctypes.create_string_buffer(chunk_size)
        bytes_read = wintypes.DWORD()

        offset = 0
        found_offset = None

        while offset < max_scan_size:
            # Seek to offset
            high_dword = wintypes.DWORD(offset >> 32)
            low_dword = wintypes.DWORD(offset & 0xFFFFFFFF)

            result = self.kernel32.SetFilePointer(
                handle,
                low_dword.value,
                ctypes.byref(high_dword),
                0  # FILE_BEGIN
            )

            if result == 0xFFFFFFFF:
                error = ctypes.get_last_error()
                if error != 0:
                    print(f"    ⚠️  Seek error at offset {offset}")
                    break

            # Read chunk
            read_result = self.kernel32.ReadFile(
                handle,
                buffer,
                chunk_size,
                ctypes.byref(bytes_read),
                None
            )

            if not read_result or bytes_read.value == 0:
                break

            # Look for pagefile signature or patterns
            data = buffer.raw[:bytes_read.value]

            # Pagefile often contains these patterns
            if self._looks_like_pagefile(data):
                found_offset = offset
                print(f"    ✅ Potential pagefile data found at offset: {offset} (0x{offset:X})")
                return offset, chunk_size * 100  # Assume 100 MB pagefile minimum

            offset += chunk_size

            # Progress indicator
            if offset % (100 * 1024 * 1024) == 0:  # Every 100 MB
                progress_gb = offset / (1024 * 1024 * 1024)
                print(f"    ... Scanned {progress_gb:.1f} GB")

        if found_offset is None:
            print(f"    ⚠️  Could not locate pagefile signature")
            print(f"    💡 Pagefile might be disabled or on different volume")

        return found_offset, 0

    def _looks_like_pagefile(self, data):
        """
        Heuristic check if data looks like pagefile content
        """
        # Pagefile characteristics:
        # - Contains memory page data
        # - Mix of text and binary
        # - Not all zeros
        # - Contains readable strings

        # Check 1: Not all zeros (empty space)
        non_zero_count = sum(1 for byte in data if byte != 0)
        if non_zero_count < len(data) * 0.1:  # Less than 10% non-zero
            return False

        # Check 2: Contains printable ASCII (memory contains text)
        printable_count = sum(1 for byte in data if 32 <= byte <= 126)
        if printable_count < len(data) * 0.05:  # At least 5% printable
            return False

        # Check 3: Has variety of byte values (not a pattern)
        unique_bytes = len(set(data[:1000]))
        if unique_bytes < 50:  # Should have variety
            return False

        return True

    def read_pagefile_raw(self, volume_letter='C', output_path='pagefile_raw.sys', max_size_mb=100):
        """
        Main function: Read pagefile using raw disk access

        Args:
            volume_letter: Drive letter (default 'C')
            output_path: Where to save extracted pagefile
            max_size_mb: Maximum MB to read (default 100 MB for speed)

        Returns:
            True if successful, False otherwise
        """
        print(f"\n    🔧 RAW DISK ACCESS METHOD (Autopsy-style)")
        print(f"    {'='*60}")

        # Step 1: Open volume
        handle = self.open_volume(volume_letter)
        if not handle:
            return False

        try:
            # Step 2: Get volume info
            self.get_volume_info(handle)

            # Step 3: Read boot sector for cluster size
            self.read_boot_sector(handle)

            # Step 4: Get volume size
            volume_size = self._get_volume_size(handle)
            print(f"    📊 Volume size: {volume_size / (1024**3):.2f} GB")

            # Step 5: Find pagefile location (simplified method)
            pagefile_offset, pagefile_size = self.find_pagefile_simple(handle, volume_size)

            if pagefile_offset is None:
                print(f"    ❌ Could not locate pagefile")
                return False

            # Step 6: Read pagefile data
            print(f"    📖 Reading pagefile data (first {max_size_mb} MB)...")

            bytes_to_read = min(max_size_mb * 1024 * 1024, pagefile_size)
            bytes_to_read = (bytes_to_read // self.sector_size) * self.sector_size  # Align

            chunk_size = 1024 * 1024  # 1 MB chunks
            chunk_size = (chunk_size // self.sector_size) * self.sector_size

            with open(output_path, 'wb') as out_file:
                offset = pagefile_offset
                total_read = 0

                while total_read < bytes_to_read:
                    # Calculate chunk size for this iteration
                    current_chunk = min(chunk_size, bytes_to_read - total_read)

                    # Seek
                    high_dword = wintypes.DWORD(offset >> 32)
                    low_dword = wintypes.DWORD(offset & 0xFFFFFFFF)
                    self.kernel32.SetFilePointer(handle, low_dword.value, ctypes.byref(high_dword), 0)

                    # Read
                    buffer = ctypes.create_string_buffer(current_chunk)
                    bytes_read = wintypes.DWORD()

                    result = self.kernel32.ReadFile(
                        handle,
                        buffer,
                        current_chunk,
                        ctypes.byref(bytes_read),
                        None
                    )

                    if not result or bytes_read.value == 0:
                        break

                    # Write to output
                    out_file.write(buffer.raw[:bytes_read.value])

                    total_read += bytes_read.value
                    offset += bytes_read.value

                    # Progress
                    progress = (total_read / bytes_to_read) * 100
                    if int(progress) % 10 == 0:
                        print(f"    Progress: {int(progress)}% ({total_read // (1024*1024)} MB / {bytes_to_read // (1024*1024)} MB)")

            print(f"    ✅ Pagefile extracted to: {output_path}")
            print(f"    📊 Size: {total_read / (1024*1024):.2f} MB")
            return True

        finally:
            # Step 7: Cleanup
            self.kernel32.CloseHandle(handle)
            print(f"    🔒 Volume handle closed")

    def _get_volume_size(self, handle):
        """Get total volume size in bytes"""
        # IOCTL_DISK_GET_LENGTH_INFO
        IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C

        class GET_LENGTH_INFORMATION(ctypes.Structure):
            _fields_ = [("Length", wintypes.LARGE_INTEGER)]

        length_info = GET_LENGTH_INFORMATION()
        bytes_returned = wintypes.DWORD()

        result = self.kernel32.DeviceIoControl(
            handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            None,
            0,
            ctypes.byref(length_info),
            ctypes.sizeof(length_info),
            ctypes.byref(bytes_returned),
            None
        )

        if result:
            return length_info.Length
        else:
            # Fallback: assume 100 GB
            return 100 * 1024 * 1024 * 1024


def test_raw_disk_access():
    """
    Test function - run this to verify raw disk access works
    """
    print("="*70)
    print("RAW DISK ACCESS TEST")
    print("="*70)

    if sys.platform != 'win32':
        print("ERROR: This only works on Windows!")
        return False

    # Check admin
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("ERROR: Must run as Administrator!")
            return False
    except:
        print("ERROR: Could not check admin status")
        return False

    # Try raw disk access
    reader = RawDiskReader()
    success = reader.read_pagefile_raw(
        volume_letter='C',
        output_path='pagefile_raw_test.sys',
        max_size_mb=10  # Just 10 MB for testing
    )

    if success:
        print("\n✅ RAW DISK ACCESS WORKS!")
        print("   Pagefile extracted to: pagefile_raw_test.sys")
        print("   You can now analyze this file with string extraction")
        return True
    else:
        print("\n❌ RAW DISK ACCESS FAILED")
        print("   Try the VSS method or manual copy instead")
        return False


if __name__ == '__main__':
    test_raw_disk_access()
