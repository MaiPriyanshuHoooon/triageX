"""
NTFS Structures Parser Module
==============================
Parses NTFS Master File Table (MFT) records and attributes

This module provides low-level parsing of NTFS structures:
- MFT Record Header (48 bytes)
- Attribute Headers (Resident/Non-Resident)
- $STANDARD_INFORMATION (0x10): MACB timestamps
- $FILE_NAME (0x30): Filename, parent reference
- $DATA (0x80): Data runs (cluster allocation)
- $ATTRIBUTE_LIST (0x20): For large/fragmented records
- Alternate Data Streams (ADS) detection

Author: Forensics Tool Team
Date: December 2025
"""

import struct
from datetime import datetime, timedelta
from typing import List, Tuple, Optional, Dict


# NTFS Attribute Types
ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_OBJECT_ID = 0x40
ATTR_SECURITY_DESCRIPTOR = 0x50
ATTR_VOLUME_NAME = 0x60
ATTR_VOLUME_INFORMATION = 0x70
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_BITMAP = 0xB0
ATTR_REPARSE_POINT = 0xC0
ATTR_EA_INFORMATION = 0xD0
ATTR_EA = 0xE0
ATTR_LOGGED_UTILITY_STREAM = 0x100

# MFT Record Flags
FILE_IN_USE = 0x01
FILE_IS_DIRECTORY = 0x02


class MFTRecord:
    """
    Represents a parsed MFT record with all attributes
    """

    def __init__(self):
        self.entry_number = 0
        self.sequence_number = 0
        self.is_in_use = False
        self.is_directory = False
        self.is_deleted = False

        # Volume information (for multi-volume scanning)
        self.volume_letter = "?"  # Drive letter (e.g., "C:", "D:")

        # Timestamps from $STANDARD_INFORMATION
        self.created = None
        self.modified = None
        self.accessed = None
        self.mft_modified = None

        # File information from $FILE_NAME
        self.filename = ""
        self.parent_reference = 0
        self.parent_sequence = 0
        self.full_path = ""

        # File size and attributes
        self.logical_size = 0
        self.physical_size = 0
        self.is_resident = False

        # Data runs (cluster allocation)
        self.data_runs = []

        # Alternate Data Streams
        self.has_ads = False
        self.ads_streams = []

        # Recovery potential
        self.recoverability = "UNKNOWN"

        # Anomaly flags
        self.is_timestomped = False
        self.anomaly_flags = []

        # Raw attributes
        self.attributes = {}

        # Raw MFT record data (for file content recovery)
        self.raw_data = b''


class NTFSParser:
    """
    Low-level NTFS structure parser
    """

    @staticmethod
    def parse_mft_header(data: bytes) -> Dict:
        """
        Parse MFT record header (48 bytes)

        Structure:
        Offset  Size  Description
        0x00    4     Signature ("FILE" or "BAAD")
        0x04    2     Offset to fixup array
        0x06    2     Number of fixup entries
        0x08    8     $LogFile sequence number
        0x10    2     Sequence number
        0x12    2     Hard link count
        0x14    2     Offset to first attribute
        0x16    2     Flags (0x01=in use, 0x02=directory)
        0x18    4     Used size of MFT entry
        0x1C    4     Allocated size of MFT entry
        0x20    8     File reference to base record
        0x28    2     Next attribute ID
        """

        if len(data) < 48:
            return None

        header = {}

        try:
            # Parse signature
            signature = data[0:4]
            header['signature'] = signature.decode('ascii', errors='ignore')

            # Check if valid MFT record
            if header['signature'] not in ['FILE', 'BAAD']:
                return None

            # Parse header fields
            header['fixup_offset'] = struct.unpack('<H', data[4:6])[0]
            header['fixup_count'] = struct.unpack('<H', data[6:8])[0]
            header['sequence_number'] = struct.unpack('<H', data[16:18])[0]
            header['hard_link_count'] = struct.unpack('<H', data[18:20])[0]
            header['first_attr_offset'] = struct.unpack('<H', data[20:22])[0]
            header['flags'] = struct.unpack('<H', data[22:24])[0]
            header['used_size'] = struct.unpack('<I', data[24:28])[0]
            header['allocated_size'] = struct.unpack('<I', data[28:32])[0]
            header['base_record_ref'] = struct.unpack('<Q', data[32:40])[0]

            # Parse flags
            header['is_in_use'] = bool(header['flags'] & FILE_IN_USE)
            header['is_directory'] = bool(header['flags'] & FILE_IS_DIRECTORY)

            return header

        except Exception as e:
            return None

    @staticmethod
    def parse_attribute_header(data: bytes, offset: int) -> Optional[Dict]:
        """
        Parse attribute header (resident or non-resident)

        Resident Attribute Header (24 bytes):
        0x00    4    Attribute type
        0x04    4    Length of attribute
        0x08    1    Non-resident flag (0=resident)
        0x09    1    Name length
        0x0A    2    Offset to name
        0x0C    2    Flags
        0x0E    2    Attribute ID
        0x10    4    Length of content
        0x14    2    Offset to content

        Non-Resident Attribute Header (64+ bytes):
        0x00    4    Attribute type
        0x04    4    Length of attribute
        0x08    1    Non-resident flag (1=non-resident)
        0x09    1    Name length
        0x0A    2    Offset to name
        0x0C    2    Flags
        0x0E    2    Attribute ID
        0x10    8    Starting VCN
        0x18    8    Ending VCN
        0x20    2    Offset to data runs
        0x22    2    Compression unit size
        0x28    8    Allocated size
        0x30    8    Real size
        0x38    8    Initialized size
        """

        if len(data) < offset + 16:
            return None

        try:
            attr = {}

            # Parse common header fields
            attr['type'] = struct.unpack('<I', data[offset:offset+4])[0]
            attr['length'] = struct.unpack('<I', data[offset+4:offset+8])[0]
            attr['is_non_resident'] = struct.unpack('B', data[offset+8:offset+9])[0]
            attr['name_length'] = struct.unpack('B', data[offset+9:offset+10])[0]
            attr['name_offset'] = struct.unpack('<H', data[offset+10:offset+12])[0]
            attr['flags'] = struct.unpack('<H', data[offset+12:offset+14])[0]
            attr['attribute_id'] = struct.unpack('<H', data[offset+14:offset+16])[0]

            # End of attributes marker
            if attr['type'] == 0xFFFFFFFF:
                return None

            # Parse attribute name if present
            attr['name'] = ""
            if attr['name_length'] > 0 and attr['name_offset'] > 0:
                name_start = offset + attr['name_offset']
                name_end = name_start + (attr['name_length'] * 2)  # Unicode
                if len(data) >= name_end:
                    attr['name'] = data[name_start:name_end].decode('utf-16le', errors='ignore')

            if attr['is_non_resident']:
                # Non-resident attribute
                if len(data) < offset + 64:
                    return None

                attr['start_vcn'] = struct.unpack('<Q', data[offset+16:offset+24])[0]
                attr['end_vcn'] = struct.unpack('<Q', data[offset+24:offset+32])[0]
                attr['datarun_offset'] = struct.unpack('<H', data[offset+32:offset+34])[0]
                attr['allocated_size'] = struct.unpack('<Q', data[offset+40:offset+48])[0]
                attr['real_size'] = struct.unpack('<Q', data[offset+48:offset+56])[0]
                attr['initialized_size'] = struct.unpack('<Q', data[offset+56:offset+64])[0]

            else:
                # Resident attribute
                if len(data) < offset + 24:
                    return None

                attr['content_length'] = struct.unpack('<I', data[offset+16:offset+20])[0]
                attr['content_offset'] = struct.unpack('<H', data[offset+20:offset+22])[0]

            return attr

        except Exception as e:
            return None

    @staticmethod
    def parse_standard_information(data: bytes) -> Dict:
        """
        Parse $STANDARD_INFORMATION attribute (0x10)
        Contains MACB timestamps (Modified, Accessed, Changed, Born)

        Structure:
        0x00    8    Creation time (FILETIME)
        0x08    8    Modified time (FILETIME)
        0x10    8    MFT modified time (FILETIME)
        0x18    8    Last access time (FILETIME)
        0x20    4    File attributes
        """

        info = {}

        try:
            if len(data) < 48:
                return info

            # Parse timestamps (Windows FILETIME format)
            info['created'] = NTFSParser.filetime_to_datetime(struct.unpack('<Q', data[0:8])[0])
            info['modified'] = NTFSParser.filetime_to_datetime(struct.unpack('<Q', data[8:16])[0])
            info['mft_modified'] = NTFSParser.filetime_to_datetime(struct.unpack('<Q', data[16:24])[0])
            info['accessed'] = NTFSParser.filetime_to_datetime(struct.unpack('<Q', data[24:32])[0])

            # File attributes
            info['attributes'] = struct.unpack('<I', data[32:36])[0]

            return info

        except Exception as e:
            return info

    @staticmethod
    def parse_file_name(data: bytes) -> Dict:
        """
        Parse $FILE_NAME attribute (0x30)
        Contains filename and parent directory reference

        Structure:
        0x00    6    Parent directory reference
        0x06    2    Parent directory sequence number
        0x08    8    Creation time
        0x10    8    Modified time
        0x18    8    MFT modified time
        0x20    8    Last access time
        0x28    8    Allocated size
        0x30    8    Real size
        0x38    4    Flags
        0x3C    4    Reparse value
        0x40    1    Filename length (characters)
        0x41    1    Namespace (0=POSIX, 1=Win32, 2=DOS, 3=Win32+DOS)
        0x42    N    Filename (Unicode)
        """

        info = {}

        try:
            if len(data) < 66:
                return info

            # Parent directory reference (48 bits entry, 16 bits sequence)
            parent_ref = struct.unpack('<Q', data[0:8])[0]
            info['parent_reference'] = parent_ref & 0xFFFFFFFFFFFF
            info['parent_sequence'] = (parent_ref >> 48) & 0xFFFF

            # Timestamps
            info['created'] = NTFSParser.filetime_to_datetime(struct.unpack('<Q', data[8:16])[0])
            info['modified'] = NTFSParser.filetime_to_datetime(struct.unpack('<Q', data[16:24])[0])
            info['mft_modified'] = NTFSParser.filetime_to_datetime(struct.unpack('<Q', data[24:32])[0])
            info['accessed'] = NTFSParser.filetime_to_datetime(struct.unpack('<Q', data[32:40])[0])

            # File size
            info['allocated_size'] = struct.unpack('<Q', data[40:48])[0]
            info['real_size'] = struct.unpack('<Q', data[48:56])[0]

            # Filename
            info['filename_length'] = struct.unpack('B', data[64:65])[0]
            info['namespace'] = struct.unpack('B', data[65:66])[0]

            # Extract filename (Unicode)
            if info['filename_length'] > 0:
                name_start = 66
                name_end = name_start + (info['filename_length'] * 2)
                if len(data) >= name_end:
                    info['filename'] = data[name_start:name_end].decode('utf-16le', errors='ignore')
                else:
                    info['filename'] = ""
            else:
                info['filename'] = ""

            return info

        except Exception as e:
            return info

    @staticmethod
    def parse_data_runs(data: bytes, offset: int) -> List[Tuple[int, int]]:
        """
        Parse data runs from non-resident $DATA attribute

        Data runs encode cluster allocation as:
        - Header byte: high nibble = offset length, low nibble = length length
        - Length: number of clusters
        - Offset: relative offset from previous run

        Returns list of (cluster_offset, cluster_count) tuples
        """

        runs = []
        current_offset = 0
        pos = offset

        try:
            while pos < len(data):
                # Read header byte
                if data[pos] == 0:
                    break  # End of data runs

                header = data[pos]
                length_bytes = header & 0x0F
                offset_bytes = (header >> 4) & 0x0F

                if length_bytes == 0 or pos + 1 + length_bytes + offset_bytes > len(data):
                    break

                pos += 1

                # Read cluster count
                cluster_count = 0
                for i in range(length_bytes):
                    cluster_count += data[pos + i] << (i * 8)
                pos += length_bytes

                # Read relative offset
                relative_offset = 0
                for i in range(offset_bytes):
                    relative_offset += data[pos + i] << (i * 8)

                # Handle signed offset (2's complement)
                if offset_bytes > 0 and data[pos + offset_bytes - 1] & 0x80:
                    relative_offset -= 1 << (offset_bytes * 8)

                pos += offset_bytes

                # Calculate absolute offset
                current_offset += relative_offset

                runs.append((current_offset, cluster_count))

            return runs

        except Exception as e:
            return runs

    @staticmethod
    def filetime_to_datetime(filetime: int) -> Optional[datetime]:
        """
        Convert Windows FILETIME (100-nanosecond intervals since 1601-01-01) to Python datetime

        IMPORTANT: Windows FILETIME is stored in UTC timezone.
        This function converts to LOCAL system timezone for accurate display.

        Example:
        - File deleted at 10:00 AM IST (UTC+5:30)
        - FILETIME stores: 04:30 AM UTC
        - This function returns: 10:00 AM (local time)
        """

        if filetime == 0:
            return None

        try:
            # FILETIME epoch: January 1, 1601 (UTC)
            epoch = datetime(1601, 1, 1)

            # Convert 100-nanosecond intervals to seconds
            seconds = filetime / 10000000.0

            # Add to epoch (result is in UTC)
            utc_result = epoch + timedelta(seconds=seconds)

            # Sanity check (valid NTFS timestamps)
            if utc_result.year < 1601 or utc_result.year > 2100:
                return None

            # ⚠️ CRITICAL FIX: Convert from UTC to LOCAL timezone
            # Windows stores FILETIME in UTC, but users expect local time display
            import time

            # Get local timezone offset in seconds
            if time.daylight:
                # DST is in effect
                offset_seconds = -time.altzone
            else:
                # Standard time
                offset_seconds = -time.timezone

            # Convert UTC to local time
            local_result = utc_result + timedelta(seconds=offset_seconds)

            return local_result

        except Exception as e:
            return None

    @staticmethod
    def detect_timestomping(si_times: Dict, fn_times: Dict) -> bool:
        """
        Detect timestomping (timestamp manipulation)

        $STANDARD_INFORMATION timestamps can be modified by SetFileTime() API
        $FILE_NAME timestamps are harder to modify (require special tools)

        If SI timestamps differ significantly from FN timestamps, likely timestomping
        """

        if not si_times or not fn_times:
            return False

        try:
            # Compare creation times
            si_created = si_times.get('created')
            fn_created = fn_times.get('created')

            if si_created and fn_created:
                # If difference is more than 1 second, suspicious
                diff = abs((si_created - fn_created).total_seconds())
                if diff > 1.0:
                    return True

            # Compare modified times
            si_modified = si_times.get('modified')
            fn_modified = fn_times.get('modified')

            if si_modified and fn_modified:
                diff = abs((si_modified - fn_modified).total_seconds())
                if diff > 1.0:
                    return True

            return False

        except Exception as e:
            return False


def format_timestamp(dt: Optional[datetime]) -> str:
    """Format datetime for display"""
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def format_filesize(size: int) -> str:
    """Format file size in human-readable format"""
    if size == 0:
        return "0 B"

    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size_float = float(size)

    while size_float >= 1024 and unit_index < len(units) - 1:
        size_float /= 1024
        unit_index += 1

    return f"{size_float:.2f} {units[unit_index]}"
