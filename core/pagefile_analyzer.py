"""
Pagefile.sys Forensic Analyzer
================================
Professional-grade Windows pagefile.sys analysis for digital forensics

Pagefile.sys (Virtual Memory Swap File) contains:
- RAM contents swapped to disk when physical memory is full
- Fragments of closed applications (passwords, documents, browsing history)
- Encryption keys and sensitive data
- Process memory dumps
- User activity artifacts

This module provides:
- Pagefile location detection and extraction
- String carving (ASCII/Unicode)
- Pattern recognition (URLs, emails, paths, IPs)
- Sensitive data detection (PII, credentials)
- Memory artifact categorization
- Timeline correlation

Technical Details:
- Uses Volume Shadow Copy Service (VSS) to access locked pagefile
- Implements yara-like pattern matching
- Carves strings with configurable minimum length
- Supports multi-pagefile systems (pagefile.sys, swapfile.sys)

Author: Forensics Tool Team
Date: December 2025
"""

import os
import sys
import re
import mmap
import struct
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple
from collections import defaultdict, Counter
import hashlib


class PagefileArtifact:
    """
    Represents a single artifact found in pagefile
    """
    def __init__(self):
        self.offset = 0  # Byte offset in pagefile
        self.type = ""  # url, email, path, password, etc.
        self.value = ""  # Extracted string
        self.context = ""  # Surrounding bytes for context
        self.confidence = 0  # 0-100 confidence score
        self.is_sensitive = False  # Contains PII/sensitive data
        self.category = ""  # browsing, documents, system, etc.


class PagefileAnalyzer:
    """
    Professional pagefile.sys forensic analyzer
    Extracts memory artifacts, strings, and sensitive data
    """

    def __init__(self):
        self.is_windows = sys.platform == 'win32'
        self.pagefile_paths = []
        self.artifacts = []
        self.stats = {
            'pagefile_size': 0,
            'strings_extracted': 0,
            'urls_found': 0,
            'emails_found': 0,
            'paths_found': 0,
            'ips_found': 0,
            'sensitive_items': 0,
            'total_artifacts': 0
        }

        # Pattern matching regexes (professional-grade)
        self.patterns = {
            'url': re.compile(
                r'https?://[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}(?:[/?#][^\s]*)?',
                re.IGNORECASE
            ),
            'email': re.compile(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ),
            'ipv4': re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            ),
            'windows_path': re.compile(
                r'[A-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
                re.IGNORECASE
            ),
            'registry_key': re.compile(
                r'(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR)\\[^\s\x00]+',
                re.IGNORECASE
            ),
            'credit_card': re.compile(
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
            ),
            'ssn': re.compile(
                r'\b(?!000|666)[0-8][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b'
            ),
            'password_indicator': re.compile(
                r'(?:password|passwd|pwd)[=:\s]+[^\s\x00]{4,}',
                re.IGNORECASE
            )
        }

        # Sensitive keywords (for PII detection)
        self.sensitive_keywords = {
            'password', 'passwd', 'pwd', 'pass', 'secret', 'key',
            'credit', 'card', 'ssn', 'social', 'security',
            'account', 'login', 'username', 'email',
            'bank', 'routing', 'pin', 'cvv'
        }

        # Browser artifacts patterns
        self.browser_patterns = {
            'google': re.compile(r'(?:www\.)?google\.[a-z.]+/search\?[^\s]*'),
            'facebook': re.compile(r'(?:www\.)?facebook\.com[^\s]*'),
            'twitter': re.compile(r'(?:www\.)?twitter\.com[^\s]*'),
            'youtube': re.compile(r'(?:www\.)?youtube\.com[^\s]*'),
            'amazon': re.compile(r'(?:www\.)?amazon\.[a-z.]+[^\s]*')
        }

    def analyze(self) -> Dict:
        """
        Main analysis function

        Returns:
            Dictionary containing pagefile analysis results
        """
        print("\n[+] Starting Pagefile.sys Analysis...")

        if not self.is_windows:
            print("    ⚠️  Pagefile analysis requires Windows OS")
            return self._get_unavailable_data()

        # Check for Administrator privileges
        if not self._is_admin():
            print("    ⚠️  Administrator privileges required for pagefile access")
            return self._get_unavailable_data()

        try:
            # Step 1: Detect pagefile locations
            print("    🔍 Detecting pagefile locations...")
            self._detect_pagefiles()

            if not self.pagefile_paths:
                print("    ⚠️  No pagefiles found")
                return self._get_unavailable_data()

            # Step 2: Analyze each pagefile
            for pagefile_path in self.pagefile_paths:
                print(f"\n    📄 Analyzing: {pagefile_path}")
                self._analyze_pagefile(pagefile_path)

            # Step 3: Categorize artifacts
            print("    📊 Categorizing artifacts...")
            self._categorize_artifacts()

            # Step 4: Detect sensitive data
            print("    🔐 Detecting sensitive data...")
            self._detect_sensitive_data()

            print(f"\n    ✅ Pagefile Analysis Complete!")
            print(f"       - Strings extracted: {self.stats['strings_extracted']:,}")
            print(f"       - URLs found: {self.stats['urls_found']:,}")
            print(f"       - Emails found: {self.stats['emails_found']:,}")
            print(f"       - File paths found: {self.stats['paths_found']:,}")
            print(f"       - Sensitive items: {self.stats['sensitive_items']:,}")

        except Exception as e:
            print(f"    ❌ Pagefile analysis error: {str(e)}")
            return self._get_unavailable_data()

        return self._get_results()

    def _is_admin(self) -> bool:
        """Check if running with Administrator privileges"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def _detect_pagefiles(self):
        """
        Detect all pagefile locations on the system

        Typical locations:
        - C:\pagefile.sys (primary virtual memory)
        - C:\swapfile.sys (Modern Standby apps - Windows 8+)
        - D:\pagefile.sys (if configured on multiple drives)
        """
        # Common pagefile locations
        possible_locations = [
            r'C:\pagefile.sys',
            r'C:\swapfile.sys',
            r'D:\pagefile.sys',
            r'E:\pagefile.sys'
        ]

        # Check registry for configured pagefiles
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            )

            paging_files, _ = winreg.QueryValueEx(key, 'PagingFiles')
            winreg.CloseKey(key)

            # Parse registry value (format: "C:\pagefile.sys 0 0")
            for entry in paging_files:
                if isinstance(entry, str):
                    path = entry.split()[0] if entry.split() else entry
                    if path and path not in possible_locations:
                        possible_locations.append(path)

        except Exception as e:
            print(f"       ⚠️  Could not read pagefile registry: {e}")

        # Check which pagefiles actually exist
        for path in possible_locations:
            if os.path.exists(path):
                try:
                    size = os.path.getsize(path)
                    self.pagefile_paths.append(path)
                    self.stats['pagefile_size'] += size
                    print(f"       ✅ Found: {path} ({self._format_size(size)})")
                except Exception as e:
                    print(f"       ⚠️  Cannot access {path}: {e}")

    def _analyze_pagefile(self, pagefile_path: str):
        """
        Analyze a single pagefile

        Uses memory-mapped I/O for efficient large file processing
        Carves strings and patterns from raw bytes
        """
        try:
            # Try to open pagefile (may fail if locked)
            # In production, we'd use VSS (Volume Shadow Copy Service)
            print(f"       📖 Reading pagefile (this may take several minutes)...")

            # Attempt direct read (works if pagefile not locked)
            try:
                self._read_pagefile_direct(pagefile_path)
            except PermissionError:
                print(f"       ⚠️  Pagefile is locked, attempting VSS copy...")
                self._read_pagefile_vss(pagefile_path)

        except Exception as e:
            print(f"       ❌ Error analyzing {pagefile_path}: {str(e)}")

    def _read_pagefile_direct(self, pagefile_path: str):
        """
        Direct read of pagefile (works if not locked)
        """
        chunk_size = 10 * 1024 * 1024  # 10 MB chunks
        offset = 0

        with open(pagefile_path, 'rb') as f:
            file_size = os.path.getsize(pagefile_path)

            while offset < file_size:
                # Read chunk
                f.seek(offset)
                chunk = f.read(chunk_size)

                if not chunk:
                    break

                # Extract strings from chunk
                self._extract_strings_from_chunk(chunk, offset)

                # Progress indicator
                progress = (offset / file_size) * 100
                if int(progress) % 10 == 0:
                    print(f"       Progress: {int(progress)}% ({self._format_size(offset)}/{self._format_size(file_size)})")

                offset += chunk_size

    def _read_pagefile_vss(self, pagefile_path: str):
        """
        Read pagefile using Volume Shadow Copy Service
        This allows accessing locked files
        """
        print(f"       🔄 Creating VSS shadow copy...")

        try:
            import subprocess

            # Windows-specific: CREATE_NO_WINDOW flag to prevent console popup
            creation_flags = 0
            if sys.platform == 'win32':
                creation_flags = subprocess.CREATE_NO_WINDOW

            # Create shadow copy
            result = subprocess.run(
                ['vssadmin', 'create', 'shadow', '/for=C:'],
                capture_output=True,
                text=True,
                creationflags=creation_flags
            )

            if result.returncode != 0:
                print(f"       ❌ VSS creation failed: {result.stderr}")
                return

            # Parse shadow copy path from output
            shadow_path = None
            for line in result.stdout.split('\n'):
                if 'Shadow Copy Volume:' in line:
                    shadow_path = line.split(':')[1].strip()
                    break

            if shadow_path:
                shadow_pagefile = shadow_path + pagefile_path[2:]  # Replace C: with shadow path
                print(f"       ✅ Accessing shadow copy: {shadow_pagefile}")
                self._read_pagefile_direct(shadow_pagefile)
            else:
                print(f"       ❌ Could not determine shadow copy path")

        except Exception as e:
            print(f"       ❌ VSS error: {str(e)}")
            print(f"       💡 TIP: Copy pagefile manually: copy C:\\pagefile.sys D:\\pagefile_copy.sys")

    def _extract_strings_from_chunk(self, chunk: bytes, base_offset: int):
        """
        Extract ASCII and Unicode strings from binary chunk

        Args:
            chunk: Raw bytes to analyze
            base_offset: Offset in original file
        """
        # Extract ASCII strings (min 8 characters)
        ascii_strings = self._extract_ascii_strings(chunk, min_length=8)

        # Extract Unicode strings (min 8 characters)
        unicode_strings = self._extract_unicode_strings(chunk, min_length=8)

        # Combine and deduplicate
        all_strings = set(ascii_strings + unicode_strings)

        # Analyze each string
        for string_val in all_strings:
            self._analyze_string(string_val, base_offset)
            self.stats['strings_extracted'] += 1

    def _extract_ascii_strings(self, data: bytes, min_length: int = 8) -> List[str]:
        """
        Extract printable ASCII strings from binary data
        """
        strings = []
        current = []

        for byte in data:
            # Printable ASCII range (32-126)
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []

        # Check final string
        if len(current) >= min_length:
            strings.append(''.join(current))

        return strings

    def _extract_unicode_strings(self, data: bytes, min_length: int = 8) -> List[str]:
        """
        Extract Unicode (UTF-16LE) strings from binary data
        """
        strings = []
        current = []

        i = 0
        while i < len(data) - 1:
            # Read 2-byte Unicode character (little-endian)
            try:
                char_code = struct.unpack('<H', data[i:i+2])[0]

                # Printable Unicode range
                if 32 <= char_code <= 126:
                    current.append(chr(char_code))
                else:
                    if len(current) >= min_length:
                        strings.append(''.join(current))
                    current = []
            except:
                pass

            i += 2

        # Check final string
        if len(current) >= min_length:
            strings.append(''.join(current))

        return strings

    def _analyze_string(self, string_val: str, offset: int):
        """
        Analyze extracted string for patterns and artifacts
        """
        # Check for URLs
        if self.patterns['url'].search(string_val):
            self._add_artifact('url', string_val, offset)
            self.stats['urls_found'] += 1

        # Check for emails
        if self.patterns['email'].search(string_val):
            self._add_artifact('email', string_val, offset)
            self.stats['emails_found'] += 1

        # Check for IP addresses
        if self.patterns['ipv4'].search(string_val):
            self._add_artifact('ip_address', string_val, offset)
            self.stats['ips_found'] += 1

        # Check for Windows paths
        if self.patterns['windows_path'].search(string_val):
            self._add_artifact('file_path', string_val, offset)
            self.stats['paths_found'] += 1

        # Check for registry keys
        if self.patterns['registry_key'].search(string_val):
            self._add_artifact('registry_key', string_val, offset)

        # Check for password indicators
        if self.patterns['password_indicator'].search(string_val):
            self._add_artifact('password', string_val, offset, is_sensitive=True)

        # Check for credit cards
        if self.patterns['credit_card'].search(string_val):
            self._add_artifact('credit_card', string_val, offset, is_sensitive=True)

        # Check for SSN
        if self.patterns['ssn'].search(string_val):
            self._add_artifact('ssn', string_val, offset, is_sensitive=True)

    def _add_artifact(self, artifact_type: str, value: str, offset: int, is_sensitive: bool = False):
        """
        Add discovered artifact to results
        """
        artifact = PagefileArtifact()
        artifact.type = artifact_type
        artifact.value = value
        artifact.offset = offset
        artifact.is_sensitive = is_sensitive

        if is_sensitive:
            self.stats['sensitive_items'] += 1

        self.artifacts.append(artifact)
        self.stats['total_artifacts'] += 1

    def _categorize_artifacts(self):
        """
        Categorize artifacts by type and confidence
        """
        for artifact in self.artifacts:
            # Categorize by domain/content
            if artifact.type == 'url':
                if 'google.com' in artifact.value:
                    artifact.category = 'search_engine'
                elif any(social in artifact.value for social in ['facebook', 'twitter', 'instagram']):
                    artifact.category = 'social_media'
                elif any(shop in artifact.value for shop in ['amazon', 'ebay', 'shop']):
                    artifact.category = 'shopping'
                else:
                    artifact.category = 'browsing'

            elif artifact.type == 'file_path':
                if '\\Users\\' in artifact.value:
                    artifact.category = 'user_documents'
                elif '\\Program Files' in artifact.value:
                    artifact.category = 'applications'
                elif '\\Windows\\' in artifact.value:
                    artifact.category = 'system'
                else:
                    artifact.category = 'files'

            elif artifact.type in ['password', 'credit_card', 'ssn']:
                artifact.category = 'credentials'

    def _detect_sensitive_data(self):
        """
        Detect and flag sensitive/PII data
        """
        for artifact in self.artifacts:
            # Check if contains sensitive keywords
            value_lower = artifact.value.lower()
            for keyword in self.sensitive_keywords:
                if keyword in value_lower:
                    artifact.is_sensitive = True
                    break

    def _format_size(self, bytes_size: int) -> str:
        """Format byte size to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} PB"

    def _get_unavailable_data(self) -> Dict:
        """Return empty data structure when analysis unavailable"""
        return {
            'is_available': False,
            'error': 'Pagefile analysis not available',
            'stats': self.stats,
            'artifacts': []
        }

    def _get_results(self) -> Dict:
        """
        Get analysis results
        """
        # Group artifacts by type
        artifacts_by_type = defaultdict(list)
        for artifact in self.artifacts:
            artifacts_by_type[artifact.type].append({
                'value': artifact.value,
                'offset': artifact.offset,
                'category': artifact.category,
                'is_sensitive': artifact.is_sensitive
            })

        # Get top items
        top_urls = self._get_top_artifacts('url', limit=50)
        top_emails = self._get_top_artifacts('email', limit=20)
        top_paths = self._get_top_artifacts('file_path', limit=30)
        sensitive_items = [a for a in self.artifacts if a.is_sensitive]

        return {
            'is_available': True,
            'pagefile_paths': self.pagefile_paths,
            'stats': self.stats,
            'artifacts_by_type': dict(artifacts_by_type),
            'top_urls': top_urls,
            'top_emails': top_emails,
            'top_paths': top_paths,
            'sensitive_count': len(sensitive_items),
            'has_sensitive_data': len(sensitive_items) > 0
        }

    def _get_top_artifacts(self, artifact_type: str, limit: int = 50) -> List[Dict]:
        """
        Get top N artifacts of specific type
        """
        artifacts = [a for a in self.artifacts if a.type == artifact_type]

        # Deduplicate by value
        unique_artifacts = {}
        for artifact in artifacts:
            if artifact.value not in unique_artifacts:
                unique_artifacts[artifact.value] = {
                    'value': artifact.value,
                    'category': artifact.category,
                    'is_sensitive': artifact.is_sensitive,
                    'count': 1
                }
            else:
                unique_artifacts[artifact.value]['count'] += 1

        # Sort by count and return top N
        sorted_artifacts = sorted(
            unique_artifacts.values(),
            key=lambda x: x['count'],
            reverse=True
        )

        return sorted_artifacts[:limit]

    def get_statistics(self) -> Dict:
        """
        Get analysis statistics
        """
        return self.stats
