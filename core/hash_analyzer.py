"""
Hash Analyzer Module
===================
OS-agnostic file hash analysis and malware detection
"""

import hashlib
import os
import sys
import json
from pathlib import Path


class HashAnalyzer:
    """Calculate and analyze file hashes for forensic purposes"""

    # Known malware hashes (SHA256) - Sample list
    # In production, you'd use VirusTotal API or other threat intelligence feeds
    KNOWN_MALWARE_HASHES = {
        # WannaCry ransomware samples
        '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c': 'WannaCry Ransomware',
        'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa': 'WannaCry Ransomware',

        # Emotet samples
        '4a767b4a6e8e5d6c4d9c0b2e7f8a9c1d': 'Emotet Trojan',

        # Mimikatz
        'b24c5ffffa3b9a33a0a42e29a2f53e5c': 'Mimikatz (Credential Theft Tool)',

        # Add more known malware hashes here
        # This is a simplified example - real implementations use threat intel feeds
    }

    # Suspicious file extensions (OS-agnostic)
    SUSPICIOUS_EXTENSIONS = [
        # Windows executables
        '.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.vbs',
        '.js', '.jar', '.msi', '.com', '.pif', '.cpl', '.hta',
        # Linux/Unix executables
        '.sh', '.bin', '.run', '.so',
        # macOS executables
        '.app', '.dmg', '.pkg',
        # Scripts
        '.py', '.rb', '.pl', '.php',
    ]

    # Suspicious directory patterns (OS-agnostic)
    SUSPICIOUS_LOCATIONS = [
        'temp', 'tmp', 'download', 'downloads', 'appdata', 'cache',
        '.cache', 'trash', '.trash', 'recycl', 'temporary'
    ]

    def __init__(self):
        self.hash_database = {}
        self.malware_detections = []
        self.suspicious_files = []
        self.duplicate_files = {}
        self.scanned_paths = []

    def calculate_file_hash(self, file_path, algorithm='sha256'):
        """
        Calculate hash of a file

        Args:
            file_path: Path to file
            algorithm: Hash algorithm (md5, sha1, sha256, sha512)

        Returns:
            Tuple of (hash_value, file_size, error)
        """
        try:
            hash_func = hashlib.new(algorithm)
            file_size = os.path.getsize(file_path)

            with open(file_path, 'rb') as f:
                # Read file in chunks for large files
                chunk_size = 8192
                while chunk := f.read(chunk_size):
                    hash_func.update(chunk)

            return hash_func.hexdigest(), file_size, None

        except PermissionError:
            return None, None, "Permission Denied"
        except FileNotFoundError:
            return None, None, "File Not Found"
        except Exception as e:
            return None, None, str(e)

    def calculate_multiple_hashes(self, file_path):
        """
        Calculate MD5, SHA1, and SHA256 hashes for a file

        Returns:
            Dictionary with all hash values
        """
        result = {
            'file': file_path,
            'md5': None,
            'sha1': None,
            'sha256': None,
            'size': None,
            'error': None
        }

        try:
            file_size = os.path.getsize(file_path)
            result['size'] = file_size

            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()

            with open(file_path, 'rb') as f:
                chunk_size = 8192
                while chunk := f.read(chunk_size):
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)

            result['md5'] = md5_hash.hexdigest()
            result['sha1'] = sha1_hash.hexdigest()
            result['sha256'] = sha256_hash.hexdigest()

        except Exception as e:
            result['error'] = str(e)

        return result

    def scan_directory(self, directory, recursive=True, extensions=None):
        """
        Scan directory and calculate hashes for all files

        Args:
            directory: Directory path to scan
            recursive: Scan subdirectories
            extensions: List of file extensions to scan (None = all files)

        Returns:
            List of file hash results
        """
        results = []

        try:
            if recursive:
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)

                        # Filter by extension if specified
                        if extensions:
                            if not any(file.lower().endswith(ext) for ext in extensions):
                                continue

                        hash_result = self.calculate_multiple_hashes(file_path)
                        results.append(hash_result)

                        # Check for malware
                        self.check_malware(hash_result)

                        # Check for suspicious files
                        self.check_suspicious(file_path, hash_result)

                        # Track duplicates
                        self.track_duplicates(hash_result)
            else:
                # Scan only top-level directory
                for file in os.listdir(directory):
                    file_path = os.path.join(directory, file)
                    if os.path.isfile(file_path):

                        if extensions:
                            if not any(file.lower().endswith(ext) for ext in extensions):
                                continue

                        hash_result = self.calculate_multiple_hashes(file_path)
                        results.append(hash_result)
                        self.check_malware(hash_result)
                        self.check_suspicious(file_path, hash_result)
                        self.track_duplicates(hash_result)

        except Exception as e:
            results.append({'error': f'Failed to scan directory: {str(e)}'})

        return results

    def get_common_evidence_directories(self):
        """
        Get common directories to scan based on OS
        Returns list of directories that exist on the current system
        """
        directories = []

        if sys.platform == 'win32':
            # Windows-specific directories
            potential_dirs = [
                os.path.expandvars('C:\\Windows\\Temp'),
                os.path.expandvars('C:\\Users\\Public\\Downloads'),
                os.path.expandvars('C:\\Users\\%USERNAME%\\AppData\\Local\\Temp'),
                os.path.expandvars('C:\\Users\\%USERNAME%\\Downloads'),
                os.path.expandvars('C:\\Users\\%USERNAME%\\Desktop'),
                'C:\\ProgramData',
                'C:\\Temp',
            ]
        elif sys.platform == 'darwin':
            # macOS-specific directories
            home = os.path.expanduser('~')
            potential_dirs = [
                os.path.join(home, 'Downloads'),
                os.path.join(home, 'Desktop'),
                os.path.join(home, '.Trash'),
                '/tmp',
                '/var/tmp',
                os.path.join(home, 'Library', 'Caches'),
            ]
        else:
            # Linux/Unix directories
            home = os.path.expanduser('~')
            potential_dirs = [
                os.path.join(home, 'Downloads'),
                os.path.join(home, 'Desktop'),
                '/tmp',
                '/var/tmp',
                os.path.join(home, '.cache'),
                os.path.join(home, '.local', 'share', 'Trash'),
            ]

        # Only return directories that exist and are accessible
        for dir_path in potential_dirs:
            if os.path.exists(dir_path) and os.path.isdir(dir_path):
                try:
                    # Test if we can read the directory
                    os.listdir(dir_path)
                    directories.append(dir_path)
                except PermissionError:
                    pass  # Skip directories we can't access

        return directories

    def scan_evidence_directory(self, evidence_dir, max_files=100, extensions=None):
        """
        Scan a user-specified evidence directory

        Args:
            evidence_dir: Path to evidence directory to scan
            max_files: Maximum number of files to scan (prevent huge scans)
            extensions: List of extensions to filter (None = common suspicious types)

        Returns:
            List of file hash results
        """
        if not os.path.exists(evidence_dir):
            return [{'error': f'Evidence directory does not exist: {evidence_dir}'}]

        if not os.path.isdir(evidence_dir):
            return [{'error': f'Path is not a directory: {evidence_dir}'}]

        # Default to suspicious file extensions if not specified
        if extensions is None:
            extensions = self.SUSPICIOUS_EXTENSIONS

        results = []
        file_count = 0

        self.scanned_paths.append(evidence_dir)

        try:
            for root, dirs, files in os.walk(evidence_dir):
                for file in files:
                    if file_count >= max_files:
                        results.append({'info': f'Reached max file limit ({max_files}). Use max_files parameter to scan more.'})
                        return results

                    file_path = os.path.join(root, file)

                    # Filter by extension if specified
                    if extensions:
                        if not any(file.lower().endswith(ext.lower()) for ext in extensions):
                            continue

                    try:
                        hash_result = self.calculate_multiple_hashes(file_path)
                        results.append(hash_result)
                        file_count += 1

                        # Perform security checks
                        self.check_malware(hash_result)
                        self.check_suspicious(file_path, hash_result)
                        self.track_duplicates(hash_result)

                    except Exception as e:
                        results.append({
                            'file': file_path,
                            'error': f'Failed to hash: {str(e)}'
                        })

        except Exception as e:
            results.append({'error': f'Failed to scan evidence directory: {str(e)}'})

        return results

    def scan_multiple_directories(self, directories, max_files_per_dir=50, extensions=None):
        """
        Scan multiple directories and combine results

        Args:
            directories: List of directory paths to scan
            max_files_per_dir: Max files to scan per directory
            extensions: File extensions to filter

        Returns:
            Combined list of all file hash results
        """
        all_results = []

        for directory in directories:
            if os.path.exists(directory) and os.path.isdir(directory):
                dir_results = self.scan_evidence_directory(
                    directory,
                    max_files=max_files_per_dir,
                    extensions=extensions
                )
                all_results.extend(dir_results)

        return all_results

    def check_malware(self, hash_result):
        """Check if file hash matches known malware"""
        if hash_result.get('sha256'):
            sha256 = hash_result['sha256'].lower()
            if sha256 in self.KNOWN_MALWARE_HASHES:
                detection = {
                    'file': hash_result['file'],
                    'hash': sha256,
                    'threat': self.KNOWN_MALWARE_HASHES[sha256],
                    'severity': '🔴 CRITICAL'
                }
                self.malware_detections.append(detection)

    def check_suspicious(self, file_path, hash_result):
        """Check if file is suspicious based on extension and location (OS-agnostic)"""
        file_ext = os.path.splitext(file_path)[1].lower()

        # Check suspicious extension
        if file_ext in [ext.lower() for ext in self.SUSPICIOUS_EXTENSIONS]:
            # Check if in suspicious location (OS-agnostic)
            file_path_lower = file_path.lower()

            if any(loc in file_path_lower for loc in self.SUSPICIOUS_LOCATIONS):
                self.suspicious_files.append({
                    'file': file_path,
                    'reason': f'Executable/script in suspicious location',
                    'extension': file_ext,
                    'sha256': hash_result.get('sha256', 'N/A')
                })

    def track_duplicates(self, hash_result):
        """Track duplicate files by hash"""
        sha256 = hash_result.get('sha256')
        if sha256:
            if sha256 in self.duplicate_files:
                self.duplicate_files[sha256].append(hash_result['file'])
            else:
                self.duplicate_files[sha256] = [hash_result['file']]

    def get_duplicate_files(self):
        """Get list of duplicate files"""
        duplicates = {}
        for hash_val, files in self.duplicate_files.items():
            if len(files) > 1:
                duplicates[hash_val] = files
        return duplicates

    def verify_file_integrity(self, file_path, known_hash, algorithm='sha256'):
        """
        Verify file integrity against known hash

        Args:
            file_path: Path to file
            known_hash: Known good hash
            algorithm: Hash algorithm

        Returns:
            Boolean indicating if hashes match
        """
        calculated_hash, _, error = self.calculate_file_hash(file_path, algorithm)

        if error:
            return False, error

        if calculated_hash.lower() == known_hash.lower():
            return True, "✅ Hash matches - File integrity verified"
        else:
            return False, f"❌ Hash mismatch - File may be corrupted or modified\nExpected: {known_hash}\nCalculated: {calculated_hash}"

    def export_hash_database(self, output_file):
        """Export hash database to JSON file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.hash_database, f, indent=2)
            return True, f"Hash database exported to {output_file}"
        except Exception as e:
            return False, str(e)

    def compare_with_virustotal(self, file_hash):
        """
        Compare hash with VirusTotal (requires API key)

        Note: This is a placeholder. In production, you would use:
        - VirusTotal API
        - AlienVault OTX
        - Hybrid Analysis
        - Other threat intelligence platforms

        Args:
            file_hash: File hash to check

        Returns:
            Dictionary with threat intelligence info
        """
        # Placeholder - Would integrate with real API
        return {
            'hash': file_hash,
            'status': 'Not implemented',
            'note': 'Integrate VirusTotal API for real-time threat detection',
            'virustotal_link': f'https://www.virustotal.com/gui/file/{file_hash}'
        }


def calculate_string_hash(text, algorithm='sha256'):
    """Calculate hash of a string"""
    hash_func = hashlib.new(algorithm)
    hash_func.update(text.encode('utf-8'))
    return hash_func.hexdigest()


def compare_hashes(hash1, hash2):
    """Compare two hashes"""
    return hash1.lower() == hash2.lower()


def get_common_file_hashes():
    """
    Get known hashes of common system files
    (This would be populated from a threat intelligence feed)
    """
    return {
        'windows': {
            'C:\\Windows\\System32\\cmd.exe': {
                'md5': 'example_md5_hash',
                'sha256': 'example_sha256_hash',
                'description': 'Windows Command Processor'
            },
            # Add more known good hashes
        },
        'linux': {
            '/bin/bash': {
                'md5': 'example_md5_hash',
                'sha256': 'example_sha256_hash',
                'description': 'Bash Shell'
            },
            # Add more known good hashes
        }
    }
