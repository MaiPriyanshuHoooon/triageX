"""
Encrypted File Scanner for Forensic Analysis
============================================

Detects encrypted files across Windows and macOS systems.
Excludes system files and focuses on user-accessible encrypted data.

Supports:
- Windows EFS (Encrypting File System)
- BitLocker encrypted files
- Common encryption software (VeraCrypt, 7-Zip, etc.)
- Password-protected documents
- macOS FileVault and encrypted DMG detection
"""

import os
import sys
import subprocess
from pathlib import Path
from datetime import datetime


class EncryptedFileScanner:
    """Scanner for detecting encrypted files in user directories"""

    def __init__(self):
        self.platform = sys.platform
        self.encrypted_files = []
        self.stats = {
            'total_scanned': 0,
            'encrypted_found': 0,
            'efs_files': 0,
            'password_protected': 0,
            'encrypted_archives': 0,
            'encrypted_containers': 0,
            'filevault_files': 0
        }

        # Common encrypted file extensions
        self.encrypted_extensions = {
            # Encrypted archives
            '.7z': 'Encrypted 7-Zip Archive',
            '.zip': 'Potentially Encrypted ZIP',
            '.rar': 'Potentially Encrypted RAR',
            '.aes': 'AES Encrypted File',
            '.pgp': 'PGP Encrypted File',
            '.gpg': 'GPG Encrypted File',

            # Encrypted containers
            '.tc': 'TrueCrypt Container',
            '.hc': 'VeraCrypt Container',
            '.dmg': 'macOS Disk Image (may be encrypted)',
            '.sparsebundle': 'macOS Sparse Bundle (may be encrypted)',
            '.sparseimage': 'macOS Sparse Image (may be encrypted)',

            # Encrypted documents
            '.docx': 'Password-Protected Word Document',
            '.xlsx': 'Password-Protected Excel Spreadsheet',
            '.pptx': 'Password-Protected PowerPoint',
            '.pdf': 'Password-Protected PDF',

            # Encryption software files
            '.kdbx': 'KeePass Database',
            '.axx': 'AxCrypt Encrypted File',
            '.crypted': 'Generic Encrypted File',
            '.encrypted': 'Generic Encrypted File',
            '.enc': 'Encrypted File',
            '.vault': 'Vault Encrypted File',

            # Cryptocurrency wallets (often encrypted)
            '.wallet': 'Cryptocurrency Wallet',
            '.dat': 'Potential Bitcoin Wallet'
        }

        # Directories to exclude (system directories)
        self.excluded_dirs = self._get_excluded_directories()

    def _get_excluded_directories(self):
        """Get list of system directories to exclude"""
        if self.platform == 'win32':
            return [
                'C:\\Windows',
                'C:\\Program Files',
                'C:\\Program Files (x86)',
                'C:\\ProgramData\\Microsoft',
                'C:\\$Recycle.Bin',
                'C:\\System Volume Information'
            ]
        elif self.platform == 'darwin':
            return [
                '/System',
                '/Library/Apple',
                '/private/var',
                '/usr',
                '/bin',
                '/sbin',
                '/cores',
                '/dev'
            ]
        else:  # Linux
            return [
                '/sys',
                '/proc',
                '/dev',
                '/boot',
                '/usr/lib',
                '/usr/share'
            ]

    def _should_skip_directory(self, dir_path):
        """Check if directory should be skipped"""
        dir_path_lower = dir_path.lower()

        for excluded in self.excluded_dirs:
            if dir_path_lower.startswith(excluded.lower()):
                return True

        return False

    def _is_efs_encrypted_windows(self, file_path):
        """Check if file is encrypted with Windows EFS"""
        try:
            # Windows-specific: CREATE_NO_WINDOW flag to prevent console popup
            creation_flags = 0
            if sys.platform == 'win32':
                creation_flags = subprocess.CREATE_NO_WINDOW

            # Use PowerShell to check encryption attribute
            cmd = f'powershell -Command "(Get-Item \'{file_path}\').Attributes -match \'Encrypted\'"'
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=creation_flags
            )
            return 'True' in result.stdout
        except Exception:
            return False

    def _check_archive_encryption(self, file_path):
        """Check if archive is password-protected (works on both platforms)"""
        ext = Path(file_path).suffix.lower()

        try:
            if ext == '.zip':
                # Check ZIP encryption flag
                with open(file_path, 'rb') as f:
                    # Read ZIP header
                    data = f.read(100)
                    # Check for encryption flag (bit 0 of general purpose bit flag)
                    if len(data) >= 30:
                        flags = int.from_bytes(data[6:8], 'little')
                        if flags & 0x0001:  # Encryption bit
                            return True

            elif ext == '.7z':
                # 7z files with passwords have specific headers
                with open(file_path, 'rb') as f:
                    header = f.read(32)
                    # 7z signature and check for encryption marker
                    if header[:6] == b'7z\xbc\xaf\x27\x1c':
                        return True  # Assume encrypted if 7z

            elif ext == '.pdf':
                # Check PDF encryption
                with open(file_path, 'rb') as f:
                    content = f.read(1024)
                    if b'/Encrypt' in content:
                        return True

            elif ext in ['.docx', '.xlsx', '.pptx']:
                # Office documents - check for encryption
                # These are ZIP archives, check for EncryptionInfo
                try:
                    import zipfile
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        if 'EncryptionInfo' in zip_ref.namelist() or 'EncryptedPackage' in zip_ref.namelist():
                            return True
                except Exception:
                    pass

        except Exception:
            pass

        return False

    def _check_macos_encryption(self, file_path):
        """Check macOS-specific encryption (FileVault, encrypted DMG)"""
        try:
            ext = Path(file_path).suffix.lower()

            # Windows-specific: CREATE_NO_WINDOW flag to prevent console popup
            creation_flags = 0
            if sys.platform == 'win32':
                creation_flags = subprocess.CREATE_NO_WINDOW

            # Check DMG encryption
            if ext == '.dmg':
                cmd = ['hdiutil', 'isencrypted', file_path]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=creation_flags
                )
                if 'encrypted: YES' in result.stdout:
                    return True

            # Check extended attributes for encryption
            cmd = ['xattr', '-l', file_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=creation_flags
            )

            # Look for encryption-related attributes
            if 'com.apple.quarantine' in result.stdout or 'com.apple.decmpfs' in result.stdout:
                return False  # Not encrypted, just compressed/quarantined

        except Exception:
            pass

        return False

    def scan_file(self, file_path):
        """Scan a single file for encryption"""
        self.stats['total_scanned'] += 1

        try:
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            file_ext = Path(file_path).suffix.lower()

            # Skip very large files (>2GB) for performance
            if file_size > 2 * 1024 * 1024 * 1024:
                return None

            # Skip empty files
            if file_size == 0:
                return None

            encryption_type = None
            is_encrypted = False

            # Platform-specific checks
            if self.platform == 'win32':
                # Check Windows EFS
                if self._is_efs_encrypted_windows(file_path):
                    encryption_type = 'Windows EFS'
                    is_encrypted = True
                    self.stats['efs_files'] += 1

            elif self.platform == 'darwin':
                # Check macOS encryption
                if self._check_macos_encryption(file_path):
                    encryption_type = 'macOS FileVault/Encrypted DMG'
                    is_encrypted = True
                    self.stats['filevault_files'] += 1

            # Check archive/document encryption (cross-platform)
            if not is_encrypted and file_ext in self.encrypted_extensions:
                if self._check_archive_encryption(file_path):
                    encryption_type = f'Password-Protected {self.encrypted_extensions[file_ext]}'
                    is_encrypted = True
                    self.stats['password_protected'] += 1
                elif file_ext in ['.tc', '.hc', '.vault']:
                    # Encryption containers
                    encryption_type = self.encrypted_extensions[file_ext]
                    is_encrypted = True
                    self.stats['encrypted_containers'] += 1
                elif file_ext in ['.7z', '.aes', '.pgp', '.gpg', '.kdbx', '.axx']:
                    # Known encrypted formats
                    encryption_type = self.encrypted_extensions[file_ext]
                    is_encrypted = True
                    self.stats['encrypted_archives'] += 1

            if is_encrypted:
                self.stats['encrypted_found'] += 1

                return {
                    'path': file_path,
                    'filename': os.path.basename(file_path),
                    'size': file_size,
                    'size_mb': round(file_size / (1024 * 1024), 2),
                    'extension': file_ext,
                    'encryption_type': encryption_type,
                    'modified': datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'accessed': datetime.fromtimestamp(file_stat.st_atime).strftime('%Y-%m-%d %H:%M:%S')
                }

        except Exception as e:
            # Skip permission errors silently
            pass

        return None

    def scan_directory(self, directory, max_files=500):
        """Scan a directory for encrypted files"""
        found_files = []
        files_checked = 0

        try:
            for root, dirs, files in os.walk(directory):
                # Skip excluded directories
                if self._should_skip_directory(root):
                    dirs.clear()  # Don't recurse into subdirectories
                    continue

                # Filter out system directories from dirs list
                dirs[:] = [d for d in dirs if not self._should_skip_directory(os.path.join(root, d))]

                for file in files:
                    if files_checked >= max_files:
                        break

                    file_path = os.path.join(root, file)
                    result = self.scan_file(file_path)

                    if result:
                        found_files.append(result)

                    files_checked += 1

                if files_checked >= max_files:
                    break

        except Exception as e:
            print(f"    ⚠️  Error scanning {directory}: {str(e)}")

        return found_files

    def scan_user_directories(self, max_files_per_dir=200):
        """Scan common user directories for encrypted files"""
        scan_results = []

        # Get user directories based on platform
        if self.platform == 'win32':
            user_dirs = [
                str(Path.home() / 'Documents'),
                str(Path.home() / 'Desktop'),
                str(Path.home() / 'Downloads'),
                str(Path.home() / 'Pictures'),
                str(Path.home() / 'Videos'),
                'D:\\',  # Check D: drive if exists
                'E:\\'   # Check E: drive if exists
            ]
        elif self.platform == 'darwin':
            user_dirs = [
                str(Path.home() / 'Documents'),
                str(Path.home() / 'Desktop'),
                str(Path.home() / 'Downloads'),
                str(Path.home() / 'Pictures'),
                str(Path.home() / 'Movies')
            ]
        else:  # Linux
            user_dirs = [
                str(Path.home() / 'Documents'),
                str(Path.home() / 'Desktop'),
                str(Path.home() / 'Downloads'),
                str(Path.home() / 'Pictures'),
                str(Path.home() / 'Videos')
            ]

        # Only scan directories that exist
        existing_dirs = [d for d in user_dirs if os.path.exists(d)]

        for directory in existing_dirs:
            print(f"    └─ Scanning: {directory}")
            results = self.scan_directory(directory, max_files=max_files_per_dir)
            scan_results.extend(results)

        self.encrypted_files = scan_results
        return scan_results

    def generate_report_data(self):
        """Generate structured report data"""
        return {
            'platform': self.platform,
            'stats': self.stats,
            'encrypted_files': self.encrypted_files,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
