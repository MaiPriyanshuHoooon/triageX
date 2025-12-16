"""
Enhanced File Scanner Module
===========================
Scans actual files on the system for PII and sensitive data
Supports PDFs, DOCs, images (OCR), videos (frame extraction + OCR), and text files
"""

import os
import re
import json
import mimetypes
from pathlib import Path
from datetime import datetime
import subprocess
import platform
import tempfile

try:
    # PDF processing
    import PyPDF2
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    # Image OCR processing
    from PIL import Image
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

try:
    # Word document processing
    import docx
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

try:
    # Excel processing
    import openpyxl
    EXCEL_AVAILABLE = True
except ImportError:
    EXCEL_AVAILABLE = False

try:
    # Additional document formats
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    # Video processing for frame extraction
    import cv2
    VIDEO_AVAILABLE = True
except ImportError:
    VIDEO_AVAILABLE = False


class PiiAnalyzer:
    """Enhanced PII detector with Indian-specific patterns for law enforcement"""

    # Comprehensive PII patterns for investigations
    PII_PATTERNS = {
        # Indian Government IDs
        'aadhar_card': {
            'pattern': r'\b\d{4}\s?\d{4}\s?\d{4}\b',
            'description': 'Aadhar Card Number (12 digits)',
            'category': 'Government ID',
            'severity': 'HIGH',
            'points': 5
        },
        'pan_card': {
            'pattern': r'\b[A-Z]{5}\d{4}[A-Z]\b',
            'description': 'PAN Card Number',
            'category': 'Government ID',
            'severity': 'HIGH',
            'points': 5
        },
        'voter_id': {
            'pattern': r'\b[A-Z]{3}\d{7}\b',
            'description': 'Voter ID Card',
            'category': 'Government ID',
            'severity': 'MEDIUM',
            'points': 3
        },
        'driving_license': {
            'pattern': r'\b[A-Z]{2}\d{2}\s?\d{11}\b',
            'description': 'Indian Driving License',
            'category': 'Government ID',
            'severity': 'MEDIUM',
            'points': 3
        },
        'passport': {
            'pattern': r'\b[A-PR-WYZ][1-9]\d\s?\d{4}\d\s?\d{4}\d\s?\d\b',
            'description': 'Indian Passport Number',
            'category': 'Government ID',
            'severity': 'HIGH',
            'points': 4
        },
        'gstin': {
            'pattern': r'\b\d{2}[A-Z]{5}\d{4}[A-Z]\d[Z]\d\b',
            'description': 'GSTIN Number',
            'category': 'Business ID',
            'severity': 'MEDIUM',
            'points': 3
        },

        # Financial Information
        'credit_card': {
            'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            'description': 'Credit Card Number',
            'category': 'Financial',
            'severity': 'HIGH',
            'points': 4
        },
        'bank_account': {
            'pattern': r'\b(?:(?!\+91[\-\s]?[6-9]\d{9}\b)\d{11,18})\b',
            'description': 'Bank Account Number',
            'category': 'Financial',
            'severity': 'HIGH',
            'points': 4
        },
        'ifsc_code': {
            'pattern': r'\b[A-Z]{4}0[A-Z0-9]{6}\b',
            'description': 'IFSC Code',
            'category': 'Financial',
            'severity': 'MEDIUM',
            'points': 2
        },
        'upi_id': {
            'pattern': r'\b[a-zA-Z0-9.\-_]{2,49}@(?:paytm|phonepe|gpay|bhim|upi|okaxis|okicici|okhdfcbank|oksbi|ybl|ibl|axl)\b',
            'description': 'UPI ID',
            'category': 'Financial',
            'severity': 'MEDIUM',
            'points': 2
        },

        # Contact Information
        'phone_number': {
            'pattern': r'\b(?:\+91[\-\s]?)?[6-9]\d{9}\b',
            'description': 'Indian Phone Number',
            'category': 'Personal Contact',
            'severity': 'LOW',
            'points': 1
        },
        'email': {
            'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'description': 'Email Address',
            'category': 'Personal Contact',
            'severity': 'LOW',
            'points': 1
        },

        # International IDs
        'social_security': {
            'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
            'description': 'US Social Security Number',
            'category': 'Government ID',
            'severity': 'HIGH',
            'points': 4
        }
    }

    def analyze_text(self, text):
        """
        Analyze text for PII patterns

        Returns:
            Dictionary with analysis results
        """
        results = {
            'pii_findings': [],
            'privacy_risk_score': 0,
            'categories_found': set(),
            'iocs': []  # For compatibility
        }

        for pattern_name, pattern_info in self.PII_PATTERNS.items():
            matches = re.findall(pattern_info['pattern'], text, re.IGNORECASE)
            if matches:
                unique_matches = list(dict.fromkeys(matches))

                for match in unique_matches:
                    results['pii_findings'].append({
                        'type': pattern_name,
                        'value': match,
                        'category': pattern_info['category'],
                        'severity': pattern_info['severity'],
                        'description': pattern_info['description'],
                        'points': pattern_info['points']
                    })

                    results['privacy_risk_score'] += pattern_info['points']
                    results['categories_found'].add(pattern_info['category'])

        results['categories_found'] = list(results['categories_found'])
        return results


class FileScanner:
    """Enhanced file scanner with PII detection for law enforcement investigations"""

    def __init__(self, regex_analyzer=None):
        """Initialize file scanner with PII analyzer"""
        self.pii_analyzer = PiiAnalyzer()
        self.regex_analyzer = regex_analyzer  # Keep for compatibility

        # Supported file extensions by category
        self.supported_extensions = {
            'text': ['.txt', '.log', '.csv', '.tsv', '.json', '.xml', '.md'],
            'pdf': ['.pdf'],
            'document': ['.docx', '.doc'],
            'image': ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff'],
            'video': ['.mp4', '.avi', '.mov', '.mkv', '.wmv', '.flv'],
            'spreadsheet': ['.xlsx', '.xls'],
            'code': ['.py', '.js', '.html', '.css', '.java', '.cpp', '.c', '.php', '.rb'],
            'data': ['.json', '.xml', '.csv', '.tsv']
        }

        # Scan configuration - Optimized for LEA Investigations
        self.scan_config = {
            'max_file_size_mb': 50,  # Maximum file size to scan
            'enable_ocr': OCR_AVAILABLE,
            'enable_pdf': PDF_AVAILABLE,
            'enable_docx': DOCX_AVAILABLE,
            'enable_excel': EXCEL_AVAILABLE,
            'enable_video': VIDEO_AVAILABLE,
            'scan_hidden_files': False,
            'scan_system_dirs': False,
            'excluded_dirs': ['.git', '__pycache__', 'node_modules', '.vscode', '.idea'],
            'custom_directories': [],
            'max_ocr_file_size_mb': 5,  # Smaller limit for OCR processing
            'max_video_file_size_mb': 100,  # Limit for video processing
            'video_frame_interval': 30,  # Extract 1 frame every 30 frames (1 per second at 30fps)
            'max_video_frames': 50,  # Maximum frames to extract per video

            # LEA Investigation Thresholds - LOWERED for better detection
            'min_privacy_score': 2,      # Lowered from 5
            'min_pii_count': 1,          # Lowered from 2
            'min_investigative_score': 1, # Lowered from 3
            'filter_screenshots': True,  # Filter out random screenshots
            'focus_financial_data': True # Prioritize financial/ID documents
        }

        self.scan_results = []

    def configure_scan(self, **kwargs):
        """Configure scan parameters"""
        for key, value in kwargs.items():
            if key in self.scan_config:
                self.scan_config[key] = value
                print(f"📝 Configuration updated: {key} = {value}")
            else:
                print(f"⚠️  Unknown configuration: {key}")

    def scan_common_directories(self, max_files=50):
        """
        Scan common directories for files containing PII

        Args:
            max_files: Maximum number of files to scan

        Returns:
            List of file results with PII found
        """
        directories = self._get_common_directories()
        return self.scan_specific_directories(directories, max_files_per_dir=max_files//len(directories))

    def scan_specific_directories(self, directories, max_files_per_dir=20):
        """
        Scan specific directories for PII

        Args:
            directories: List of directory paths to scan
            max_files_per_dir: Maximum files per directory

        Returns:
            List of file results with PII found
        """
        all_results = []

        print(f"🔍 Starting comprehensive file scan for PII...")
        print(f"📁 Scanning {len(directories)} directories")
        print(f"⚙️  Max file size: {self.scan_config['max_file_size_mb']}MB")
        print(f"🖼️  OCR enabled: {self.scan_config['enable_ocr']}")
        print(f"🎬 Video analysis enabled: {self.scan_config['enable_video']}")
        print(f"📄 PDF enabled: {self.scan_config['enable_pdf']}")
        print(f"🎯 Min Privacy Score: {self.scan_config['min_privacy_score']}")
        print(f"🎯 Min PII Count: {self.scan_config['min_pii_count']}")
        print(f"🎯 Min Investigation Score: {self.scan_config['min_investigative_score']}")
        print()

        print(f"🎯 Scanning {len(directories)} specific directories...")

        for dir_path in directories:
            if os.path.exists(dir_path) and os.path.isdir(dir_path):
                print(f"  📂 Scanning: {dir_path}")
                results = self._scan_directory(dir_path, max_files_per_dir=max_files_per_dir)
                all_results.extend(results)
            else:
                print(f"  ⚠️  Directory not found: {dir_path}")

        self.scan_results = all_results
        return all_results

    def _get_common_directories(self):
        """Get list of common directories to scan based on OS"""
        system = platform.system().lower()
        home_dir = Path.home()

        if system == 'windows':
            common_dirs = [
                str(home_dir / 'Desktop'),
                str(home_dir / 'Documents'),
                str(home_dir / 'Downloads'),
                str(home_dir / 'Pictures'),
                'C:\\Users\\Public\\Documents',
                'C:\\Users\\Public\\Desktop',
                'C:\\temp',
                'C:\\tmp'
            ]
        elif system == 'darwin':  # macOS
            common_dirs = [
                str(home_dir / 'Desktop'),
                str(home_dir / 'Documents'),
                str(home_dir / 'Downloads'),
                str(home_dir / 'Pictures'),
                '/tmp',
                '/var/tmp'
            ]
        else:  # Linux
            common_dirs = [
                str(home_dir / 'Desktop'),
                str(home_dir / 'Documents'),
                str(home_dir / 'Downloads'),
                str(home_dir / 'Pictures'),
                '/tmp',
                '/var/tmp',
                '/home'
            ]

        return common_dirs

    def _scan_directory(self, directory, max_files_per_dir=20):
        """Scan a specific directory for files containing PII"""
        results = []
        files_scanned = 0

        try:
            for root, dirs, files in os.walk(directory):
                # Apply directory filtering based on configuration
                filtered_dirs = []
                for d in dirs:
                    # Skip hidden directories unless enabled
                    if d.startswith('.') and not self.scan_config['scan_hidden_files']:
                        continue
                    # Skip excluded directories
                    if d in self.scan_config['excluded_dirs']:
                        continue
                    # Skip system directories unless enabled
                    if not self.scan_config['scan_system_dirs'] and d in ['System32', 'Windows', 'AppData']:
                        continue
                    filtered_dirs.append(d)
                dirs[:] = filtered_dirs

                for file in files:
                    if files_scanned >= max_files_per_dir:
                        break

                    file_path = os.path.join(root, file)

                    # Skip hidden files unless enabled
                    if file.startswith('.') and not self.scan_config['scan_hidden_files']:
                        continue
                    # Skip temporary files
                    if file.startswith('~') or file.endswith('.tmp'):
                        continue

                    # Check if file extension is supported
                    file_ext = Path(file).suffix.lower()
                    if self._is_supported_file(file_ext):
                        result = self._scan_file(file_path)
                        if result and result['pii_found']:
                            results.append(result)
                        files_scanned += 1

                if files_scanned >= max_files_per_dir:
                    break

        except PermissionError:
            print(f"    ⚠️  Permission denied: {directory}")
        except Exception as e:
            print(f"    ❌ Error scanning {directory}: {str(e)}")

        return results

    def _is_supported_file(self, file_ext):
        """Check if file extension is supported"""
        for category, extensions in self.supported_extensions.items():
            if file_ext in extensions:
                return True
        return False

    def _scan_file(self, file_path):
        """Scan individual file for PII with investigative value filtering"""
        try:
            file_ext = Path(file_path).suffix.lower()
            file_size = os.path.getsize(file_path)
            file_modified = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
            file_name = os.path.basename(file_path).lower()
            mime_type, _ = mimetypes.guess_type(file_path)

            # Skip files larger than configured size
            max_size = self.scan_config['max_file_size_mb'] * 1024 * 1024
            if file_size > max_size:
                return None

            # For OCR files, apply smaller size limit
            if (file_ext in self.supported_extensions['image'] and
                file_size > self.scan_config['max_ocr_file_size_mb'] * 1024 * 1024):
                return None

            # For video files, apply video size limit
            if (file_ext in self.supported_extensions['video'] and
                file_size > self.scan_config['max_video_file_size_mb'] * 1024 * 1024):
                return None

            # Quick validation for image files before OCR
            if file_ext in self.supported_extensions['image']:
                if not self._is_valid_image_file(file_path):
                    return None

            # Filter out files with low investigative value for LEA
            if (self.scan_config['filter_screenshots'] and
                self._is_low_value_file(file_path, file_name)):
                return None

            # Extract text based on file type
            text_content = self._extract_text_from_file(file_path, file_ext)

            if not text_content or len(text_content.strip()) < 20:
                return None

            # Analyze text for PII using our enhanced analyzer
            analysis_results = self.pii_analyzer.analyze_text(text_content)

            # Apply investigative value scoring
            investigative_score = self._calculate_investigative_value(analysis_results, text_content, file_name)

            # Only return results if significant PII was found with investigative value
            privacy_score = analysis_results.get('privacy_risk_score', 0)
            pii_count = len(analysis_results.get('pii_findings', []))

            # Apply LEA investigation thresholds for focused results
            if (privacy_score >= self.scan_config['min_privacy_score'] and
                pii_count >= self.scan_config['min_pii_count'] and
                investigative_score >= self.scan_config['min_investigative_score']):

                return {
                    'file_path': file_path,
                    'file_name': os.path.basename(file_path),
                    'file_size': file_size,
                    'file_modified': file_modified,
                    'file_type': mime_type or self._get_file_category(file_ext),
                    'scan_timestamp': datetime.now().isoformat(),
                    'pii_found': True,
                    'analysis_results': analysis_results,
                    'investigative_score': investigative_score,
                    'text_preview': text_content[:500] + '...' if len(text_content) > 500 else text_content
                }

        except Exception as e:
            print(f"    ❌ Error scanning file {file_path}: {str(e)}")
            return None

        return None

    def _extract_text_from_file(self, file_path, file_ext):
        """Extract text content from various file types"""
        text_content = ""

        try:
            if file_ext in self.supported_extensions['text'] or file_ext in self.supported_extensions['code']:
                # Plain text files
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text_content = f.read()

            elif file_ext in self.supported_extensions['pdf'] and PDF_AVAILABLE:
                # PDF files
                text_content = self._extract_pdf_text(file_path)

            elif file_ext in self.supported_extensions['document'] and DOCX_AVAILABLE:
                # Word documents
                text_content = self._extract_docx_text(file_path)

            elif file_ext in self.supported_extensions['image'] and self.scan_config['enable_ocr']:
                # Images with OCR
                text_content = self._extract_image_text(file_path)

            elif file_ext in self.supported_extensions['video'] and self.scan_config['enable_video']:
                # Videos with frame extraction + OCR
                text_content = self._extract_video_text(file_path)

            elif file_ext in self.supported_extensions['spreadsheet'] and EXCEL_AVAILABLE:
                # Excel files
                text_content = self._extract_excel_text(file_path)

            elif file_ext in self.supported_extensions['data']:
                # Data files (CSV, JSON, etc.)
                text_content = self._extract_data_file_text(file_path)

        except Exception as e:
            print(f"    ⚠️  Error extracting text from {file_path}: {str(e)}")
            return ""

        return text_content

    def _extract_pdf_text(self, file_path):
        """Extract text from PDF using PyPDF2"""
        text = ""
        try:
            with open(file_path, 'rb') as file:
                reader = PyPDF2.PdfReader(file)
                for page in reader.pages:
                    text += page.extract_text() + "\n"
        except Exception as e:
            print(f"    ⚠️  Error reading PDF {file_path}: {str(e)}")
        return text

    def _extract_docx_text(self, file_path):
        """Extract text from Word documents"""
        text = ""
        try:
            doc = docx.Document(file_path)
            for paragraph in doc.paragraphs:
                text += paragraph.text + "\n"
        except Exception as e:
            print(f"    ⚠️  Error reading DOCX {file_path}: {str(e)}")
        return text

    def _extract_image_text(self, file_path):
        """Extract text from images using OCR"""
        text = ""
        if not OCR_AVAILABLE:
            return text

        try:
            # First, try to open and verify the image
            with Image.open(file_path) as image:
                # Check if image is corrupted by trying to load it
                image.verify()

            # Reopen the image after verify() as it's no longer usable
            with Image.open(file_path) as image:
                # Convert to RGB if needed (some formats cause issues)
                if image.mode not in ('RGB', 'L'):
                    image = image.convert('RGB')

                # Perform OCR
                text = pytesseract.image_to_string(image, config='--psm 6')

        except (OSError, IOError) as e:
            if "premature end of data" in str(e).lower() or "corrupt" in str(e).lower():
                print(f"    ⚠️  Skipping corrupted image: {os.path.basename(file_path)} (JPEG corruption)")
            else:
                print(f"    ⚠️  Image read error for {os.path.basename(file_path)}: {str(e)}")
        except Exception as e:
            # Handle Tesseract OCR errors more gracefully
            error_msg = str(e)
            if "corrupt" in error_msg.lower() or "premature end" in error_msg.lower():
                print(f"    ⚠️  Skipping corrupted image: {os.path.basename(file_path)} (OCR failed - corrupted data)")
            elif "tesseract" in error_msg.lower():
                print(f"    ⚠️  OCR processing failed for {os.path.basename(file_path)} (Tesseract error)")
            else:
                print(f"    ⚠️  OCR error for {os.path.basename(file_path)}: {error_msg[:100]}...")

        return text

    def _extract_video_text(self, file_path):
        """
        Extract text from video by extracting frames and performing OCR

        Args:
            file_path: Path to video file

        Returns:
            Combined text from all extracted frames
        """
        text = ""
        if not VIDEO_AVAILABLE or not OCR_AVAILABLE:
            print(f"    ⚠️  Video/OCR not available for {os.path.basename(file_path)}")
            return text

        temp_frames = []
        try:
            # Open video file
            video = cv2.VideoCapture(file_path)

            if not video.isOpened():
                print(f"    ⚠️  Failed to open video: {os.path.basename(file_path)}")
                return text

            # Get video properties
            fps = video.get(cv2.CAP_PROP_FPS)
            total_frames = int(video.get(cv2.CAP_PROP_FRAME_COUNT))

            # Calculate frame extraction interval
            frame_interval = self.scan_config['video_frame_interval']
            max_frames = self.scan_config['max_video_frames']

            print(f"    🎬 Processing video: {os.path.basename(file_path)} ({total_frames} frames, {fps:.1f} fps)")

            frame_count = 0
            extracted_count = 0

            while video.isOpened() and extracted_count < max_frames:
                ret, frame = video.read()

                if not ret:
                    break

                # Extract frame at intervals
                if frame_count % frame_interval == 0:
                    # Save frame to temporary file
                    temp_frame_path = os.path.join(tempfile.gettempdir(), f"forensic_frame_{extracted_count}.png")
                    cv2.imwrite(temp_frame_path, frame)
                    temp_frames.append(temp_frame_path)

                    # Perform OCR on frame
                    try:
                        with Image.open(temp_frame_path) as image:
                            # Convert to RGB if needed
                            if image.mode not in ('RGB', 'L'):
                                image = image.convert('RGB')

                            # Perform OCR
                            frame_text = pytesseract.image_to_string(image, config='--psm 6')

                            if frame_text and len(frame_text.strip()) > 10:  # Only add meaningful text
                                text += f"\n[Frame {frame_count}]: {frame_text}\n"

                    except Exception as ocr_error:
                        print(f"    ⚠️  OCR error on frame {frame_count}: {str(ocr_error)[:50]}...")

                    extracted_count += 1

                frame_count += 1

            video.release()

            print(f"    ✅ Extracted text from {extracted_count} frames")

        except Exception as e:
            error_msg = str(e)
            print(f"    ⚠️  Video processing error for {os.path.basename(file_path)}: {error_msg[:100]}...")
        finally:
            # Clean up temporary frames
            for temp_frame in temp_frames:
                try:
                    if os.path.exists(temp_frame):
                        os.remove(temp_frame)
                except:
                    pass

        return text

    def _extract_excel_text(self, file_path):
        """Extract text from Excel files"""
        text = ""
        try:
            if EXCEL_AVAILABLE:
                import openpyxl
                workbook = openpyxl.load_workbook(file_path)
                for sheet in workbook.worksheets:
                    for row in sheet.iter_rows():
                        for cell in row:
                            if cell.value:
                                text += str(cell.value) + " "
                    text += "\n"
            elif PANDAS_AVAILABLE:
                try:
                    import pandas as pd
                    df = pd.read_excel(file_path)
                    text = df.to_string()
                except:
                    pass
        except Exception as e:
            print(f"    ⚠️  Error reading Excel {file_path}: {str(e)}")
        return text

    def _extract_data_file_text(self, file_path):
        """Extract text from data files (CSV, JSON, etc.)"""
        text = ""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        except Exception as e:
            print(f"    ⚠️  Error reading data file {file_path}: {str(e)}")
        return text

    def _get_file_category(self, file_ext):
        """Get file category for display"""
        for category, extensions in self.supported_extensions.items():
            if file_ext in extensions:
                return category.title()
        return 'Unknown'

    def _is_valid_image_file(self, file_path):
        """
        Quick validation to check if image file is readable and not corrupted
        Returns False for corrupted files that should be skipped
        """
        if not OCR_AVAILABLE:
            return True  # Skip validation if PIL not available

        try:
            with Image.open(file_path) as img:
                # Try to access basic image properties
                img.size  # This will fail for corrupted images
                img.mode  # Check if mode is accessible

                # Quick format validation
                if img.format in ['JPEG', 'JPG'] and img.size[0] * img.size[1] > 50000000:  # Very large images
                    return False

            return True
        except (OSError, IOError, Exception) as e:
            error_msg = str(e).lower()
            if any(keyword in error_msg for keyword in ['corrupt', 'premature', 'truncated', 'broken']):
                print(f"    ⚠️  Skipping corrupted image: {os.path.basename(file_path)}")
                return False
            # For other errors, still try to process
            return True

    def _is_low_value_file(self, file_path, file_name):
        """
        Filter out files with low investigative value for law enforcement

        Returns True if file should be skipped
        """
        # Skip random screenshots (common pattern: Screenshot YYYY-MM-DD at...)
        if 'screenshot' in file_name and any(x in file_name for x in ['at ', 'am.', 'pm.']):
            return True

        # Skip system/application screenshots with generic names
        generic_screenshot_patterns = [
            r'screenshot[\s_-]*\d{4}[-_]\d{2}[-_]\d{2}',  # Screenshot 2024-11-28 style
            r'screen[\s_-]*shot[\s_-]*\d+',               # Screen shot 1, 2, etc
            r'image[\s_-]*\d+\.png',                      # Generic image1.png, image2.png
            r'capture[\s_-]*\d+',                         # Capture1, Capture2
        ]

        for pattern in generic_screenshot_patterns:
            if re.search(pattern, file_name, re.IGNORECASE):
                return True

        # Skip test files and temporary files
        test_patterns = ['test', 'sample', 'example', 'demo', 'temp', 'tmp']
        if any(pattern in file_name for pattern in test_patterns):
            return True

        # Skip very small files (likely not documents)
        if os.path.getsize(file_path) < 100:  # Less than 100 bytes
            return True

        return False

    def _calculate_investigative_value(self, analysis_results, text_content, file_name):
        """
        Calculate investigative value score for law enforcement (1-10)

        Higher scores indicate more valuable findings for investigations
        """
        score = 0

        pii_findings = analysis_results.get('pii_findings', [])

        # High-value PII patterns for investigations
        high_value_patterns = {
            'pan_card': 5,           # Indian PAN cards - very valuable
            'credit_card': 4,        # Financial data
            'bank_account': 4,       # Banking information
            'aadhar_card': 5,        # Indian ID documents
            'passport': 4,           # Official documents
            'driving_license': 3,    # Government IDs
            'voter_id': 3,           # Indian voter IDs
            'gstin': 3,              # Business registrations
            'social_security': 4,    # SSN
            'phone_number': 2,       # Contact info
            'email': 1,              # Basic contact info
        }

        # Score based on PII types found
        for finding in pii_findings:
            pattern_type = finding.get('type', '').lower()
            for valuable_type, points in high_value_patterns.items():
                if valuable_type in pattern_type:
                    score += points
                    break

        # Bonus for multiple different PII types (suggests real documents)
        unique_types = set(finding.get('type', '').lower() for finding in pii_findings)
        if len(unique_types) >= 3:
            score += 2
        elif len(unique_types) >= 2:
            score += 1

        # Bonus for structured document content
        document_indicators = ['name:', 'address:', 'phone:', 'date of birth', 'account number', 'card number']
        indicator_count = sum(1 for indicator in document_indicators if indicator.lower() in text_content.lower())
        if indicator_count >= 3:
            score += 2
        elif indicator_count >= 2:
            score += 1

        # Bonus for financial/official document keywords
        official_keywords = ['statement', 'certificate', 'license', 'registration', 'invoice', 'receipt', 'contract']
        if any(keyword.lower() in file_name.lower() or keyword.lower() in text_content.lower() for keyword in official_keywords):
            score += 1

        return min(score, 10)  # Cap at 10

    def _format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes / (1024 * 1024):.1f} MB"

    def generate_html_report(self, results):
        """Generate HTML report for file scan results"""
        if not results:
            return '<div style="text-align: center; padding: 2rem;"><p>No files with PII found meeting investigation criteria.</p></div>'

        # Summary stats
        total_files = len(results)
        total_pii_items = sum(len(r['analysis_results'].get('pii_findings', [])) for r in results)

        html = f'''
        <div class="file-scan-results">
            <div class="scan-summary" style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-bottom: 2rem;">
                <div class="stat-card" style="background: rgba(59, 130, 246, 0.1); padding: 1rem; border-radius: 0.5rem; text-align: center;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #3b82f6;">{total_files}</div>
                    <div style="color: var(--text-secondary); font-size: 0.875rem;">Files with PII</div>
                </div>
                <div class="stat-card" style="background: rgba(16, 185, 129, 0.1); padding: 1rem; border-radius: 0.5rem; text-align: center;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #10b981;">{total_pii_items}</div>
                    <div style="color: var(--text-secondary); font-size: 0.875rem;">PII Items Found</div>
                </div>
                <div class="stat-card" style="background: rgba(245, 158, 11, 0.1); padding: 1rem; border-radius: 0.5rem; text-align: center;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #f59e0b;">High</div>
                    <div style="color: var(--text-secondary); font-size: 0.875rem;">Investigation Priority</div>
                </div>
            </div>

            <div class="file-list">
        '''

        for i, result in enumerate(results, 1):
            pii_count = len(result['analysis_results'].get('pii_findings', []))
            privacy_score = result['analysis_results'].get('privacy_risk_score', 0)
            invest_score = result.get('investigative_score', 0)

            # Color coding based on investigation score
            if invest_score >= 7:
                priority_color = "#ef4444"
                priority_text = "Critical"
            elif invest_score >= 5:
                priority_color = "#f59e0b"
                priority_text = "High"
            elif invest_score >= 3:
                priority_color = "#3b82f6"
                priority_text = "Medium"
            else:
                priority_color = "#10b981"
                priority_text = "Low"

            html += f'''
                <div class="file-item" style="border: 1px solid var(--border-primary); border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem; background: var(--bg-card);">
                    <div style="display: flex; justify-content: between; align-items: start; margin-bottom: 0.5rem;">
                        <div style="flex: 1;">
                            <h4 style="margin: 0 0 0.5rem 0; color: var(--text-primary);">📄 {result['file_name']}</h4>
                            <div style="color: var(--text-secondary); font-size: 0.875rem; margin-bottom: 0.5rem;">
                                📁 {result['file_path']}<br>
                                📊 Size: {self._format_file_size(result['file_size'])} | Type: {result['file_type']}
                            </div>
                        </div>
                        <div style="text-align: right;">
                            <div style="color: {priority_color}; font-weight: bold; font-size: 0.875rem;">{priority_text} Priority</div>
                            <div style="color: var(--text-tertiary); font-size: 0.75rem;">Score: {invest_score}/10</div>
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-bottom: 1rem; font-size: 0.875rem;">
                        <div>
                            <span style="color: var(--text-secondary);">PII Items:</span>
                            <span style="color: var(--text-primary); font-weight: 600;">{pii_count}</span>
                        </div>
                        <div>
                            <span style="color: var(--text-secondary);">Privacy Score:</span>
                            <span style="color: var(--text-primary); font-weight: 600;">{privacy_score}</span>
                        </div>
                        <div>
                            <span style="color: var(--text-secondary);">Categories:</span>
                            <span style="color: var(--text-primary); font-weight: 600;">{len(set(f['category'] for f in result['analysis_results'].get('pii_findings', [])))}</span>
                        </div>
                    </div>

                    <div class="pii-items" style="margin-bottom: 1rem;">
                        <strong style="color: var(--text-primary);">PII Found:</strong><br>
            '''

            # Group PII by category
            pii_by_category = {}
            for finding in result['analysis_results'].get('pii_findings', []):
                category = finding['category']
                if category not in pii_by_category:
                    pii_by_category[category] = []
                pii_by_category[category].append(finding)

            for category, findings in pii_by_category.items():
                html += f'<div style="margin: 0.5rem 0;"><strong style="color: var(--text-secondary);">{category}:</strong> '
                for finding in findings[:3]:  # Limit to 3 per category
                    html += f'<span style="background: rgba(59, 130, 246, 0.1); padding: 0.25rem 0.5rem; border-radius: 0.25rem; margin-right: 0.5rem; font-size: 0.75rem;">{finding["description"]}</span>'
                if len(findings) > 3:
                    html += f'<span style="color: var(--text-tertiary); font-size: 0.75rem;">+{len(findings) - 3} more</span>'
                html += '</div>'

            html += f'''
                    </div>

                    <div class="file-actions" style="display: flex; gap: 0.5rem;">
                        <button class="btn-secondary" onclick="openFile('{result['file_path']}')" style="font-size: 0.75rem; padding: 0.5rem 1rem;">📂 Open</button>
                        <button class="btn-secondary" onclick="copyPath('{result['file_path']}')" style="font-size: 0.75rem; padding: 0.5rem 1rem;">📋 Copy Path</button>
                        <button class="btn-secondary" onclick="showPreview('{i}')" style="font-size: 0.75rem; padding: 0.5rem 1rem;">👁️ Preview</button>
                    </div>
                </div>
            '''

        html += '''
            </div>
        </div>
        '''

        return html


def get_missing_dependencies():
    """Check which optional dependencies are missing"""
    missing = []

    if not PDF_AVAILABLE:
        missing.append("PyPDF2 (for PDF scanning)")
    if not OCR_AVAILABLE:
        missing.append("PIL + pytesseract (for image OCR)")
    if not DOCX_AVAILABLE:
        missing.append("python-docx (for Word document scanning)")
    if not EXCEL_AVAILABLE:
        missing.append("openpyxl (for Excel file scanning)")
    if not PANDAS_AVAILABLE:
        missing.append("pandas (for enhanced data file processing)")

    return missing

def get_available_features():
    """Get list of available features based on installed dependencies"""
    features = ['Text files', 'CSV/JSON files', 'Code files']

    if PDF_AVAILABLE:
        features.append('PDF documents')
    if OCR_AVAILABLE:
        features.append('Image OCR')
    if DOCX_AVAILABLE:
        features.append('Word documents')
    if EXCEL_AVAILABLE:
        features.append('Excel spreadsheets')

    return features
