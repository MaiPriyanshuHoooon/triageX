"""
Tesseract OCR Configuration Helper
===================================
Automatically configures Tesseract OCR path for bundled or system installation
"""

import os
import sys

def configure_tesseract():
    """
    Configure pytesseract to find Tesseract executable
    Handles both bundled (in EXE) and system installations
    """
    try:
        import pytesseract
        
        # Check if running as bundled EXE (frozen)
        if getattr(sys, 'frozen', False):
            # Running as EXE - look for bundled Tesseract
            base_path = sys._MEIPASS if hasattr(sys, '_MEIPASS') else os.path.dirname(sys.executable)
            tesseract_path = os.path.join(base_path, 'tesseract', 'tesseract.exe')
            
            if os.path.exists(tesseract_path):
                pytesseract.pytesseract.tesseract_cmd = tesseract_path
                os.environ['TESSDATA_PREFIX'] = os.path.join(base_path, 'tesseract', 'tessdata')
                return True, "Using bundled Tesseract"
        
        # Try system installations
        system_paths = [
            r'C:\Program Files\Tesseract-OCR\tesseract.exe',
            r'C:\Program Files (x86)\Tesseract-OCR\tesseract.exe',
        ]
        
        for path in system_paths:
            if os.path.exists(path):
                pytesseract.pytesseract.tesseract_cmd = path
                return True, f"Using system Tesseract: {path}"
        
        # Tesseract not found
        return False, "Tesseract not found"
        
    except ImportError:
        return False, "pytesseract not installed"
    except Exception as e:
        return False, f"Error configuring Tesseract: {str(e)}"


def is_ocr_available():
    """Check if OCR is available"""
    success, _ = configure_tesseract()
    return success
