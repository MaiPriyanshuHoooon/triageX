@echo off
REM ================================================================
REM  Install Tesseract OCR (Required for bundling in EXE)
REM ================================================================

echo ================================================================
echo   Tesseract OCR Installer Helper
echo ================================================================
echo.
echo This script will guide you to install Tesseract OCR
echo which is required to bundle OCR features in the EXE.
echo.

REM Check if already installed
if exist "C:\Program Files\Tesseract-OCR\tesseract.exe" (
    echo ✅ Tesseract OCR is already installed!
    echo    Location: C:\Program Files\Tesseract-OCR\
    echo.
    "C:\Program Files\Tesseract-OCR\tesseract.exe" --version
    echo.
    echo You're ready to build the EXE!
    pause
    exit /b 0
)

if exist "C:\Program Files (x86)\Tesseract-OCR\tesseract.exe" (
    echo ✅ Tesseract OCR is already installed!
    echo    Location: C:\Program Files (x86)\Tesseract-OCR\
    echo.
    "C:\Program Files (x86)\Tesseract-OCR\tesseract.exe" --version
    echo.
    echo You're ready to build the EXE!
    pause
    exit /b 0
)

echo ❌ Tesseract OCR is NOT installed!
echo.
echo ================================================================
echo   Download and Install Tesseract OCR:
echo ================================================================
echo.
echo 1. Opening download page in your browser...
echo    URL: https://github.com/UB-Mannheim/tesseract/wiki
echo.

REM Open browser to download page
start https://github.com/UB-Mannheim/tesseract/wiki

echo 2. Download the Windows installer:
echo    - Look for: tesseract-ocr-w64-setup-X.X.X.exe
echo    - Download the latest version (64-bit)
echo.
echo 3. Run the installer:
echo    - Use default installation location
echo    - Check "Add to PATH" if available
echo.
echo 4. After installation, run this script again to verify!
echo.
echo ================================================================
pause
