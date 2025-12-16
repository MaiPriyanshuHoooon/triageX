@echo off
REM ================================================================
REM  NUITKA BUILD SCRIPT - Automated Rebuild
REM  Rebuilds the EXE whenever you make code changes
REM ================================================================

echo ================================================================
echo   FORENSIC TOOL - NUITKA BUILD (Automated)
echo ================================================================
echo.

REM Clean previous build
echo [1/4] Cleaning previous build...
if exist "gui_launcher.dist" rmdir /s /q "gui_launcher.dist"
if exist "gui_launcher.build" rmdir /s /q "gui_launcher.build"
if exist "gui_launcher.onefile-build" rmdir /s /q "gui_launcher.onefile-build"
echo       Done!
echo.

REM Check for Tesseract OCR
echo [2/6] Checking for Tesseract OCR...
set TESSERACT_PATH=
if exist "C:\Program Files\Tesseract-OCR\tesseract.exe" (
    set TESSERACT_PATH=C:\Program Files\Tesseract-OCR
    echo       Found: C:\Program Files\Tesseract-OCR
) else if exist "C:\Program Files (x86)\Tesseract-OCR\tesseract.exe" (
    set TESSERACT_PATH=C:\Program Files (x86)\Tesseract-OCR
    echo       Found: C:\Program Files (x86)\Tesseract-OCR
) else (
    echo       WARNING: Tesseract OCR not found!
    echo       OCR features will not work in the EXE.
    echo       Download from: https://github.com/UB-Mannheim/tesseract/wiki
    echo.
    echo       Press any key to continue without OCR, or Ctrl+C to cancel...
    pause >nul
)

REM Build with Nuitka
echo.
echo [3/6] Building with Nuitka (this may take a few minutes)...
echo.

REM Build command with optional Tesseract inclusion
if defined TESSERACT_PATH (
    echo       Including Tesseract OCR in EXE...
    python -m nuitka ^
        --standalone ^
        --onefile ^
        --windows-disable-console ^
        --enable-plugin=pyqt5 ^
        --windows-icon-from-ico=assets/icon.ico ^
        --company-name="Forensic Tools" ^
        --product-name="Windows Forensic Triage Tool" ^
        --file-version=1.0.0.0 ^
        --product-version=1.0.0.0 ^
        --file-description="Professional Forensic Analysis Tool" ^
        --windows-uac-admin ^
        --include-data-dir=templates=templates ^
        --include-data-dir=assets=assets ^
        --include-data-dir=config=config ^
        --include-data-dir=core=core ^
        --include-data-file="%TESSERACT_PATH%\tesseract.exe"=tesseract/tesseract.exe ^
        --include-data-dir="%TESSERACT_PATH%\tessdata"=tesseract/tessdata ^
        --include-package=cryptography ^
        --include-package=PyQt5 ^
        --include-package=requests ^
        --include-package=psutil ^
        --include-package=wmi ^
        --include-package=pytesseract ^
        --include-package=PIL ^
        --include-package=cv2 ^
        --follow-imports ^
        --assume-yes-for-downloads ^
        --output-filename=ForensicTool.exe ^
        gui_launcher.py
) else (
    echo       Building without Tesseract OCR...
    python -m nuitka ^
        --standalone ^
        --onefile ^
        --windows-disable-console ^
        --enable-plugin=pyqt5 ^
        --windows-icon-from-ico=assets/icon.ico ^
        --company-name="Forensic Tools" ^
        --product-name="Windows Forensic Triage Tool" ^
        --file-version=1.0.0.0 ^
        --product-version=1.0.0.0 ^
        --file-description="Professional Forensic Analysis Tool" ^
        --windows-uac-admin ^
        --include-data-dir=templates=templates ^
        --include-data-dir=assets=assets ^
        --include-data-dir=config=config ^
        --include-data-dir=core=core ^
        --include-package=cryptography ^
        --include-package=PyQt5 ^
        --include-package=requests ^
        --include-package=psutil ^
        --include-package=wmi ^
        --follow-imports ^
        --assume-yes-for-downloads ^
        --output-filename=ForensicTool.exe ^
        gui_launcher.py
)

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ================================================================
    echo   BUILD FAILED!
    echo ================================================================
    pause
    exit /b 1
)

echo.
echo [4/6] Build successful!
echo.

REM Create distribution folder
echo [5/6] Creating distribution package...
if not exist "dist" mkdir dist
if exist "dist\ForensicTool.exe" del "dist\ForensicTool.exe"
move "gui_launcher.exe" "dist\ForensicTool.exe" >nul 2>&1
if not exist "dist\ForensicTool.exe" (
    if exist "ForensicTool.exe" move "ForensicTool.exe" "dist\ForensicTool.exe" >nul 2>&1
)

REM Clean up build artifacts
if exist "gui_launcher.build" rmdir /s /q "gui_launcher.build"
if exist "gui_launcher.dist" rmdir /s /q "gui_launcher.dist"
if exist "gui_launcher.onefile-build" rmdir /s /q "gui_launcher.onefile-build"

echo       Done!
echo.

REM Create README for distribution
echo [6/6] Creating distribution README...
(
echo ================================================================
echo   Windows Forensic Triage Tool - Professional Edition
echo ================================================================
echo.
echo INSTALLATION:
echo   1. Extract ForensicTool.exe to any folder
echo   2. Right-click ForensicTool.exe
echo   3. Select "Run as Administrator"
echo   4. All dependencies are included!
echo.
echo INCLUDED FEATURES:
echo   - Full forensic data collection
echo   - IOC scanning
echo   - Browser history analysis
echo   - Event log analysis
echo   - MFT analysis ^(requires admin^)
echo   - Pagefile analysis ^(requires admin^)
echo   - Registry analysis
if defined TESSERACT_PATH (
echo   - OCR text extraction ^(Tesseract included^)
) else (
echo   - OCR text extraction ^(NOT included - Tesseract not found^)
)
echo.
echo SYSTEM REQUIREMENTS:
echo   - Windows 10/11
echo   - Administrator privileges
echo   - 4GB RAM minimum
echo   - 500MB free disk space
echo.
echo SUPPORT:
echo   - Contact: support@forensictool.com
echo   - Documentation: Included in report
echo.
echo ================================================================
) > "dist\README.txt"

echo       Done!
echo.

REM Show results
echo ================================================================
echo   BUILD COMPLETE!
echo ================================================================
echo.
echo   Output: dist\ForensicTool.exe
echo.

if exist "dist\ForensicTool.exe" (
    for %%A in (dist\ForensicTool.exe) do echo   Size: %%~zA bytes
    echo.
    echo   Features:
    echo     - Single EXE file (all-in-one)
    echo     - No console window
    echo     - Auto-requests Administrator privileges
    echo     - Includes all dependencies
    echo.
    echo   Test it:
    echo     cd dist
    echo     ForensicTool.exe
    echo.
) else (
    echo   WARNING: EXE not found in expected location!
    echo   Check for errors above.
    echo.
)

echo ================================================================
pause
