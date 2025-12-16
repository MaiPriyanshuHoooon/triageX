@echo off
REM ================================================================
REM  QUICK REBUILD - For code changes
REM  Faster rebuild without cleaning cache
REM ================================================================

echo ================================================================
echo   QUICK REBUILD (uses cached modules)
echo ================================================================
echo.

python -m nuitka ^
    --standalone ^
    --onefile ^
    --windows-disable-console ^
    --enable-plugin=pyqt5 ^
    --windows-uac-admin ^
    --include-data-dir=templates=templates ^
    --include-data-dir=assets=assets ^
    --include-data-dir=config=config ^
    --include-data-dir=core=core ^
    --output-filename=ForensicTool.exe ^
    gui_launcher.py

if %ERRORLEVEL% EQU 0 (
    if not exist "dist" mkdir dist
    if exist "ForensicTool.exe" move /y "ForensicTool.exe" "dist\ForensicTool.exe" >nul
    if exist "gui_launcher.exe" move /y "gui_launcher.exe" "dist\ForensicTool.exe" >nul
    echo.
    echo ✅ REBUILD COMPLETE: dist\ForensicTool.exe
) else (
    echo.
    echo ❌ BUILD FAILED!
)

echo.
pause
