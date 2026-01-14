@echo off
REM Quick setup script for PyQt6 migration
echo ==========================================
echo Forensic Tool - PyQt6 Setup
echo ==========================================
echo.

echo Step 1: Uninstalling old PyQt5 packages...
pip uninstall -y PyQt5 PyQt5-Qt5 PyQt5-sip

echo.
echo Step 2: Installing PyQt6 and dependencies...
pip install PyQt6 PyQt6-Qt6 PyQt6-sip watchdog

echo.
echo Step 3: Verifying installation...
python -c "from PyQt6 import QtWidgets; print('✅ PyQt6 installed successfully!')"
python -c "from watchdog.observers import Observer; print('✅ Watchdog installed successfully!')print('')"

echo.
echo ==========================================
echo Setup complete!
echo ==========================================
echo.
echo To run the application:
echo   python main.py
echo.
echo To run in development mode with live-reload:
echo   python run_dev.py
echo.
pause
