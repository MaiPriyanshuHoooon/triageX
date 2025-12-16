<<<<<<< HEAD
@echo off
echo ================================================================
echo   FORENSIC TOOL - COMPLETE TEST AND BUILD GUIDE
echo ================================================================
echo.

:MENU
echo Choose an option:
echo.
echo 1. Test Setup (Check if everything is ready)
echo 2. Run GUI Application (Test the tool)
echo 3. Generate License for Customer
echo 4. Build EXE (Create distributable)
echo 5. Test Built EXE
echo 6. Exit
echo.
set /p choice="Enter your choice (1-6): "

if "%choice%"=="1" goto TEST_SETUP
if "%choice%"=="2" goto RUN_GUI
if "%choice%"=="3" goto GEN_LICENSE
if "%choice%"=="4" goto BUILD_EXE
if "%choice%"=="5" goto TEST_EXE
if "%choice%"=="6" goto END

:TEST_SETUP
echo.
echo ================================================================
echo   Running Pre-Build Tests...
echo ================================================================
python test_setup.py
echo.
pause
goto MENU

:RUN_GUI
echo.
echo ================================================================
echo   Launching Forensic Tool GUI...
echo ================================================================
echo.
echo TIP: Click "Start 7-Day Trial" to test the application
echo.
python gui_launcher.py
echo.
pause
goto MENU

:GEN_LICENSE
echo.
echo ================================================================
echo   License Generator
echo ================================================================
echo.
python quick_license_gen.py
echo.
pause
goto MENU

:BUILD_EXE
echo.
echo ================================================================
echo   Building EXE with PyInstaller...
echo ================================================================
echo.
echo Step 1: Installing/Updating PyInstaller...
pip install --upgrade pyinstaller
echo.
echo Step 2: Building EXE...
if exist forensic_tool_onedir.spec (
    echo Using existing spec file: forensic_tool_onedir.spec
    pyinstaller forensic_tool_onedir.spec --clean
) else (
    echo Creating new build...
    pyinstaller --name ForensicTool --onedir --windowed --icon=assets/icon.ico gui_launcher.py
)
echo.
echo ================================================================
echo   BUILD COMPLETE!
echo ================================================================
echo.
echo Output location: dist\ForensicTool\
echo.
echo Files created:
dir /b dist\ForensicTool\
echo.
pause
goto MENU

:TEST_EXE
echo.
echo ================================================================
echo   Testing Built EXE...
echo ================================================================
echo.
if exist dist\ForensicTool\ForensicTool.exe (
    echo Found: dist\ForensicTool\ForensicTool.exe
    echo Launching...
    echo.
    cd dist\ForensicTool
    start ForensicTool.exe
    cd ..\..
    echo.
    echo EXE is running in a new window!
) else (
    echo ERROR: EXE not found!
    echo Please build the EXE first (Option 4)
)
echo.
pause
goto MENU

:END
echo.
echo Thank you for using Forensic Tool Build Manager!
echo.
pause
exit
=======
@echo off
echo ================================================================
echo   FORENSIC TOOL - COMPLETE TEST AND BUILD GUIDE
echo ================================================================
echo.

:MENU
echo Choose an option:
echo.
echo 1. Test Setup (Check if everything is ready)
echo 2. Run GUI Application (Test the tool)
echo 3. Generate License for Customer
echo 4. Build EXE (Create distributable)
echo 5. Test Built EXE
echo 6. Exit
echo.
set /p choice="Enter your choice (1-6): "

if "%choice%"=="1" goto TEST_SETUP
if "%choice%"=="2" goto RUN_GUI
if "%choice%"=="3" goto GEN_LICENSE
if "%choice%"=="4" goto BUILD_EXE
if "%choice%"=="5" goto TEST_EXE
if "%choice%"=="6" goto END

:TEST_SETUP
echo.
echo ================================================================
echo   Running Pre-Build Tests...
echo ================================================================
python test_setup.py
echo.
pause
goto MENU

:RUN_GUI
echo.
echo ================================================================
echo   Launching Forensic Tool GUI...
echo ================================================================
echo.
echo TIP: Click "Start 7-Day Trial" to test the application
echo.
python gui_launcher.py
echo.
pause
goto MENU

:GEN_LICENSE
echo.
echo ================================================================
echo   License Generator
echo ================================================================
echo.
python quick_license_gen.py
echo.
pause
goto MENU

:BUILD_EXE
echo.
echo ================================================================
echo   Building EXE with PyInstaller...
echo ================================================================
echo.
echo Step 1: Installing/Updating PyInstaller...
pip install --upgrade pyinstaller
echo.
echo Step 2: Building EXE...
if exist forensic_tool_onedir.spec (
    echo Using existing spec file: forensic_tool_onedir.spec
    pyinstaller forensic_tool_onedir.spec --clean
) else (
    echo Creating new build...
    pyinstaller --name ForensicTool --onedir --windowed --icon=assets/icon.ico gui_launcher.py
)
echo.
echo ================================================================
echo   BUILD COMPLETE!
echo ================================================================
echo.
echo Output location: dist\ForensicTool\
echo.
echo Files created:
dir /b dist\ForensicTool\
echo.
pause
goto MENU

:TEST_EXE
echo.
echo ================================================================
echo   Testing Built EXE...
echo ================================================================
echo.
if exist dist\ForensicTool\ForensicTool.exe (
    echo Found: dist\ForensicTool\ForensicTool.exe
    echo Launching...
    echo.
    cd dist\ForensicTool
    start ForensicTool.exe
    cd ..\..
    echo.
    echo EXE is running in a new window!
) else (
    echo ERROR: EXE not found!
    echo Please build the EXE first (Option 4)
)
echo.
pause
goto MENU

:END
echo.
echo Thank you for using Forensic Tool Build Manager!
echo.
pause
exit
>>>>>>> 96e80ec (feat: added complete build automation for EXE distribution)
