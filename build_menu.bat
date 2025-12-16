@echo off
:MENU
cls
echo ================================================================
echo   FORENSIC TOOL - BUILD MENU
echo ================================================================
echo.
echo   1. Full Clean Build (Nuitka - First time or major changes)
echo   2. Quick Rebuild (Nuitka - After code changes)
echo   3. Test Current EXE
echo   4. Clean Build Artifacts
echo   5. Exit
echo.
echo ================================================================
set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" goto FULL_BUILD
if "%choice%"=="2" goto QUICK_BUILD
if "%choice%"=="3" goto TEST_EXE
if "%choice%"=="4" goto CLEAN
if "%choice%"=="5" goto END
goto MENU

:FULL_BUILD
echo.
echo Starting FULL CLEAN BUILD...
call build_nuitka.bat
pause
goto MENU

:QUICK_BUILD
echo.
echo Starting QUICK REBUILD...
call rebuild_quick.bat
pause
goto MENU

:TEST_EXE
echo.
if exist "dist\ForensicTool.exe" (
    echo Testing: dist\ForensicTool.exe
    echo.
    cd dist
    start ForensicTool.exe
    cd ..
    echo.
    echo EXE launched!
) else (
    echo ERROR: dist\ForensicTool.exe not found!
    echo Build it first (Option 1 or 2)
)
echo.
pause
goto MENU

:CLEAN
echo.
echo Cleaning build artifacts...
if exist "gui_launcher.dist" rmdir /s /q "gui_launcher.dist"
if exist "gui_launcher.build" rmdir /s /q "gui_launcher.build"
if exist "gui_launcher.onefile-build" rmdir /s /q "gui_launcher.onefile-build"
if exist "__pycache__" rmdir /s /q "__pycache__"
for /d /r %%d in (__pycache__) do @if exist "%%d" rmdir /s /q "%%d"
echo Done!
echo.
pause
goto MENU

:END
echo.
echo Goodbye!
timeout /t 2 >nul
exit
