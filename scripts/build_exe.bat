@echo off
REM Build script for Forensic Scanner EXE

echo ================================================
echo   Building Forensic Scanner Portable EXE
echo ================================================
echo.

REM Clean previous builds
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build

REM Build with PyInstaller
echo Building single-file executable...
pyinstaller --clean --noconfirm forensic_scanner.spec

if exist dist\ForensicScanner.exe (
    echo.
    echo ================================================
    echo   BUILD SUCCESSFUL!
    echo ================================================
    echo.
    echo Executable location: dist\ForensicScanner.exe
    echo File size:
    dir dist\ForensicScanner.exe | find "ForensicScanner.exe"
    echo.
    echo You can now copy dist\ForensicScanner.exe to USB or other media.
) else (
    echo.
    echo ================================================
    echo   BUILD FAILED!
    echo ================================================
    echo.
    echo Please check the error messages above.
)

pause
