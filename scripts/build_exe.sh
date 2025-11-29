#!/bin/bash
# Build script for Forensic Scanner EXE (Linux/Mac build host)

echo "================================================"
echo "  Building Forensic Scanner Portable EXE"
echo "================================================"
echo ""

# Clean previous builds
rm -rf dist build

# Build with PyInstaller
echo "Building single-file executable..."
pyinstaller --clean --noconfirm forensic_scanner.spec

if [ -f dist/ForensicScanner.exe ] || [ -f dist/ForensicScanner ]; then
    echo ""
    echo "================================================"
    echo "  BUILD SUCCESSFUL!"
    echo "================================================"
    echo ""
    echo "Executable location: dist/ForensicScanner*"
    ls -lh dist/
    echo ""
    echo "You can now copy the executable to USB or other media."
else
    echo ""
    echo "================================================"
    echo "  BUILD FAILED!"
    echo "================================================"
    echo ""
    echo "Please check the error messages above."
    exit 1
fi
