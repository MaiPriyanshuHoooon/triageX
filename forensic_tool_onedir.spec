# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller Build Configuration (DIRECTORY MODE - More Reliable!)
==================================================================
Builds as a folder instead of single file - better DLL compatibility

Build command:
    python -m PyInstaller forensic_tool_onedir.spec

Output:
    dist/ForensicTool/ folder containing:
        - ForensicTool.exe
        - All DLLs (visible and debuggable)
        - Python runtime
        - Dependencies

Advantages:
    - Better DLL loading (fixes ordinal 380 error)
    - Easier to debug
    - More compatible with different Windows versions
    - Faster builds
"""

import os

block_cipher = None

a = Analysis(
    ['gui_launcher.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('templates', 'templates'),
        ('assets', 'assets'),
        ('config', 'config'),
        ('core', 'core'),
    ],
    hiddenimports=[
        'PyQt5',
        'PyQt5.QtCore',
        'PyQt5.QtGui',
        'PyQt5.QtWidgets',
        'cryptography',
        'cryptography.fernet',
        'cryptography.hazmat',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.kdf.pbkdf2',
        'cryptography.hazmat.backends',
        'requests',
        'pywin32',
        'win32com',
        'win32com.client',
        'win32api',
        'win32con',
        'pywintypes',
        'wmi',
        'pytsk3',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        '_ssl',
        '_tkinter',
        'tkinter',
        'unittest',
        'pydoc',
        'doctest',
        'test',
        'lib2to3',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# Build as directory (NOT single file)
# This keeps DLLs separate and visible
exe = EXE(
    pyz,
    a.scripts,
    [],  # Empty - don't bundle binaries in exe
    exclude_binaries=True,  # Keep DLLs separate - KEY FIX!
    name='ForensicTool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # Disabled - can cause DLL issues
    console=False,  # No console window (GUI only)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico' if os.path.exists('assets/icon.ico') else None,
    manifest='ForensicTool.manifest',  # ← Request Administrator privileges
    uac_admin=True,  # ← Force UAC prompt for admin rights
    uac_uiaccess=False,
)

# Collect all files into a directory
coll = COLLECT(
    exe,
    a.binaries,  # All DLLs go here
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='ForensicTool',  # Creates dist/ForensicTool/ folder
)
