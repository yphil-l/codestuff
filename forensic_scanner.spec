# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['portable_scanner/__main__.py'],
    pathex=[],
    binaries=[],
    datas=[('portable_scanner/assets', 'portable_scanner/assets')],
    hiddenimports=[
        'portable_scanner',
        'portable_scanner.app',
        'portable_scanner.context',
        'portable_scanner.correlation',
        'portable_scanner.engine',
        'portable_scanner.gui',
        'portable_scanner.models',
        'portable_scanner.reporting',
        'portable_scanner.utils',
        'portable_scanner.scanners',
        'portable_scanner.scanners.base',
        'portable_scanner.scanners.event_logs',
        'portable_scanner.scanners.filesystem',
        'portable_scanner.scanners.processes',
        'portable_scanner.scanners.registry',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ForensicScanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    uac_admin=True,
)
