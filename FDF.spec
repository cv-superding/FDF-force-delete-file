# -*- mode: python ; coding: utf-8 -*-
import os


a = Analysis(
    ['main.py'],
    pathex=['src'],
    binaries=[],
    datas=[],
    hiddenimports=['fdf', 'fdf.gui', 'fdf.engine', 'fdf.winapi', 'fdf.worker'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='FDF',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[os.path.join(SPECPATH, 'assets', 'fdf.ico')],
    manifest='fdf.manifest',
)
