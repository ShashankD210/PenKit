# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

block_cipher = None

hiddenimports = [
    'flask', 'flask.render_template', 'flask.request', 'flask.jsonify',
    'penkit_keys', 'penkit_recon',
    'rich', 'rich.console', 'rich.panel', 'rich.prompt',
    'rich.table', 'rich.syntax', 'rich.text', 'rich.columns',
    'rich.box',
]

datas = [
    ('webapp/templates', 'templates'),
    ('webapp/static', 'static'),
]
binaries = []
for pkg in ['flask', 'rich']:
    try:
        d, b, h = collect_all(pkg)
        datas += d; binaries += b; hiddenimports += h
    except Exception: pass

a = Analysis(
    ['webapp/__init__.py'],
    pathex=['.'],
    binaries=datas + binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'unittest', 'email', 'pdb', 'doctest',
              'xml.etree', 'http', 'html',
              'ossaudiodev', 'sunaudiodev', 'ossaudio',
              'test', 'ensurepip', 'distutils'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [],
    name='penkit-web',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
