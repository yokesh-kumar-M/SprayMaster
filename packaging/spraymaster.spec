# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec — builds a single-file `spraymaster` executable.
# Run from repo root:
#     pyinstaller packaging/spraymaster.spec --clean --noconfirm
# Produces:  dist/spraymaster(.exe)

import importlib.util


def _has(modname):
    try:
        return importlib.util.find_spec(modname) is not None
    except (ImportError, ValueError):
        return False


# Optional protocol deps — include hidden imports only for those actually
# installed in the build environment, so the binary works for users who don't
# have the same extras.
_OPTIONAL = [
    ("pymysql", ["pymysql"]),
    ("psycopg2", ["psycopg2"]),
    ("pymssql", ["pymssql", "_mssql"]),
    ("ldap3", ["ldap3"]),
    ("redis", ["redis"]),
    ("impacket", ["impacket", "impacket.smbconnection"]),
    ("Crypto", ["Crypto", "Crypto.Cipher.DES"]),
    ("pysnmp", ["pysnmp", "pysnmp.hlapi"]),
]

hiddenimports = [
    "spraymaster",
    "spraymaster.core.engine",
    "spraymaster.core.output",
    "spraymaster.core.utils",
    "spraymaster.protocols",
    "spraymaster.protocols.ftp",
    "spraymaster.protocols.ssh",
    "spraymaster.protocols.telnet",
    "spraymaster.protocols.smtp",
    "spraymaster.protocols.pop3",
    "spraymaster.protocols.imap",
    "spraymaster.protocols.http",
    "spraymaster.protocols.smb",
    "spraymaster.protocols.mysql",
    "spraymaster.protocols.postgres",
    "spraymaster.protocols.mssql",
    "spraymaster.protocols.ldap",
    "spraymaster.protocols.redis_proto",
    "spraymaster.protocols.vnc",
    "spraymaster.protocols.snmp",
]

for probe, mods in _OPTIONAL:
    if _has(probe):
        hiddenimports.extend(mods)


a = Analysis(
    ["entry.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "PIL", "numpy", "matplotlib", "pytest"],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="spraymaster",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
