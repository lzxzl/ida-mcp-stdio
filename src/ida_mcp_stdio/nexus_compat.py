"""Narrow compatibility fixes for the optional Nexus dependency."""

import ctypes
import os
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


class DarwinStatFS(ctypes.Structure):
    """Darwin's __DARWIN_STRUCT_STATFS64 from sys/mount.h."""

    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_int32 * 2),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


def darwin_network_filesystem(path: Path) -> bool | None:
    """Read MNT_LOCAL using the symbol matching the 64-bit Darwin structure."""
    # The unversioned statfs symbol uses the legacy ABI, despite this Python
    # process being 64-bit. C's __DARWIN_INODE64 macro selects this symbol.
    statfs = getattr(ctypes.CDLL(None, use_errno=True), "statfs$INODE64")
    statfs.argtypes = (ctypes.c_char_p, ctypes.POINTER(DarwinStatFS))
    statfs.restype = ctypes.c_int
    state = DarwinStatFS()
    if statfs(os.fsencode(path), ctypes.byref(state)) != 0:
        return None
    return not bool(state.f_flags & 0x00001000)


def install_nexus_compatibility() -> bool:
    """Correct Nexus 0.13.0's Darwin probe in this process only."""
    if sys.platform != "darwin":
        return False
    try:
        if version("ida-nexus") != "0.13.0":
            return False
        from ida_nexus import database_state
    except (ImportError, PackageNotFoundError):
        return False
    if not hasattr(database_state, "_network_filesystem"):
        return False
    database_state._network_filesystem = darwin_network_filesystem
    return True
