"""Regression coverage for Nexus 0.13's Darwin filesystem ABI."""

import ctypes
import sys

import pytest

from ida_mcp_stdio.backends import NexusBackend


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin filesystem ABI")
def test_nexus_classifies_local_macos_filesystem_correctly(tmp_path):
    database_state = pytest.importorskip("ida_nexus.database_state")
    backend = NexusBackend()
    try:
        assert database_state._network_filesystem(tmp_path) is False
    finally:
        backend.shutdown()


@pytest.mark.parametrize(
    ("flags", "status", "expected"), [(0x1000, 0, False), (0, 0, True), (0, -1, None)]
)
def test_darwin_probe_preserves_network_and_error_results(
    monkeypatch, tmp_path, flags, status, expected
):
    from ida_mcp_stdio import nexus_compat

    class Library:
        def __getattr__(self, symbol):
            assert symbol == "statfs$INODE64"

            def statfs(path, pointer):
                assert path == bytes(tmp_path)
                state = ctypes.cast(
                    pointer, ctypes.POINTER(nexus_compat.DarwinStatFS)
                ).contents
                state.f_flags = flags
                return status

            return statfs

    monkeypatch.setattr(nexus_compat.ctypes, "CDLL", lambda *args, **kwargs: Library())
    assert nexus_compat.darwin_network_filesystem(tmp_path) is expected


def test_darwin_layout_matches_sdk():
    from ida_mcp_stdio.nexus_compat import DarwinStatFS

    assert ctypes.sizeof(DarwinStatFS) == 2168
    assert DarwinStatFS.f_flags.offset == 64
