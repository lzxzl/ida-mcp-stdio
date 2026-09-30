"""Opt-in real IDA 9.2/9.4 native and official Nexus database roundtrips."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ida_mcp_stdio.backends import LocalBackend, NexusBackend

pytestmark = [
    pytest.mark.ida_enabled,
    pytest.mark.skipif(
        os.environ.get("AI4BA_IDA_MCP_TESTS") != "1",
        reason="Set AI4BA_IDA_MCP_TESTS=1 to run licensed IDA integration tests",
    ),
]


@pytest.mark.parametrize(
    ("version", "backend_name"),
    [("9.2", "native"), ("9.4", "native"), ("9.4", "nexus")],
)
def test_real_database_roundtrip(version, backend_name, tmp_path, monkeypatch):
    installation = Path(f"/Applications/IDA Professional {version}.app/Contents/MacOS")
    if not installation.is_dir():
        pytest.skip(f"IDA {version} installation not found")
    monkeypatch.setenv("IDADIR", str(installation))
    compiler = shutil.which("clang")
    if not compiler:
        pytest.skip("clang required to build a temporary integration fixture")
    source = tmp_path / "sample.c"
    source.write_text("int ida_mcp_sample(int value) { return value + 42; }\n")
    binary = tmp_path / "sample.dylib"
    subprocess.run(
        [compiler, "-dynamiclib", "-O0", "-g", str(source), "-o", str(binary)],
        check=True,
        capture_output=True,
    )
    backend = LocalBackend() if backend_name == "native" else NexusBackend()
    try:
        target = backend.open_database(str(binary))["instance_id"]
        result = backend.execute_python(
            "import ida_kernwin, os\nprint('captured')\nos.write(1, b'native output\\n')\n{'version': ida_kernwin.get_kernel_version(), 'functions': tools.list_funcs(count=5)}",
            target,
        )
        assert result["result"]["version"].startswith(version)
        assert result["result"]["functions"]["total"] > 0
        assert result["stdout"] == "captured\n"
        assert (
            backend.execute_python("tools.get_current_database()", target)["result"][
                "loaded"
            ]
            is True
        )
        assert (
            backend.execute_python(
                "import asyncio\nawait asyncio.sleep(0)\n42", target
            )["result"]
            == 42
        )
        backend.execute_python("saved_value = 42", target)
        assert (
            backend.execute_python(
                "temporary = saved_value + 1; temporary", target, persist_globals=False
            )["result"]
            == 43
        )
        assert backend.execute_python("saved_value", target)["result"] == 42
        assert len(backend.list_databases()["instances"]) >= 1
        saved = backend.save_database(target)
        assert saved.get("path") or saved.get("idb_path")
        backend.close_database(target)
    finally:
        backend.shutdown()
