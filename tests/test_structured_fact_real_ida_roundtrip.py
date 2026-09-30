from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

pytestmark = [
    pytest.mark.ida_enabled,
    pytest.mark.skipif(
        os.environ.get("AI4BA_IDA_MCP_TESTS") != "1",
        reason="IDA-enabled structured fact roundtrip tests require AI4BA_IDA_MCP_TESTS=1",
    ),
]


FIXTURE_SOURCE = (
    Path(__file__).parent
    / "fixtures"
    / "structured_facts"
    / "structured_fact_roundtrip.cpp"
)


def _ensure_idalib_available() -> Any:
    idadir = os.environ.get("IDADIR")
    if idadir:
        candidates = [
            Path(idadir) / "idalib" / "python",
            Path(idadir).parent / "idalib" / "python",
            Path(idadir) / "python",
        ]
        for candidate in candidates:
            if candidate.exists() and str(candidate) not in sys.path:
                sys.path.insert(0, str(candidate))
    try:
        import idapro
    except ImportError as exc:
        pytest.fail(
            f"idapro module is not available while AI4BA_IDA_MCP_TESTS=1: {exc}"
        )
    return idapro


def _build_fixture_binary(tmp_path: Path, *, stripped: bool) -> Path:
    compiler = shutil.which("g++") or shutil.which("c++")
    if not compiler:
        pytest.fail("g++/c++ is required for IDA-enabled structured fact fixture tests")

    output = tmp_path / (
        "libstructured_fact_roundtrip_stripped.so"
        if stripped
        else "libstructured_fact_roundtrip.so"
    )
    cmd = [
        compiler,
        "-shared",
        "-fPIC",
        "-O0",
        "-g",
        "-pthread",
        str(FIXTURE_SOURCE),
        "-o",
        str(output),
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)

    if stripped:
        strip_tool = shutil.which("strip")
        if not strip_tool:
            pytest.fail(
                "strip is required for partial-strip IDA-enabled structured fact tests"
            )
        subprocess.run(
            [
                strip_tool,
                "-x" if sys.platform == "darwin" else "--strip-unneeded",
                str(output),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    return output


class _OpenedDatabase:
    def __init__(self, binary_path: Path):
        self.binary_path = binary_path
        self.idapro = None

    def __enter__(self):
        self.idapro = _ensure_idalib_available()
        self.idapro.open_database(str(self.binary_path), True)
        import ida_auto

        ida_auto.auto_wait()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.idapro is not None and hasattr(self.idapro, "close_database"):
            try:
                self.idapro.close_database(False)
            except TypeError:
                self.idapro.close_database(save=False)


def _entry_function_addr() -> str:
    from ida_mcp_stdio.tools.analysis import list_funcs

    funcs = list_funcs(filter="*framework_structured_fact_entry*", count=20)
    matches = funcs.get("data", [])
    if not matches:
        pytest.fail(
            f"framework_structured_fact_entry not found in IDA functions: {funcs}"
        )
    return str(matches[0]["addr"])


def test_12a_tools_roundtrip_on_unstripped_cpp_fixture(tmp_path: Path) -> None:
    binary = _build_fixture_binary(tmp_path, stripped=False)
    with _OpenedDatabase(binary):
        from ida_mcp_stdio.tools.analysis import (
            batch_search_decompiled_patterns,
            extract_accesses,
            extract_carrier_facts,
            extract_function_facts,
            extract_lock_regions,
            extract_size_flow_facts,
            list_callsites,
            search_decompiled_code,
        )

        entry_addr = _entry_function_addr()
        baseline = search_decompiled_code(
            pattern=r"(memcpy|framework_fixture_clear|pthread_mutex_lock)",
            scope="selected_functions",
            addrs=[entry_addr],
            case_sensitive=False,
        )
        batch = batch_search_decompiled_patterns(
            patterns=[
                {"id": "copy.memcpy", "regex": r"memcpy"},
                {"id": "cleanup.clear", "regex": r"framework_fixture_clear|clear"},
                {"id": "sync.lock", "regex": r"pthread_mutex_lock|lock"},
            ],
            scope="selected_functions",
            addrs=[entry_addr],
            case_sensitive=False,
        )
        calls = list_callsites(func=entry_addr)
        facts = extract_function_facts(func=entry_addr)
        accesses = extract_accesses(func=entry_addr)
        locks = extract_lock_regions(func=entry_addr)
        carriers = extract_carrier_facts(func=entry_addr)
        size_flow = extract_size_flow_facts(func=entry_addr)

        assert baseline["error"] is None
        assert baseline["count"] >= 1
        assert batch["schema_version"] == "ida-mcp-structured-facts-v1"
        assert batch["count"] >= 1
        assert batch["scanned_functions"] == 1
        assert all(
            match["function_ea"] == entry_addr.lower() for match in batch["matches"]
        )

        assert calls["schema_version"] == "ida-mcp-structured-facts-v1"
        assert calls["function_ea"] == entry_addr.lower()
        assert calls["callsites"]
        assert any(call["args"] for call in calls["callsites"])

        assert facts["schema_version"] == "ida-mcp-structured-facts-v1"
        assert facts["function_ea"] == entry_addr.lower()
        assert facts["callsites"]
        assert facts["accesses"] or facts["assignments"]
        assert any(
            item["kind"].lower().endswith("clear") for item in facts["invalidations"]
        )
        assert facts["locks"] or any(
            "lock" in call["callee_name"].lower() for call in facts["callsites"]
        )

        assert accesses["schema_version"] == "ida-mcp-structured-facts-v1"
        assert accesses["function_ea"] == entry_addr.lower()
        assert any(access["base"] == "g_registry" for access in accesses["accesses"])

        assert locks["schema_version"] == "ida-mcp-structured-facts-v1"
        assert locks["function_ea"] == entry_addr.lower()
        assert locks["regions"]
        assert any("mutex" in region["lock_name"] for region in locks["regions"])

        assert carriers["schema_version"] == "ida-mcp-structured-facts-v1"
        assert carriers["function_ea"] == entry_addr.lower()
        assert any(carrier["key"] == "g_registry" for carrier in carriers["carriers"])

        assert size_flow["schema_version"] == "ida-mcp-structured-facts-v1"
        assert size_flow["function_ea"] == entry_addr.lower()
        assert any(source["size_expr"] == "len" for source in size_flow["size_sources"])
        assert any(
            sink["sink_kind"] in {"memcpy", "memmove"}
            for sink in size_flow["access_sinks"]
        )


def test_12a_batch_search_returns_consumable_facts_on_partial_strip_fixture(
    tmp_path: Path,
) -> None:
    binary = _build_fixture_binary(tmp_path, stripped=True)
    with _OpenedDatabase(binary):
        from ida_mcp_stdio.tools.analysis import batch_search_decompiled_patterns

        result = batch_search_decompiled_patterns(
            patterns=[
                {"id": "copy.memcpy", "regex": r"memcpy|memmove"},
                {"id": "sync.lock", "regex": r"pthread_mutex_lock|lock"},
            ],
            scope="all_functions",
            max_functions=200,
            max_matches=20,
            case_sensitive=False,
        )

        assert result["schema_version"] == "ida-mcp-structured-facts-v1"
        assert result["decompiled_functions"] >= 1
        assert result["count"] >= 1
        for match in result["matches"]:
            assert match["function_ea"]
            assert match["line_no"] is not None
            assert match["symbol"]["symbol_quality"] in {
                "exact",
                "demangled",
                "mangled",
                "synthetic",
                "stripped",
                "unknown",
            }
