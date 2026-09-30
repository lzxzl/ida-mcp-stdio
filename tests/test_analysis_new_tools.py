"""Tests for newly added analysis tools."""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

from ida_mcp_stdio.tools import get_registry
from ida_mcp_stdio.tools.analysis import (
    batch_search_decompiled_patterns,
    extract_accesses,
    extract_carrier_facts,
    extract_function_facts,
    extract_lock_regions,
    extract_size_flow_facts,
    get_data_flow,
    get_function_prototype,
    get_stack_frame,
    list_callsites,
    search_decompiled_code,
    trace_parameter,
)


def _install_common_modules(monkeypatch):
    ida_funcs = ModuleType("ida_funcs")
    ida_name = ModuleType("ida_name")
    idaapi = ModuleType("idaapi")
    ida_typeinf = ModuleType("ida_typeinf")
    idc = ModuleType("idc")

    target_fn = SimpleNamespace(start_ea=0x4C54, end_ea=0x4D40)
    caller_fn = SimpleNamespace(start_ea=0x7000, end_ea=0x7100)
    other_fn = SimpleNamespace(start_ea=0x1000, end_ea=0x1100)
    scan_fn = SimpleNamespace(start_ea=0x2000, end_ea=0x2100)

    def _get_func(ea: int):
        if target_fn.start_ea <= ea < target_fn.end_ea:
            return target_fn
        if caller_fn.start_ea <= ea < caller_fn.end_ea:
            return caller_fn
        if other_fn.start_ea <= ea < other_fn.end_ea:
            return other_fn
        if scan_fn.start_ea <= ea < scan_fn.end_ea:
            return scan_fn
        return None

    def _get_func_name(ea: int):
        names = {
            0x4C54: "TransDataUnpacket",
            0x7000: "HandleRecvVoiceEncryptTransData",
            0x1000: "DecryptPath",
            0x2000: "NoMatch",
        }
        return names.get(ea, "")

    ida_funcs.get_func = _get_func
    ida_funcs.get_func_name = _get_func_name
    ida_name.get_name = lambda ea: _get_func_name(ea)

    idaapi.get_tinfo = lambda tif, ea: False

    class _FakeTInfo:
        pass

    ida_typeinf.tinfo_t = _FakeTInfo

    def _get_type(ea: int):
        mapping = {
            0x4C54: "uint32_t TransDataUnpacket(const uint8_t *packet, uint32_t packetSize, TransData *transData)",
            0x7000: "int HandleRecvVoiceEncryptTransData(const uint8_t *packet, uint32_t packetSize)",
        }
        return mapping.get(ea)

    idc.get_type = _get_type

    monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
    monkeypatch.setitem(sys.modules, "ida_name", ida_name)
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    monkeypatch.setitem(sys.modules, "ida_typeinf", ida_typeinf)
    monkeypatch.setitem(sys.modules, "idc", idc)


def test_get_function_prototype_returns_parsed_signature(monkeypatch):
    _install_common_modules(monkeypatch)

    result = get_function_prototype(addr="0x4c54")

    assert result["error"] is None
    assert result["name"] == "TransDataUnpacket"
    assert result["return_type"] == "uint32_t"
    assert len(result["params"]) == 3
    assert result["params"][1]["name"] == "packetSize"
    assert result["params"][1]["type"] == "uint32_t"


def test_get_stack_frame_parses_decompile_comments(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")

    class _CFunc:
        def __str__(self) -> str:
            return "\n".join(
                [
                    "int v12; // [xsp+08h] [xbp-4A0h] BYREF",
                    "uint8_t plaintext[1036]; // [xsp+0Ch] [xbp-49Ch] BYREF",
                    "TransData s; // [xsp+418h] [xbp-90h] BYREF",
                    "return 0;",
                ]
            )

    ida_hexrays.decompile = lambda ea: _CFunc()
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    result = get_stack_frame(addr="0x4c54")

    assert result["error"] is None
    assert result["count"] == 3
    assert result["vars"][0]["offset_expr"] == "[xsp+8h]"
    assert result["vars"][0]["name"] == "v12"
    assert result["vars"][1]["name"] == "plaintext[1036]"
    assert result["vars"][1]["size"] == 1036


def test_get_stack_frame_infers_stack_regions_from_stack_refs(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    ida_frame = ModuleType("ida_frame")

    class _CFunc:
        def __str__(self) -> str:
            return "\n".join(
                [
                    "__int64 v13; // [xsp+DB0h] [xbp+40h]",
                    "memset(&STACK[0x1678], 0, 0x4A8u);",
                    "memset(&STACK[0x11C8], 0, 0x4B0u);",
                    "return 0;",
                ]
            )

    ida_hexrays.decompile = lambda ea: _CFunc()
    ida_frame.get_frame_size = lambda fn: 0xDB0

    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setitem(sys.modules, "ida_frame", ida_frame)

    result = get_stack_frame(addr="0x4c54")

    assert result["error"] is None
    assert result["frame"]["total_size"] == 0xDB0
    by_stack_index = {
        item.get("stack_index"): item
        for item in result["vars"]
        if item.get("source") == "stack_region"
    }
    assert by_stack_index[0x11C8]["offset"] == 0x418
    assert by_stack_index[0x11C8]["size"] == 0x4B0
    assert by_stack_index[0x1678]["offset"] == 0x8C8
    assert by_stack_index[0x1678]["size"] == 0x4A8


def test_search_decompiled_code_finds_matches(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    idautils = ModuleType("idautils")

    class _CFunc:
        def __init__(self, text: str):
            self._text = text

        def __str__(self) -> str:
            return self._text

    code_map = {
        0x1000: _CFunc("if (Decrypt(v3, v4) <= 0)\n  log_error();"),
        0x2000: _CFunc("if (value > 0)\n  return value;"),
    }
    ida_hexrays.decompile = lambda ea: code_map[ea]
    idautils.Functions = lambda: [0x1000, 0x2000]

    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setitem(sys.modules, "idautils", idautils)

    result = search_decompiled_code(pattern=r"Decrypt.*<=.*0", scope="all_functions")

    assert result["error"] is None
    assert result["count"] == 1
    assert result["matches"][0]["function"] == "DecryptPath"
    assert "Decrypt" in result["matches"][0]["line_text"]


def test_search_decompiled_code_rejects_unbounded_scan(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    idautils = ModuleType("idautils")
    ida_hexrays.decompile = lambda ea: ""
    idautils.Functions = lambda: [0x1000]

    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setitem(sys.modules, "idautils", idautils)

    result = search_decompiled_code(
        pattern=r"g_callers", scope="all_functions", max_functions=0
    )

    assert result["count"] == 0
    assert result["scanned_functions"] == 0
    assert "max_functions=0" in result["error"]
    assert result["search_policy"]["code"] == "max-functions-zero-blocked"


def test_search_decompiled_code_applies_global_function_cap(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    idautils = ModuleType("idautils")

    class _CFunc:
        def __str__(self) -> str:
            return "return 0;"

    ida_hexrays.decompile = lambda ea: _CFunc()
    idautils.Functions = lambda: list(range(0x1000, 0x1000 + 75))

    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setitem(sys.modules, "idautils", idautils)

    result = search_decompiled_code(
        pattern=r"missing", scope="all_functions", max_functions=100
    )

    assert result["scanned_functions"] == 50
    assert result["decompiled_functions"] == 50
    assert result["search_policy"]["capped"] is True
    assert result["search_policy"]["effective_max_functions"] == 50


def test_batch_search_decompiled_patterns_finds_multiple_patterns_with_baseline_shape(
    monkeypatch,
):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    idautils = ModuleType("idautils")

    class _CFunc:
        def __init__(self, text: str):
            self._text = text

        def __str__(self) -> str:
            return self._text

    code_map = {
        0x1000: _CFunc("if (Decrypt(v3, v4) <= 0)\n  cache.clear();"),
        0x2000: _CFunc("memcpy(dst, src, size);\nreturn value;"),
    }
    ida_hexrays.decompile = lambda ea: code_map[ea]
    idautils.Functions = lambda: [0x1000, 0x2000]

    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setitem(sys.modules, "idautils", idautils)

    baseline = search_decompiled_code(pattern=r"Decrypt.*<=.*0", scope="all_functions")
    result = batch_search_decompiled_patterns(
        patterns=[
            {"id": "guard.decrypt", "regex": r"Decrypt.*<=.*0"},
            {"id": "invalidation.clear", "regex": r"\.clear\s*\("},
            {"id": "copy.memcpy", "regex": r"memcpy\s*\("},
        ],
        scope="all_functions",
    )

    assert baseline["count"] == 1
    assert result["schema_version"] == "ida-mcp-structured-facts-v1"
    assert result["tool"] == "batch_search_decompiled_patterns"
    assert result["count"] == 3
    assert result["scanned_functions"] == 2
    assert result["decompiled_functions"] == 2
    by_pattern = {match["pattern_id"]: match for match in result["matches"]}
    assert by_pattern["guard.decrypt"]["function_name"] == "DecryptPath"
    assert (
        by_pattern["guard.decrypt"]["line_text"] == baseline["matches"][0]["line_text"]
    )
    assert by_pattern["copy.memcpy"]["function_ea"] == "0x2000"


def test_batch_search_decompiled_patterns_reports_invalid_regex_and_decompile_failures(
    monkeypatch,
):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    idautils = ModuleType("idautils")

    class _CFunc:
        def __str__(self) -> str:
            return "Release(buffer);"

    def _decompile(ea: int):
        if ea == 0x2000:
            raise RuntimeError("hexrays unavailable")
        return _CFunc()

    ida_hexrays.decompile = _decompile
    idautils.Functions = lambda: [0x1000, 0x2000]

    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setitem(sys.modules, "idautils", idautils)

    result = batch_search_decompiled_patterns(
        patterns=[
            {"id": "bad", "regex": "("},
            {"id": "release", "regex": r"Release\s*\("},
        ],
        scope="all_functions",
    )

    assert result["count"] == 1
    assert result["partial"] is True
    assert any(item["code"] == "invalid-regex" for item in result["diagnostics"])
    assert result["skipped"] == [
        {"addr": "0x2000", "name": "NoMatch", "error": "hexrays unavailable"}
    ]


def test_batch_search_decompiled_patterns_honors_case_and_scan_limits(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    idautils = ModuleType("idautils")

    class _CFunc:
        def __init__(self, text: str):
            self._text = text

        def __str__(self) -> str:
            return self._text

    code_map = {
        0x1000: _CFunc("Release(buffer);\nrelease(buffer);"),
        0x2000: _CFunc("Release(other);"),
    }
    ida_hexrays.decompile = lambda ea: code_map[ea]
    idautils.Functions = lambda: [0x1000, 0x2000]

    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setitem(sys.modules, "idautils", idautils)

    case_sensitive = batch_search_decompiled_patterns(
        patterns=[{"id": "release.upper", "regex": r"Release\s*\("}],
        scope="all_functions",
        max_functions=1,
        case_sensitive=True,
    )
    limited = batch_search_decompiled_patterns(
        patterns=[{"id": "release.any", "regex": r"Release\s*\("}],
        scope="all_functions",
        max_matches=1,
        case_sensitive=False,
    )
    no_hit = batch_search_decompiled_patterns(
        patterns=[{"id": "missing", "regex": r"DoesNotExist\s*\("}],
        scope="all_functions",
    )

    assert case_sensitive["count"] == 1
    assert case_sensitive["scanned_functions"] == 1
    assert limited["count"] == 1
    assert limited["truncated"] is True
    assert no_hit["count"] == 0
    assert no_hit["partial"] is False


def test_list_callsites_extracts_direct_method_import_thunk_and_filters(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")

    class _CFunc:
        def __str__(self) -> str:
            return "\n".join(
                [
                    "foo(a, b);",
                    "obj->Release(x);",
                    "std::vector<unsigned char>::clear();",
                    "__imp_memcpy(dst, src, n);",
                    "j_operator_delete(ptr);",
                    "if (predicate(foo2()))",
                    "  return;",
                ]
            )

    ida_hexrays.decompile = lambda ea: _CFunc()
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    result = list_callsites(func="0x1000")
    filtered = list_callsites(func="0x1000", callee_filter="*Release*")

    assert result["schema_version"] == "ida-mcp-structured-facts-v1"
    assert result["tool"] == "list_callsites"
    names = [item["callee_name"] for item in result["callsites"]]
    assert names[:5] == ["foo", "Release", "clear", "__imp_memcpy", "j_operator_delete"]
    assert result["callsites"][0]["args"][0]["expr"] == "a"
    assert result["callsites"][1]["call_kind"] == "method"
    assert result["callsites"][3]["target_kind"] == "import"
    assert result["callsites"][4]["target_kind"] == "thunk"
    assert result["partial"] is True
    assert filtered["count"] == 1
    assert filtered["callsites"][0]["callee_name"] == "Release"


def test_extract_function_facts_aggregates_calls_accesses_invalidations_locks(
    monkeypatch,
):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")

    class _CFunc:
        def __str__(self) -> str:
            return "\n".join(
                [
                    "std::lock_guard<std::mutex> guard(creatorMutex_);",
                    "g_registry[key] = this;",
                    "value = g_registry[key];",
                    "this->listener_ = 0;",
                    "buffer.clear();",
                    "pthread_mutex_lock(&mutex);",
                ]
            )

    ida_hexrays.decompile = lambda ea: _CFunc()
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    result = extract_function_facts(func="0x1000")

    assert result["schema_version"] == "ida-mcp-structured-facts-v1"
    assert result["tool"] == "extract_function_facts"
    assert any(call["callee_name"] == "clear" for call in result["callsites"])
    assert any(
        access["access_kind"] == "container-index" and access["base"] == "g_registry"
        for access in result["accesses"]
    )
    assert any(
        access["access_kind"] == "member" and access["base"] == "listener_"
        for access in result["accesses"]
    )
    assert any(item["kind"] == "clear" for item in result["invalidations"])
    assert any(lock["lock_name"] == "creatorMutex_" for lock in result["locks"])
    assert any(lock["lock_kind"] == "explicit-lock" for lock in result["locks"])
    assert any(
        assignment["lhs"] == "g_registry[key]" for assignment in result["assignments"]
    )
    assert "g_registry" in result["globals"]
    assert "listener_" in result["member_fields"]


def test_function_facts_extract_multiline_cpp_map_store_find_and_erase(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")

    class _CFunc:
        def __str__(self) -> str:
            return "\n".join(
                [
                    "std::lock_guard<std::mutex>::lock_guard(&guard, &Owner::registry_mutex_);",
                    "*std::map<void *,Owner *>::operator[](",
                    "   &Owner::registry_,",
                    "   &key) = this;",
                    "iter._M_node = std::map<void *,Owner *>::find(",
                    "   &Owner::registry_,",
                    "   &key)._M_node;",
                    "std::map<void *,Owner *>::erase(",
                    "   &Owner::registry_,",
                    "   &key);",
                ]
            )

    ida_hexrays.decompile = lambda ea: _CFunc()
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    calls = list_callsites(func="0x1000")
    facts = extract_function_facts(func="0x1000")

    assert any("operator[]" in item["callee_name"] for item in calls["callsites"])
    assert any("find" in item["callee_name"] for item in calls["callsites"])
    assert any("erase" in item["callee_name"] for item in calls["callsites"])
    assert any(
        "Owner::registry_" in item["lhs"] and item["rhs"] == "this"
        for item in facts["assignments"]
    )
    assert any(
        "erase" in item["kind"].lower() and "Owner::registry_" in item["target"]
        for item in facts["invalidations"]
    )


def test_extract_accesses_filters_global_member_and_container_facts(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")

    class _CFunc:
        def __str__(self) -> str:
            return "\n".join(
                [
                    "g_registry[key] = this;",
                    "value = g_registry[key];",
                    "this->listener_ = value;",
                    "local[index] = value;",
                ]
            )

    ida_hexrays.decompile = lambda ea: _CFunc()
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    result = extract_accesses(func="0x1000")
    filtered = extract_accesses(
        func="0x1000", filters={"symbols": ["g_registry"], "include_members": False}
    )

    assert result["schema_version"] == "ida-mcp-structured-facts-v1"
    assert result["tool"] == "extract_accesses"
    assert any(
        item["access_kind"] == "container-index" and item["base"] == "g_registry"
        for item in result["accesses"]
    )
    assert any(
        item["access_kind"] == "member" and item["base"] == "listener_"
        for item in result["accesses"]
    )
    assert filtered["count"] >= 1
    assert all("g_registry" in item["expr"] for item in filtered["accesses"])
    assert all(item["access_kind"] != "member" for item in filtered["accesses"])


def test_extract_lock_regions_reports_explicit_and_raii_regions(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")

    class _CFunc:
        def __str__(self) -> str:
            return "\n".join(
                [
                    "std::lock_guard<std::mutex> guard(creatorMutex_);",
                    "g_registry[key] = this;",
                    "pthread_mutex_lock(&mutex);",
                    "value = g_registry[key];",
                    "pthread_mutex_unlock(&mutex);",
                ]
            )

    ida_hexrays.decompile = lambda ea: _CFunc()
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    result = extract_lock_regions(func="0x1000")
    filtered = extract_lock_regions(func="0x1000", lock_names=["mutex"])

    assert result["schema_version"] == "ida-mcp-structured-facts-v1"
    assert result["tool"] == "extract_lock_regions"
    assert any(region["lock_name"] == "creatorMutex_" for region in result["regions"])
    explicit = next(
        region for region in result["regions"] if region["lock_name"] == "mutex"
    )
    assert explicit["unlock_kind"] == "explicit"
    assert explicit["start_line"] == 3
    assert explicit["end_line"] == 5
    assert any(
        access["base"] == "g_registry" for access in explicit["covered_accesses"]
    )
    assert filtered["count"] == 1
    assert filtered["regions"][0]["lock_name"] == "mutex"


def test_extract_carrier_facts_aggregates_accesses_invalidations_aliases_and_locks(
    monkeypatch,
):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")

    class _CFunc:
        def __str__(self) -> str:
            return "\n".join(
                [
                    "pthread_mutex_lock(&mutex);",
                    "g_registry[key] = this;",
                    "FixtureOwner *selected = g_registry[key];",
                    "selected->Release(&value);",
                    "framework_fixture_clear(g_registry, key);",
                    "pthread_mutex_unlock(&mutex);",
                ]
            )

    ida_hexrays.decompile = lambda ea: _CFunc()
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    result = extract_carrier_facts(func="0x1000")

    assert result["schema_version"] == "ida-mcp-structured-facts-v1"
    assert result["tool"] == "extract_carrier_facts"
    carrier = next(item for item in result["carriers"] if item["key"] == "g_registry")
    assert carrier["kind"] == "global-static-registry"
    assert any(access["base"] == "g_registry" for access in carrier["accesses"])
    assert any("clear" in item["kind"].lower() for item in carrier["invalidations"])
    assert "selected" in carrier["aliases"]
    assert carrier["locks"]


def test_structured_fact_tool_metadata_explains_partial_and_non_verdict_semantics():
    registry = get_registry()

    for tool_name in [
        "extract_accesses",
        "extract_lock_regions",
        "extract_carrier_facts",
        "extract_size_flow_facts",
    ]:
        tool_def = registry.get_tool(tool_name)
        assert tool_def is not None
        description = tool_def.description.lower()
        assert "structured fact extractor" in description
        assert "not" in description and (
            "verdict" in description or "vulnerability detector" in description
        )
        assert "partial" in description
        assert "limitations" in description
        assert "func" in tool_def.input_schema["properties"]
        assert tool_def.input_schema["properties"]["func"]["description"]

    search_tool = registry.get_tool("search_decompiled_code")
    assert search_tool is not None
    search_desc = search_tool.description.lower()
    assert "non-semantic" in search_desc
    assert "selected_functions" in search_desc
    assert "capped by default" in search_desc
    max_functions = search_tool.input_schema["properties"]["max_functions"]
    assert (
        "avoid" in max_functions["description"].lower()
        or "限额" in max_functions["description"]
    )


def test_extract_size_flow_facts_reports_sources_transforms_guards_allocs_writes_and_allocator_state(
    monkeypatch,
):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")

    class _CFunc:
        def __str__(self) -> str:
            return "\n".join(
                [
                    "void DecodeFrame(char *dst, const char *src, size_t payload_len, size_t extra)",
                    "{",
                    "  total_size = payload_len + extra;",
                    "  if (total_size < payload_len)",
                    "    return 0;",
                    "  total_size += (8 - total_size) % total_size;",
                    "  buffer = evo_malloc(heap, total_size, extra);",
                    "  if (total_size > heap->remaining)",
                    "    return 0;",
                    "  heap->remaining -= total_size;",
                    "  heap->curr_mem += total_size;",
                    "  memcpy(buffer, src, payload_len);",
                    "  outstruct.buf[index++] = byte_read;",
                    "}",
                ]
            )

    ida_hexrays.decompile = lambda ea: _CFunc()
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    result = extract_size_flow_facts(func="0x1000")

    assert result["schema_version"] == "ida-mcp-structured-facts-v1"
    assert result["tool"] == "extract_size_flow_facts"
    assert any(
        item["source_kind"] == "function-arg" and item["size_expr"] == "payload_len"
        for item in result["size_sources"]
    )
    assert any(
        item["op_kind"] == "add" and item["output_expr"] == "total_size"
        for item in result["size_transforms"]
    )
    assert any(
        item["op_kind"] == "align" and item["output_expr"] == "total_size"
        for item in result["size_transforms"]
    )
    assert any(
        item["guard_kind"] == "overflow" and item["dominance"] == "partial"
        for item in result["guards"]
    )
    assert any(item["guard_kind"] == "remaining" for item in result["guards"])
    assert any(
        item["sink_kind"] == "custom" and item["size_expr"] == "total_size"
        for item in result["allocation_sinks"]
    )
    assert any(
        item["sink_kind"] == "memcpy" and item["bound_expr"] == "payload_len"
        for item in result["access_sinks"]
    )
    assert any(item["sink_kind"] == "indexed-store" for item in result["access_sinks"])
    assert any(
        item["state_kind"] == "bump-advance"
        for item in result["custom_allocator_state"]
    )
    assert any(
        item["allocation_ref_status"] == "unknown" for item in result["access_sinks"]
    )


def test_extract_size_flow_facts_infers_stripped_custom_alloc_and_pointer_store(
    monkeypatch,
):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")

    class _CFunc:
        def __str__(self) -> str:
            return "\n".join(
                [
                    "int DecodeFrame(__int64 heap, __int64 reader, size_t payload_len, size_t extra)",
                    "{",
                    "  total_size = payload_len + extra;",
                    "  if (total_size < payload_len)",
                    "    return 0;",
                    "  total_size += (8 - total_size) % total_size;",
                    "  buffer = sub_123456(heap, total_size, extra);",
                    "  if (!buffer)",
                    "    return 2;",
                    "  index = 0;",
                    "  while ( read_byte(reader, &byte_read) == 0 )",
                    "  {",
                    "    *(_BYTE *)(buffer + index++) = byte_read;",
                    "    if ( index >= payload_len )",
                    "      return 3;",
                    "  }",
                    "}",
                ]
            )

    ida_hexrays.decompile = lambda ea: _CFunc()
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    result = extract_size_flow_facts(func="0x1000")

    assert any(
        item["sink_kind"] == "custom"
        and item["size_expr"] == "total_size"
        and item["unavailable_reason"] == "callee-name-not-allocator-like"
        for item in result["allocation_sinks"]
    )
    assert any(
        item["sink_kind"] == "loop-store"
        and item["dest_expr"] == "buffer + index++"
        and item["bound_expr"] == "payload_len"
        for item in result["access_sinks"]
    )


def test_extract_size_flow_facts_infers_reader_out_param_and_operator_new_without_signature_state(
    monkeypatch,
):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")

    class _CFunc:
        def __str__(self) -> str:
            return "\n".join(
                [
                    "__int64 __fastcall Provider::updateCapacity(__int64 this, int a2)",
                    "{",
                    "  result = bitstream_read_bits(reader, 8, (__int64)&payload_len);",
                    "  total_size = payload_len + extra;",
                    "  buffer = operator new[](total_size);",
                    "  *(_BYTE *)(buffer + index++) = byte_read;",
                    "  if ( index >= payload_len )",
                    "    return 3;",
                    "}",
                ]
            )

    ida_hexrays.decompile = lambda ea: _CFunc()
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    result = extract_size_flow_facts(func="0x1000")

    assert any(
        item["source_kind"] == "cursor-read"
        and item["size_expr"] == "payload_len"
        and item["width_bits"] == 8
        for item in result["size_sources"]
    )
    assert any(
        item["sink_kind"] == "new"
        and item["size_expr"] == "total_size"
        and item["returned_ptr_expr"] == "buffer"
        for item in result["allocation_sinks"]
    )
    assert not any(
        item["line_text"].startswith("__int64 __fastcall Provider::updateCapacity")
        for item in result["custom_allocator_state"]
    )
    assert not any(
        "operator" in item.get("input_exprs", []) for item in result["size_transforms"]
    )


def test_extract_size_flow_facts_ignores_fixed_field_pointer_store_but_keeps_dynamic_store(
    monkeypatch,
):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")

    class _CFunc:
        def __str__(self) -> str:
            return "\n".join(
                [
                    "int ConfigureAndFill(__int64 this, char *buffer, int payload_len)",
                    "{",
                    "  v4 = operator new(0x20u);",
                    "  *(_QWORD *)v4 = &off_123456;",
                    "  *(_DWORD *)(this + 40) = payload_len;",
                    "  *(_QWORD *)(this + 56) = buffer;",
                    "  while ( read_byte(reader, &byte_read) == 0 )",
                    "  {",
                    "    *(_BYTE *)(buffer + index++) = byte_read;",
                    "    if ( index >= payload_len )",
                    "      return 3;",
                    "  }",
                    "}",
                ]
            )

    ida_hexrays.decompile = lambda ea: _CFunc()
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    result = extract_size_flow_facts(func="0x1000")

    assert not any(
        item["dest_expr"] in {"v4", "this + 40", "this + 56"}
        for item in result["access_sinks"]
    )
    assert any(
        item["sink_kind"] == "loop-store"
        and item["dest_expr"] == "buffer + index++"
        and item["bound_expr"] == "payload_len"
        for item in result["access_sinks"]
    )


def test_extract_size_flow_facts_treats_pointer_byte_load_as_partial_input_source(
    monkeypatch,
):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")

    class _CFunc:
        def __str__(self) -> str:
            return "\n".join(
                [
                    "int ParseBits(unsigned __int8 *a3, int a4)",
                    "{",
                    "  v5 = *a3;",
                    "  v8 = 8 * a4;",
                    "  v17 = *++a3;",
                    "  return v5 + v17;",
                    "}",
                ]
            )

    ida_hexrays.decompile = lambda ea: _CFunc()
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    result = extract_size_flow_facts(func="0x1000")

    sources = result["size_sources"]
    assert any(
        item["source_kind"] == "input-buffer" and item["size_expr"] == "v5"
        for item in sources
    )
    assert any(
        item["source_kind"] == "input-buffer" and item["size_expr"] == "v17"
        for item in sources
    )


def test_extract_size_flow_facts_uses_disasm_fallback_when_decompile_fails(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    ida_hexrays.decompile = lambda ea: (_ for _ in ()).throw(RuntimeError("no hexrays"))
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    ida_ua = ModuleType("ida_ua")
    ida_lines = ModuleType("ida_lines")
    idaapi = sys.modules["idaapi"]
    lines = {
        0x1000: "LDRB            W9, [X2]",
        0x1004: "ADD             W10, W9, W3",
        0x1008: "CMP             W10, #0xFF",
        0x100C: "STRB            W9, [X4,X10]",
    }

    class _Insn:
        pass

    ida_ua.insn_t = _Insn
    ida_ua.decode_insn = lambda insn, ea: 4 if ea in lines else 0
    ida_lines.generate_disasm_line = lambda ea, flags=0: lines.get(ea, "")
    idaapi.BADADDR = -1
    idaapi.next_head = lambda ea, end: (
        ea + 4 if ea + 4 < end and ea + 4 in lines else -1
    )
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)
    monkeypatch.setitem(sys.modules, "ida_lines", ida_lines)

    result = extract_size_flow_facts(func="0x1000")

    assert result["partial"] is True
    assert any(item["code"] == "disasm-fallback-used" for item in result["diagnostics"])
    assert any(
        item["source_kind"] == "input-buffer" and item["size_expr"] == "W9"
        for item in result["size_sources"]
    )
    assert any(
        item["op_kind"] == "add" and item["output_expr"] == "W10"
        for item in result["size_transforms"]
    )
    assert any(item["guard_expr"].startswith("CMP") for item in result["guards"])
    assert any(
        item["sink_kind"] == "loop-store" and item["bound_expr"] == "X10"
        for item in result["access_sinks"]
    )


def test_extract_size_flow_facts_disasm_indexed_store_uses_loop_cmp_bound(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    ida_hexrays.decompile = lambda ea: (_ for _ in ()).throw(RuntimeError("no hexrays"))
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    ida_ua = ModuleType("ida_ua")
    ida_lines = ModuleType("ida_lines")
    idaapi = sys.modules["idaapi"]
    lines = {
        0x1000: "ADDS            X9, X9, X12",
        0x1004: "LDR             X13, [X2,#8]",
        0x1008: "SUBS            X10, X13, X9",
        0x100C: "B.CS            loc_success",
        0x1010: "STRB            W15, [X13,X9]",
        0x1014: "ADD             X9, X9, #1",
        0x1018: "CMP             X9, X12",
        0x101C: "B.EQ            loc_done",
    }

    class _Insn:
        pass

    ida_ua.insn_t = _Insn
    ida_ua.decode_insn = lambda insn, ea: 4 if ea in lines else 0
    ida_lines.generate_disasm_line = lambda ea, flags=0: lines.get(ea, "")
    idaapi.BADADDR = -1
    idaapi.next_head = lambda ea, end: (
        ea + 4 if ea + 4 < end and ea + 4 in lines else -1
    )
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)
    monkeypatch.setitem(sys.modules, "ida_lines", ida_lines)

    result = extract_size_flow_facts(func="0x1000")

    assert any(
        item["site_ea"] == "0x1010"
        and item["sink_kind"] == "loop-store"
        and item["dest_expr"] == "X13,X9"
        and item["bound_expr"] == "X12"
        for item in result["access_sinks"]
    )


def test_extract_size_flow_facts_overlays_disasm_when_decompile_succeeds(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")

    class _CFunc:
        def __str__(self) -> str:
            return "\n".join(
                [
                    "int sub_1000(__int64 ctx)",
                    "{",
                    "  v1 = ctx;",
                    "  return 0;",
                    "}",
                ]
            )

    ida_hexrays.decompile = lambda ea: _CFunc()
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    ida_ua = ModuleType("ida_ua")
    ida_lines = ModuleType("ida_lines")
    idaapi = sys.modules["idaapi"]
    lines = {
        0x1000: "LDR             X2, [X0,#0x48]",
        0x1004: "ADD             X3, X1, X2",
        0x1008: "SUB             W2, W3, W16",
        0x100C: "CMP             W2, W13",
        0x1010: "SUBS            W4, W4, #0x1",
        0x1014: "LDRB            W5, [X6],#1",
        0x1018: "STRB            W5, [X1],#1",
    }

    class _Insn:
        pass

    ida_ua.insn_t = _Insn
    ida_ua.decode_insn = lambda insn, ea: 4 if ea in lines else 0
    ida_lines.generate_disasm_line = lambda ea, flags=0: lines.get(ea, "")
    idaapi.BADADDR = -1
    idaapi.next_head = lambda ea, end: (
        ea + 4 if ea + 4 < end and ea + 4 in lines else -1
    )
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)
    monkeypatch.setitem(sys.modules, "ida_lines", ida_lines)

    result = extract_size_flow_facts(func="0x1000", filters={"max_instructions": 64})

    assert any(item["code"] == "disasm-overlay-used" for item in result["diagnostics"])
    assert any(
        item["sink_kind"] == "custom"
        and item["size_expr"] == "X2"
        and item["capacity_relation"] == "pointer-add-capacity-check"
        for item in result["allocation_sinks"]
    )
    assert any(
        item["sink_kind"] == "loop-store"
        and item["dest_expr"] == "X1,#1"
        and item["bound_expr"] == "W4"
        for item in result["access_sinks"]
    )


def test_extract_size_flow_facts_disasm_fallback_ignores_fixed_offset_field_store(
    monkeypatch,
):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    ida_hexrays.decompile = lambda ea: (_ for _ in ()).throw(RuntimeError("no hexrays"))
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    ida_ua = ModuleType("ida_ua")
    ida_lines = ModuleType("ida_lines")
    idaapi = sys.modules["idaapi"]
    lines = {
        0x1000: "LDRB            W9, [X2]",
        0x1004: "STRH            W9, [X20,#0x208]",
        0x1008: "STRB            W9, [X4,X10]",
    }

    class _Insn:
        pass

    ida_ua.insn_t = _Insn
    ida_ua.decode_insn = lambda insn, ea: 4 if ea in lines else 0
    ida_lines.generate_disasm_line = lambda ea, flags=0: lines.get(ea, "")
    idaapi.BADADDR = -1
    idaapi.next_head = lambda ea, end: (
        ea + 4 if ea + 4 < end and ea + 4 in lines else -1
    )
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)
    monkeypatch.setitem(sys.modules, "ida_lines", ida_lines)

    result = extract_size_flow_facts(func="0x1000")

    dest_exprs = {item["dest_expr"] for item in result["access_sinks"]}
    assert "X20,#0x208" not in dest_exprs
    assert "X4,X10" in dest_exprs


def test_extract_size_flow_facts_disasm_fallback_captures_post_index_payload_store(
    monkeypatch,
):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    ida_hexrays.decompile = lambda ea: (_ for _ in ()).throw(RuntimeError("no hexrays"))
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    ida_ua = ModuleType("ida_ua")
    ida_lines = ModuleType("ida_lines")
    idaapi = sys.modules["idaapi"]
    lines = {
        0x1000: "SUBS            W4, W4, #0x1",
        0x1004: "LDRB            W5, [X2],#1",
        0x1008: "STRB            W5, [X1],#1",
        0x100C: "B.NE            loc_1000",
    }

    class _Insn:
        pass

    ida_ua.insn_t = _Insn
    ida_ua.decode_insn = lambda insn, ea: 4 if ea in lines else 0
    ida_lines.generate_disasm_line = lambda ea, flags=0: lines.get(ea, "")
    idaapi.BADADDR = -1
    idaapi.next_head = lambda ea, end: (
        ea + 4 if ea + 4 < end and ea + 4 in lines else -1
    )
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)
    monkeypatch.setitem(sys.modules, "ida_lines", ida_lines)

    result = extract_size_flow_facts(func="0x1000")

    assert any(
        item["sink_kind"] == "loop-store"
        and item["dest_expr"] == "X1,#1"
        and item["bound_expr"] == "W4"
        for item in result["access_sinks"]
    )


def test_extract_size_flow_facts_disasm_fallback_captures_custom_slab_capacity_check(
    monkeypatch,
):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    ida_hexrays.decompile = lambda ea: (_ for _ in ()).throw(RuntimeError("no hexrays"))
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    ida_ua = ModuleType("ida_ua")
    ida_lines = ModuleType("ida_lines")
    idaapi = sys.modules["idaapi"]
    lines = {
        0x1000: "LDR             X2, [X0,#0x48]",
        0x1004: "ADD             X3, X1, X2",
        0x1008: "SUB             W2, W3, W16",
        0x100C: "CMP             W2, W13",
        0x1010: "LDR             X4, [X0,#0x48]",
        0x1014: "SUBS            W4, W4, #0x1",
        0x1018: "LDRB            W5, [X6],#1",
        0x101C: "STRB            W5, [X1],#1",
    }

    class _Insn:
        pass

    ida_ua.insn_t = _Insn
    ida_ua.decode_insn = lambda insn, ea: 4 if ea in lines else 0
    ida_lines.generate_disasm_line = lambda ea, flags=0: lines.get(ea, "")
    idaapi.BADADDR = -1
    idaapi.next_head = lambda ea, end: (
        ea + 4 if ea + 4 < end and ea + 4 in lines else -1
    )
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)
    monkeypatch.setitem(sys.modules, "ida_lines", ida_lines)

    result = extract_size_flow_facts(func="0x1000")

    assert any(
        item["size_expr"] == "X2" and item.get("source_family_key") == "mem:X0+0x48"
        for item in result["size_sources"]
    )
    assert any(
        item["sink_kind"] == "custom"
        and item["size_expr"] == "X2"
        and item["returned_ptr_expr"] == "X1"
        and item["capacity_relation"] == "pointer-add-capacity-check"
        and item["overflow_sensitive"] is True
        for item in result["allocation_sinks"]
    )
    assert any(
        item["state_kind"] == "capacity-check" and "X1+X2" in item["state_expr"]
        for item in result["custom_allocator_state"]
    )


def test_extract_size_flow_facts_disasm_fallback_captures_bump_remaining_capacity_check(
    monkeypatch,
):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    ida_hexrays.decompile = lambda ea: (_ for _ in ()).throw(RuntimeError("no hexrays"))
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    ida_ua = ModuleType("ida_ua")
    ida_lines = ModuleType("ida_lines")
    idaapi = sys.modules["idaapi"]
    idc = sys.modules["idc"]
    lines = {
        0x1000: "ADDS            X9, X9, X12",
        0x1004: "B.CS            loc_fail",
        0x1008: "AND             X10, X9, #0x7",
        0x100C: "MOV             W11, #8",
        0x1010: "LDR             X13, [X2,#8]",
        0x1014: "SUB             X10, X11, X10",
        0x1018: "TST             X9, #0x7",
        0x101C: "CSEL            X10, XZR, X10, EQ",
        0x1020: "ADD             X9, X10, X9",
        0x1024: "SUBS            X10, X13, X9",
        0x1028: "B.CS            loc_success",
        0x102C: "STR             XZR, [X4,#0x50]",
    }

    class _Insn:
        pass

    ida_ua.insn_t = _Insn
    ida_ua.decode_insn = lambda insn, ea: 4 if ea in lines else 0
    created_insns = set()
    idc.create_insn = lambda ea: created_insns.add(ea) or True
    ida_lines.generate_disasm_line = lambda ea, flags=0: (
        lines.get(ea, "") if ea in created_insns else "DCB             0"
    )
    idaapi.BADADDR = -1
    idaapi.next_head = lambda ea, end: (
        ea + 4 if ea + 4 < end and ea + 4 in lines else -1
    )
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)
    monkeypatch.setitem(sys.modules, "ida_lines", ida_lines)

    result = extract_size_flow_facts(func="0x1000")

    matching_allocations = [
        item
        for item in result["allocation_sinks"]
        if item["capacity_relation"] == "bump-pointer-remaining-check"
    ]
    assert len(matching_allocations) == 1
    assert any(
        item["sink_kind"] == "custom"
        and item["size_expr"] == "X9"
        and item["capacity_expr"] == "X13"
        and item["capacity_relation"] == "bump-pointer-remaining-check"
        and item["overflow_sensitive"] is True
        for item in result["allocation_sinks"]
    )
    assert any(
        item["state_kind"] == "bump-remaining-check" and "SUBS" in item["state_expr"]
        for item in result["custom_allocator_state"]
    )


def test_list_callsites_and_function_facts_report_decompile_failure(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    ida_hexrays.decompile = lambda ea: (_ for _ in ()).throw(RuntimeError("no hexrays"))
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)

    calls = list_callsites(func="0x1000")
    facts = extract_function_facts(func="0x1000")

    assert calls["partial"] is True
    assert calls["callsites"] == []
    assert calls["diagnostics"][0]["code"] == "decompile-failed"
    assert facts["partial"] is True
    assert facts["callsites"] == []
    assert facts["diagnostics"][0]["code"] == "decompile-failed"


def test_trace_parameter_backward_collects_assignment_chain(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    idautils = ModuleType("idautils")

    class _CFunc:
        def __init__(self, text: str):
            self._text = text

        def __str__(self) -> str:
            return self._text

    ida_hexrays.decompile = lambda ea: {
        0x4C54: _CFunc("return 0;"),
        0x7000: _CFunc(
            "\n".join(
                [
                    "int v6;",
                    "int v7;",
                    "v7 = Decrypt(packet);",
                    "v6 = v7;",
                    "return TransDataUnpacket(packet, v6, &s);",
                ]
            )
        ),
    }.get(ea)

    idautils.XrefsTo = lambda ea: [SimpleNamespace(frm=0x7010)] if ea == 0x4C54 else []

    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setitem(sys.modules, "idautils", idautils)

    result = trace_parameter(
        func="0x4c54", param_index=1, direction="backward", max_depth=2
    )

    assert result["error"] is None
    assert result["count"] >= 1
    first_step = result["paths"][0][0]
    assert first_step["caller"]["name"] == "HandleRecvVoiceEncryptTransData"
    assert first_step["argument"] == "v6"
    chain_exprs = [item["expr"] for item in first_step["assignment_chain"]]
    assert "v7" in chain_exprs
    assert "Decrypt(packet)" in chain_exprs


def test_get_data_flow_alias(monkeypatch):
    _install_common_modules(monkeypatch)

    ida_hexrays = ModuleType("ida_hexrays")
    idautils = ModuleType("idautils")

    class _CFunc:
        def __str__(self) -> str:
            return "return TransDataUnpacket(packet, packetSize, &s);"

    ida_hexrays.decompile = lambda ea: _CFunc()
    idautils.XrefsTo = lambda ea: []

    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setitem(sys.modules, "idautils", idautils)

    result = get_data_flow(func="0x4c54", param_index=1)

    assert result["error"] is None
    assert result["function"] == "TransDataUnpacket"
    assert result["count"] == 0
