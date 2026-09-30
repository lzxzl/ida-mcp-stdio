from __future__ import annotations

import json

import pytest

from ida_mcp_stdio.client import IDAMCPClient
from ida_mcp_stdio.structured_facts import (
    BATCH_SEARCH_TOOL,
    EXTRACT_ACCESSES_TOOL,
    EXTRACT_CARRIER_FACTS_TOOL,
    EXTRACT_FUNCTION_FACTS_TOOL,
    EXTRACT_LOCK_REGIONS_TOOL,
    EXTRACT_SIZE_FLOW_FACTS_TOOL,
    IDA_FACT_SCHEMA_VERSION,
    LIST_CALLSITES_TOOL,
    FactSchemaError,
    normalize_batch_search_decompiled_patterns_result,
    normalize_extract_accesses_result,
    normalize_extract_carrier_facts_result,
    normalize_extract_function_facts_result,
    normalize_extract_lock_regions_result,
    normalize_extract_size_flow_facts_result,
    normalize_list_callsites_result,
)


def test_batch_search_schema_accepts_current_search_decompiled_baseline() -> None:
    raw = {
        "pattern": r"\.clear\s*\(",
        "matches": [
            {
                "addr": "0x401000",
                "function": "_ZN6FCodec14ReleaseBuffersEv",
                "line": 17,
                "match": "renderAvailQue_->Clear(",
                "line_text": "renderAvailQue_->Clear();",
                "snippet": "if (surface) {\n  renderAvailQue_->Clear();\n}",
            },
            {
                "addr": "0x402000",
                "function": "sub_402000",
                "line": 4,
                "match": "cache.clear(",
                "line_text": "cache.clear();",
                "snippet": "cache.clear();",
                "symbol_quality": "synthetic",
            },
        ],
        "truncated": False,
        "error": None,
    }

    result = normalize_batch_search_decompiled_patterns_result(
        raw,
        patterns=[{"id": "invalidation.clear", "regex": r"\.clear\s*\("}],
    )
    reloaded = json.loads(json.dumps(result, sort_keys=True))

    assert reloaded["schema_version"] == IDA_FACT_SCHEMA_VERSION
    assert reloaded["tool"] == BATCH_SEARCH_TOOL
    assert reloaded["count"] == 2
    assert reloaded["matches"][0]["pattern_id"] == "invalidation.clear"
    assert reloaded["matches"][0]["function_ea"] == "0x401000"
    assert reloaded["matches"][0]["symbol"]["symbol_quality"] == "mangled"
    assert reloaded["matches"][1]["symbol"]["symbol_quality"] == "synthetic"


def test_batch_search_marks_missing_location_as_partial_not_exception() -> None:
    result = normalize_batch_search_decompiled_patterns_result(
        {
            "pattern_id": "hint.partial",
            "matches": [{"function": "", "line_text": "unknown();"}],
        }
    )

    assert result["partial"] is True
    assert result["matches"][0]["partial"] is True
    assert result["matches"][0]["function_ea"] is None


def test_list_callsites_schema_covers_direct_method_import_thunk_and_empty_args() -> (
    None
):
    raw = {
        "function_ea": 0x5000,
        "function": "HandleFrame",
        "callsites": [
            {
                "ea": 0x5010,
                "callee_ea": 0x9000,
                "callee": "malloc",
                "target_kind": "direct",
                "call_kind": "call",
                "args": ["payload_len"],
                "line": "buf = malloc(payload_len);",
            },
            {
                "ea": 0x5020,
                "callee": "std::vector<unsigned char>::clear",
                "target_kind": "direct",
                "call_kind": "method",
                "args": [],
                "unavailable_reason": "ctree-args-unavailable",
            },
            {
                "ea": 0x5030,
                "callee": "__imp_memcpy",
                "target_kind": "import",
                "call_kind": "call",
                "args": [{"index": 2, "expr": "payload_len"}],
            },
            {
                "ea": 0x5040,
                "callee": "j_operator_delete",
                "target_kind": "thunk",
                "call_kind": "operator",
            },
        ],
    }

    result = normalize_list_callsites_result(raw)

    assert result["tool"] == LIST_CALLSITES_TOOL
    assert result["function_ea"] == "0x5000"
    assert [item["target_kind"] for item in result["callsites"]] == [
        "direct",
        "direct",
        "import",
        "thunk",
    ]
    assert result["callsites"][0]["args"][0]["expr"] == "payload_len"
    assert result["callsites"][1]["unavailable_reason"] == "ctree-args-unavailable"
    assert result["callsites"][3]["partial"] is False


def test_extract_function_facts_schema_preserves_partial_strip_and_fact_groups() -> (
    None
):
    raw = {
        "function_ea": "0x7100",
        "function_name": "sub_7100",
        "calls": [
            {
                "ea": "0x7110",
                "callee": "",
                "target_kind": "vtable",
                "call_kind": "method",
                "args": ["this", "buffer"],
                "source_refs": {"xref_ea": "0x7110"},
            }
        ],
        "accesses": [
            {
                "ea": "0x7120",
                "expr": "g_registry[key]",
                "base": "g_registry",
                "kind": "handle-map",
                "access": "read",
            }
        ],
        "invalidations": [
            {
                "ea": "0x7130",
                "kind": "clear",
                "target": "g_registry",
                "expr": "g_registry.clear()",
            }
        ],
        "locks": [
            {
                "ea": "0x7140",
                "lock": "creatorMutex_",
                "kind": "std-lock-guard",
                "start_line": 8,
                "end_line": 18,
            }
        ],
        "globals": ["g_registry"],
        "member_fields": ["listener_"],
    }

    result = normalize_extract_function_facts_result(raw)

    assert result["tool"] == EXTRACT_FUNCTION_FACTS_TOOL
    assert result["symbol"]["symbol_quality"] == "synthetic"
    assert result["callsites"][0]["target_kind"] == "vtable"
    assert result["accesses"][0]["access_kind"] == "handle-map"
    assert result["invalidations"][0]["target"] == "g_registry"
    assert result["locks"][0]["lock_name"] == "creatorMutex_"


def test_schema_validator_rejects_wrong_tool_payload() -> None:
    with pytest.raises(FactSchemaError):
        normalize_list_callsites_result(
            {
                "schema_version": IDA_FACT_SCHEMA_VERSION,
                "tool": BATCH_SEARCH_TOOL,
                "callsites": "not-a-list",
            }
        )


def test_12b_schema_normalizers_cover_access_lock_and_carrier_payloads() -> None:
    accesses = normalize_extract_accesses_result(
        {
            "function_ea": "0x5000",
            "function": "Handle",
            "accesses": [
                {
                    "ea": "0x5010",
                    "expr": "g_registry[key]",
                    "base": "g_registry",
                    "kind": "container-index",
                },
            ],
        }
    )
    locks = normalize_extract_lock_regions_result(
        {
            "function_ea": "0x5000",
            "function": "Handle",
            "regions": [
                {
                    "ea": "0x5020",
                    "lock": "mutex",
                    "kind": "explicit-lock",
                    "start_line": 3,
                    "end_line": 7,
                    "covered_accesses": accesses["accesses"],
                }
            ],
        }
    )
    carriers = normalize_extract_carrier_facts_result(
        {
            "function_ea": "0x5000",
            "function": "Handle",
            "carriers": [
                {
                    "key": "g_registry",
                    "kind": "global-static-registry",
                    "accesses": accesses["accesses"],
                    "locks": locks["regions"],
                    "aliases": ["owner"],
                }
            ],
        }
    )

    assert accesses["tool"] == EXTRACT_ACCESSES_TOOL
    assert accesses["accesses"][0]["access_kind"] == "container-index"
    assert locks["tool"] == EXTRACT_LOCK_REGIONS_TOOL
    assert locks["regions"][0]["covered_accesses"][0]["base"] == "g_registry"
    assert carriers["tool"] == EXTRACT_CARRIER_FACTS_TOOL
    assert carriers["carriers"][0]["aliases"] == ["owner"]


def test_12c_schema_normalizer_covers_size_flow_payloads() -> None:
    result = normalize_extract_size_flow_facts_result(
        {
            "function_ea": "0x6000",
            "function": "Decode",
            "size_sources": [
                {
                    "source_ea": "0x6000",
                    "source_kind": "function-arg",
                    "size_expr": "payload_len",
                    "width_bits": 64,
                    "signedness": "unsigned",
                    "trust_boundary": "unknown",
                }
            ],
            "size_transforms": [
                {
                    "site_ea": "0x6010",
                    "op_kind": "add",
                    "input_exprs": ["payload_len", "extra"],
                    "output_expr": "total_size",
                    "input_signedness": "unknown",
                    "output_signedness": "unknown",
                    "conversion_kind": "none",
                }
            ],
            "guards": [
                {
                    "site_ea": "0x6020",
                    "guard_kind": "overflow",
                    "guard_expr": "total_size < payload_len",
                    "guarded_exprs": ["total_size", "payload_len"],
                    "dominance": "unknown",
                }
            ],
            "allocation_sinks": [
                {
                    "site_ea": "0x6030",
                    "sink_kind": "custom",
                    "size_expr": "total_size",
                    "returned_ptr_expr": "buffer",
                }
            ],
            "access_sinks": [
                {
                    "site_ea": "0x6040",
                    "direction": "write",
                    "sink_kind": "memcpy",
                    "dest_expr": "buffer",
                    "source_expr": "src",
                    "bound_expr": "payload_len",
                    "allocation_ref_status": "unknown",
                }
            ],
            "custom_allocator_state": [
                {
                    "site_ea": "0x6050",
                    "state_kind": "bump-advance",
                    "state_expr": "heap->curr_mem += total_size",
                    "update_expr": "heap->curr_mem += total_size",
                }
            ],
        }
    )

    assert result["tool"] == EXTRACT_SIZE_FLOW_FACTS_TOOL
    assert result["size_sources"][0]["trust_boundary"] == "unknown"
    assert result["size_transforms"][0]["conversion_kind"] == "none"
    assert result["guards"][0]["dominance"] == "unknown"
    assert result["access_sinks"][0]["allocation_ref_status"] == "unknown"
    assert result["custom_allocator_state"][0]["state_kind"] == "bump-advance"


class _FakeClient(IDAMCPClient):
    def __init__(self, responses: dict[str, dict]):
        self.responses = responses
        self.calls: list[tuple[str, dict]] = []

    def call_tool(self, tool_name: str, arguments: dict | None = None):
        self.calls.append((tool_name, arguments or {}))
        return self.responses[tool_name]


def test_client_wrappers_normalize_mock_mcp_responses() -> None:
    client = _FakeClient(
        {
            "batch_search_decompiled_patterns": {
                "matches": [
                    {
                        "pattern_id": "copy.sink",
                        "addr": 0x4000,
                        "line": 3,
                        "line_text": "memcpy(a,b,n);",
                    }
                ],
            },
            "list_callsites": {
                "function_ea": 0x4000,
                "function": "DecodeFrame",
                "callsites": [
                    {
                        "ea": 0x4010,
                        "callee": "memcpy",
                        "target_kind": "import",
                        "args": ["dst", "src", "n"],
                    }
                ],
            },
            "extract_function_facts": {
                "function_ea": 0x4000,
                "function": "DecodeFrame",
                "calls": [
                    {
                        "ea": 0x4010,
                        "callee": "memcpy",
                        "target_kind": "import",
                        "args": ["dst", "src", "n"],
                    }
                ],
            },
            "extract_accesses": {
                "function_ea": 0x4000,
                "function": "DecodeFrame",
                "accesses": [
                    {
                        "ea": 0x4020,
                        "expr": "g_registry[key]",
                        "base": "g_registry",
                        "kind": "container-index",
                    }
                ],
            },
            "extract_lock_regions": {
                "function_ea": 0x4000,
                "function": "DecodeFrame",
                "regions": [{"ea": 0x4030, "lock": "mutex", "kind": "explicit-lock"}],
            },
            "extract_carrier_facts": {
                "function_ea": 0x4000,
                "function": "DecodeFrame",
                "carriers": [{"key": "g_registry", "kind": "global-static-registry"}],
            },
            "extract_size_flow_facts": {
                "function_ea": 0x4000,
                "function": "DecodeFrame",
                "size_sources": [
                    {
                        "source_ea": 0x4000,
                        "source_kind": "function-arg",
                        "size_expr": "len",
                    }
                ],
                "size_transforms": [],
                "guards": [],
                "allocation_sinks": [],
                "access_sinks": [
                    {
                        "site_ea": 0x4010,
                        "direction": "write",
                        "sink_kind": "memcpy",
                        "bound_expr": "len",
                    }
                ],
                "custom_allocator_state": [],
            },
        }
    )

    batch = client.batch_search_decompiled_patterns(
        [{"id": "copy.sink", "regex": "memcpy"}]
    )
    calls = client.list_callsites("DecodeFrame")
    facts = client.extract_function_facts("DecodeFrame")
    accesses = client.extract_accesses("DecodeFrame")
    locks = client.extract_lock_regions("DecodeFrame")
    carriers = client.extract_carrier_facts("DecodeFrame")
    size_flow = client.extract_size_flow_facts("DecodeFrame")

    assert batch["schema_version"] == IDA_FACT_SCHEMA_VERSION
    assert calls["callsites"][0]["callee_name"] == "memcpy"
    assert facts["callsites"][0]["target_kind"] == "import"
    assert accesses["accesses"][0]["base"] == "g_registry"
    assert locks["regions"][0]["lock_name"] == "mutex"
    assert carriers["carriers"][0]["key"] == "g_registry"
    assert size_flow["size_sources"][0]["size_expr"] == "len"
    assert size_flow["access_sinks"][0]["sink_kind"] == "memcpy"
    assert [call[0] for call in client.calls] == [
        "batch_search_decompiled_patterns",
        "list_callsites",
        "extract_function_facts",
        "extract_accesses",
        "extract_lock_regions",
        "extract_carrier_facts",
        "extract_size_flow_facts",
    ]
