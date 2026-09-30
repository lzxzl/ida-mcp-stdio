from __future__ import annotations

import sys
from types import ModuleType

from ida_mcp_stdio.tools import analysis

TARGET = "_ZN7android13C2SoftDdpDec7processERK12WorkList"


def _target_symbol() -> dict:
    return {
        "ea": "0x3000",
        "name": TARGET,
        "demangled_name": "android::C2SoftDdpDec::process(WorkList const&)",
        "short_name": "process",
    }


def test_itanium_raw_symbol_supplies_display_name_when_demangle_is_missing():
    assert (
        analysis._ida_function_symbol_display_name(
            "_ZN4OHOS12MediaAVCodec5Codec6FCodec4StopEv",
            "",
        )
        == "OHOS::MediaAVCodec::Codec::FCodec::Stop"
    )
    assert analysis._ida_function_symbol_short_name("FCodec::Stop()", "") == "Stop"


def test_indirect_callsite_row_uses_structural_microcode_opcode(monkeypatch):
    ida_hexrays = ModuleType("ida_hexrays")
    ida_hexrays.m_icall = 57
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setattr(analysis, "_MICROCODE_OPCODE_NAMES", None)

    assert analysis._microcode_opcode_name(57) == "m_icall"
    assert analysis._indirect_callsite_row_is_indirect(
        {"opcode_name": "m_icall"},
        "mov v1.8, v2.8",
    )


def test_indirect_callsite_diagnostic_rows_report_true_indirect_only():
    rows = [
        {
            "index": 0,
            "ea": "0x2100",
            "opcode_name": "m_call",
            "text": "call $.__cfi_slowpath <fast:_QWORD #-1.8>",
        },
        {
            "index": 1,
            "ea": "0x2200",
            "opcode_name": "m_icall",
            "text": "mov v1.8, v2.8",
            "operands": ["[vptr+#0x88]", "", ""],
        },
    ]

    result = analysis._indirect_callsite_diagnostic_rows(
        rows=rows,
        caller_function="android::C2SoftDdpDec::dispatchWork",
        caller_ea="0x2000",
    )

    assert len(result) == 1
    assert result[0]["site_ea"] == "0x2200"
    assert result[0]["opcode_name"] == "m_icall"
    assert result[0]["indirect_reason"] == "m_icall"


def test_indirect_callsite_slot_evidence_does_not_treat_plain_microcode_pointer_as_vtable_slot():
    evidence = analysis._indirect_callsite_slot_evidence(
        "icall cs.2, [cs.2:([cs.2:v14.8].8+#0x10.8)].8, <fast:_QWORD v14.8> => __int64 .0"
    )

    assert evidence["dispatch_slot_observed"] is False
    assert evidence["exact_vtable_slot_observed"] is False
    assert "slot_offset" not in evidence


def test_indirect_callsite_slot_evidence_prefers_current_icall_offset_with_vtable_context():
    row_text = "icall cs.2, [cs.2:(v11.8+#0x28.8)].8, <fast:_QWORD v9.8> => __int64 .0"
    window_text = "\n".join(
        [
            "mov call !__ROR8__<fast:_QWORD ((v11.8-&($_ZTVN4OHOS5Rosen7Drawing10SkiaBitmapE).8)-#0x950.8),char #5.1>",
            row_text,
        ]
    )

    evidence = analysis._indirect_callsite_slot_evidence(window_text, row_text=row_text)

    assert evidence["dispatch_slot_observed"] is True
    assert evidence["exact_vtable_slot_observed"] is True
    assert evidence["slot_offset"] == "0x28"
    assert evidence["slot_offset_int"] == 0x28


def test_target_entries_accept_itanium_fallback_display_name():
    entries, diagnostics = analysis._indirect_callsite_target_entries(
        function_symbols=[
            {
                "ea": "0x14fc8",
                "name": "_ZN4OHOS12MediaAVCodec5Codec6FCodec4StopEv",
                "demangled_name": "FCodec::Stop",
                "itanium_display_name": "OHOS::MediaAVCodec::Codec::FCodec::Stop",
                "short_name": "Stop",
            }
        ],
        target_method_names=["Stop"],
        class_prefixes=["OHOS::MediaAVCodec::Codec::FCodec"],
    )

    assert diagnostics == []
    assert len(entries) == 1
    assert entries[0]["_target_match_kind"] == "class_scoped_method"


def test_indirect_callsite_row_parser_emits_function_table_callback_raw_fact():
    rows = [
        {
            "index": 0,
            "ea": "0x2200",
            "text": "vptr = _ZTVN7android13C2SoftDdpDecE + #0x20",
        },
        {
            "index": 1,
            "ea": "0x2204",
            "text": "call (*vptr) android::C2SoftDdpDec::process(WorkList const&)",
        },
    ]

    facts, diagnostics = analysis._indirect_callsite_facts_from_microcode_rows(
        rows=rows,
        dispatch_so="libcodec2_soft_ddpdec.so",
        caller_function="Codec2Dispatch",
        caller_ea="0x2000",
        function_symbols=[_target_symbol()],
        target_functions=[TARGET],
        class_prefixes=["android::C2SoftDdpDec"],
        extractor_profile="cpp_vtable_callsite",
    )

    assert diagnostics == []
    assert len(facts) == 1
    fact = facts[0]
    assert fact["kind"] == "function_table_callback"
    assert fact["source_kind"] == "microcode-indirect-callsite"
    assert fact["dispatch_function"] == "Codec2Dispatch"
    assert fact["target_function"] == TARGET
    assert fact["slot_name"] == "0x2204"
    assert fact["identity"]["callsite_ea"] == "0x2204"
    assert fact["identity"]["target_ea"] == "0x3000"
    assert fact["identity"]["slot_offset"] == "0x20"
    assert fact["provenance"]["source"] == "microcode"
    assert (
        fact["provenance"]["extractor_tool"]
        == "extract_indirect_callsite_microcode_facts"
    )
    assert fact["provenance"]["exact_callsite_observed"] is True
    assert fact["provenance"]["exact_vtable_slot_observed"] is True
    assert fact["provenance"]["dispatch_slot_observed"] is True


def test_indirect_callsite_requires_bounded_target_filter():
    facts, diagnostics = analysis._indirect_callsite_facts_from_microcode_rows(
        rows=[{"index": 0, "ea": "0x2204", "text": "call (*vptr)"}],
        dispatch_so="liba.so",
        caller_function="Dispatch",
        caller_ea="0x2000",
        function_symbols=[_target_symbol()],
    )

    assert facts == []
    assert diagnostics[0]["code"] == "target-filter-required"


def test_indirect_callsite_does_not_match_short_name_inside_unrelated_symbol():
    rows = [
        {
            "index": 0,
            "ea": "0x2204",
            "text": "call $.StartTraceArgsEx <fast:_QWORD #1.8> => __int64 .0",
        },
    ]

    facts, diagnostics = analysis._indirect_callsite_facts_from_microcode_rows(
        rows=rows,
        dispatch_so="libfcodec.z.so",
        caller_function="OHOS::MediaAVCodec::Codec::FCodec::ReleaseOutputBuffer",
        caller_ea="0x2000",
        function_symbols=[
            {
                "ea": "0x3000",
                "name": "_ZN4OHOS12MediaAVCodec5Codec6FCodec5StartEv",
                "demangled_name": "OHOS::MediaAVCodec::Codec::FCodec::Start",
                "itanium_display_name": "OHOS::MediaAVCodec::Codec::FCodec::Start",
                "short_name": "Start",
            }
        ],
        target_method_names=["Start"],
        class_prefixes=["OHOS::MediaAVCodec::Codec::FCodec"],
        extractor_profile="cpp_vtable_callsite",
    )

    assert diagnostics == []
    assert facts == []


def test_indirect_callsite_does_not_use_direct_cfi_call_as_static_vtable_edge():
    rows = [
        {
            "index": 0,
            "ea": "0x2200",
            "text": "jz [cs.2:this.8].8, &($__typeid__ZTSN4OHOS12MediaAVCodec5Codec6FCodecE_global_addr).8, @5",
        },
        {
            "index": 1,
            "ea": "0x2204",
            "text": "call $.__cfi_slowpath <fast:_QWORD #-1.8> => __int64 .0",
        },
        {
            "index": 2,
            "ea": "0x2208",
            "text": "add this.8, #0x50.8, v1.8",
        },
    ]

    facts, diagnostics = analysis._indirect_callsite_facts_from_microcode_rows(
        rows=rows,
        dispatch_so="libfcodec.z.so",
        caller_function="OHOS::MediaAVCodec::Codec::FCodec::SetOutputSurface",
        caller_ea="0x2000",
        function_symbols=[
            {
                "ea": "0x3000",
                "name": "_ZN4OHOS12MediaAVCodec5Codec6FCodec5ResetEv",
                "demangled_name": "OHOS::MediaAVCodec::Codec::FCodec::Reset",
                "itanium_display_name": "OHOS::MediaAVCodec::Codec::FCodec::Reset",
                "short_name": "Reset",
            }
        ],
        vtable_entries=[
            {
                "vtable_symbol": "_ZTVN4OHOS12MediaAVCodec5Codec6FCodecE",
                "class_name": "OHOS::MediaAVCodec::Codec::FCodec",
                "vtable_entry_offset": "0x50",
                "address_point_adjusted_offset": "0x40",
                "target_ea": "0x3000",
                "target_function": "_ZN4OHOS12MediaAVCodec5Codec6FCodec5ResetEv",
                "target_demangled_name": "OHOS::MediaAVCodec::Codec::FCodec::Reset",
                "target_short_name": "Reset",
            }
        ],
        target_method_names=["Reset"],
        class_prefixes=["OHOS::MediaAVCodec::Codec::FCodec"],
        extractor_profile="cpp_vtable_callsite",
    )

    assert diagnostics == []
    assert facts == []


def test_indirect_callsite_does_not_match_target_symbol_only_in_nearby_context():
    rows = [
        {
            "index": 0,
            "ea": "0x2200",
            "text": "call $._ZN7android12C2SoftDdpDec28setMultiChannelPCMOutDownmixEv <fast:this.8>",
        },
        {
            "index": 1,
            "ea": "0x2204",
            "text": "icall cs.2, [cs.2:(v7.8+#0x10.8)].8, <fast:v7.8> => __int64 .0",
        },
    ]

    facts, diagnostics = analysis._indirect_callsite_facts_from_microcode_rows(
        rows=rows,
        dispatch_so="libcodec2_soft_ddpdec.so",
        caller_function="android::C2SoftDdpDec::initDecoder",
        caller_ea="0x2000",
        function_symbols=[
            {
                "ea": "0x3000",
                "name": "_ZN7android12C2SoftDdpDec28setMultiChannelPCMOutDownmixEv",
                "demangled_name": "android::C2SoftDdpDec::setMultiChannelPCMOutDownmix",
                "short_name": "setMultiChannelPCMOutDownmix",
            }
        ],
        target_method_names=["setMultiChannelPCMOutDownmix"],
        class_prefixes=["android::C2SoftDdpDec"],
        extractor_profile="cpp_vtable_callsite",
    )

    assert diagnostics == []
    assert facts == []


def test_indirect_callsite_row_parser_resolves_static_vtable_slot_without_target_text():
    rows = [
        {
            "index": 0,
            "ea": "0x2204",
            "text": "call (*(_QWORD *)this + 0x88)(this, work)",
        },
    ]

    facts, diagnostics = analysis._indirect_callsite_facts_from_microcode_rows(
        rows=rows,
        dispatch_so="libcodec2_soft_ddpdec.so",
        caller_function="android::C2SoftDdpDec::dispatchWork",
        caller_ea="0x2000",
        function_symbols=[_target_symbol()],
        vtable_entries=[
            {
                "vtable_ea": "0x2b0140",
                "vtable_symbol": "_ZTVN7android13C2SoftDdpDecE",
                "vtable_demangled_name": "vtable for android::C2SoftDdpDec",
                "class_name": "android::C2SoftDdpDec",
                "slot_index": 19,
                "itanium_slot_index": 17,
                "vtable_entry_offset": "0x98",
                "address_point_adjusted_offset": "0x88",
                "target_ea": "0x3000",
                "target_function": TARGET,
                "target_demangled_name": "android::C2SoftDdpDec::process(WorkList const&)",
                "target_short_name": "process",
            }
        ],
        target_functions=[TARGET],
        class_prefixes=["android::C2SoftDdpDec"],
        extractor_profile="cpp_vtable_callsite",
    )

    assert diagnostics == []
    assert len(facts) == 1
    fact = facts[0]
    assert fact["target_function"] == TARGET
    assert fact["identity"]["slot_offset"] == "0x88"
    assert fact["identity"]["vtable_entry_offset"] == "0x98"
    assert fact["provenance"]["match_kind"] == "static-vtable-slot"
    assert fact["provenance"]["exact_vtable_slot_observed"] is True
    assert fact["provenance"]["vtable_slot_resolved_from_static_vtable"] is True
    assert fact["provenance"]["vtable_symbol"] == "_ZTVN7android13C2SoftDdpDecE"


def test_indirect_callsite_row_parser_resolves_icall_slot_from_mangled_class_context():
    target = (
        "_ZN4OHOS5Rosen7Drawing15DDGRColorFilter18InitWithColorFloatEPKfNS1_5ClampE"
    )
    rows = [
        {
            "index": 0,
            "ea": "0x121370",
            "text": 'call $"._ZN4OHOS5Rosen7Drawing15DDGRColorFilterC2Ev" <fast:"OHOS::Rosen::Drawing::DDGRColorFilter *this" v9.8>',
        },
        {
            "index": 1,
            "ea": "0x121390",
            "text": "mov v1.8, v2.8",
        },
        *[
            {
                "index": index,
                "ea": hex(0x121390 + index),
                "text": f"mov v{index}.8, v{index + 1}.8",
            }
            for index in range(2, 6)
        ],
        {
            "index": 6,
            "ea": "0x121396",
            "text": "mov call !__ROR8__<fast:_QWORD ((v11.8-&($_ZTVN4OHOS5Rosen7Drawing10SkiaBitmapE).8)-#0x950.8),char #5.1>",
        },
        *[
            {
                "index": index,
                "ea": hex(0x121390 + index),
                "text": f"mov v{index}.8, v{index + 1}.8",
            }
            for index in range(7, 10)
        ],
        {
            "index": 10,
            "ea": "0x1213a8",
            "opcode_name": "m_icall",
            "text": "icall cs.2, [cs.2:(v11.8+#0x28.8)].8, <fast:_QWORD v9.8,_QWORD f.8> => __int64 .0",
        },
    ]

    facts, diagnostics = analysis._indirect_callsite_facts_from_microcode_rows(
        rows=rows,
        dispatch_so="lib2d_graphics.z.so",
        caller_function="_ZN4OHOS5Rosen7Drawing11ColorFilterC2ENS2_10FilterTypeEPKfNS1_5ClampE",
        caller_ea="0x1212c0",
        function_symbols=[
            {
                "ea": "0x1fbfa8",
                "name": target,
                "demangled_name": "OHOS::Rosen::Drawing::DDGRColorFilter::InitWithColorFloat(float const*,OHOS::Rosen::Drawing::Clamp)",
                "short_name": "InitWithColorFloat",
            }
        ],
        vtable_entries=[
            {
                "vtable_ea": "0x2ea7f0",
                "vtable_symbol": "_ZTVN4OHOS5Rosen7Drawing15DDGRColorFilterE",
                "vtable_demangled_name": "vtable for OHOS::Rosen::Drawing::DDGRColorFilter",
                "class_name": "OHOS::Rosen::Drawing::DDGRColorFilter",
                "slot_index": 7,
                "itanium_slot_index": 5,
                "vtable_entry_offset": "0x38",
                "address_point_adjusted_offset": "0x28",
                "target_ea": "0x1fbfa8",
                "target_function": target,
                "target_demangled_name": "OHOS::Rosen::Drawing::DDGRColorFilter::InitWithColorFloat(float const*,OHOS::Rosen::Drawing::Clamp)",
                "target_short_name": "InitWithColorFloat",
            }
        ],
        target_functions=[target],
        class_prefixes=["OHOS::Rosen::Drawing::DDGRColorFilter"],
        extractor_profile="cpp_vtable_callsite",
    )

    assert diagnostics == []
    assert len(facts) == 1
    fact = facts[0]
    assert fact["dispatch_function"].endswith(
        "ColorFilterC2ENS2_10FilterTypeEPKfNS1_5ClampE"
    )
    assert fact["target_function"] == target
    assert fact["identity"]["slot_offset"] == "0x28"
    assert fact["identity"]["address_point_adjusted_offset"] == "0x28"
    assert fact["provenance"]["match_kind"] == "static-vtable-slot"
    assert fact["provenance"]["exact_vtable_slot_observed"] is True


def test_indirect_callsite_microcode_tool_returns_canonical_raw_fact(monkeypatch):
    ida_hexrays = ModuleType("ida_hexrays")
    idc = ModuleType("idc")
    cfunc = object()
    ida_hexrays.decompile = lambda _ea: cfunc
    idc.get_input_file_path = lambda: "/work/libcodec2_soft_ddpdec.so"
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setitem(sys.modules, "idc", idc)
    monkeypatch.setattr(
        analysis, "_resolve_function", lambda target: (0x2000, str(target))
    )
    monkeypatch.setattr(
        analysis,
        "_microcode_rows",
        lambda _cfunc: (
            [
                {
                    "index": 0,
                    "ea": "0x2200",
                    "text": "vptr = _ZTVN7android13C2SoftDdpDecE + #0x20",
                },
                {
                    "index": 1,
                    "ea": "0x2204",
                    "text": "call (*vptr) android::C2SoftDdpDec::process(WorkList const&)",
                },
            ],
            [],
        ),
    )
    monkeypatch.setattr(
        analysis, "_list_ida_function_symbols", lambda: [_target_symbol()]
    )

    result = analysis.extract_indirect_callsite_microcode_facts(
        caller_funcs=["Codec2Dispatch"],
        target_functions=[TARGET],
        class_prefixes=["android::C2SoftDdpDec"],
        extractor_profile="cpp_vtable_callsite",
    )

    assert result["tool"] == "extract_indirect_callsite_microcode_facts"
    assert result["source"] == "ida_hexrays_microcode"
    assert result["raw_facts"][0]["kind"] == "function_table_callback"
    assert result["raw_facts"][0]["target_function"] == TARGET
    assert result["raw_facts"][0]["provenance"]["source"] == "microcode"
    assert result["raw_facts"][0]["provenance"]["exact_vtable_slot_observed"] is True


def test_list_indirect_callsite_microcode_rows_tool_returns_diagnostics(monkeypatch):
    ida_hexrays = ModuleType("ida_hexrays")
    cfunc = object()
    ida_hexrays.decompile = lambda _ea: cfunc
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setattr(
        analysis, "_resolve_function", lambda target: (0x2000, str(target))
    )
    monkeypatch.setattr(
        analysis,
        "_microcode_rows",
        lambda _cfunc: (
            [
                {
                    "index": 0,
                    "ea": "0x2204",
                    "opcode_name": "m_icall",
                    "text": "icall cs.2, [cs.2:(v7.8+#0x10.8)].8, <fast:v7.8> => __int64 .0",
                    "operands": ["cs.2", "[cs.2:(v7.8+#0x10.8)].8", ""],
                },
            ],
            [],
        ),
    )

    result = analysis.list_indirect_callsite_microcode_rows(
        caller_funcs=["Codec2Dispatch"],
    )

    assert result["tool"] == "list_indirect_callsite_microcode_rows"
    assert result["source"] == "ida_hexrays_microcode"
    assert result["functions"][0]["indirect_row_count"] == 1
    assert result["rows"][0]["dispatch_function"] == "Codec2Dispatch"
    assert result["rows"][0]["site_ea"] == "0x2204"
    assert result["rows"][0]["opcode_name"] == "m_icall"


def test_list_vtable_slot_entries_filters_by_class_target_and_offset(monkeypatch):
    monkeypatch.setattr(
        analysis, "_list_ida_function_symbols", lambda: [_target_symbol()]
    )
    monkeypatch.setattr(
        analysis,
        "_list_ida_vtable_slot_entries",
        lambda _symbols, max_entries_per_vtable=128: [
            {
                "vtable_ea": "0x5000",
                "vtable_symbol": "_ZTVN7android13C2SoftDdpDecE",
                "vtable_demangled_name": "vtable for android::C2SoftDdpDec",
                "class_name": "android::C2SoftDdpDec",
                "slot_index": 4,
                "vtable_entry_offset": "0x30",
                "address_point_adjusted_offset": "0x20",
                "target_ea": "0x3000",
                "target_function": TARGET,
                "target_demangled_name": "android::C2SoftDdpDec::process(WorkList const&)",
                "target_short_name": "process",
            },
            {
                "vtable_ea": "0x6000",
                "vtable_symbol": "_ZTVN7android5OtherE",
                "class_name": "android::Other",
                "vtable_entry_offset": "0x30",
                "address_point_adjusted_offset": "0x20",
                "target_function": "android::Other::process",
            },
        ],
    )

    result = analysis.list_vtable_slot_entries(
        class_prefixes=["android::C2SoftDdpDec"],
        target_functions=[TARGET],
        slot_offsets=["0x20"],
    )

    assert result["tool"] == "list_vtable_slot_entries"
    assert result["source"] == "ida_names_vtable_slots"
    assert result["entry_count"] == 1
    assert result["entries"][0]["target_function"] == TARGET


def test_vtable_callsite_decompile_tool_extracts_typed_slot(monkeypatch):
    class CFunc:
        def __str__(self):
            return "\n".join(
                [
                    "__int64 __fastcall GetSurfaceBufferStride(void *this)",
                    "{",
                    "  OHOS::SurfaceBuffer *refs;",
                    "  refs = (OHOS::SurfaceBuffer *)this->surfaceBuffer_.refs_;",
                    "  v3 = *(_QWORD *)refs;",
                    "  v4 = (*(__int64 (__fastcall **)(OHOS::SurfaceBuffer *))(v3 + 64))(refs);",
                    "}",
                ]
            )

    ida_hexrays = ModuleType("ida_hexrays")
    ida_hexrays.decompile = lambda _ea: CFunc()
    idc = ModuleType("idc")
    idc.get_input_file_path = lambda: "/work/libfcodec.z.so"
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setitem(sys.modules, "idc", idc)
    monkeypatch.setattr(
        analysis, "_resolve_function", lambda target: (0x2FA44, str(target))
    )

    result = analysis.extract_vtable_callsite_decompile_facts(
        caller_funcs=["OHOS::MediaAVCodec::FSurfaceMemory::GetSurfaceBufferStride"],
        receiver_type_prefixes=["OHOS::SurfaceBuffer"],
        slot_offsets=["0x40"],
    )

    assert result["tool"] == "extract_vtable_callsite_decompile_facts"
    assert result["callsite_count"] == 1
    callsite = result["callsites"][0]
    assert callsite["dispatch_so"] == "libfcodec.z.so"
    assert callsite["slot_offset"] == "0x40"
    assert callsite["receiver_expr"] == "refs"
    assert callsite["receiver_type"] == "OHOS::SurfaceBuffer"
    assert callsite["provenance"]["pattern"] == "pseudocode_cpp_vtable_callsite"


def test_indirect_callsite_microcode_tool_rejects_unsupported_profile():
    result = analysis.extract_indirect_callsite_microcode_facts(
        caller_funcs=["Caller"],
        target_functions=[TARGET],
        extractor_profile="profile-that-does-not-exist",
    )

    assert result["raw_facts"] == []
    assert result["partial"] is True
    assert result["diagnostics"][0]["code"] == "unsupported-extractor-profile"
