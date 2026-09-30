from __future__ import annotations

import sys
from types import ModuleType

from ida_mcp_stdio.tools import analysis


def test_selector_dispatch_row_parser_emits_generic_raw_fact():
    rows = [
        {"index": 0, "ea": "0x1100", "text": "std::__tree::__emplace_unique_key_args"},
        {"index": 1, "ea": "0x1104", "text": "#3052"},
        {
            "index": 2,
            "ea": "0x1108",
            "text": "_ZN4OHOS9Telephony7HRilIms16VowifiImsaMapconEP7HdfSBuf",
        },
    ]
    facts = analysis._selector_dispatch_facts_from_microcode_rows(
        rows=rows,
        dispatch_so="libhril_ext.z.so",
        dispatch_function="DispatchRequestExt",
        registration_function="InitMap",
        function_symbols=[
            {
                "name": "_ZN4OHOS9Telephony7HRilIms16VowifiImsaMapconEP7HdfSBuf",
                "demangled_name": "OHOS::Telephony::HRilIms::VowifiImsaMapcon(HdfSBuf*)",
                "short_name": "VowifiImsaMapcon",
            }
        ],
        expected_selectors={3052},
        handler_prefixes=["_ZN4OHOS9Telephony7HRil"],
    )

    assert facts == [
        {
            "kind": "selector_dispatch_entry",
            "dispatch_so": "libhril_ext.z.so",
            "dispatch_function": "DispatchRequestExt",
            "target_so": "libhril_ext.z.so",
            "target_function": "_ZN4OHOS9Telephony7HRilIms16VowifiImsaMapconEP7HdfSBuf",
            "selector": 3052,
            "selector_source": "registration-key",
            "confidence": 0.9,
            "provenance": {
                "source": "microcode",
                "pattern": "microcode_selector_dispatch_registration",
                "extractor_profile": "generic_selector_dispatch",
                "registration_function": "InitMap",
                "microcode_row": 1,
                "function_ea": None,
                "site_ea": "0x1104",
                "registration_marker_observed": True,
                "handler_evidence_kind": "ida-function-symbol",
                "handler_evidence_token": "_ZN4OHOS9Telephony7HRilIms16VowifiImsaMapconEP7HdfSBuf",
                "window_start": 0,
                "window_end": 3,
            },
        }
    ]


def test_selector_dispatch_row_parser_accepts_target_function_filter_without_prefix():
    handler = (
        "_ZN4OHOS9Telephony12HRilBooster21ApDsFlowInfoReportIndEi13HRilErrNumberPKvm"
    )
    facts = analysis._selector_dispatch_facts_from_microcode_rows(
        rows=[
            {
                "index": 0,
                "ea": "0x1100",
                "text": "std::__tree::__emplace_unique_key_args",
            },
            {"index": 1, "ea": "0x1104", "text": "#4212"},
            {"index": 2, "ea": "0x1108", "text": handler},
        ],
        dispatch_so="libhril_ext.z.so",
        dispatch_function="DispatchRequestExt",
        registration_function="AddBoosterNotificationToMap",
        function_symbols=[
            {
                "name": handler,
                "demangled_name": "OHOS::Telephony::HRilBooster::ApDsFlowInfoReportInd(int, HRilErrNumber, void const*, unsigned long)",
                "short_name": "ApDsFlowInfoReportInd",
            }
        ],
        expected_selectors={4212},
        handler_prefixes=[],
        target_functions=["ApDsFlowInfoReportInd"],
    )

    assert len(facts) == 1
    assert facts[0]["target_function"] == handler
    assert facts[0]["selector"] == 4212


def test_selector_dispatch_row_parser_bounds_repeated_registration_blocks():
    ap_handler = (
        "_ZN4OHOS9Telephony11HRilBooster21ApDsFlowInfoReportIndEi13HRilErrNumberPKvm"
    )
    other_handler = "_ZN4OHOS9Telephony11HRilBooster18OtherReportIndEv"
    facts = analysis._selector_dispatch_facts_from_microcode_rows(
        rows=[
            {
                "index": 0,
                "ea": "0x1100",
                "text": "std::__tree::__emplace_unique_key_args",
            },
            {"index": 1, "ea": "0x1104", "text": "#4201"},
            {"index": 2, "ea": "0x1108", "text": other_handler},
            {
                "index": 3,
                "ea": "0x110c",
                "text": "std::__tree::__emplace_unique_key_args",
            },
            {"index": 4, "ea": "0x1110", "text": "#4212"},
            {"index": 5, "ea": "0x1114", "text": ap_handler},
        ],
        dispatch_so="libhril_ext.z.so",
        dispatch_function="OnDataServiceReport",
        registration_function="AddBoosterNotificationToMap",
        function_symbols=[
            {
                "name": other_handler,
                "demangled_name": "OHOS::Telephony::HRilBooster::OtherReportInd()",
                "short_name": "OtherReportInd",
            },
            {
                "name": ap_handler,
                "demangled_name": (
                    "OHOS::Telephony::HRilBooster::ApDsFlowInfoReportInd"
                    "(int, HRilErrNumber, void const*, unsigned long)"
                ),
                "short_name": "ApDsFlowInfoReportInd",
            },
        ],
        target_functions=["ApDsFlowInfoReportInd"],
    )

    assert [fact["selector"] for fact in facts] == [4212]
    assert facts[0]["target_function"] == ap_handler
    assert facts[0]["provenance"]["window_start"] == 3
    assert facts[0]["provenance"]["window_end"] == 6


def test_selector_dispatch_row_parser_emits_compatible_dispatch_scoped_entry():
    handler = (
        "_ZN4OHOS9Telephony11HRilBooster21ApDsFlowInfoReportIndEi13HRilErrNumberPKvm"
    )
    facts = analysis._selector_dispatch_facts_from_microcode_rows(
        rows=[
            {
                "index": 0,
                "ea": "0x1100",
                "text": "std::__tree::__emplace_unique_key_args",
            },
            {"index": 1, "ea": "0x1104", "text": "#4212"},
            {"index": 2, "ea": "0x1108", "text": handler},
        ],
        dispatch_so="libhril_ext.z.so",
        dispatch_function="DispatchRequestExt",
        dispatch_functions=[
            "DispatchRequestExt",
            "OnCardReport",
            "OnDataServiceReport",
        ],
        registration_function="AddBoosterNotificationToMap",
        function_symbols=[
            {
                "name": handler,
                "demangled_name": (
                    "OHOS::Telephony::HRilBooster::ApDsFlowInfoReportInd"
                    "(int, HRilErrNumber, void const*, unsigned long)"
                ),
                "short_name": "ApDsFlowInfoReportInd",
            }
        ],
        target_functions=["ApDsFlowInfoReportInd"],
        emit_registration_partial=True,
    )

    entries = [fact for fact in facts if fact["kind"] == "selector_dispatch_entry"]
    partials = [
        fact for fact in facts if fact["kind"] == "selector_dispatch_registration"
    ]
    assert len(partials) == 1
    assert [entry["dispatch_function"] for entry in entries] == ["OnDataServiceReport"]
    assert entries[0]["target_function"] == handler
    assert (
        entries[0]["provenance"]["pattern"]
        == "microcode_selector_dispatch_registration_with_dispatch_scope"
    )


def test_selector_dispatch_row_parser_recovers_type_erased_member_function_reference():
    handler = (
        "_ZN4OHOS9Telephony11HRilBooster21ApDsFlowInfoReportIndEi13HRilErrNumberPKvm"
    )
    rows = [
        {"index": 0, "ea": "0x1100", "text": "std::__tree::__emplace_unique_key_args"},
        {"index": 1, "ea": "0x1104", "text": "#4212"},
        *[
            {
                "index": index,
                "ea": hex(0x1100 + index * 4),
                "text": f"tmp_{index} = std::any helper",
            }
            for index in range(2, 34)
        ],
        {
            "index": 34,
            "ea": "0x1188",
            "text": "std::any::__any_imp::SmallHandler<void (OHOS::Telephony::HRilBooster::*)(int)>",
        },
        {
            "index": 35,
            "ea": "0x118c",
            "text": "&OHOS::Telephony::HRilBooster::ApDsFlowInfoReportInd",
        },
    ]

    facts = analysis._selector_dispatch_facts_from_microcode_rows(
        rows=rows,
        dispatch_so="libhril_ext.z.so",
        dispatch_function="OnDataServiceReport",
        registration_function="AddBoosterNotificationToMap",
        function_symbols=[
            {
                "name": handler,
                "demangled_name": (
                    "OHOS::Telephony::HRilBooster::ApDsFlowInfoReportInd"
                    "(int, HRilErrNumber, void const*, unsigned long)"
                ),
                "short_name": "ApDsFlowInfoReportInd",
            }
        ],
        expected_selectors={4212},
        target_functions=["ApDsFlowInfoReportInd"],
    )

    assert len(facts) == 1
    assert facts[0]["target_function"] == handler
    assert facts[0]["provenance"]["handler_evidence_token"] == "ApDsFlowInfoReportInd"
    assert facts[0]["provenance"]["window_end"] == len(rows)


def test_selector_dispatch_row_parser_does_not_use_type_erased_wrapper_as_handler():
    diagnostics: list[dict] = []
    facts = analysis._selector_dispatch_facts_from_microcode_rows(
        rows=[
            {
                "index": 0,
                "ea": "0x1100",
                "text": "std::__tree::__emplace_unique_key_args",
            },
            {"index": 1, "ea": "0x1104", "text": "#4212"},
            {
                "index": 2,
                "ea": "0x1108",
                "text": "std::any::__any_imp::SmallHandler<void (OHOS::Telephony::HRilBooster::*)(int)>",
            },
        ],
        dispatch_so="libhril_ext.z.so",
        dispatch_function="OnDataServiceReport",
        registration_function="AddBoosterNotificationToMap",
        function_symbols=[],
        expected_selectors={4212},
        target_functions=["ApDsFlowInfoReportInd"],
        diagnostics_out=diagnostics,
    )

    assert facts == []
    assert (
        diagnostics[0]["code"] == "unresolved_type_erased_member_function_registration"
    )
    assert diagnostics[0]["selectors"] == [4212]


def test_selector_dispatch_row_parser_does_not_treat_target_filter_as_proof():
    handler = (
        "_ZN4OHOS9Telephony11HRilBooster21ApDsFlowInfoReportIndEi13HRilErrNumberPKvm"
    )
    facts = analysis._selector_dispatch_facts_from_microcode_rows(
        rows=[
            {
                "index": 0,
                "ea": "0x1100",
                "text": "std::__tree::__emplace_unique_key_args",
            },
            {"index": 1, "ea": "0x1104", "text": "#4212"},
            {
                "index": 2,
                "ea": "0x1108",
                "text": "std::any stores a member-function payload",
            },
        ],
        dispatch_so="libhril_ext.z.so",
        dispatch_function="OnDataServiceReport",
        registration_function="AddBoosterNotificationToMap",
        function_symbols=[
            {
                "name": handler,
                "demangled_name": (
                    "OHOS::Telephony::HRilBooster::ApDsFlowInfoReportInd"
                    "(int, HRilErrNumber, void const*, unsigned long)"
                ),
                "short_name": "ApDsFlowInfoReportInd",
            }
        ],
        expected_selectors={4212},
        target_functions=["ApDsFlowInfoReportInd"],
    )

    assert facts == []


def test_generic_selector_microcode_tool_does_not_call_legacy_hdf_tool(monkeypatch):
    ida_hexrays = ModuleType("ida_hexrays")
    idc = ModuleType("idc")
    cfunc = object()
    ida_hexrays.decompile = lambda _ea: cfunc
    idc.get_input_file_path = lambda: "/work/libhril_ext.z.so"
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setitem(sys.modules, "idc", idc)
    monkeypatch.setattr(
        analysis, "_resolve_function", lambda target: (0x1000, str(target))
    )
    monkeypatch.setattr(
        analysis,
        "_microcode_rows",
        lambda _cfunc: (
            [
                {
                    "index": 0,
                    "ea": "0x1100",
                    "text": "std::__tree::__emplace_unique_key_args",
                },
                {"index": 1, "ea": "0x1104", "text": "#3052"},
                {
                    "index": 2,
                    "ea": "0x1108",
                    "text": "_ZN4OHOS9Telephony7HRilIms16VowifiImsaMapconEP7HdfSBuf",
                },
            ],
            [],
        ),
    )
    monkeypatch.setattr(
        analysis,
        "_list_ida_function_symbols",
        lambda: [
            {
                "ea": "0x2000",
                "name": "_ZN4OHOS9Telephony7HRilIms16VowifiImsaMapconEP7HdfSBuf",
                "demangled_name": "OHOS::Telephony::HRilIms::VowifiImsaMapcon(HdfSBuf*)",
                "short_name": "VowifiImsaMapcon",
            }
        ],
    )
    monkeypatch.setattr(
        analysis,
        "extract_hdf_ril_dispatch_microcode_facts",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("legacy hdf tool called")
        ),
    )

    result = analysis.extract_selector_dispatch_microcode_facts(
        dispatch_funcs=["DispatchRequestExt"],
        registration_funcs=["InitMap"],
        expected_selectors=[3052],
        handler_prefixes=["_ZN4OHOS9Telephony7HRil"],
    )

    assert result["tool"] == "extract_selector_dispatch_microcode_facts"
    assert result["source"] == "ida_hexrays_microcode"
    assert "source_tool" not in result
    registration_facts = [
        fact
        for fact in result["raw_facts"]
        if fact["kind"] == "selector_dispatch_registration"
    ]
    assert registration_facts
    assert registration_facts[0]["provenance"]["source"] == "microcode"
    assert any(
        fact["kind"] == "selector_dispatch_dispatcher" for fact in result["raw_facts"]
    )


def test_generic_selector_microcode_tool_infers_cpp_handler_family(monkeypatch):
    ida_hexrays = ModuleType("ida_hexrays")
    idc = ModuleType("idc")
    cfunc = object()
    ida_hexrays.decompile = lambda _ea: cfunc
    idc.get_input_file_path = lambda: "/work/libhril_ext.z.so"
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setitem(sys.modules, "idc", idc)
    registration = "_ZN4OHOS9Telephony7HRilIms18AddImsRequestToMapEv"
    handler = "_ZN4OHOS9Telephony7HRilIms16VowifiImsaMapconEP7HdfSBuf"
    monkeypatch.setattr(
        analysis, "_resolve_function", lambda target: (0x1000, str(target))
    )
    monkeypatch.setattr(
        analysis,
        "_microcode_rows",
        lambda _cfunc: (
            [
                {
                    "index": 0,
                    "ea": "0x1100",
                    "text": "std::__tree::__emplace_unique_key_args",
                },
                {"index": 1, "ea": "0x1104", "text": "#3052"},
                {"index": 2, "ea": "0x1108", "text": handler},
            ],
            [],
        ),
    )
    monkeypatch.setattr(
        analysis,
        "_list_ida_function_symbols",
        lambda: [
            {
                "ea": "0x1000",
                "name": registration,
                "demangled_name": "OHOS::Telephony::HRilIms::AddImsRequestToMap()",
                "short_name": "AddImsRequestToMap",
            },
            {
                "ea": "0x2000",
                "name": handler,
                "demangled_name": "OHOS::Telephony::HRilIms::VowifiImsaMapcon(HdfSBuf*)",
                "short_name": "VowifiImsaMapcon",
            },
        ],
    )

    result = analysis.extract_selector_dispatch_microcode_facts(
        dispatch_funcs=["DispatchRequestExt"],
        registration_funcs=[registration],
        expected_selectors=[3052],
        handler_prefixes=[],
    )

    function = result["functions"][0]
    assert function["handler_prefix_source"] == "inferred-registration-family"
    assert "_ZN4OHOS9Telephony7HRilIms" in function["handler_prefixes_used"]
    assert result["raw_facts"][0]["target_function"] == handler
    assert result["raw_facts"][0]["kind"] == "selector_dispatch_registration"


def test_generic_selector_microcode_tool_emits_dispatcher_endpoint(monkeypatch):
    ida_hexrays = ModuleType("ida_hexrays")
    idc = ModuleType("idc")
    cfunc = object()
    ida_hexrays.decompile = lambda _ea: cfunc
    idc.get_input_file_path = lambda: "/work/libdispatch.z.so"
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    monkeypatch.setitem(sys.modules, "idc", idc)
    monkeypatch.setattr(
        analysis, "_resolve_function", lambda target: (0x3000, str(target))
    )
    monkeypatch.setattr(analysis, "_microcode_rows", lambda _cfunc: ([], []))
    monkeypatch.setattr(analysis, "_list_ida_function_symbols", lambda: [])

    result = analysis.extract_selector_dispatch_microcode_facts(
        dispatch_funcs=["DispatchRequestExt"],
        registration_funcs=[],
        expected_selectors=[3052],
    )

    assert result["raw_facts"] == [
        {
            "kind": "selector_dispatch_dispatcher",
            "dispatch_so": "libdispatch.z.so",
            "dispatch_function": "DispatchRequestExt",
            "selector": 3052,
            "selector_source": "configured-selector",
            "confidence": 0.82,
            "provenance": {
                "source": "microcode",
                "pattern": "microcode_selector_dispatch_dispatcher_endpoint",
                "extractor_profile": "generic_selector_dispatch",
                "dispatch_function": "DispatchRequestExt",
                "function_ea": "0x3000",
                "selector_observed_in_dispatch": False,
                "dispatch_function_resolved": True,
            },
        }
    ]
    assert result["functions"][0]["raw_dispatch_endpoint_count"] == 1


def test_generic_selector_microcode_tool_reports_unsupported_profile():
    result = analysis.extract_selector_dispatch_microcode_facts(
        extractor_profile="profile-that-does-not-exist"
    )

    assert result["raw_facts"] == []
    assert result["partial"] is True
    assert result["diagnostics"][0]["code"] == "unsupported-extractor-profile"
