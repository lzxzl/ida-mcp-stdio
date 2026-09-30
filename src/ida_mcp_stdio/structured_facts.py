"""Schema helpers for structured IDA facts.

The helpers in this module intentionally do not import IDA APIs.  They define
the stable payload shape shared by MCP fact-extraction tools, client
wrappers, and mock regression tests.
"""

from __future__ import annotations

from typing import Any

IDA_FACT_SCHEMA_VERSION = "ida-mcp-structured-facts-v1"

BATCH_SEARCH_TOOL = "batch_search_decompiled_patterns"
LIST_CALLSITES_TOOL = "list_callsites"
EXTRACT_FUNCTION_FACTS_TOOL = "extract_function_facts"
EXTRACT_ACCESSES_TOOL = "extract_accesses"
EXTRACT_LOCK_REGIONS_TOOL = "extract_lock_regions"
EXTRACT_CARRIER_FACTS_TOOL = "extract_carrier_facts"
EXTRACT_SIZE_FLOW_FACTS_TOOL = "extract_size_flow_facts"

SYMBOL_QUALITY_VALUES = {
    "exact",
    "demangled",
    "mangled",
    "synthetic",
    "stripped",
    "unknown",
}

TARGET_KIND_VALUES = {
    "direct",
    "indirect",
    "vtable",
    "import",
    "thunk",
    "unknown",
}

CALL_KIND_VALUES = {
    "call",
    "method",
    "operator",
    "unknown",
}

ACCESS_KIND_VALUES = {
    "global",
    "member",
    "container",
    "container-index",
    "handle-map",
    "ref-wrapper",
    "unknown",
}

ACCESS_MODE_VALUES = {
    "read",
    "write",
    "read-write",
    "call",
    "unknown",
}

SIZE_SOURCE_KIND_VALUES = {
    "function-arg",
    "input-buffer",
    "cursor-read",
    "field-load",
    "metadata-length",
    "return-value",
    "unknown",
}

TRUST_BOUNDARY_VALUES = {
    "external-input",
    "ipc-parameter",
    "file-field",
    "network-packet",
    "media-bitstream",
    "parcel-field",
    "jni-arg",
    "system-callback-data",
    "internal-derived",
    "internal-constant",
    "unknown",
}

SIGNEDNESS_VALUES = {
    "signed",
    "unsigned",
    "mixed",
    "unknown",
}

SIZE_TRANSFORM_KIND_VALUES = {
    "add",
    "mul",
    "shift",
    "align",
    "round-up",
    "cast",
    "truncate",
    "realloc-shrink",
    "min",
    "max",
    "subtract",
    "unknown",
}

CONVERSION_KIND_VALUES = {
    "none",
    "sign-extend",
    "zero-extend",
    "truncate",
    "signed-to-unsigned",
    "unsigned-to-signed",
    "reinterpret",
    "unknown",
}

GUARD_KIND_VALUES = {
    "overflow",
    "range",
    "capacity",
    "remaining",
    "null",
    "error-return",
    "clamp",
    "unknown",
}

DOMINANCE_VALUES = {
    "dominates",
    "partial",
    "not-dominates",
    "unknown",
}

ALLOCATION_SINK_KIND_VALUES = {
    "libc",
    "new",
    "realloc",
    "calloc",
    "vector-resize",
    "custom",
    "bump",
    "pool",
    "slab",
    "unknown",
}

ACCESS_SINK_KIND_VALUES = {
    "memcpy",
    "memmove",
    "loop-store",
    "indexed-store",
    "stream-read-into-buffer",
    "decoder-write",
    "unknown",
}

ACCESS_DIRECTION_VALUES = {
    "read",
    "write",
    "unknown",
}

ALLOCATION_REF_STATUS_VALUES = {
    "known",
    "probable",
    "unknown",
    "non-alias",
}

CUSTOM_ALLOCATOR_STATE_KIND_VALUES = {
    "curr-pointer",
    "remaining-capacity",
    "slab-base",
    "slab-end",
    "bump-advance",
    "bump-remaining-check",
    "capacity-check",
    "reset",
    "unknown",
}


class FactSchemaError(ValueError):
    """Raised when a structured fact payload violates the public contract."""


def normalize_batch_search_decompiled_patterns_result(
    raw: dict[str, Any],
    *,
    patterns: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Normalize batch-search output or current single-pattern baseline output."""
    _check_declared_tool(raw, BATCH_SEARCH_TOOL)
    pattern_id_by_regex = {
        str(item.get("regex", "")): str(item.get("id", ""))
        for item in (patterns or [])
        if item.get("id")
    }
    default_pattern_id = _coerce_str(raw.get("pattern_id"))
    if not default_pattern_id and raw.get("pattern") is not None:
        default_pattern_id = pattern_id_by_regex.get(
            str(raw.get("pattern")), str(raw.get("pattern"))
        )

    diagnostics = _normalize_diagnostics(raw.get("diagnostics", []))
    if raw.get("error"):
        diagnostics.append(_diagnostic("tool-error", str(raw["error"])))

    matches = [
        _normalize_pattern_match(match, default_pattern_id=default_pattern_id)
        for match in _coerce_list(raw.get("matches"))
    ]
    payload = {
        "schema_version": IDA_FACT_SCHEMA_VERSION,
        "tool": BATCH_SEARCH_TOOL,
        "matches": matches,
        "count": len(matches),
        "scanned_functions": _coerce_int(raw.get("scanned_functions"), default=0),
        "decompiled_functions": _coerce_int(raw.get("decompiled_functions"), default=0),
        "skipped": _coerce_list(raw.get("skipped")),
        "truncated": bool(raw.get("truncated", False)),
        "diagnostics": diagnostics,
        "partial": bool(raw.get("partial", False))
        or any(item["partial"] for item in matches),
    }
    _raise_if_schema_errors(payload, _schema_errors_batch_search(payload))
    return payload


def normalize_list_callsites_result(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize callsite output while preserving partial/unavailable facts."""
    _check_declared_tool(raw, LIST_CALLSITES_TOOL)
    diagnostics = _normalize_diagnostics(raw.get("diagnostics", []))
    if raw.get("error"):
        diagnostics.append(_diagnostic("tool-error", str(raw["error"])))

    function_ea = _normalize_ea(
        raw.get("function_ea", raw.get("addr", raw.get("resolved_addr")))
    )
    function_name = _coerce_str(
        raw.get("function_name", raw.get("function", raw.get("name")))
    )
    calls = [
        _normalize_callsite_fact(
            item, function_ea=function_ea, function_name=function_name
        )
        for item in _coerce_list(raw.get("callsites", raw.get("calls")))
    ]
    payload = {
        "schema_version": IDA_FACT_SCHEMA_VERSION,
        "tool": LIST_CALLSITES_TOOL,
        "function_ea": function_ea,
        "function_name": function_name,
        "symbol": _normalize_symbol(raw, default_name=function_name),
        "callsites": calls,
        "count": len(calls),
        "diagnostics": diagnostics,
        "partial": bool(raw.get("partial", False))
        or any(item["partial"] for item in calls),
    }
    _raise_if_schema_errors(payload, _schema_errors_list_callsites(payload))
    return payload


def normalize_extract_function_facts_result(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize aggregate function facts used by seed and work-unit planning."""
    _check_declared_tool(raw, EXTRACT_FUNCTION_FACTS_TOOL)
    diagnostics = _normalize_diagnostics(raw.get("diagnostics", []))
    if raw.get("error"):
        diagnostics.append(_diagnostic("tool-error", str(raw["error"])))

    function_ea = _normalize_ea(
        raw.get("function_ea", raw.get("addr", raw.get("resolved_addr")))
    )
    function_name = _coerce_str(
        raw.get("function_name", raw.get("function", raw.get("name")))
    )
    calls = [
        _normalize_callsite_fact(
            item, function_ea=function_ea, function_name=function_name
        )
        for item in _coerce_list(raw.get("callsites", raw.get("calls")))
    ]
    accesses = [
        _normalize_access_fact(item, function_ea=function_ea)
        for item in _coerce_list(raw.get("accesses"))
    ]
    invalidations = [
        _normalize_invalidation_fact(item, function_ea=function_ea)
        for item in _coerce_list(raw.get("invalidations"))
    ]
    locks = [
        _normalize_lock_fact(item, function_ea=function_ea)
        for item in _coerce_list(raw.get("locks"))
    ]
    assignments = [
        _normalize_assignment_fact(item, function_ea=function_ea)
        for item in _coerce_list(raw.get("assignments"))
    ]

    payload = {
        "schema_version": IDA_FACT_SCHEMA_VERSION,
        "tool": EXTRACT_FUNCTION_FACTS_TOOL,
        "function_ea": function_ea,
        "function_name": function_name,
        "symbol": _normalize_symbol(raw, default_name=function_name),
        "callsites": calls,
        "accesses": accesses,
        "invalidations": invalidations,
        "locks": locks,
        "assignments": assignments,
        "globals": _coerce_list(raw.get("globals")),
        "member_fields": _coerce_list(raw.get("member_fields")),
        "string_hints": _coerce_list(raw.get("string_hints", raw.get("strings"))),
        "symbol_hints": _coerce_list(raw.get("symbol_hints")),
        "diagnostics": diagnostics,
        "partial": (
            bool(raw.get("partial", False))
            or any(item["partial"] for item in calls)
            or any(item["partial"] for item in accesses)
            or any(item["partial"] for item in invalidations)
            or any(item["partial"] for item in locks)
            or any(item["partial"] for item in assignments)
        ),
    }
    _raise_if_schema_errors(payload, _schema_errors_extract_function_facts(payload))
    return payload


def normalize_extract_accesses_result(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize generic access facts."""
    _check_declared_tool(raw, EXTRACT_ACCESSES_TOOL)
    diagnostics = _normalize_diagnostics(raw.get("diagnostics", []))
    if raw.get("error"):
        diagnostics.append(_diagnostic("tool-error", str(raw["error"])))
    function_ea = _normalize_ea(
        raw.get("function_ea", raw.get("addr", raw.get("resolved_addr")))
    )
    function_name = _coerce_str(
        raw.get("function_name", raw.get("function", raw.get("name")))
    )
    accesses = [
        _normalize_access_fact(item, function_ea=function_ea)
        for item in _coerce_list(raw.get("accesses"))
    ]
    payload = {
        "schema_version": IDA_FACT_SCHEMA_VERSION,
        "tool": EXTRACT_ACCESSES_TOOL,
        "function_ea": function_ea,
        "function_name": function_name,
        "symbol": _normalize_symbol(raw, default_name=function_name),
        "accesses": accesses,
        "count": len(accesses),
        "diagnostics": diagnostics,
        "partial": bool(raw.get("partial", False))
        or any(item["partial"] for item in accesses),
    }
    _raise_if_schema_errors(payload, _schema_errors_extract_accesses(payload))
    return payload


def normalize_extract_lock_regions_result(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize lock/synchronization region facts."""
    _check_declared_tool(raw, EXTRACT_LOCK_REGIONS_TOOL)
    diagnostics = _normalize_diagnostics(raw.get("diagnostics", []))
    if raw.get("error"):
        diagnostics.append(_diagnostic("tool-error", str(raw["error"])))
    function_ea = _normalize_ea(
        raw.get("function_ea", raw.get("addr", raw.get("resolved_addr")))
    )
    function_name = _coerce_str(
        raw.get("function_name", raw.get("function", raw.get("name")))
    )
    regions = [
        _normalize_lock_region_fact(item, function_ea=function_ea)
        for item in _coerce_list(raw.get("regions", raw.get("locks")))
    ]
    payload = {
        "schema_version": IDA_FACT_SCHEMA_VERSION,
        "tool": EXTRACT_LOCK_REGIONS_TOOL,
        "function_ea": function_ea,
        "function_name": function_name,
        "symbol": _normalize_symbol(raw, default_name=function_name),
        "regions": regions,
        "count": len(regions),
        "diagnostics": diagnostics,
        "partial": bool(raw.get("partial", False))
        or any(item["partial"] for item in regions),
    }
    _raise_if_schema_errors(payload, _schema_errors_extract_lock_regions(payload))
    return payload


def normalize_extract_carrier_facts_result(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize lifecycle carrier aggregate facts."""
    _check_declared_tool(raw, EXTRACT_CARRIER_FACTS_TOOL)
    diagnostics = _normalize_diagnostics(raw.get("diagnostics", []))
    if raw.get("error"):
        diagnostics.append(_diagnostic("tool-error", str(raw["error"])))
    function_ea = _normalize_ea(
        raw.get("function_ea", raw.get("addr", raw.get("resolved_addr")))
    )
    function_name = _coerce_str(
        raw.get("function_name", raw.get("function", raw.get("name")))
    )
    carriers = [
        _normalize_carrier_fact(item, function_ea=function_ea)
        for item in _coerce_list(raw.get("carriers"))
    ]
    payload = {
        "schema_version": IDA_FACT_SCHEMA_VERSION,
        "tool": EXTRACT_CARRIER_FACTS_TOOL,
        "function_ea": function_ea,
        "function_name": function_name,
        "symbol": _normalize_symbol(raw, default_name=function_name),
        "carriers": carriers,
        "count": len(carriers),
        "diagnostics": diagnostics,
        "partial": bool(raw.get("partial", False))
        or any(item["partial"] for item in carriers),
    }
    _raise_if_schema_errors(payload, _schema_errors_extract_carrier_facts(payload))
    return payload


def normalize_extract_size_flow_facts_result(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize generic size-flow facts used by OOB/integer-overflow profiles."""
    _check_declared_tool(raw, EXTRACT_SIZE_FLOW_FACTS_TOOL)
    diagnostics = _normalize_diagnostics(raw.get("diagnostics", []))
    if raw.get("error"):
        diagnostics.append(_diagnostic("tool-error", str(raw["error"])))
    function_ea = _normalize_ea(
        raw.get("function_ea", raw.get("addr", raw.get("resolved_addr")))
    )
    function_name = _coerce_str(
        raw.get("function_name", raw.get("function", raw.get("name")))
    )
    size_sources = [
        _normalize_size_source_fact(item, function_ea=function_ea)
        for item in _coerce_list(raw.get("size_sources"))
    ]
    size_transforms = [
        _normalize_size_transform_fact(item, function_ea=function_ea)
        for item in _coerce_list(raw.get("size_transforms"))
    ]
    guards = [
        _normalize_size_guard_fact(item, function_ea=function_ea)
        for item in _coerce_list(raw.get("guards"))
    ]
    allocation_sinks = [
        _normalize_allocation_sink_fact(item, function_ea=function_ea)
        for item in _coerce_list(raw.get("allocation_sinks"))
    ]
    access_sinks = [
        _normalize_access_sink_fact(item, function_ea=function_ea)
        for item in _coerce_list(raw.get("access_sinks"))
    ]
    custom_allocator_state = [
        _normalize_custom_allocator_state_fact(item, function_ea=function_ea)
        for item in _coerce_list(raw.get("custom_allocator_state"))
    ]
    payload = {
        "schema_version": IDA_FACT_SCHEMA_VERSION,
        "tool": EXTRACT_SIZE_FLOW_FACTS_TOOL,
        "function_ea": function_ea,
        "function_name": function_name,
        "symbol": _normalize_symbol(raw, default_name=function_name),
        "size_sources": size_sources,
        "size_transforms": size_transforms,
        "guards": guards,
        "allocation_sinks": allocation_sinks,
        "access_sinks": access_sinks,
        "custom_allocator_state": custom_allocator_state,
        "diagnostics": diagnostics,
        "partial": (
            bool(raw.get("partial", False))
            or any(item["partial"] for item in size_sources)
            or any(item["partial"] for item in size_transforms)
            or any(item["partial"] for item in guards)
            or any(item["partial"] for item in allocation_sinks)
            or any(item["partial"] for item in access_sinks)
            or any(item["partial"] for item in custom_allocator_state)
        ),
    }
    _raise_if_schema_errors(payload, _schema_errors_extract_size_flow_facts(payload))
    return payload


def validate_batch_search_decompiled_patterns_result(
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Validate and return a normalized batch-search payload."""
    normalized = normalize_batch_search_decompiled_patterns_result(payload)
    _raise_if_schema_errors(normalized, _schema_errors_batch_search(normalized))
    return normalized


def validate_list_callsites_result(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate and return a normalized callsite payload."""
    normalized = normalize_list_callsites_result(payload)
    _raise_if_schema_errors(normalized, _schema_errors_list_callsites(normalized))
    return normalized


def validate_extract_function_facts_result(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate and return a normalized aggregate function-facts payload."""
    normalized = normalize_extract_function_facts_result(payload)
    _raise_if_schema_errors(
        normalized, _schema_errors_extract_function_facts(normalized)
    )
    return normalized


def validate_extract_accesses_result(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_extract_accesses_result(payload)
    _raise_if_schema_errors(normalized, _schema_errors_extract_accesses(normalized))
    return normalized


def validate_extract_lock_regions_result(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_extract_lock_regions_result(payload)
    _raise_if_schema_errors(normalized, _schema_errors_extract_lock_regions(normalized))
    return normalized


def validate_extract_carrier_facts_result(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_extract_carrier_facts_result(payload)
    _raise_if_schema_errors(
        normalized, _schema_errors_extract_carrier_facts(normalized)
    )
    return normalized


def validate_extract_size_flow_facts_result(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_extract_size_flow_facts_result(payload)
    _raise_if_schema_errors(
        normalized, _schema_errors_extract_size_flow_facts(normalized)
    )
    return normalized


def _normalize_pattern_match(raw: Any, *, default_pattern_id: str) -> dict[str, Any]:
    item = raw if isinstance(raw, dict) else {"line_text": str(raw)}
    function_name = _coerce_str(
        item.get("function_name", item.get("function", item.get("name")))
    )
    line_no = _coerce_int(item.get("line_no", item.get("line")))
    function_ea = _normalize_ea(
        item.get("function_ea", item.get("addr", item.get("resolved_addr")))
    )
    pattern_id = (
        _coerce_str(item.get("pattern_id", item.get("pattern", default_pattern_id)))
        or "unknown"
    )
    line_text = _coerce_str(item.get("line_text", item.get("line")))
    snippet = _coerce_str(item.get("snippet")) or line_text
    partial = bool(item.get("partial", False)) or function_ea is None or line_no is None
    return {
        "pattern_id": pattern_id,
        "function_ea": function_ea,
        "function_name": function_name,
        "line_no": line_no,
        "match_text": _coerce_str(item.get("match_text", item.get("match"))),
        "line_text": line_text,
        "snippet": snippet,
        "symbol": _normalize_symbol(item, default_name=function_name),
        "source_refs": _normalize_source_refs(item),
        "confidence": _normalize_confidence(
            item.get("confidence"), default=0.75 if partial else 1.0
        ),
        "partial": partial,
        "unavailable_reason": (
            _coerce_str(item.get("unavailable_reason")) if partial else ""
        ),
    }


def _normalize_callsite_fact(
    raw: Any, *, function_ea: str | None, function_name: str
) -> dict[str, Any]:
    item = raw if isinstance(raw, dict) else {"callee": str(raw)}
    callsite_ea = _normalize_ea(
        item.get("callsite_ea", item.get("ea", item.get("site_ea")))
    )
    callee_name = _coerce_str(
        item.get("callee_name", item.get("callee", item.get("target")))
    )
    target_kind = _normalize_choice(item.get("target_kind"), TARGET_KIND_VALUES)
    call_kind = _normalize_choice(item.get("call_kind"), CALL_KIND_VALUES)
    args = _normalize_args(item.get("args", item.get("arguments")))
    unavailable_reason = _coerce_str(item.get("unavailable_reason"))
    partial = (
        bool(item.get("partial", False))
        or callsite_ea is None
        or target_kind == "unknown"
    )
    if not args and not unavailable_reason and item.get("include_args", True):
        unavailable_reason = "args-unavailable"
    return {
        "callsite_ea": callsite_ea,
        "function_ea": _normalize_ea(item.get("function_ea")) or function_ea,
        "function_name": _coerce_str(item.get("function_name")) or function_name,
        "callee_ea": _normalize_ea(item.get("callee_ea", item.get("target_ea"))),
        "callee_name": callee_name,
        "target_kind": target_kind,
        "call_kind": call_kind,
        "args": args,
        "line_no": _coerce_int(item.get("line_no")),
        "line_text": _coerce_str(item.get("line_text", item.get("line"))),
        "snippet": _coerce_str(item.get("snippet")),
        "symbol": _normalize_symbol(item, default_name=callee_name),
        "source_refs": _normalize_source_refs(item),
        "confidence": _normalize_confidence(
            item.get("confidence"), default=0.5 if partial else 1.0
        ),
        "partial": partial,
        "unavailable_reason": (
            unavailable_reason if partial or unavailable_reason else ""
        ),
    }


def _normalize_access_fact(raw: Any, *, function_ea: str | None) -> dict[str, Any]:
    item = raw if isinstance(raw, dict) else {"expr": str(raw)}
    site_ea = _normalize_ea(item.get("site_ea", item.get("ea", item.get("access_ea"))))
    access_kind = _normalize_choice(
        item.get("access_kind", item.get("kind")), ACCESS_KIND_VALUES
    )
    access_mode = _normalize_choice(
        item.get("access", item.get("mode")), ACCESS_MODE_VALUES
    )
    partial = (
        bool(item.get("partial", False)) or site_ea is None or access_kind == "unknown"
    )
    return {
        "site_ea": site_ea,
        "function_ea": _normalize_ea(item.get("function_ea")) or function_ea,
        "expr": _coerce_str(item.get("expr")),
        "base": _coerce_str(item.get("base")),
        "access_kind": access_kind,
        "access": access_mode,
        "index_expr": _coerce_str(item.get("index_expr")),
        "line_no": _coerce_int(item.get("line_no")),
        "line_text": _coerce_str(item.get("line_text", item.get("line"))),
        "source_refs": _normalize_source_refs(item),
        "confidence": _normalize_confidence(
            item.get("confidence"), default=0.5 if partial else 1.0
        ),
        "partial": partial,
        "unavailable_reason": (
            _coerce_str(item.get("unavailable_reason")) if partial else ""
        ),
    }


def _normalize_invalidation_fact(
    raw: Any, *, function_ea: str | None
) -> dict[str, Any]:
    item = raw if isinstance(raw, dict) else {"expr": str(raw)}
    site_ea = _normalize_ea(
        item.get("site_ea", item.get("ea", item.get("callsite_ea")))
    )
    partial = bool(item.get("partial", False)) or site_ea is None
    return {
        "site_ea": site_ea,
        "function_ea": _normalize_ea(item.get("function_ea")) or function_ea,
        "kind": _coerce_str(item.get("kind", item.get("invalidation_kind")))
        or "unknown",
        "target": _coerce_str(item.get("target", item.get("base"))),
        "expr": _coerce_str(item.get("expr")),
        "line_no": _coerce_int(item.get("line_no")),
        "line_text": _coerce_str(item.get("line_text", item.get("line"))),
        "source_refs": _normalize_source_refs(item),
        "confidence": _normalize_confidence(
            item.get("confidence"), default=0.5 if partial else 1.0
        ),
        "partial": partial,
        "unavailable_reason": (
            _coerce_str(item.get("unavailable_reason")) if partial else ""
        ),
    }


def _normalize_lock_fact(raw: Any, *, function_ea: str | None) -> dict[str, Any]:
    item = raw if isinstance(raw, dict) else {"lock_name": str(raw)}
    site_ea = _normalize_ea(item.get("site_ea", item.get("ea", item.get("start_ea"))))
    partial = bool(item.get("partial", False)) or site_ea is None
    return {
        "site_ea": site_ea,
        "function_ea": _normalize_ea(item.get("function_ea")) or function_ea,
        "lock_name": _coerce_str(item.get("lock_name", item.get("lock"))),
        "lock_kind": _coerce_str(item.get("lock_kind", item.get("kind"))) or "unknown",
        "region_start_ea": _normalize_ea(
            item.get("region_start_ea", item.get("start_ea"))
        ),
        "region_end_ea": _normalize_ea(item.get("region_end_ea", item.get("end_ea"))),
        "start_line": _coerce_int(item.get("start_line")),
        "end_line": _coerce_int(item.get("end_line")),
        "unlock_kind": _coerce_str(item.get("unlock_kind")) or "unknown",
        "line_text": _coerce_str(item.get("line_text", item.get("line"))),
        "source_refs": _normalize_source_refs(item),
        "confidence": _normalize_confidence(
            item.get("confidence"), default=0.5 if partial else 1.0
        ),
        "partial": partial,
        "unavailable_reason": (
            _coerce_str(item.get("unavailable_reason")) if partial else ""
        ),
    }


def _normalize_lock_region_fact(raw: Any, *, function_ea: str | None) -> dict[str, Any]:
    item = raw if isinstance(raw, dict) else {"lock_name": str(raw)}
    site_ea = _normalize_ea(item.get("site_ea", item.get("ea", item.get("start_ea"))))
    partial = bool(item.get("partial", False)) or site_ea is None
    return {
        "site_ea": site_ea,
        "function_ea": _normalize_ea(item.get("function_ea")) or function_ea,
        "lock_name": _coerce_str(item.get("lock_name", item.get("lock"))),
        "lock_key": _coerce_str(
            item.get("lock_key", item.get("lock_name", item.get("lock")))
        ),
        "lock_kind": _coerce_str(item.get("lock_kind", item.get("kind"))) or "unknown",
        "region_start_ea": _normalize_ea(
            item.get("region_start_ea", item.get("start_ea"))
        ),
        "region_end_ea": _normalize_ea(item.get("region_end_ea", item.get("end_ea"))),
        "start_line": _coerce_int(item.get("start_line")),
        "end_line": _coerce_int(item.get("end_line")),
        "unlock_kind": _coerce_str(item.get("unlock_kind")) or "unknown",
        "covered_accesses": _coerce_list(item.get("covered_accesses")),
        "covered_site_eas": _coerce_list(item.get("covered_site_eas")),
        "line_text": _coerce_str(item.get("line_text", item.get("line"))),
        "source_refs": _normalize_source_refs(item),
        "confidence": _normalize_confidence(
            item.get("confidence"), default=0.5 if partial else 0.75
        ),
        "partial": partial,
        "unavailable_reason": (
            _coerce_str(item.get("unavailable_reason")) if partial else ""
        ),
    }


def _normalize_assignment_fact(raw: Any, *, function_ea: str | None) -> dict[str, Any]:
    item = raw if isinstance(raw, dict) else {"line_text": str(raw)}
    partial = bool(item.get("partial", False))
    return {
        "function_ea": _normalize_ea(item.get("function_ea")) or function_ea,
        "line_no": _coerce_int(item.get("line_no")),
        "lhs": _coerce_str(item.get("lhs")),
        "rhs": _coerce_str(item.get("rhs")),
        "line_text": _coerce_str(item.get("line_text", item.get("line"))),
        "source_refs": _normalize_source_refs(item),
        "confidence": _normalize_confidence(
            item.get("confidence"), default=0.5 if partial else 0.75
        ),
        "partial": partial,
        "unavailable_reason": (
            _coerce_str(item.get("unavailable_reason")) if partial else ""
        ),
    }


def _normalize_carrier_fact(raw: Any, *, function_ea: str | None) -> dict[str, Any]:
    item = raw if isinstance(raw, dict) else {"key": str(raw)}
    partial = bool(item.get("partial", False))
    site_eas = _coerce_list(item.get("site_eas"))
    if not site_eas:
        site_eas = [
            access.get("site_ea")
            for access in _coerce_list(item.get("accesses"))
            if isinstance(access, dict) and access.get("site_ea")
        ]
    return {
        "key": _coerce_str(item.get("key", item.get("carrier_key"))),
        "kind": _coerce_str(item.get("kind", item.get("carrier_kind"))) or "unknown",
        "function_ea": _normalize_ea(item.get("function_ea")) or function_ea,
        "accesses": _coerce_list(item.get("accesses")),
        "invalidations": _coerce_list(item.get("invalidations")),
        "aliases": _coerce_list(item.get("aliases")),
        "locks": _coerce_list(item.get("locks")),
        "site_eas": site_eas,
        "source_refs": _normalize_source_refs(item),
        "confidence": _normalize_confidence(
            item.get("confidence"), default=0.5 if partial else 0.75
        ),
        "partial": partial,
        "unavailable_reason": (
            _coerce_str(item.get("unavailable_reason")) if partial else ""
        ),
    }


def _normalize_size_source_fact(raw: Any, *, function_ea: str | None) -> dict[str, Any]:
    item = raw if isinstance(raw, dict) else {"size_expr": str(raw)}
    source_ea = _normalize_ea(
        item.get("source_ea", item.get("site_ea", item.get("ea")))
    )
    partial = (
        bool(item.get("partial", False))
        or not _coerce_str(item.get("size_expr"))
        or source_ea is None
    )
    return {
        "source_kind": _normalize_choice(
            item.get("source_kind", item.get("kind")), SIZE_SOURCE_KIND_VALUES
        ),
        "function_ea": _normalize_ea(item.get("function_ea")) or function_ea,
        "source_ea": source_ea,
        "site_ea": _normalize_ea(item.get("site_ea")) or source_ea,
        "size_expr": _coerce_str(item.get("size_expr", item.get("expr"))),
        "source_family_key": _coerce_str(item.get("source_family_key")),
        "width_bits": _coerce_int(item.get("width_bits")),
        "signedness": _normalize_choice(item.get("signedness"), SIGNEDNESS_VALUES),
        "trust_boundary": _normalize_choice(
            item.get("trust_boundary"), TRUST_BOUNDARY_VALUES
        ),
        "line_no": _coerce_int(item.get("line_no")),
        "line_text": _coerce_str(item.get("line_text", item.get("line"))),
        "source_refs": _normalize_source_refs(item),
        "confidence": _normalize_confidence(
            item.get("confidence"), default=0.5 if partial else 0.7
        ),
        "partial": partial,
        "unavailable_reason": (
            _coerce_str(item.get("unavailable_reason")) if partial else ""
        ),
    }


def _normalize_size_transform_fact(
    raw: Any, *, function_ea: str | None
) -> dict[str, Any]:
    item = raw if isinstance(raw, dict) else {"output_expr": str(raw)}
    site_ea = _normalize_ea(item.get("site_ea", item.get("ea")))
    partial = (
        bool(item.get("partial", False))
        or site_ea is None
        or not _coerce_str(item.get("output_expr"))
    )
    return {
        "op_kind": _normalize_choice(
            item.get("op_kind", item.get("kind")), SIZE_TRANSFORM_KIND_VALUES
        ),
        "function_ea": _normalize_ea(item.get("function_ea")) or function_ea,
        "site_ea": site_ea,
        "input_exprs": [
            _coerce_str(expr)
            for expr in _coerce_list(item.get("input_exprs", item.get("inputs")))
        ],
        "output_expr": _coerce_str(item.get("output_expr", item.get("expr"))),
        "input_width_bits": _coerce_int(item.get("input_width_bits")),
        "output_width_bits": _coerce_int(item.get("output_width_bits")),
        "input_signedness": _normalize_choice(
            item.get("input_signedness"), SIGNEDNESS_VALUES
        ),
        "output_signedness": _normalize_choice(
            item.get("output_signedness"), SIGNEDNESS_VALUES
        ),
        "conversion_kind": _normalize_choice(
            item.get("conversion_kind"), CONVERSION_KIND_VALUES
        ),
        "line_no": _coerce_int(item.get("line_no")),
        "line_text": _coerce_str(item.get("line_text", item.get("line"))),
        "source_refs": _normalize_source_refs(item),
        "confidence": _normalize_confidence(
            item.get("confidence"), default=0.5 if partial else 0.65
        ),
        "partial": partial,
        "unavailable_reason": (
            _coerce_str(item.get("unavailable_reason")) if partial else ""
        ),
    }


def _normalize_size_guard_fact(raw: Any, *, function_ea: str | None) -> dict[str, Any]:
    item = raw if isinstance(raw, dict) else {"guard_expr": str(raw)}
    site_ea = _normalize_ea(item.get("site_ea", item.get("ea")))
    partial = bool(item.get("partial", False)) or site_ea is None
    return {
        "guard_kind": _normalize_choice(
            item.get("guard_kind", item.get("kind")), GUARD_KIND_VALUES
        ),
        "function_ea": _normalize_ea(item.get("function_ea")) or function_ea,
        "site_ea": site_ea,
        "guard_expr": _coerce_str(item.get("guard_expr", item.get("expr"))),
        "guarded_exprs": [
            _coerce_str(expr) for expr in _coerce_list(item.get("guarded_exprs"))
        ],
        "dominates_site_eas": [
            _normalize_ea(ea)
            for ea in _coerce_list(item.get("dominates_site_eas"))
            if _normalize_ea(ea)
        ],
        "dominance": _normalize_choice(item.get("dominance"), DOMINANCE_VALUES),
        "guard_scope": _coerce_str(item.get("guard_scope")),
        "line_no": _coerce_int(item.get("line_no")),
        "line_text": _coerce_str(item.get("line_text", item.get("line"))),
        "source_refs": _normalize_source_refs(item),
        "confidence": _normalize_confidence(
            item.get("confidence"), default=0.5 if partial else 0.65
        ),
        "partial": partial,
        "unavailable_reason": (
            _coerce_str(item.get("unavailable_reason")) if partial else ""
        ),
    }


def _normalize_allocation_sink_fact(
    raw: Any, *, function_ea: str | None
) -> dict[str, Any]:
    item = raw if isinstance(raw, dict) else {"size_expr": str(raw)}
    site_ea = _normalize_ea(item.get("site_ea", item.get("ea")))
    partial = (
        bool(item.get("partial", False))
        or site_ea is None
        or not _coerce_str(item.get("size_expr"))
    )
    return {
        "sink_kind": _normalize_choice(
            item.get("sink_kind", item.get("kind")), ALLOCATION_SINK_KIND_VALUES
        ),
        "function_ea": _normalize_ea(item.get("function_ea")) or function_ea,
        "site_ea": site_ea,
        "size_expr": _coerce_str(item.get("size_expr", item.get("expr"))),
        "returned_ptr_expr": _coerce_str(
            item.get("returned_ptr_expr", item.get("lhs"))
        ),
        "capacity_expr": _coerce_str(item.get("capacity_expr")),
        "capacity_relation": _coerce_str(item.get("capacity_relation")),
        "size_width_bits": _coerce_int(item.get("size_width_bits")),
        "capacity_width_bits": _coerce_int(item.get("capacity_width_bits")),
        "overflow_sensitive": bool(item.get("overflow_sensitive", False)),
        "line_no": _coerce_int(item.get("line_no")),
        "line_text": _coerce_str(item.get("line_text", item.get("line"))),
        "source_refs": _normalize_source_refs(item),
        "confidence": _normalize_confidence(
            item.get("confidence"), default=0.5 if partial else 0.7
        ),
        "partial": partial,
        "unavailable_reason": (
            _coerce_str(item.get("unavailable_reason")) if partial else ""
        ),
    }


def _normalize_access_sink_fact(raw: Any, *, function_ea: str | None) -> dict[str, Any]:
    item = raw if isinstance(raw, dict) else {"dest_expr": str(raw)}
    site_ea = _normalize_ea(item.get("site_ea", item.get("ea")))
    partial = bool(item.get("partial", False)) or site_ea is None
    return {
        "direction": _normalize_choice(item.get("direction"), ACCESS_DIRECTION_VALUES),
        "sink_kind": _normalize_choice(
            item.get("sink_kind", item.get("kind")), ACCESS_SINK_KIND_VALUES
        ),
        "function_ea": _normalize_ea(item.get("function_ea")) or function_ea,
        "site_ea": site_ea,
        "source_expr": _coerce_str(item.get("source_expr")),
        "dest_expr": _coerce_str(item.get("dest_expr")),
        "bound_expr": _coerce_str(item.get("bound_expr")),
        "element_width": _coerce_int(item.get("element_width")),
        "allocation_ref": _coerce_str(item.get("allocation_ref")),
        "allocation_ref_status": _normalize_choice(
            item.get("allocation_ref_status"), ALLOCATION_REF_STATUS_VALUES
        ),
        "line_no": _coerce_int(item.get("line_no")),
        "line_text": _coerce_str(item.get("line_text", item.get("line"))),
        "source_refs": _normalize_source_refs(item),
        "confidence": _normalize_confidence(
            item.get("confidence"), default=0.45 if partial else 0.65
        ),
        "partial": partial,
        "unavailable_reason": (
            _coerce_str(item.get("unavailable_reason")) if partial else ""
        ),
    }


def _normalize_custom_allocator_state_fact(
    raw: Any, *, function_ea: str | None
) -> dict[str, Any]:
    item = raw if isinstance(raw, dict) else {"state_expr": str(raw)}
    site_ea = _normalize_ea(item.get("site_ea", item.get("ea")))
    partial = bool(item.get("partial", False)) or site_ea is None
    return {
        "state_kind": _normalize_choice(
            item.get("state_kind", item.get("kind")), CUSTOM_ALLOCATOR_STATE_KIND_VALUES
        ),
        "function_ea": _normalize_ea(item.get("function_ea")) or function_ea,
        "site_ea": site_ea,
        "state_expr": _coerce_str(item.get("state_expr", item.get("expr"))),
        "update_expr": _coerce_str(item.get("update_expr")),
        "line_no": _coerce_int(item.get("line_no")),
        "line_text": _coerce_str(item.get("line_text", item.get("line"))),
        "source_refs": _normalize_source_refs(item),
        "confidence": _normalize_confidence(
            item.get("confidence"), default=0.45 if partial else 0.65
        ),
        "partial": partial,
        "unavailable_reason": (
            _coerce_str(item.get("unavailable_reason")) if partial else ""
        ),
    }


def _normalize_symbol(raw: dict[str, Any], *, default_name: str = "") -> dict[str, Any]:
    nested = raw.get("symbol") if isinstance(raw.get("symbol"), dict) else {}
    raw_name = _coerce_str(
        raw.get(
            "raw_name",
            nested.get(
                "raw_name",
                raw.get("function_name", raw.get("function", raw.get("name"))),
            ),
        )
    )
    raw_name = raw_name or default_name
    demangled_name = _coerce_str(
        raw.get("demangled_name", nested.get("demangled_name"))
    )
    normalized_name = _coerce_str(
        raw.get("normalized_name", nested.get("normalized_name"))
    ) or _normalize_symbol_name(demangled_name or raw_name)
    quality = _normalize_choice(
        raw.get("symbol_quality", nested.get("symbol_quality")), SYMBOL_QUALITY_VALUES
    )
    if quality == "unknown":
        quality = _infer_symbol_quality(raw_name, demangled_name)
    return {
        "raw_name": raw_name,
        "demangled_name": demangled_name,
        "normalized_name": normalized_name,
        "symbol_quality": quality,
    }


def _infer_symbol_quality(raw_name: str, demangled_name: str) -> str:
    if demangled_name:
        return "demangled"
    if not raw_name:
        return "stripped"
    if raw_name.startswith("_Z"):
        return "mangled"
    if raw_name.startswith(("sub_", "loc_", "nullsub_")):
        return "synthetic"
    return "exact"


def _normalize_symbol_name(name: str) -> str:
    name = _coerce_str(name)
    if not name:
        return ""
    for prefix in ("public: ", "private: ", "protected: ", "virtual "):
        name = name.replace(prefix, "")
    return " ".join(name.split())


def _normalize_args(value: Any) -> list[dict[str, Any]]:
    args = _coerce_list(value)
    normalized = []
    for index, item in enumerate(args):
        if isinstance(item, dict):
            expr = _coerce_str(item.get("expr", item.get("value")))
            unavailable_reason = _coerce_str(item.get("unavailable_reason"))
            normalized.append(
                {
                    "index": _coerce_int(item.get("index"), default=index),
                    "expr": expr,
                    "location": _coerce_str(item.get("location")),
                    "unavailable_reason": unavailable_reason,
                }
            )
        else:
            normalized.append(
                {
                    "index": index,
                    "expr": str(item),
                    "location": "",
                    "unavailable_reason": "",
                }
            )
    return normalized


def _normalize_source_refs(raw: dict[str, Any]) -> dict[str, Any]:
    refs = raw.get("source_refs")
    if isinstance(refs, dict):
        result = dict(refs)
    else:
        result = {}
    for key in ("xref_ea", "ctree_item", "disasm_operand", "data_ea"):
        if key in raw and key not in result:
            result[key] = raw[key]
    if "source" in raw and "source" not in result:
        result["source"] = raw["source"]
    return result


def _normalize_diagnostics(value: Any) -> list[dict[str, str]]:
    diagnostics = []
    for item in _coerce_list(value):
        if isinstance(item, dict):
            diagnostics.append(
                {
                    "code": _coerce_str(item.get("code")) or "diagnostic",
                    "message": _coerce_str(item.get("message", item.get("detail"))),
                }
            )
        else:
            diagnostics.append(_diagnostic("diagnostic", str(item)))
    return diagnostics


def _diagnostic(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _schema_errors_batch_search(payload: dict[str, Any]) -> list[str]:
    errors = _schema_errors_common(payload, expected_tool=BATCH_SEARCH_TOOL)
    if not isinstance(payload.get("matches"), list):
        errors.append("matches must be a list")
    for index, item in enumerate(payload.get("matches", [])):
        errors.extend(
            _require_keys(
                item,
                f"matches[{index}]",
                ["pattern_id", "function_ea", "line_no", "snippet"],
            )
        )
    return errors


def _schema_errors_list_callsites(payload: dict[str, Any]) -> list[str]:
    errors = _schema_errors_common(payload, expected_tool=LIST_CALLSITES_TOOL)
    if not isinstance(payload.get("callsites"), list):
        errors.append("callsites must be a list")
    for index, item in enumerate(payload.get("callsites", [])):
        errors.extend(
            _require_keys(
                item, f"callsites[{index}]", ["callsite_ea", "target_kind", "args"]
            )
        )
    return errors


def _schema_errors_extract_function_facts(payload: dict[str, Any]) -> list[str]:
    errors = _schema_errors_common(payload, expected_tool=EXTRACT_FUNCTION_FACTS_TOOL)
    for key in ("callsites", "accesses", "invalidations", "locks", "assignments"):
        if not isinstance(payload.get(key), list):
            errors.append(f"{key} must be a list")
    return errors


def _schema_errors_extract_accesses(payload: dict[str, Any]) -> list[str]:
    errors = _schema_errors_common(payload, expected_tool=EXTRACT_ACCESSES_TOOL)
    if not isinstance(payload.get("accesses"), list):
        errors.append("accesses must be a list")
    return errors


def _schema_errors_extract_lock_regions(payload: dict[str, Any]) -> list[str]:
    errors = _schema_errors_common(payload, expected_tool=EXTRACT_LOCK_REGIONS_TOOL)
    if not isinstance(payload.get("regions"), list):
        errors.append("regions must be a list")
    return errors


def _schema_errors_extract_carrier_facts(payload: dict[str, Any]) -> list[str]:
    errors = _schema_errors_common(payload, expected_tool=EXTRACT_CARRIER_FACTS_TOOL)
    if not isinstance(payload.get("carriers"), list):
        errors.append("carriers must be a list")
    return errors


def _schema_errors_extract_size_flow_facts(payload: dict[str, Any]) -> list[str]:
    errors = _schema_errors_common(payload, expected_tool=EXTRACT_SIZE_FLOW_FACTS_TOOL)
    for key in (
        "size_sources",
        "size_transforms",
        "guards",
        "allocation_sinks",
        "access_sinks",
        "custom_allocator_state",
    ):
        if not isinstance(payload.get(key), list):
            errors.append(f"{key} must be a list")
    return errors


def _schema_errors_common(payload: dict[str, Any], *, expected_tool: str) -> list[str]:
    errors = []
    if payload.get("schema_version") != IDA_FACT_SCHEMA_VERSION:
        errors.append(f"schema_version must be {IDA_FACT_SCHEMA_VERSION}")
    if payload.get("tool") != expected_tool:
        errors.append(f"tool must be {expected_tool}")
    if not isinstance(payload.get("diagnostics"), list):
        errors.append("diagnostics must be a list")
    return errors


def _check_declared_tool(payload: dict[str, Any], expected_tool: str) -> None:
    declared_tool = payload.get("tool")
    if declared_tool and declared_tool != expected_tool:
        raise FactSchemaError(f"tool must be {expected_tool}")


def _require_keys(payload: dict[str, Any], prefix: str, keys: list[str]) -> list[str]:
    errors = []
    for key in keys:
        if key not in payload:
            errors.append(f"{prefix}.{key} is required")
    return errors


def _raise_if_schema_errors(payload: dict[str, Any], errors: list[str]) -> None:
    if errors:
        raise FactSchemaError("; ".join(errors))


def _coerce_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _coerce_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _coerce_int(value: Any, *, default: int | None = None) -> int | None:
    if value is None or value == "":
        return default
    try:
        return int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return default


def _normalize_ea(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return hex(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return hex(int(text, 0))
    except ValueError:
        return text


def _normalize_choice(value: Any, allowed: set[str]) -> str:
    text = _coerce_str(value).strip().lower()
    if text in allowed:
        return text
    return "unknown"


def _normalize_confidence(value: Any, *, default: float) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        confidence = default
    return max(0.0, min(1.0, confidence))
